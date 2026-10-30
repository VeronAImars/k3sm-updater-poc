// peerauth-demo: a scoped proof-of-concept for design gap (2) — per-call peer
// authentication, not per-connection. It demonstrates the MECHANISM (re-validate the
// caller's code identity on every message, not once at accept), not full parity with
// XPC's own guarantee. Real k3sm should use XPC directly and resolve the peer via
// xpc_connection_get_audit_token, not a bare pid: this demo instead looks up the peer by
// pid (getsockopt(LOCAL_PEERPID) + SecCodeCopyGuestWithAttributes), which has a real
// TOCTOU gap XPC's audit token does not — if the peer process exits and the OS recycles
// its pid onto a different process between messages, this demo could authorize the wrong
// process. That is a known, disclosed limitation of this prototype's chosen transport, not
// of the design being proposed (which specifies XPC, not raw sockets, for exactly this
// reason).
//
// Usage:
//   peerauth-demo server <socket-path> <required-identifier>
//   peerauth-demo client <socket-path> <message> [repeat-count]
//
// The attack this proves a fix for: a server that checks the peer's identity only in its
// accept()/connect callback, then trusts every later message on that same connection
// without re-checking, is exactly the shape behind CVE-2019-13013, Sparkle's
// CVE-2026-47122, and Docker Desktop's CVE-2020-15360. This server re-checks on every
// single message instead.

import Foundation
import Security

func fail(_ msg: String) -> Never {
    FileHandle.standardError.write((msg + "\n").data(using: .utf8)!)
    exit(1)
}

// sockaddr_un.sun_path is a fixed-size C array (104 bytes on macOS, null-terminator
// included). strcpy has no bound and would overflow the stack-allocated sockaddr_un if
// given a longer path, so every write into sun_path goes through this instead.
func copySocketPath(_ path: String, into ptr: UnsafeMutablePointer<CChar>, capacity: Int) {
    guard path.utf8.count < capacity else {
        fail("socket path \"\(path)\" is \(path.utf8.count) bytes, too long for sun_path (max \(capacity - 1))")
    }
    _ = path.withCString { strlcpy(ptr, $0, capacity) }
}

// MARK: - getting the connected peer's pid off a Unix domain stream socket

func peerPID(of fd: Int32) -> pid_t? {
    var pid: pid_t = 0
    var len = socklen_t(MemoryLayout<pid_t>.size)
    let rc = getsockopt(fd, SOL_LOCAL, LOCAL_PEERPID, &pid, &len)
    return rc == 0 ? pid : nil
}

// MARK: - the actual per-call check: does the CURRENT peer process satisfy our requirement?

enum AuthResult { case ok, denied(String) }

func checkPeerAuthorized(fd: Int32, requiredIdentifier: String) -> AuthResult {
    guard let pid = peerPID(of: fd) else {
        return .denied("could not determine peer pid")
    }

    var code: SecCode?
    let attrs = [kSecGuestAttributePid as String: pid] as CFDictionary
    let copyStatus = SecCodeCopyGuestWithAttributes(nil, attrs, [], &code)
    guard copyStatus == errSecSuccess, let code else {
        return .denied("SecCodeCopyGuestWithAttributes failed (\(copyStatus)) for pid \(pid)")
    }

    // The requirement: the peer's own embedded identifier (set via `codesign -i`) must
    // match exactly what we expect for a legitimate k3sm-app caller. A real deployment
    // would anchor this to the Apple Developer ID chain + Team ID, same as the binary
    // verification step — this demo isolates just the per-call re-check mechanism.
    var requirement: SecRequirement?
    let reqString = "identifier \"\(requiredIdentifier)\"" as CFString
    guard SecRequirementCreateWithString(reqString, [], &requirement) == errSecSuccess,
          let requirement else {
        return .denied("could not build the requirement")
    }

    let validity = SecCodeCheckValidity(code, [], requirement)
    if validity == errSecSuccess {
        return .ok
    }
    return .denied("SecCodeCheckValidity rejected pid \(pid): status \(validity)")
}

// MARK: - server: accepts one connection, re-checks the peer on EVERY line it sends

func runServer(socketPath: String, requiredIdentifier: String) {
    unlink(socketPath)
    let listenFD = socket(AF_UNIX, SOCK_STREAM, 0)
    guard listenFD >= 0 else { fail("socket() failed") }

    var addr = sockaddr_un()
    addr.sun_family = sa_family_t(AF_UNIX)
    withUnsafeMutablePointer(to: &addr.sun_path) { ptr in
        ptr.withMemoryRebound(to: CChar.self, capacity: 104) { cptr in
            copySocketPath(socketPath, into: cptr, capacity: 104)
        }
    }
    let addrSize = socklen_t(MemoryLayout<sockaddr_un>.size)
    let bindResult = withUnsafePointer(to: &addr) {
        $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { bind(listenFD, $0, addrSize) }
    }
    guard bindResult == 0 else { fail("bind() failed") }
    guard listen(listenFD, 4) == 0 else { fail("listen() failed") }

    print("server: listening on \(socketPath), requiring identifier=\(requiredIdentifier)")

    let connFD = accept(listenFD, nil, nil)
    guard connFD >= 0 else { fail("accept() failed") }
    print("server: connection accepted (NOT yet trusted — every message gets its own check)")

    let fh = FileHandle(fileDescriptor: connFD)
    var buffer = Data()
    while true {
        let chunk = fh.availableData
        if chunk.isEmpty { break } // peer closed
        buffer.append(chunk)
        while let nlRange = buffer.range(of: Data([0x0A])) {
            let lineData = buffer.subdata(in: buffer.startIndex..<nlRange.lowerBound)
            buffer.removeSubrange(buffer.startIndex..<nlRange.upperBound)
            let line = String(data: lineData, encoding: .utf8) ?? "<binary>"

            // THE per-call check — run again for this specific message, not cached from
            // whatever was true when the connection was first accepted.
            switch checkPeerAuthorized(fd: connFD, requiredIdentifier: requiredIdentifier) {
            case .ok:
                print("server: ACCEPTED message (peer re-verified this call): \(line)")
            case .denied(let reason):
                print("server: REJECTED message (peer failed per-call check: \(reason)): \(line)")
            }
        }
    }
    print("server: peer disconnected")
}

// MARK: - client: connects once, then sends N messages on the SAME connection

func runClient(socketPath: String, message: String, repeatCount: Int) {
    let fd = socket(AF_UNIX, SOCK_STREAM, 0)
    guard fd >= 0 else { fail("socket() failed") }
    var addr = sockaddr_un()
    addr.sun_family = sa_family_t(AF_UNIX)
    withUnsafeMutablePointer(to: &addr.sun_path) { ptr in
        ptr.withMemoryRebound(to: CChar.self, capacity: 104) { cptr in
            copySocketPath(socketPath, into: cptr, capacity: 104)
        }
    }
    let addrSize = socklen_t(MemoryLayout<sockaddr_un>.size)
    let connectResult = withUnsafePointer(to: &addr) {
        $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { connect(fd, $0, addrSize) }
    }
    guard connectResult == 0 else { fail("connect() failed — is the server running?") }

    for i in 0..<repeatCount {
        let line = "\(message) #\(i)\n"
        _ = line.withCString { write(fd, $0, strlen($0)) }
        usleep(20_000)
    }
    close(fd)
}

// MARK: - entry point

let args = CommandLine.arguments
guard args.count >= 3 else {
    fail("usage: peerauth-demo server <socket-path> <required-identifier> | client <socket-path> <message> [repeat-count]")
}

switch args[1] {
case "server":
    runServer(socketPath: args[2], requiredIdentifier: args.count > 3 ? args[3] : "com.k3sm.legit-client")
case "client":
    let repeatCount = args.count > 4 ? Int(args[4]) ?? 3 : 3
    runClient(socketPath: args[2], message: args.count > 3 ? args[3] : "ping", repeatCount: repeatCount)
default:
    fail("unknown mode \(args[1])")
}
