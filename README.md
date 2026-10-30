# k3sm-updater-poc

Standalone proofs-of-concept for a proposed privileged-updater design for
[k3sm](https://github.com/k3sm-io/k3sm) (Kubernetes for macOS, natively). Not a
drop-in implementation and not affiliated with the k3sm-io project — each package
here validates one specific property of the design, in isolation and (for the Go
packages) wired together, so the proposal is backed by working code and passing
tests rather than description alone.

See the design proposal: k3sm-io/k3sm#\<issue-number\>.

## Packages

| Package | Proves |
|---|---|
| `versionfloor` | A validly-signed candidate at or below the currently installed version is refused (rollback/freeze protection) |
| `clustersig` | A minimal pinned-root → certified-signer-key → artifact-signature chain (Ed25519 only) correctly accepts a valid chain and rejects a wrong root, an expired cert, a tampered digest, and a fully forged chain |
| `atomicswitch` | A versioned-folder promotion via a single atomic `rename(2)` of a `current` symlink survives 200 real `kill -9`s mid-switch with no corrupted state |
| `safetar` | A tar-extraction guard refuses path traversal, absolute paths, and any symlink/hardlink entry — including the exact shape of Sparkle's real CVE-2026-47121 — verified by both targeted tests and a 50k+-execution fuzz run |
| `healthgate` | The post-switch health verdict is owned by an independent probe, not the newly-installed process's own self-report — a build that self-reports healthy while the probe never succeeds is still rolled back |
| `integration` | The five packages above wired into one `ApplyUpdate` pipeline, proving correct ordering (a rejection at any stage leaves disk untouched past that point) and that a failed health check **actually** flips the live version back, not just returns an error |
| `peerauth-demo` | A scoped demonstration (Swift, macOS Security framework) of per-call peer authentication over a long-lived connection — one process's messages are accepted on every call, a differently-identified process's are rejected on every call, individually. Uses a Unix domain socket standing in for XPC's transport; **not** a claim of full parity with XPC's own audit-token guarantee (see the comment at the top of `main.swift` for the specific, disclosed limitation) |

## Running it

```sh
go test ./... -v                                  # all Go packages
go test ./safetar/... -run=^$ -fuzz=FuzzCheckSafePath -fuzztime=30s
cd peerauth-demo && swiftc -O main.swift -o peerauth-demo && ./peerauth-demo -h
```

## Prior art consulted

This design draws on, and is independently consistent with, several public sources —
listed here for attribution, not because this code depends on any of them:

- **TUF (The Update Framework)** and **Uptane** — the closest formal academic/industry
  standard for exactly this threat model (unattended, fleet-wide, privilege-separated
  software updates); role separation and rollback/freeze-attack prevention via a
  monotonic version floor are both TUF concepts.
- **Google's Omaha/Chromium Updater** and the **ChromeOS/Android A/B update scheme** —
  the self-qualifying "update the updater first" pattern and the versioned-slot,
  independently-re-verified-after-switch pattern both come from here.
- Detached CMS/PKCS#7 SignedData verification (RFC 5652) is the standards-based version
  of the same "signature chaining to a pinned root" shape `clustersig` demonstrates.
  `clustersig` deliberately does not use a CMS/ASN.1/X.509 library, favoring a smaller,
  purpose-built Ed25519 chain instead — see that package's doc comment for why.
- Several real, public CVEs shaped this design's "per-call, not per-connection" and
  "extraction guard independent of signature" requirements directly: CVE-2019-13013,
  Sparkle's CVE-2026-47122 and CVE-2026-47121, Docker Desktop's CVE-2020-15360, and
  TeamViewer's CVE-2026-92374.

## License

Apache-2.0 (see `LICENSE`).
