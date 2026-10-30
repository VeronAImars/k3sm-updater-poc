// Package clustersig is a clean-room, stdlib-only demonstration of design point 2: the
// second, narrower signature chain (independent of Apple's) that proves "this specific
// build is cleared for this cluster." It deliberately does not use CMS/PKCS#7 or any
// third-party library — Ed25519 directly, in the Go standard library, is enough to show
// the pattern is small and auditable. This is a concept demonstration, not a drop-in: a
// real implementation would still need its own format decisions (this proposal's job is
// to name them as open questions, not settle them here).
//
// The chain mirrors Apple's own shape at a smaller scale: a pinned root key signs an
// intermediate "cluster signer" key; the signer key signs each release artifact's digest.
// Rotating the signer key never requires redistributing the root key to every node.
package clustersig

import (
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"fmt"
)

// RootKey is the one key every node is shipped with (equivalent to pinning a specific
// Apple Team ID: this is the trust anchor, distributed once, out of band).
type RootKey ed25519.PublicKey

// SignerCert is the root's attestation that a given signer key speaks for this cluster
// for a bounded time window — intentionally minimal (no ASN.1/X.509 needed for this
// concept check).
type SignerCert struct {
	SignerPublicKey ed25519.PublicKey
	NotAfter        int64 // unix seconds; a real implementation would also need NotBefore
	RootSignature   []byte
}

// signerCertSigningInput is exactly what the root signs — binding the signer key to its
// expiry so a cert can't be replayed past its validity window.
func signerCertSigningInput(signerPub ed25519.PublicKey, notAfter int64) []byte {
	msg := fmt.Sprintf("k3sm-cluster-signer-cert|%x|%d", signerPub, notAfter)
	return []byte(msg)
}

// IssueSignerCert is run offline by whoever holds the cluster root key — never by a node.
func IssueSignerCert(rootPriv ed25519.PrivateKey, signerPub ed25519.PublicKey, notAfter int64) SignerCert {
	sig := ed25519.Sign(rootPriv, signerCertSigningInput(signerPub, notAfter))
	return SignerCert{SignerPublicKey: signerPub, NotAfter: notAfter, RootSignature: sig}
}

// ArtifactSignature is what ships alongside a release payload: the signer's signature
// over the artifact's digest, plus the cert proving that signer key is currently valid.
type ArtifactSignature struct {
	Cert      SignerCert
	Signature []byte
}

// SignArtifact is run by the release pipeline, using the (rotatable) signer key.
func SignArtifact(signerPriv ed25519.PrivateKey, cert SignerCert, artifactDigest [32]byte) ArtifactSignature {
	sig := ed25519.Sign(signerPriv, artifactDigest[:])
	return ArtifactSignature{Cert: cert, Signature: sig}
}

// Verify is the only thing the updater actually runs, on the node, at install time. It
// checks two things, both required: the signer cert chains to the pinned root and hasn't
// expired, and the artifact's digest is actually signed by that signer key. Neither check
// alone is sufficient — this is the "both signatures required" half of design point 2,
// scoped to just this one (the cluster) signature; Apple's chain is verified separately.
func Verify(root RootKey, artifactDigest [32]byte, as ArtifactSignature, now int64) error {
	if as.Cert.NotAfter < now {
		return errors.New("clustersig: signer cert expired")
	}
	if !ed25519.Verify(ed25519.PublicKey(root), signerCertSigningInput(as.Cert.SignerPublicKey, as.Cert.NotAfter), as.Cert.RootSignature) {
		return errors.New("clustersig: signer cert does not chain to the pinned root")
	}
	if !ed25519.Verify(as.Cert.SignerPublicKey, artifactDigest[:], as.Signature) {
		return errors.New("clustersig: artifact signature does not verify under the certified signer key")
	}
	return nil
}

// Digest is a convenience the real updater would call over the staged tarball's bytes
// before Verify — kept separate so Verify's signature stays testable without large inputs.
func Digest(content []byte) [32]byte {
	return sha256.Sum256(content)
}
