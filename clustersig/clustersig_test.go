package clustersig

import (
	"crypto/ed25519"
	"testing"
)

func genKeys(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	return pub, priv
}

func TestVerify_ValidChainAccepted(t *testing.T) {
	rootPub, rootPriv := genKeys(t)
	signerPub, signerPriv := genKeys(t)

	cert := IssueSignerCert(rootPriv, signerPub, 2000000000) // far future
	digest := Digest([]byte("fake-release-tarball-bytes"))
	as := SignArtifact(signerPriv, cert, digest)

	if err := Verify(RootKey(rootPub), digest, as, 1700000000); err != nil {
		t.Fatalf("expected a valid chain to verify, got: %v", err)
	}
}

func TestVerify_WrongRootRejected(t *testing.T) {
	_, rootPriv := genKeys(t)
	wrongRootPub, _ := genKeys(t) // a different root than the one that actually signed
	signerPub, signerPriv := genKeys(t)

	cert := IssueSignerCert(rootPriv, signerPub, 2000000000)
	digest := Digest([]byte("payload"))
	as := SignArtifact(signerPriv, cert, digest)

	if err := Verify(RootKey(wrongRootPub), digest, as, 1700000000); err == nil {
		t.Fatal("expected verification against the wrong root to fail, got nil error")
	}
}

func TestVerify_ExpiredCertRejected(t *testing.T) {
	rootPub, rootPriv := genKeys(t)
	signerPub, signerPriv := genKeys(t)

	cert := IssueSignerCert(rootPriv, signerPub, 1000) // already expired
	digest := Digest([]byte("payload"))
	as := SignArtifact(signerPriv, cert, digest)

	if err := Verify(RootKey(rootPub), digest, as, 1700000000); err == nil {
		t.Fatal("expected an expired signer cert to be rejected, got nil error")
	}
}

func TestVerify_TamperedArtifactRejected(t *testing.T) {
	rootPub, rootPriv := genKeys(t)
	signerPub, signerPriv := genKeys(t)

	cert := IssueSignerCert(rootPriv, signerPub, 2000000000)
	digest := Digest([]byte("original-payload"))
	as := SignArtifact(signerPriv, cert, digest)

	tamperedDigest := Digest([]byte("tampered-payload"))
	if err := Verify(RootKey(rootPub), tamperedDigest, as, 1700000000); err == nil {
		t.Fatal("expected a signature over a different digest to be rejected, got nil error")
	}
}

func TestVerify_ForgedSignerCertRejected(t *testing.T) {
	// An attacker who doesn't hold the root key tries to mint their own cert for their
	// own signer key, then sign an artifact with it. This is the actual attack the chain
	// exists to stop.
	rootPub, _ := genKeys(t)
	attackerSignerPub, attackerSignerPriv := genKeys(t)
	_, attackerRootPriv := genKeys(t) // attacker's own fake "root"

	forgedCert := IssueSignerCert(attackerRootPriv, attackerSignerPub, 2000000000)
	digest := Digest([]byte("payload"))
	as := SignArtifact(attackerSignerPriv, forgedCert, digest)

	if err := Verify(RootKey(rootPub), digest, as, 1700000000); err == nil {
		t.Fatal("expected a cert not signed by the real root to be rejected, got nil error")
	}
}
