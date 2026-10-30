package integration

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/ed25519"
	"os"
	"path/filepath"
	"testing"
	"time"

	"k3sm-updater-poc/atomicswitch"
	"k3sm-updater-poc/clustersig"
	"k3sm-updater-poc/versionfloor"
)

func buildTarball(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for name, content := range files {
		hdr := &tar.Header{Name: name, Mode: 0o755, Size: int64(len(content)), Typeflag: tar.TypeReg}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatalf("WriteHeader: %v", err)
		}
		if _, err := tw.Write([]byte(content)); err != nil {
			t.Fatalf("Write: %v", err)
		}
	}
	tw.Close()
	return buf.Bytes()
}

func setupClusterKeys(t *testing.T) (clustersig.RootKey, ed25519.PrivateKey, clustersig.SignerCert) {
	t.Helper()
	rootPub, rootPriv, _ := ed25519.GenerateKey(nil)
	signerPub, signerPriv, _ := ed25519.GenerateKey(nil)
	cert := clustersig.IssueSignerCert(rootPriv, signerPub, 2000000000)
	return clustersig.RootKey(rootPub), signerPriv, cert
}

func baseDeps(t *testing.T, root string, rootKey clustersig.RootKey, probeHealthy bool) Deps {
	t.Helper()
	return Deps{
		Root:          root,
		InstalledVer:  mustVer(t, "1.0.0"),
		ClusterRoot:   rootKey,
		Now:           1700000000,
		StartService:  func(ctx context.Context) error { return nil },
		ProbeHealthy:  func(ctx context.Context) (bool, error) { return probeHealthy, nil },
		HealthTimeout: 100 * time.Millisecond,
		PollEvery:     5 * time.Millisecond,
	}
}

func mustVer(t *testing.T, s string) versionfloor.Version {
	t.Helper()
	v, err := versionfloor.Parse(s)
	if err != nil {
		t.Fatalf("Parse(%q): %v", s, err)
	}
	return v
}

func seedCurrent(t *testing.T, root, version string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(root, "versions", version), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := atomicswitch.Switch(root, "versions/"+version); err != nil {
		t.Fatalf("seeding current: %v", err)
	}
}

// TestApplyUpdate_HappyPath proves the whole pipeline composes end to end when every
// check should pass.
func TestApplyUpdate_HappyPath(t *testing.T) {
	root := t.TempDir()
	seedCurrent(t, root, "1.0.0")
	rootKey, signerPriv, cert := setupClusterKeys(t)

	tarball := buildTarball(t, map[string]string{"bin/k3sm": "v2-binary"})
	sig := clustersig.SignArtifact(signerPriv, cert, clustersig.Digest(tarball))

	deps := baseDeps(t, root, rootKey, true)
	err := ApplyUpdate(context.Background(), deps, Candidate{Version: "2.0.0", Tarball: tarball, Signature: sig})
	if err != nil {
		t.Fatalf("expected success, got: %v", err)
	}
	current, _ := atomicswitch.Current(root)
	if current != "versions/2.0.0" {
		t.Fatalf("expected current to be versions/2.0.0, got %q", current)
	}
	content, err := os.ReadFile(filepath.Join(root, "versions/2.0.0/bin/k3sm"))
	if err != nil || string(content) != "v2-binary" {
		t.Fatalf("extracted file wrong or missing: %v, %q", err, content)
	}
}

// TestApplyUpdate_FailedHealthCheckActuallyFlipsBack is the real composition claim: not
// just that an error is returned, but that the symlink is ACTUALLY switched back to the
// previous version on disk — proving healthgate's rollback callback, wired to
// atomicswitch, really does what the design claims.
func TestApplyUpdate_FailedHealthCheckActuallyFlipsBack(t *testing.T) {
	root := t.TempDir()
	seedCurrent(t, root, "1.0.0")
	rootKey, signerPriv, cert := setupClusterKeys(t)

	tarball := buildTarball(t, map[string]string{"bin/k3sm": "broken-v2-binary"})
	sig := clustersig.SignArtifact(signerPriv, cert, clustersig.Digest(tarball))

	deps := baseDeps(t, root, rootKey, false) // probe never succeeds
	err := ApplyUpdate(context.Background(), deps, Candidate{Version: "2.0.0", Tarball: tarball, Signature: sig})
	if err == nil {
		t.Fatal("expected an error when the health probe never succeeds")
	}

	current, err := atomicswitch.Current(root)
	if err != nil {
		t.Fatalf("current symlink broken after rollback: %v", err)
	}
	if current != "versions/1.0.0" {
		t.Fatalf("expected rollback to actually flip current back to versions/1.0.0, got %q — "+
			"an error was returned but the bad version is still live", current)
	}
}

// TestApplyUpdate_OldVersionRejectedBeforeAnyDiskWrite proves ordering: the floor check
// must run, and must reject, before extraction or switch ever touch disk.
func TestApplyUpdate_OldVersionRejectedBeforeAnyDiskWrite(t *testing.T) {
	root := t.TempDir()
	seedCurrent(t, root, "2.0.0") // installed is NEWER than the candidate below
	rootKey, signerPriv, cert := setupClusterKeys(t)

	tarball := buildTarball(t, map[string]string{"bin/k3sm": "old-binary"})
	sig := clustersig.SignArtifact(signerPriv, cert, clustersig.Digest(tarball))

	deps := baseDeps(t, root, rootKey, true)
	deps.InstalledVer = mustVer(t, "2.0.0")
	err := ApplyUpdate(context.Background(), deps, Candidate{Version: "1.0.0", Tarball: tarball, Signature: sig})
	if err == nil {
		t.Fatal("expected the old candidate to be rejected by the floor check")
	}

	if _, statErr := os.Stat(filepath.Join(root, "versions", "1.0.0")); statErr == nil {
		t.Fatal("floor-rejected candidate was still extracted to disk — ordering is wrong")
	}
	current, _ := atomicswitch.Current(root)
	if current != "versions/2.0.0" {
		t.Fatalf("current should be untouched at versions/2.0.0, got %q", current)
	}
}

// TestApplyUpdate_BadSignatureRejectedBeforeExtraction proves the signature check runs,
// and rejects, before the (otherwise well-formed) tarball is ever extracted.
func TestApplyUpdate_BadSignatureRejectedBeforeExtraction(t *testing.T) {
	root := t.TempDir()
	seedCurrent(t, root, "1.0.0")
	rootKey, signerPriv, cert := setupClusterKeys(t)

	tarball := buildTarball(t, map[string]string{"bin/k3sm": "v2-binary"})
	// Sign a DIFFERENT payload's digest than the one actually shipped — simulates a
	// tampered artifact.
	wrongSig := clustersig.SignArtifact(signerPriv, cert, clustersig.Digest([]byte("not-the-real-payload")))

	deps := baseDeps(t, root, rootKey, true)
	err := ApplyUpdate(context.Background(), deps, Candidate{Version: "2.0.0", Tarball: tarball, Signature: wrongSig})
	if err == nil {
		t.Fatal("expected the tampered-digest candidate to be rejected by the signature check")
	}
	if _, statErr := os.Stat(filepath.Join(root, "versions", "2.0.0")); statErr == nil {
		t.Fatal("signature-rejected candidate was still extracted to disk — ordering is wrong")
	}
}

// TestApplyUpdate_MaliciousTarballRejectedBeforeSwitch proves a path-traversal payload is
// caught during extraction, before the switch step ever runs — even though it carries a
// perfectly valid signature and a perfectly valid version bump.
func TestApplyUpdate_MaliciousTarballRejectedBeforeSwitch(t *testing.T) {
	root := t.TempDir()
	seedCurrent(t, root, "1.0.0")
	rootKey, signerPriv, cert := setupClusterKeys(t)

	tarball := buildTarball(t, map[string]string{"../../etc/evil": "pwned"})
	sig := clustersig.SignArtifact(signerPriv, cert, clustersig.Digest(tarball))

	deps := baseDeps(t, root, rootKey, true)
	err := ApplyUpdate(context.Background(), deps, Candidate{Version: "2.0.0", Tarball: tarball, Signature: sig})
	if err == nil {
		t.Fatal("expected the malicious tarball to be rejected during extraction")
	}
	current, _ := atomicswitch.Current(root)
	if current != "versions/1.0.0" {
		t.Fatalf("switch must never have run for a rejected tarball; current=%q", current)
	}
}
