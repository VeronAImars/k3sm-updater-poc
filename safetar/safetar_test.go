package safetar

import (
	"archive/tar"
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func buildTar(t *testing.T, entries []tar.Header, contents map[string][]byte) *tar.Reader {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, h := range entries {
		hdr := h
		data := contents[h.Name]
		hdr.Size = int64(len(data))
		if err := tw.WriteHeader(&hdr); err != nil {
			t.Fatalf("WriteHeader(%q): %v", h.Name, err)
		}
		if len(data) > 0 {
			if _, err := tw.Write(data); err != nil {
				t.Fatalf("Write(%q): %v", h.Name, err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("tar Close: %v", err)
	}
	return tar.NewReader(&buf)
}

func TestExtract_NormalPayload(t *testing.T) {
	dest := t.TempDir()
	tr := buildTar(t,
		[]tar.Header{
			{Name: "bin/k3sm", Typeflag: tar.TypeReg, Mode: 0o755},
		},
		map[string][]byte{"bin/k3sm": []byte("fake-binary-contents")},
	)
	if err := Extract(tr, dest); err != nil {
		t.Fatalf("expected a normal payload to extract cleanly, got: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(dest, "bin/k3sm"))
	if err != nil {
		t.Fatalf("reading extracted file: %v", err)
	}
	if string(got) != "fake-binary-contents" {
		t.Fatalf("extracted content mismatch: %q", got)
	}
}

func TestExtract_RefusesPathTraversal(t *testing.T) {
	dest := t.TempDir()
	// This is the Sparkle CVE-2026-47121 shape: a validly-signed container whose payload
	// tries to write outside the staged directory via "..".
	tr := buildTar(t,
		[]tar.Header{
			{Name: "../../etc/evil", Typeflag: tar.TypeReg, Mode: 0o644},
		},
		map[string][]byte{"../../etc/evil": []byte("pwned")},
	)
	if err := Extract(tr, dest); err == nil {
		t.Fatal("expected path-traversal entry to be refused, got nil error")
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(filepath.Dir(dest)), "evil")); err == nil {
		t.Fatal("traversal entry was actually written outside destDir")
	}
}

func TestExtract_RefusesAbsolutePath(t *testing.T) {
	dest := t.TempDir()
	tr := buildTar(t,
		[]tar.Header{{Name: "/etc/evil", Typeflag: tar.TypeReg, Mode: 0o644}},
		map[string][]byte{"/etc/evil": []byte("pwned")},
	)
	if err := Extract(tr, dest); err == nil {
		t.Fatal("expected absolute-path entry to be refused, got nil error")
	}
}

func TestExtract_RefusesSymlinkEscape(t *testing.T) {
	dest := t.TempDir()
	tr := buildTar(t,
		[]tar.Header{{Name: "bin/escape", Typeflag: tar.TypeSymlink, Linkname: "../../../etc/evil"}},
		nil,
	)
	if err := Extract(tr, dest); err == nil {
		t.Fatal("expected a symlink entry to be refused outright, got nil error")
	}
}
