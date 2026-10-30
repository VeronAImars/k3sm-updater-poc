// Package safetar answers gap (4) from the k3sm privileged-updater design review: a
// tarball's signature proves who wrote it, not that every path inside it is safe to
// extract. This is a separate, independent guard — a signed tarball can still carry a
// path-traversal or symlink-escape entry (this is exactly the shape of a real shipped
// bug, Sparkle's CVE-2026-47121, in another macOS updater's binary-delta handling).
package safetar

import (
	"archive/tar"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// Extract writes tr's entries under destDir, refusing any entry that would place content
// outside destDir — via "..", an absolute path, or a symlink target that escapes destDir.
// It is intentionally conservative: it refuses symlinks and hardlinks inside the archive
// entirely, since a payload tarball of plain update binaries has no legitimate need for
// either, and every real-world extraction CVE in this class comes from exactly that entry
// type being trusted.
func Extract(tr *tar.Reader, destDir string) error {
	destDir, err := filepath.Abs(destDir)
	if err != nil {
		return fmt.Errorf("safetar: resolving destDir: %w", err)
	}

	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return fmt.Errorf("safetar: reading tar stream: %w", err)
		}

		if err := checkSafePath(destDir, hdr.Name); err != nil {
			return err
		}

		switch hdr.Typeflag {
		case tar.TypeDir:
			target := filepath.Join(destDir, hdr.Name)
			if err := os.MkdirAll(target, 0o755); err != nil {
				return fmt.Errorf("safetar: mkdir %q: %w", hdr.Name, err)
			}
		case tar.TypeReg:
			target := filepath.Join(destDir, hdr.Name)
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return fmt.Errorf("safetar: mkdir parent of %q: %w", hdr.Name, err)
			}
			f, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, os.FileMode(hdr.Mode&0o777))
			if err != nil {
				return fmt.Errorf("safetar: create %q: %w", hdr.Name, err)
			}
			if _, err := io.Copy(f, tr); err != nil {
				f.Close()
				return fmt.Errorf("safetar: writing %q: %w", hdr.Name, err)
			}
			if err := f.Close(); err != nil {
				return fmt.Errorf("safetar: closing %q: %w", hdr.Name, err)
			}
		case tar.TypeSymlink, tar.TypeLink:
			return fmt.Errorf("safetar: refusing entry %q: links are never valid in an update payload", hdr.Name)
		default:
			return fmt.Errorf("safetar: refusing entry %q: unsupported type %v", hdr.Name, hdr.Typeflag)
		}
	}
}

// checkSafePath refuses an archive entry name that is absolute, contains a ".." segment,
// or whose cleaned, joined path would not stay strictly inside destDir.
func checkSafePath(destDir, name string) error {
	if filepath.IsAbs(name) {
		return fmt.Errorf("safetar: refusing absolute path entry %q", name)
	}
	for _, seg := range strings.Split(name, "/") {
		if seg == ".." {
			return fmt.Errorf("safetar: refusing path-traversal entry %q", name)
		}
	}
	target := filepath.Clean(filepath.Join(destDir, name))
	if target != destDir && !strings.HasPrefix(target, destDir+string(os.PathSeparator)) {
		return fmt.Errorf("safetar: refusing entry %q: resolves outside destination", name)
	}
	return nil
}
