package safetar

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// resolveNaively and pathIsWithin deliberately use a DIFFERENT stdlib code path
// (filepath.Rel) than checkSafePath's own hand-written prefix comparison, so this fuzz
// oracle isn't just checking the function against itself.
func resolveNaively(destDir, name string) string {
	return filepath.Clean(filepath.Join(destDir, name))
}

func pathIsWithin(destDir, target string) bool {
	rel, err := filepath.Rel(destDir, target)
	if err != nil {
		return false
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		return false
	}
	return !filepath.IsAbs(rel)
}

// FuzzCheckSafePath hammers the path-safety guard directly, independent of full tar
// extraction — this is the single function a real-world bypass would have to defeat.
func FuzzCheckSafePath(f *testing.F) {
	seeds := []string{
		"bin/k3sm",
		"../../etc/evil",
		"/etc/evil",
		"..",
		"./bin/k3sm",
		"bin/../../../etc/evil",
		"bin/./../../etc/evil",
		"bin//k3sm",
		"bin/k3sm/",
		"....//etc/evil",
		"bin/k3sm\x00/etc/evil",
		"",
		".",
		"a/" + strings.Repeat("../", 50) + "etc/evil",
		strings.Repeat("a/", 2000) + "evil",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, name string) {
		destDir := t.TempDir()
		err := checkSafePath(destDir, name)
		if err != nil {
			return // refusing is always a safe outcome
		}
		// If it was NOT refused, the resolved path must be provably inside destDir —
		// recompute independently (not reusing checkSafePath's own logic) and compare.
		resolved := resolveNaively(destDir, name)
		if !pathIsWithin(destDir, resolved) {
			t.Fatalf("checkSafePath accepted %q but it resolves to %q, outside destDir %q", name, resolved, destDir)
		}
	})
}
