// Package atomicswitch answers gap (3) from the k3sm privileged-updater design review:
// the "current" pointer must flip in one atomic step, with the new version fully staged
// and verified beforehand, so a crash mid-switch can never leave a half-written state.
//
// The mechanism: write a new symlink under a temp name in the SAME directory as the real
// "current" link, then os.Rename it over "current". Rename of one path over another within
// the same directory is atomic on both APFS and HFS+ (and POSIX generally) — the directory
// entry for "current" is replaced in a single operation; there is no window where it is
// missing or points at a partially-written target, because the new target (versions/<ver>/)
// was already fully staged and fsynced before this call.
package atomicswitch

import (
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
)

// Switch atomically repoints the "current" symlink inside root at target (a path relative
// to root, e.g. "versions/1.5.0"). It never touches "current" except via one os.Rename.
func Switch(root, target string) error {
	currentPath := filepath.Join(root, "current")
	tmpName := fmt.Sprintf("current.tmp.%d.%d", os.Getpid(), rand.Int63())
	tmpPath := filepath.Join(root, tmpName)

	if err := os.Symlink(target, tmpPath); err != nil {
		return fmt.Errorf("atomicswitch: staging new symlink: %w", err)
	}
	// Rename is the one atomic step. Either this succeeds and "current" now points at
	// target, or it never ran and "current" is untouched — there is no partial state.
	if err := os.Rename(tmpPath, currentPath); err != nil {
		os.Remove(tmpPath) // best-effort cleanup of the stage file on failure
		return fmt.Errorf("atomicswitch: renaming into place: %w", err)
	}
	return nil
}

// Current reads which version "current" points at, relative to root.
func Current(root string) (string, error) {
	target, err := os.Readlink(filepath.Join(root, "current"))
	if err != nil {
		return "", err
	}
	return target, nil
}
