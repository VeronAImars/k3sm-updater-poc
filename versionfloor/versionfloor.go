// Package versionfloor answers gap (1) from the k3sm privileged-updater design review:
// a validly-signed old payload must still be refused if it is not newer than what is
// already installed. Signature validity and version-floor validity are two independent
// checks; this package is only the second one.
package versionfloor

import (
	"fmt"
	"strconv"
	"strings"
)

// Version is a parsed dotted-integer release version, e.g. "1.4.2".
type Version struct {
	Core []int
	Raw  string
}

// Parse accepts a plain "<int>.<int>.<int>..." version. It deliberately does not accept
// pre-release/build suffixes (that is a separate, already-solved problem in k3sm's own
// pkg/version/release.go — this package only does the floor check on the core version).
func Parse(s string) (Version, error) {
	parts := strings.Split(s, ".")
	core := make([]int, len(parts))
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil {
			return Version{}, fmt.Errorf("versionfloor: %q is not a dotted-integer version: %w", s, err)
		}
		core[i] = n
	}
	return Version{Core: core, Raw: s}, nil
}

// Compare returns -1, 0, or 1 as a < b, a == b, a > b, comparing core components
// left to right and treating a missing trailing component as 0 (so "1.4" == "1.4.0").
func Compare(a, b Version) int {
	n := len(a.Core)
	if len(b.Core) > n {
		n = len(b.Core)
	}
	for i := 0; i < n; i++ {
		var av, bv int
		if i < len(a.Core) {
			av = a.Core[i]
		}
		if i < len(b.Core) {
			bv = b.Core[i]
		}
		if av != bv {
			if av < bv {
				return -1
			}
			return 1
		}
	}
	return 0
}

// AllowInstall is the updater's floor check: a candidate may only be installed if it is
// strictly newer than what is currently running. This is independent of, and runs after,
// the dual-signature check — a candidate can pass both signatures and still be refused
// here. This is the fix for a rollback/freeze attack: a validly-signed OLD build replayed
// onto a node must not be treated as an update.
func AllowInstall(installed, candidate Version) error {
	switch Compare(candidate, installed) {
	case 1:
		return nil
	case 0:
		return fmt.Errorf("versionfloor: candidate %s is not newer than installed %s (replay of current version)", candidate.Raw, installed.Raw)
	default:
		return fmt.Errorf("versionfloor: candidate %s is older than installed %s (rollback refused even though signatures are valid)", candidate.Raw, installed.Raw)
	}
}
