package versionfloor

import "testing"

func mustParse(t *testing.T, s string) Version {
	t.Helper()
	v, err := Parse(s)
	if err != nil {
		t.Fatalf("Parse(%q): %v", s, err)
	}
	return v
}

func TestAllowInstall_NewerAllowed(t *testing.T) {
	installed := mustParse(t, "1.4.2")
	candidate := mustParse(t, "1.5.0")
	if err := AllowInstall(installed, candidate); err != nil {
		t.Fatalf("expected newer candidate to be allowed, got: %v", err)
	}
}

func TestAllowInstall_RollbackRefused(t *testing.T) {
	// This is the actual attack: a validly-signed OLD build, replayed.
	installed := mustParse(t, "1.5.0")
	candidate := mustParse(t, "1.4.2")
	err := AllowInstall(installed, candidate)
	if err == nil {
		t.Fatal("expected a signed-but-older candidate to be refused, got nil error")
	}
	t.Logf("correctly refused: %v", err)
}

func TestAllowInstall_ReplayOfCurrentRefused(t *testing.T) {
	installed := mustParse(t, "1.5.0")
	candidate := mustParse(t, "1.5.0")
	if err := AllowInstall(installed, candidate); err == nil {
		t.Fatal("expected a replay of the exact current version to be refused, got nil error")
	}
}

func TestCompare_TrailingZeroEquivalence(t *testing.T) {
	a := mustParse(t, "1.4")
	b := mustParse(t, "1.4.0")
	if Compare(a, b) != 0 {
		t.Fatalf("expected 1.4 == 1.4.0, got Compare=%d", Compare(a, b))
	}
}
