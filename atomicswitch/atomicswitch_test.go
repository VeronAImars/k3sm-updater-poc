package atomicswitch

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func setupVersions(t *testing.T, root string) {
	t.Helper()
	for _, v := range []string{"versions/1.0.0", "versions/2.0.0"} {
		if err := os.MkdirAll(filepath.Join(root, v), 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", v, err)
		}
	}
}

func TestSwitch_Basic(t *testing.T) {
	root := t.TempDir()
	setupVersions(t, root)
	if err := Switch(root, "versions/1.0.0"); err != nil {
		t.Fatalf("first switch: %v", err)
	}
	got, err := Current(root)
	if err != nil || got != "versions/1.0.0" {
		t.Fatalf("Current = %q, err=%v, want versions/1.0.0", got, err)
	}
	if err := Switch(root, "versions/2.0.0"); err != nil {
		t.Fatalf("second switch: %v", err)
	}
	got, err = Current(root)
	if err != nil || got != "versions/2.0.0" {
		t.Fatalf("Current = %q, err=%v, want versions/2.0.0", got, err)
	}
}

// crashLoopEnv, when set, makes this test binary act as a worker that repeatedly calls
// Switch, alternating targets, as fast as it can, forever — until something kills it.
const crashLoopEnv = "ATOMICSWITCH_CRASH_LOOP_ROOT"

func TestMain(m *testing.M) {
	if root := os.Getenv(crashLoopEnv); root != "" {
		runCrashLoopWorker(root)
		return // unreachable: runCrashLoopWorker loops until killed
	}
	os.Exit(m.Run())
}

func runCrashLoopWorker(root string) {
	targets := []string{"versions/1.0.0", "versions/2.0.0"}
	i := 0
	for {
		_ = Switch(root, targets[i%2])
		i++
	}
}

// TestSwitch_SurvivesKillMidLoop is the actual crash-safety claim: spawn a real OS
// subprocess hammering Switch, SIGKILL it at an unpredictable point, and confirm "current"
// never ends up missing, empty, or pointed at a stage file — only ever at a fully-formed
// version directory. Repeated many times to catch a narrow race.
func TestSwitch_SurvivesKillMidLoop(t *testing.T) {
	if os.Getenv("CI") != "" {
		t.Skip("spawns and SIGKILLs a subprocess repeatedly; skip under CI timeouts")
	}
	root := t.TempDir()
	setupVersions(t, root)
	// Seed a valid starting state so Current() never has to observe "doesn't exist yet".
	if err := Switch(root, "versions/1.0.0"); err != nil {
		t.Fatalf("seeding initial switch: %v", err)
	}

	const iterations = 200
	for i := 0; i < iterations; i++ {
		cmd := exec.Command(os.Args[0], "-test.run=^$") // run no tests; TestMain handles the rest
		cmd.Env = append(os.Environ(), fmt.Sprintf("%s=%s", crashLoopEnv, root))
		if err := cmd.Start(); err != nil {
			t.Fatalf("iteration %d: starting worker: %v", i, err)
		}

		// Let it race for a tiny, jittered window, then kill it mid-flight. There is no
		// synchronization with the worker's internal state on purpose — the point is to
		// kill it at an unpredictable moment relative to any given Switch call.
		time.Sleep(time.Duration(200+i%300) * time.Microsecond)
		if err := cmd.Process.Kill(); err != nil {
			t.Fatalf("iteration %d: killing worker: %v", i, err)
		}
		_ = cmd.Wait()

		// The invariant: "current" always resolves to exactly one of the two real version
		// directories. It must never be missing, never point at a "current.tmp.*" stage
		// file, and never be unreadable.
		target, err := Current(root)
		if err != nil {
			t.Fatalf("iteration %d: Current() failed after kill: %v (current symlink missing or broken)", i, err)
		}
		if strings.Contains(target, "current.tmp") {
			t.Fatalf("iteration %d: current points at a stage file %q — switch was not atomic", i, target)
		}
		if target != "versions/1.0.0" && target != "versions/2.0.0" {
			t.Fatalf("iteration %d: current points at unexpected target %q", i, target)
		}
		if fi, err := os.Stat(filepath.Join(root, target)); err != nil || !fi.IsDir() {
			t.Fatalf("iteration %d: current target %q does not resolve to a real directory: %v", i, target, err)
		}

		// Clean up any leftover stage files a killed process didn't get to remove, same
		// as a real updater's startup-reconciliation pass would.
		entries, _ := os.ReadDir(root)
		for _, e := range entries {
			if strings.HasPrefix(e.Name(), "current.tmp") {
				os.Remove(filepath.Join(root, e.Name()))
			}
		}
	}
}
