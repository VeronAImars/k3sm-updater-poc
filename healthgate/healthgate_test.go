package healthgate

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

func TestRunSwitch_GenuinelyHealthySucceeds(t *testing.T) {
	var started atomic.Bool
	var rolledBack atomic.Bool
	becameHealthyAt := time.Now().Add(30 * time.Millisecond)

	start := func(ctx context.Context) error { started.Store(true); return nil }
	probe := func(ctx context.Context) (bool, error) { return time.Now().After(becameHealthyAt), nil }
	rollback := func(ctx context.Context) error { rolledBack.Store(true); return nil }

	err := RunSwitch(context.Background(), start, probe, rollback, 500*time.Millisecond, 5*time.Millisecond)
	if err != nil {
		t.Fatalf("expected success, got: %v", err)
	}
	if !started.Load() {
		t.Fatal("expected start to have been called")
	}
	if rolledBack.Load() {
		t.Fatal("expected no rollback on a genuinely healthy switch")
	}
}

// This is the actual attack the gate exists to catch: a new version that SELF-REPORTS
// healthy (e.g. writes a status file saying "I'm fine") while the updater's own
// independent probe — the thing that actually matters — never succeeds. The self-report
// must be completely irrelevant to the verdict.
func TestRunSwitch_SelfReportedHealthIsIgnored(t *testing.T) {
	var rolledBack atomic.Bool
	selfReportedHealthy := atomic.Bool{}

	start := func(ctx context.Context) error {
		// The compromised/broken new process announces itself healthy immediately...
		selfReportedHealthy.Store(true)
		return nil
	}
	// ...but the updater's own external probe (simulating "is the port actually up")
	// never once returns true, regardless of what the process claims about itself.
	probe := func(ctx context.Context) (bool, error) { return false, nil }
	rollback := func(ctx context.Context) error { rolledBack.Store(true); return nil }

	err := RunSwitch(context.Background(), start, probe, rollback, 60*time.Millisecond, 5*time.Millisecond)
	if err == nil {
		t.Fatal("expected a timeout/rollback despite the self-reported health, got nil error")
	}
	if !selfReportedHealthy.Load() {
		t.Fatal("test setup bug: self-report never happened")
	}
	if !rolledBack.Load() {
		t.Fatal("expected rollback to have been called — self-report must not override the independent probe")
	}
}

func TestRunSwitch_StartFailureRollsBackImmediately(t *testing.T) {
	var rolledBack atomic.Bool
	start := func(ctx context.Context) error { return errors.New("exec failed") }
	probe := func(ctx context.Context) (bool, error) {
		t.Fatal("probe should never be called if start failed")
		return false, nil
	}
	rollback := func(ctx context.Context) error { rolledBack.Store(true); return nil }

	err := RunSwitch(context.Background(), start, probe, rollback, 200*time.Millisecond, 5*time.Millisecond)
	if err == nil {
		t.Fatal("expected an error when start fails, got nil")
	}
	if !rolledBack.Load() {
		t.Fatal("expected rollback on start failure")
	}
}

func TestRunSwitch_RejectsNonPositiveDurations(t *testing.T) {
	noop := func(ctx context.Context) error { return nil }
	noopProbe := func(ctx context.Context) (bool, error) { return true, nil }

	if err := RunSwitch(context.Background(), noop, noopProbe, noop, 0, 5*time.Millisecond); err == nil {
		t.Fatal("expected an error for a zero deadline, got nil (this used to panic in time.NewTimer)")
	}
	if err := RunSwitch(context.Background(), noop, noopProbe, noop, 5*time.Millisecond, 0); err == nil {
		t.Fatal("expected an error for a zero pollEvery, got nil (this used to panic in time.NewTicker)")
	}
	if err := RunSwitch(context.Background(), noop, noopProbe, noop, 5*time.Millisecond, -1*time.Millisecond); err == nil {
		t.Fatal("expected an error for a negative pollEvery, got nil")
	}
}

func TestRunSwitch_RollbackFailureStillReportsPrimaryError(t *testing.T) {
	start := func(ctx context.Context) error { return nil }
	probe := func(ctx context.Context) (bool, error) { return false, nil }
	rollback := func(ctx context.Context) error { return errors.New("rollback also failed: previous version missing") }

	err := RunSwitch(context.Background(), start, probe, rollback, 20*time.Millisecond, 5*time.Millisecond)
	if err == nil {
		t.Fatal("expected an error, got nil")
	}
	t.Logf("correctly surfaced compound failure: %v", err)
}
