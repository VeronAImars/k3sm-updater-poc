// Package healthgate answers gap (5) from the k3sm privileged-updater design review: the
// post-switch health verdict must be produced and owned by the updater itself, from its
// own independent probe, never accepted as a self-report from the newly-installed (and
// possibly broken or compromised) daemon. A build that can lie about its own health is
// exactly the build this check exists to catch.
package healthgate

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// Prober is the updater's OWN check of the new version — e.g. "is the port accepting
// connections", "does /healthz return 200", "is the node Ready in the cluster API". It is
// never satisfied by anything the new process says about itself; it is something the
// updater independently observes from outside.
type Prober func(ctx context.Context) (healthy bool, err error)

// RunSwitch starts the new version, then polls probe on its own schedule until either it
// reports healthy or deadline elapses. On any failure to reach a healthy verdict in time,
// it calls rollback and returns an error — start's own self-reported success, if any, is
// never consulted for this decision.
func RunSwitch(ctx context.Context, start func(ctx context.Context) error, probe Prober, rollback func(context.Context) error, deadline time.Duration, pollEvery time.Duration) error {
	if deadline <= 0 {
		return fmt.Errorf("healthgate: deadline must be positive, got %s", deadline)
	}
	if pollEvery <= 0 {
		return fmt.Errorf("healthgate: pollEvery must be positive, got %s", pollEvery)
	}

	startCtx, cancelStart := context.WithCancel(ctx)
	defer cancelStart()

	startErrCh := make(chan error, 1)
	go func() { startErrCh <- start(startCtx) }()

	deadlineTimer := time.NewTimer(deadline)
	defer deadlineTimer.Stop()
	ticker := time.NewTicker(pollEvery)
	defer ticker.Stop()

	for {
		select {
		case err := <-startErrCh:
			if err != nil {
				// The new version's own process failed to even come up. No probe call
				// needed — this is an immediate, unambiguous rollback.
				rbErr := rollback(ctx)
				return joinErrs(fmt.Errorf("healthgate: start failed: %w", err), rbErr)
			}
			// start returning nil is NOT a health verdict by itself — it only means the
			// process launched. The loop keeps polling probe independently.
		case <-deadlineTimer.C:
			rbErr := rollback(ctx)
			return joinErrs(errors.New("healthgate: deadline exceeded without an independently-verified healthy probe"), rbErr)
		case <-ticker.C:
			healthy, err := probe(ctx)
			if err != nil {
				continue // a probe error is not yet a verdict; keep polling until deadline
			}
			if healthy {
				return nil
			}
		case <-ctx.Done():
			rbErr := rollback(ctx)
			return joinErrs(ctx.Err(), rbErr)
		}
	}
}

func joinErrs(primary, secondary error) error {
	if secondary == nil {
		return primary
	}
	return fmt.Errorf("%w (rollback also reported: %v)", primary, secondary)
}
