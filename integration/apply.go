// Package integration wires the five Go prototypes together into one update flow, proving
// they compose correctly — each isolated package test proves its own property, but nothing
// until now proved the ORDER and WIRING between them is actually correct: that a floor
// rejection happens before any disk write, that a bad signature is caught before
// extraction, that a malicious tarball is caught before the switch, and — the one that
// matters most — that a failed health check actually flips the symlink back, not just
// returns an error while leaving the bad version live.
package integration

import (
	"archive/tar"
	"bytes"
	"context"
	"fmt"
	"time"

	"k3sm-updater-poc/atomicswitch"
	"k3sm-updater-poc/clustersig"
	"k3sm-updater-poc/healthgate"
	"k3sm-updater-poc/safetar"
	"k3sm-updater-poc/versionfloor"
)

// Candidate is everything the updater receives for one proposed update.
type Candidate struct {
	Version   string
	Tarball   []byte // the raw, as-received payload bytes
	Signature clustersig.ArtifactSignature
}

// Deps is everything ApplyUpdate needs from the environment, injected so tests can run
// without a real filesystem service or real cluster keys.
type Deps struct {
	Root          string // e.g. /Library/k3sm
	InstalledVer  versionfloor.Version
	ClusterRoot   clustersig.RootKey
	Now           int64
	StartService  func(ctx context.Context) error
	ProbeHealthy  healthgate.Prober
	HealthTimeout time.Duration
	PollEvery     time.Duration
}

// ApplyUpdate runs the full pipeline in order: version floor, signature, extraction,
// switch, health-check-with-rollback. Any failure before the switch step leaves the
// filesystem completely untouched by design — each check below runs before the one that
// would actually change anything on disk.
func ApplyUpdate(ctx context.Context, d Deps, c Candidate) error {
	candidateVer, err := versionfloor.Parse(c.Version)
	if err != nil {
		return fmt.Errorf("integration: parsing candidate version: %w", err)
	}
	// Step 1: floor check. Nothing on disk is touched yet.
	if err := versionfloor.AllowInstall(d.InstalledVer, candidateVer); err != nil {
		return fmt.Errorf("integration: floor check failed: %w", err)
	}

	// Step 2: signature check. Still nothing on disk is touched.
	digest := clustersig.Digest(c.Tarball)
	if err := clustersig.Verify(d.ClusterRoot, digest, c.Signature, d.Now); err != nil {
		return fmt.Errorf("integration: signature check failed: %w", err)
	}

	// Step 3: extract into a NEW versioned directory, not yet live. safetar refuses
	// anything unsafe before any file outside the staged directory could be touched.
	versionDir := fmt.Sprintf("versions/%s", c.Version)
	stagePath := d.Root + "/" + versionDir
	if err := safetar.Extract(tar.NewReader(bytes.NewReader(c.Tarball)), stagePath); err != nil {
		return fmt.Errorf("integration: extraction failed, nothing switched: %w", err)
	}

	// Step 4: the one atomic, durable step that actually changes what's live.
	previousTarget, _ := atomicswitch.Current(d.Root) // best-effort, for rollback below
	if err := atomicswitch.Switch(d.Root, versionDir); err != nil {
		return fmt.Errorf("integration: switch failed: %w", err)
	}

	// Step 5: the updater owns the health verdict. A failure here must flip the symlink
	// BACK, not just report an error — that's the composition property this package
	// exists to prove, since healthgate's own tests only check that its rollback callback
	// was invoked, not that invoking it actually produces a correct, verified switch-back.
	rollback := func(ctx context.Context) error {
		if previousTarget == "" {
			return fmt.Errorf("integration: no previous version recorded, cannot roll back")
		}
		return atomicswitch.Switch(d.Root, previousTarget)
	}
	if err := healthgate.RunSwitch(ctx, d.StartService, d.ProbeHealthy, rollback, d.HealthTimeout, d.PollEvery); err != nil {
		return fmt.Errorf("integration: health check failed, rolled back: %w", err)
	}

	return nil
}
