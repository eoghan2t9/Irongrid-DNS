package tunnel

import (
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// TestBuildArgsFlagOrdering guards against a regression where --no-autoupdate
// and --logfile were appended *after* the `tunnel run` subcommand.
// cloudflared only defines those as app-level (global) flags, not as flags of
// the `run` subcommand, so it fails with "flag provided but not defined:
// -no-autoupdate" if they land after the subcommand.
func TestBuildArgsFlagOrdering(t *testing.T) {
	logFile := filepath.Join(t.TempDir(), "cloudflared.log")
	args := buildArgs(ModeToken, "definitely-not-a-valid-tunnel-token", "", "", logFile)

	tunnelIdx := slices.Index(args, "tunnel")
	if tunnelIdx < 0 {
		t.Fatalf("expected a tunnel subcommand in args: %v", args)
	}
	for _, flag := range []string{"--no-autoupdate", "--logfile"} {
		if idx := slices.Index(args, flag); idx < 0 || idx > tunnelIdx {
			t.Fatalf("%s must precede the tunnel subcommand: %v", flag, args)
		}
	}
}

// TestStartTwiceNoPanic reproduces the production crash where the second
// Start call panicked with "duplicate metrics collector registration
// attempted" back when cloudflared ran embedded in-process. Now that
// cloudflared runs as a managed subprocess, the same "start twice" sequence
// is exercised against the deterministic failure mode available in a unit
// test — no cloudflared binary installed at t.TempDir() — but the guard
// being tested (repeated failed starts must never wedge the Manager or
// panic) is identical.
func TestStartTwiceNoPanic(t *testing.T) {
	m := NewManager(t.TempDir())

	if err := m.Start(ModeToken, "definitely-not-a-valid-tunnel-token", "", "", ""); err == nil {
		t.Fatal("expected first start to fail: no cloudflared binary installed")
	}
	if err := m.Start(ModeToken, "definitely-not-a-valid-tunnel-token", "", "", ""); err == nil {
		t.Fatal("expected second start to fail: no cloudflared binary installed")
	}

	st := m.Status()
	if st.Running {
		t.Fatal("manager must not report running after failed starts")
	}
	if !strings.Contains(st.Error, "cloudflared") {
		t.Fatalf("expected a cloudflared-binary error in status, got: %q", st.Error)
	}
}

// TestStartRejectedLeavesUsable ensures a rejected start (unknown mode)
// resets the manager to not-running and that a normal token-mode start is
// still possible afterwards.
func TestStartRejectedLeavesUsable(t *testing.T) {
	m := NewManager(t.TempDir())

	// Unknown mode hits the validation path before touching the binary.
	if err := m.Start("bogus-mode", "", "", "", ""); err == nil {
		t.Fatal("expected unknown-mode start to fail")
	}
	if st := m.Status(); st.Running {
		t.Fatal("manager must not report running after a rejected start")
	}

	// And a normal token-mode start is still possible afterwards (fails here
	// only because no cloudflared binary is installed in the test env).
	if err := m.Start(ModeToken, "definitely-not-a-valid-tunnel-token", "", "", ""); err == nil {
		t.Fatal("expected token-mode start to fail: no cloudflared binary installed")
	}
}
