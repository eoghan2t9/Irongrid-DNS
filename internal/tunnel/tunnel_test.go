package tunnel

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
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
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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

// installFake puts a stand-in cloudflared at the manager's binary path. It
// reports ver for `--version` and otherwise idles until it is signalled, so
// Start/Stop/Restart can be exercised without Cloudflare. The file is
// swapped with a rename, as cfupdate does, so a running copy is unaffected.
func installFake(t *testing.T, m *Manager, ver string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("fake cloudflared is a shell script")
	}
	script := "#!/bin/sh\nif [ \"$1\" = \"--version\" ]; then echo \"cloudflared version " + ver + " (built x)\"; exit 0; fi\nexec sleep 30\n"
	tmp := m.BinaryPath() + ".new"
	if err := os.WriteFile(tmp, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, m.BinaryPath()); err != nil {
		t.Fatal(err)
	}
}

func TestStatusReportsTheVersionTheTunnelWasStartedFrom(t *testing.T) {
	t.Parallel()
	m := NewManager(t.TempDir())
	installFake(t, m, "2026.11.1")
	if err := m.Start(ModeQuick, "", "", "http://localhost:8080", ""); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(m.Stop)

	if st := m.Status(); !st.Running || st.RunningVersion != "2026.11.1" {
		t.Fatalf("status = running %v, version %q; want running 2026.11.1", st.Running, st.RunningVersion)
	}

	// An update replaces the file on disk, but the live process is still the
	// old release — the status must keep saying so until a restart.
	installFake(t, m, "2026.11.2")
	if got := m.Status().RunningVersion; got != "2026.11.1" {
		t.Errorf("RunningVersion = %q after the binary was swapped; want the still-running 2026.11.1", got)
	}

	m.Stop()
	if got := m.Status().RunningVersion; got != "" {
		t.Errorf("RunningVersion = %q after Stop; want empty", got)
	}
}

func TestRestartRunsTheNewBinaryWithTheSameSettings(t *testing.T) {
	t.Parallel()
	m := NewManager(t.TempDir())
	installFake(t, m, "2026.11.1")
	const origin = "http://localhost:9999"
	if err := m.Start(ModeQuick, "", "", origin, "dns.example.com"); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(m.Stop)
	firstStart := m.Status().Started

	installFake(t, m, "2026.11.2")
	if err := m.Restart(); err != nil {
		t.Fatalf("Restart: %v", err)
	}

	st := m.Status()
	if !st.Running || st.RunningVersion != "2026.11.2" {
		t.Errorf("after Restart: running %v, version %q; want running 2026.11.2", st.Running, st.RunningVersion)
	}
	if !st.Started.After(firstStart) {
		t.Error("Started did not advance: the process was not relaunched")
	}
	if st.Mode != ModeQuick || m.last.origin != origin || m.last.hostname != "dns.example.com" {
		t.Errorf("restart lost the original settings: mode %q, args %+v", st.Mode, m.last)
	}
}

func TestRestartDoesNothingWhenStopped(t *testing.T) {
	t.Parallel()
	m := NewManager(t.TempDir())
	installFake(t, m, "2026.11.1")
	if err := m.Restart(); !errors.Is(err, ErrNotRunning) {
		t.Fatalf("Restart on a never-started tunnel = %v, want ErrNotRunning", err)
	}

	if err := m.Start(ModeQuick, "", "", "", ""); err != nil {
		t.Fatalf("Start: %v", err)
	}
	m.Stop()
	if err := m.Restart(); !errors.Is(err, ErrNotRunning) {
		t.Fatalf("Restart on a stopped tunnel = %v, want ErrNotRunning", err)
	}
	if m.Status().Running {
		t.Error("Restart turned a stopped tunnel back on")
	}
}
