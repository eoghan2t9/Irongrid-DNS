package tunnel

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cloudflare/cloudflared/cmd/cloudflared/cliutil"
	cftunnel "github.com/cloudflare/cloudflared/cmd/cloudflared/tunnel"
)

// TestStartFlagOrdering guards against a regression where --no-autoupdate and
// --logfile were appended *after* the `tunnel run` subcommand. cloudflared
// only defines those as app-level (global) flags, not as flags of the `run`
// subcommand, so urfave/cli failed with
// "flag provided but not defined: -no-autoupdate". The construction here
// mirrors Manager.Start: global flags first, subcommand last.
func index(args []string, want string) int {
	for i, a := range args {
		if a == want {
			return i
		}
	}
	return -1
}

func TestStartFlagOrdering(t *testing.T) {
	os.Setenv("QUIC_GO_DISABLE_ECN", "1")
	registerBuildInfo()
	shutdownC := make(chan struct{})
	cftunnel.Init(cliutil.GetBuildInfo("IrongridDNS", ""), shutdownC)

	app := cloudflaredApp()

	// Token mode with a garbage token: cloudflared fails fast and offline in
	// ParseToken (hyphens are invalid base64), so the error we get back is a
	// token-validation error rather than a flag-parse error. If the global
	// flags regress to after `tunnel run`, parsing fails first.
	args := buildArgs(ModeToken, "definitely-not-a-valid-tunnel-token", "", "",
		filepath.Join(t.TempDir(), "cloudflared.log"))

	// The whole point: --no-autoupdate / --logfile must precede the
	// subcommand, or cloudflared rejects them as undefined subcommand flags.
	if i, j := index(args, "tunnel"), index(args, "--no-autoupdate"); j > i {
		t.Fatalf("--no-autoupdate must precede the tunnel subcommand: %v", args)
	}

	err := app.Run(args)
	if err == nil {
		t.Fatal("expected cloudflared to reject the bogus token, got no error")
	}
	if strings.Contains(err.Error(), "flag provided but not defined") {
		t.Fatalf("global flags must precede the tunnel subcommand, got: %v", err)
	}
	if !strings.Contains(err.Error(), "token") {
		t.Fatalf("expected a token-validation error, got: %v", err)
	}
}

// TestStartTwiceNoPanic reproduces the production crash where the second
// Start call panicked with "duplicate metrics collector registration
// attempted" (cloudflared's RegisterBuildInfo calls prometheus.MustRegister,
// which cannot be called twice). The sync.Once guard plus panic recovery in
// Start must turn that into a clean error and leave the manager not-running.
func TestStartTwiceNoPanic(t *testing.T) {
	os.Setenv("QUIC_GO_DISABLE_ECN", "1")
	registerBuildInfo()

	m := NewManager(t.TempDir())

	// First start with a garbage token: cloudflared fails fast and offline.
	// The panic that previously happened here would crash the whole test
	// binary, so reaching this line at all is the regression check.
	if err := m.Start(ModeToken, "definitely-not-a-valid-tunnel-token", "", "", ""); err == nil {
		t.Fatal("expected first start to fail on the bogus token")
	}

	// Second start must not panic; it must return a clean error too.
	if err := m.Start(ModeToken, "definitely-not-a-valid-tunnel-token", "", "", ""); err == nil {
		t.Fatal("expected second start to fail on the bogus token")
	}

	st := m.Status()
	if st.Running {
		t.Fatal("manager must not report running after failed starts")
	}
	if !strings.Contains(st.Error, "token") {
		t.Fatalf("expected a token error in status, got: %q", st.Error)
	}
}

// TestStartRejectedLeavesUsable ensures a rejected start (unknown mode)
// resets the manager to not-running and that a normal token-mode start is
// still possible afterwards.
func TestStartRejectedLeavesUsable(t *testing.T) {
	os.Setenv("QUIC_GO_DISABLE_ECN", "1")
	registerBuildInfo()

	m := NewManager(t.TempDir())

	// Unknown mode hits the validation path before launching cloudflared.
	if err := m.Start("bogus-mode", "", "", "", ""); err == nil {
		t.Fatal("expected unknown-mode start to fail")
	}
	if st := m.Status(); st.Running {
		t.Fatal("manager must not report running after a rejected start")
	}

	// And a normal token-mode start is still possible afterwards.
	if err := m.Start(ModeToken, "definitely-not-a-valid-tunnel-token", "", "", ""); err == nil {
		t.Fatal("expected token-mode start to fail on the bogus token")
	}
}
