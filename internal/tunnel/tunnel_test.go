package tunnel

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cloudflare/cloudflared/cmd/cloudflared/cliutil"
	cftunnel "github.com/cloudflare/cloudflared/cmd/cloudflared/tunnel"
	"github.com/cloudflare/cloudflared/metrics"
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
	metrics.RegisterBuildInfo("IrongridDNS", time.Now().Format(time.RFC3339), "v0.1.0")
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
