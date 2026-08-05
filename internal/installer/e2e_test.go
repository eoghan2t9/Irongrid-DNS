//go:build !windows

// The E2E wizard tests drive a real PTY via github.com/creack/pty, which is
// Unix-only. Windows builds of the package skip this file entirely.

package installer

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/creack/pty"
)

// TestRunEndToEnd drives the full wizard in accessible mode over a real PTY
// with scripted answers, declining the Dragonfly install (offline), then
// verifies the written config and service files.
func TestRunEndToEnd(t *testing.T) {
	runEndToEnd(t, false)
}

// TestRunEndToEndWithDragonfly is the same flow but answers "yes" to the
// "Install and start Dragonfly now?" question. A fake Redis (the same one
// the dragonfly tests use) answers PING on the configured address, so
// EnsureDragonfly takes its reuse path — no downloads, no side effects.
func TestRunEndToEndWithDragonfly(t *testing.T) {
	runEndToEnd(t, true)
}

// runEndToEnd drives the wizard once. IRONGRID_ACCESSIBLE=1 forces line-based
// rendering even though stdin is a TTY, which is exactly how CI/non-interactive
// installs run. The PTY is required so the password fields can read from a
// real terminal fd. IRONGRID_SKIP_PRIVILEGED=1 keeps the run offline and side
// effect free (no binary placement, no system service).
func runEndToEnd(t *testing.T, withDragonfly bool) {
	if testing.Short() {
		t.Skip("skipping interactive wizard E2E in -short mode")
	}
	if err := os.Setenv("IRONGRID_ACCESSIBLE", "1"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Unsetenv("IRONGRID_ACCESSIBLE") })
	if err := os.Setenv("IRONGRID_SKIP_PRIVILEGED", "1"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Unsetenv("IRONGRID_SKIP_PRIVILEGED") })

	dragonflyAddr := "localhost:6379"
	if withDragonfly {
		dragonflyAddr = fakeRedis(t)
	}

	dir := t.TempDir()
	configPath := filepath.Join(dir, "irongrid.yaml")

	master, slave, err := pty.Open()
	if err != nil {
		t.Fatalf("pty.Open: %v", err)
	}
	defer master.Close()
	defer slave.Close()

	done := make(chan error, 1)
	go func() {
		done <- Run(Options{
			ConfigPath: configPath,
			DataDir:    filepath.Join(dir, "data"),
			In:         slave,
			Out:        slave,
		})
	}()

	// Feed answers one prompt at a time. The wizard's accessible renderer
	// prints each prompt to the slave; we read it back on the master so we
	// know exactly when to send the next answer.
	//
	// Matching uses a cursor over the ANSI-stripped stream: each expect() only
	// searches the output appended since the previous match, so an earlier
	// prompt ("Dragonfly password") can never satisfy a later expect() for
	// "Password".
	var output bytes.Buffer
	consumed := 0 // index into stripANSI(output.String()) already matched
	expect := func(want string, answers ...string) {
		t.Helper()
		deadline := time.Now().Add(10 * time.Second)
		for {
			seen := stripANSI(output.String())
			if strings.Contains(seen[consumed:], want) {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("timed out waiting for %q; output so far:\n%s", want, output.String())
			}
			buf := make([]byte, 4096)
			n, rerr := master.Read(buf)
			if rerr != nil {
				t.Fatalf("reading pty master: %v", rerr)
			}
			output.Write(buf[:n])
			time.Sleep(10 * time.Millisecond)
		}
		// Advance the cursor past this match.
		seen := stripANSI(output.String())
		if idx := strings.Index(seen[consumed:], want); idx >= 0 {
			consumed += idx + len(want)
		}
		for _, a := range answers {
			if _, werr := fmt.Fprintf(master, "%s\n", a); werr != nil {
				t.Fatalf("writing answer %q: %v", a, werr)
			}
			time.Sleep(30 * time.Millisecond)
		}
	}

	// 1. Deployment -> Native (option 2).
	expect("Deployment", "2")
	// 2. Service manager -> systemd (option 1, pre-selected on Linux).
	expect("Service manager", "1")
	// 3. Protocols: UDP+TCP are pre-selected; confirm with 0.
	expect("Select up to 5 options", "0")
	// 4. Listen address.
	expect("Listen address", "0.0.0.0")
	// 5. Upstream preset -> Cloudflare (option 1).
	expect("Upstream preset", "1")
	// 6. Custom upstreams (empty).
	expect("Custom upstreams", "")
	// 7. Dragonfly address.
	expect("Dragonfly address", dragonflyAddr)
	// 8. Dragonfly password (empty).
	expect("Dragonfly password", "")
	// 9. Install Dragonfly now? -> yes (offline path answers no).
	answer := "n"
	if withDragonfly {
		answer = "y"
	}
	expect("Install and start Dragonfly now?", answer)
	// 10. Blocklists: toggle OISD Big (1), then confirm (0).
	expect("Blocklists", "1", "0")
	// 11. Whitelist presets: toggle OS updates (1), then confirm (0).
	expect("Always-allow presets", "1", "0")
	// 12. Username.
	expect("Username", "admin")
	// 13. Password.
	expect("Password", "testpass123")
	// 14. Confirm password.
	expect("Confirm password", "testpass123")
	// 15. TLS hosts.
	expect("Self-signed certificate hosts", "localhost, dns.example.com")
	// 16. Final confirm -> Install (y).
	expect("Write configuration and service files?", "y")

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
	case <-time.After(30 * time.Second):
		t.Fatalf("Run did not finish; output so far:\n%s", output.String())
	}

	// Config was written and validates.
	raw, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("config not written: %v", err)
	}
	cfg := string(raw)
	for _, want := range []string{
		"listen_udp: 0.0.0.0:53",
		"listen_tcp: 0.0.0.0:53",
		"listen_dot: \"\"",
		"username: admin",
		"id: oisd-big",
		"update.microsoft.com", // from the OS-updates whitelist preset
		"dns.example.com",      // TLS SAN
	} {
		if !strings.Contains(cfg, want) {
			t.Errorf("config missing %q:\n%s", want, cfg)
		}
	}
	if !strings.Contains(cfg, dragonflyAddr) {
		t.Errorf("config cache addr should be %q:\n%s", dragonflyAddr, cfg)
	}

	// systemd service file was generated next to the config.
	svc := filepath.Join(dir, "deploy", "irongrid.service")
	if _, err := os.Stat(svc); err != nil {
		t.Errorf("systemd unit not written: %v", err)
	}
	// The "already running" reuse logic itself is covered by
	// TestEnsureDragonflyAlreadyRunning in dragonfly_test.go; here we only
	// verify the wizard accepts the Dragonfly install step and writes the
	// chosen cache address into the config.
}

// stripANSI removes ANSI escape sequences from captured output so prompts can
// be matched on their plain text.
func stripANSI(s string) string {
	var b strings.Builder
	inEsc := false
	for _, r := range s {
		if inEsc {
			if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') {
				inEsc = false
			}
			continue
		}
		if r == '\x1b' {
			inEsc = true
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}
