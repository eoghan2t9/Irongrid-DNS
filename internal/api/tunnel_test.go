package api

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/eoghan2t9/Irongrid-DNS/internal/config"
	"github.com/eoghan2t9/Irongrid-DNS/internal/tunnel"
)

// newTunnelTestHandler builds a Handler with a real config file on disk so
// the persistence behaviour (tunnelStart writes the token/config to the
// config file, tunnelStop disables auto-start) can be asserted end to end.
func newTunnelTestHandler(t *testing.T) (*Handler, *config.Config, string, *bool) {
	t.Helper()
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "irongrid.yaml")
	cfg := config.Default()
	saved := false
	h := &Handler{
		Cfg:        cfg,
		ConfigPath: cfgPath,
		SaveConfig: func() error {
			saved = true
			return cfg.Save(cfgPath)
		},
		Tunnel: tunnel.NewManager(dir),
	}
	return h, cfg, cfgPath, &saved
}

// TestTunnelStartPersistsOnFailure covers the "failed start" path: starting
// with a bad token fails fast and offline in cloudflared's ParseToken (the
// hyphenated string is invalid base64), returning 500. The settings must
// still be written to the config file so the form is pre-filled next time,
// but auto-start must NOT be enabled — a bad token must not retry on every
// boot.
func TestTunnelStartPersistsOnFailure(t *testing.T) {
	h, cfg, cfgPath, saved := newTunnelTestHandler(t)

	const token = "definitely-not-a-valid-tunnel-token"
	body := `{"mode":"token","token":"` + token + `","hostname":"dns.example.com"}`
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/tunnel/start", bytes.NewBufferString(body))
	h.tunnelStart(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("start status = %d, want 500 (bogus token must fail); body %s", rr.Code, rr.Body.String())
	}
	if !*saved {
		t.Fatal("SaveConfig was never called — settings not persisted on failure")
	}
	if cfg.Tunnel.Token != token {
		t.Errorf("cfg.Tunnel.Token = %q, want %q", cfg.Tunnel.Token, token)
	}
	if cfg.Tunnel.Hostname != "dns.example.com" {
		t.Errorf("cfg.Tunnel.Hostname = %q, want dns.example.com", cfg.Tunnel.Hostname)
	}
	if cfg.Tunnel.Enabled {
		t.Error("cfg.Tunnel.Enabled = true after a failed start, want false (no auto-start with a bad token)")
	}

	// The settings made it to disk even though the start failed.
	data, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatalf("read saved config: %v", err)
	}
	if !strings.Contains(string(data), token) {
		t.Error("saved config file does not contain the tunnel token")
	}
}

// TestTunnelStartPersistsEnabledOnSuccess covers the happy path: a started
// tunnel is written to the config with Enabled=true so main's auto-start
// block brings it back on the next boot. The persistence helper is exercised
// directly because reaching a real successful cloudflared start in a unit
// test would require network access.
func TestTunnelStartPersistsEnabledOnSuccess(t *testing.T) {
	h, cfg, cfgPath, saved := newTunnelTestHandler(t)

	p := tunnelStartPayload{Token: "real-tunnel-token", Hostname: "dns.example.com"}
	if err := h.persistTunnelSettings(tunnel.ModeToken, p, true); err != nil {
		t.Fatalf("persistTunnelSettings: %v", err)
	}
	if !*saved {
		t.Fatal("SaveConfig was never called")
	}
	if !cfg.Tunnel.Enabled {
		t.Error("cfg.Tunnel.Enabled = false, want true (auto-start enabled after a successful start)")
	}
	if cfg.Tunnel.Token != "real-tunnel-token" {
		t.Errorf("cfg.Tunnel.Token = %q, want real-tunnel-token", cfg.Tunnel.Token)
	}
	if cfg.Tunnel.QuickTunnel {
		t.Error("cfg.Tunnel.QuickTunnel = true, want false for token mode")
	}

	data, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatalf("read saved config: %v", err)
	}
	if !strings.Contains(string(data), "real-tunnel-token") {
		t.Error("saved config file does not contain the tunnel token")
	}
	if !strings.Contains(string(data), "enabled: true") {
		t.Error("saved config file does not have tunnel enabled: true")
	}
}

// TestTunnelStartQuickPersistsOrigin verifies quick-mode persistence records
// the origin URL (used as the auto-start origin) and the quick flag. Also
// exercised through the helper so no real trycloudflare tunnel is launched.
func TestTunnelStartQuickPersistsOrigin(t *testing.T) {
	h, cfg, _, saved := newTunnelTestHandler(t)

	p := tunnelStartPayload{Origin: "http://localhost:8443"}
	if err := h.persistTunnelSettings(tunnel.ModeQuick, p, true); err != nil {
		t.Fatalf("persistTunnelSettings: %v", err)
	}
	if !*saved {
		t.Fatal("SaveConfig was never called")
	}
	if !cfg.Tunnel.Enabled {
		t.Error("cfg.Tunnel.Enabled = false, want true")
	}
	if !cfg.Tunnel.QuickTunnel {
		t.Error("cfg.Tunnel.QuickTunnel = false, want true for quick mode")
	}
	if cfg.Tunnel.QuickTunnelURL != "http://localhost:8443" {
		t.Errorf("cfg.Tunnel.QuickTunnelURL = %q, want http://localhost:8443", cfg.Tunnel.QuickTunnelURL)
	}
}

// TestTunnelStartRejectsBadInput guards the validation so a broken
// configuration (empty token, missing config file, unknown mode) is rejected
// with 400 and never persisted as auto-start-enabled.
func TestTunnelStartRejectsBadInput(t *testing.T) {
	h, cfg, _, saved := newTunnelTestHandler(t)

	cases := []struct {
		name string
		body string
	}{
		{"empty token", `{"mode":"token","token":""}`},
		{"missing config file", `{"mode":"config","config_file":"/nonexistent/cloudflared.yml"}`},
		{"unknown mode", `{"mode":"bogus"}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rr := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, "/api/tunnel/start", bytes.NewBufferString(tc.body))
			h.tunnelStart(rr, req)
			if rr.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400; body %s", rr.Code, rr.Body.String())
			}
		})
	}
	if *saved {
		t.Fatal("SaveConfig was called for a rejected start — broken settings must not persist")
	}
	if cfg.Tunnel.Enabled {
		t.Fatal("cfg.Tunnel.Enabled = true after rejected starts, want false")
	}
}

// TestTunnelStopDisablesAutoStart verifies stopping a tunnel persists
// Enabled=false so it does not auto-start on the next boot, while keeping
// the token so the form is still pre-filled.
func TestTunnelStopDisablesAutoStart(t *testing.T) {
	h, cfg, _, saved := newTunnelTestHandler(t)
	cfg.Tunnel.Enabled = true
	cfg.Tunnel.Token = "previously-saved-token"

	rr := httptest.NewRecorder()
	h.tunnelStop(rr)

	if !*saved {
		t.Fatal("SaveConfig was never called on stop")
	}
	if cfg.Tunnel.Enabled {
		t.Error("cfg.Tunnel.Enabled = true after stop, want false (auto-start disabled)")
	}
	if cfg.Tunnel.Token != "previously-saved-token" {
		t.Errorf("cfg.Tunnel.Token = %q, want the token kept for re-use", cfg.Tunnel.Token)
	}
}
