package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"slices"
	"testing"

	"github.com/eoghan2t9/Irongrid-DNS/internal/config"
)

func reloadStillRequires(t *testing.T, h *Handler) []string {
	t.Helper()
	rec := httptest.NewRecorder()
	h.reloadConfig(rec)
	if rec.Code != http.StatusOK {
		t.Fatalf("reload status = %d, body %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		StillRequiresRestart []string `json:"still_requires_restart"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return resp.StillRequiresRestart
}

// TestReloadIgnoresStaleTunnelConfig: a disabled tunnel that merely still has
// a token in the config (and was never changed) must not be reported as
// "still requires restart". It used to be, on every reload, so the dashboard's
// "Apply & restart" prompt came straight back after each click and could never
// be cleared.
func TestReloadIgnoresStaleTunnelConfig(t *testing.T) {
	h := &Handler{Cfg: &config.Config{}, Reload: func() error { return nil }}
	h.Cfg.Tunnel.Token = "leftover-token"
	h.Cfg.Tunnel.Enabled = false
	if got := reloadStillRequires(t, h); len(got) != 0 {
		t.Fatalf("still_requires_restart = %v, want none", got)
	}
	// An enabled tunnel that nobody changed this run is likewise already
	// running the config it was started with.
	h.Cfg.Tunnel.Enabled = true
	if got := reloadStillRequires(t, h); len(got) != 0 {
		t.Fatalf("enabled-but-unchanged tunnel still_requires_restart = %v, want none", got)
	}
}

// TestCarryOverUneditablePreservesAllowFrom: the dashboard payload has no
// server.allow_from, so a save built a config without it. That wiped the
// allow-list from memory and from irongrid.yaml, and made the restart diff
// see the (empty-but-non-nil) running value as "changed" — raising a
// spurious "Apply & restart" after the first save of every run.
func TestCarryOverUneditablePreservesAllowFrom(t *testing.T) {
	running := &config.Config{}
	running.Server.AllowFrom = []string{"10.0.0.0/8", "192.168.1.5"}
	fresh := &config.Config{} // what a payload-built config looks like
	carryOverUneditable(fresh, running)
	if !slices.Equal(fresh.Server.AllowFrom, running.Server.AllowFrom) {
		t.Fatalf("allow_from = %v, want %v", fresh.Server.AllowFrom, running.Server.AllowFrom)
	}

	// An empty-but-non-nil list (`allow_from: []` in YAML) must compare equal
	// to itself after the carry-over — no false "server changed".
	running.Server.AllowFrom = []string{}
	fresh = &config.Config{}
	carryOverUneditable(fresh, running)
	if !reflect.DeepEqual(running.Server, fresh.Server) {
		t.Fatalf("server sections differ after carry-over: %#v vs %#v", running.Server, fresh.Server)
	}
}

// TestReloadReportsPendingTunnelChange: a tunnel change saved since the
// process started is not applied by an in-place reload, so it must still be
// reported until the process restarts.
func TestReloadReportsPendingTunnelChange(t *testing.T) {
	h := &Handler{Cfg: &config.Config{}, Reload: func() error { return nil }}
	h.tunnelPending.Store(true)
	got := reloadStillRequires(t, h)
	if !slices.Equal(got, []string{"tunnel"}) {
		t.Fatalf("still_requires_restart = %v, want [tunnel]", got)
	}
	// A reload does not clear it: only a real restart does.
	if got := reloadStillRequires(t, h); !slices.Equal(got, []string{"tunnel"}) {
		t.Fatalf("second reload still_requires_restart = %v, want [tunnel]", got)
	}
}
