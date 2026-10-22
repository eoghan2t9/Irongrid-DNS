package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/eoghan2t9/Irongrid-DNS/internal/config"
)

func updatesHandler(cacheAddr string) *Handler {
	cfg := &config.Config{}
	cfg.Cache.Addr = cacheAddr
	return &Handler{Cfg: cfg, Version: "v1.0.0"}
}

// TestGetUpdatesShape verifies the combined status lists Irongrid and Dragonfly
// (cloudflared is omitted without a tunnel manager) and that an unreachable
// upstream is reported per tool instead of failing the whole response. A
// cancelled context makes every release lookup fail fast, offline.
func TestGetUpdatesShape(t *testing.T) {
	t.Parallel()
	h := updatesHandler("dragonfly:6379")

	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	rr := httptest.NewRecorder()
	h.HandleAPI(rr, httptest.NewRequest(http.MethodGet, "/api/updates", nil).WithContext(ctx))
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body %s", rr.Code, rr.Body.String())
	}
	var out struct {
		Tools []toolStatus `json:"tools"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	byID := map[string]toolStatus{}
	for _, tool := range out.Tools {
		byID[tool.ID] = tool
	}
	if len(byID) != 2 || byID["irongrid"].ID == "" || byID["dragonfly"].ID == "" {
		t.Fatalf("tools = %+v, want irongrid + dragonfly only", out.Tools)
	}
	if byID["irongrid"].Current != "v1.0.0" {
		t.Fatalf("irongrid current = %q, want v1.0.0", byID["irongrid"].Current)
	}
	if byID["irongrid"].Error == "" {
		t.Fatal("a failed release lookup must surface as that tool's error")
	}
}

// TestManagedDragonflyBinRefusesRemoteCache verifies Irongrid will not offer to
// swap a binary on this machine when the cache lives elsewhere (for example
// Docker Compose's internal "dragonfly" host).
func TestManagedDragonflyBinRefusesRemoteCache(t *testing.T) {
	t.Parallel()
	for _, addr := range []string{"dragonfly:6379", "redis://10.0.0.5:6379", "cache.example.net:6379"} {
		bin, why := updatesHandler(addr).managedDragonflyBin()
		if bin != "" || !strings.Contains(why, "not this machine") {
			t.Fatalf("addr %q: bin=%q why=%q, want refusal for a non-local cache", addr, bin, why)
		}
	}
}

func TestDragonflyInstallRefusedForRemoteCache(t *testing.T) {
	t.Parallel()
	h := updatesHandler("dragonfly:6379")
	for _, path := range []string{"/api/updates/dragonfly/install", "/api/updates/dragonfly/restart"} {
		rr := httptest.NewRecorder()
		h.HandleAPI(rr, httptest.NewRequest(http.MethodPost, path, nil))
		if rr.Code != http.StatusBadRequest || !strings.Contains(rr.Body.String(), "not this machine") {
			t.Fatalf("POST %s = %d %s, want 400 refusal", path, rr.Code, rr.Body.String())
		}
	}
}

// TestUpdatesRoutesRejectWrongMethod keeps the install endpoints POST-only and
// the status endpoint GET-only.
func TestUpdatesRoutesRejectWrongMethod(t *testing.T) {
	t.Parallel()
	h := updatesHandler("dragonfly:6379")
	for _, tc := range []struct{ method, path string }{
		{http.MethodGet, "/api/updates/dragonfly/install"},
		{http.MethodGet, "/api/updates/dragonfly/restart"},
		{http.MethodPost, "/api/updates"},
	} {
		rr := httptest.NewRecorder()
		h.HandleAPI(rr, httptest.NewRequest(tc.method, tc.path, nil))
		if rr.Code != http.StatusNotFound {
			t.Fatalf("%s %s = %d, want 404", tc.method, tc.path, rr.Code)
		}
	}
}
