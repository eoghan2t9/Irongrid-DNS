package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/eoghan2t9/Irongrid-DNS/internal/config"
)

func updatesHandler() *Handler {
	return &Handler{Cfg: &config.Config{}, Version: "v1.0.0"}
}

// TestGetUpdatesShape verifies the combined status lists only Irongrid
// (cloudflared is omitted without a tunnel manager, and the cache is embedded
// so there is nothing else to update) and that an unreachable upstream is
// reported per tool instead of failing the whole response. A cancelled
// context makes every release lookup fail fast, offline.
func TestGetUpdatesShape(t *testing.T) {
	t.Parallel()
	h := updatesHandler()

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
	if len(byID) != 1 || byID["irongrid"].ID == "" {
		t.Fatalf("tools = %+v, want irongrid only", out.Tools)
	}
	if byID["irongrid"].Current != "v1.0.0" {
		t.Fatalf("irongrid current = %q, want v1.0.0", byID["irongrid"].Current)
	}
	if byID["irongrid"].Error == "" {
		t.Fatal("a failed release lookup must surface as that tool's error")
	}
}

// TestUpdatesRoutesRejectWrongMethod keeps the status endpoint GET-only, and
// confirms the removed Dragonfly endpoints are really gone.
func TestUpdatesRoutesRejectWrongMethod(t *testing.T) {
	t.Parallel()
	h := updatesHandler()
	for _, tc := range []struct{ method, path string }{
		{http.MethodPost, "/api/updates/dragonfly/install"},
		{http.MethodPost, "/api/updates/dragonfly/restart"},
		{http.MethodPost, "/api/updates"},
	} {
		rr := httptest.NewRecorder()
		h.HandleAPI(rr, httptest.NewRequest(tc.method, tc.path, nil))
		if rr.Code != http.StatusNotFound {
			t.Fatalf("%s %s = %d, want 404", tc.method, tc.path, rr.Code)
		}
	}
}
