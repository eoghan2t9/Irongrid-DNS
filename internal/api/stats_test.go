package api

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/eoghan2t9/Irongrid-DNS/internal/cache"
	"github.com/eoghan2t9/Irongrid-DNS/internal/config"
	"github.com/eoghan2t9/Irongrid-DNS/internal/dnsserver"
	"github.com/eoghan2t9/Irongrid-DNS/internal/filter"
	"github.com/eoghan2t9/Irongrid-DNS/internal/querylog"
)

// TestGetStatsShape verifies the stats response carries the cache block (L1
// counters, best-effort L2) and the query_today window that the dashboard's
// Dragonfly-cache and query-log cards read. A disabled log and local-only
// cache keep the test free of a live Redis server.
func TestGetStatsShape(t *testing.T) {
	ql := querylog.NewDisabled(30)
	defer ql.Close()
	h := &Handler{
		Cfg:    config.Default(),
		Log:    ql,
		DNS:    dnsserver.NewHandler(filter.NewEngine(), nil, nil, nil, "nxdomain", 600, 5),
		Engine: filter.NewEngine(),
		Cache:  cache.NewLocalOnly(time.Hour, time.Minute, 512),
	}
	rr := httptest.NewRecorder()
	h.getStats(context.Background(), rr)
	if rr.Code != 200 {
		t.Fatalf("getStats status = %d, body %s", rr.Code, rr.Body.String())
	}
	var out map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode stats: %v", err)
	}

	cacheBlock, ok := out["cache"].(map[string]any)
	if !ok {
		t.Fatalf("stats missing cache block: %v", out)
	}
	l1, ok := cacheBlock["l1"].(map[string]any)
	if !ok {
		t.Fatalf("cache block missing l1: %v", cacheBlock)
	}
	if l1["hits"] == nil || l1["misses"] == nil {
		t.Fatalf("l1 counters missing: %v", l1)
	}
	// A local-only cache has no L2: the key must exist but stay nil (the
	// dashboard's optional chaining handles it).
	if _, ok := cacheBlock["l2"]; !ok {
		t.Fatalf("cache block missing l2 key: %v", cacheBlock)
	}

	qt, ok := out["query_today"].(map[string]any)
	if !ok {
		t.Fatalf("stats missing query_today: %v", out)
	}
	for _, k := range []string{"total", "allowed", "blocked", "cached", "avg_rt_ms", "top_blocked", "top_clients"} {
		if _, ok := qt[k]; !ok {
			t.Fatalf("query_today missing field %q: %v", k, qt)
		}
	}
}
