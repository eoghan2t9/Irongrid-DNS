package api

import (
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/eoghan2t9/Irongrid-DNS/internal/cache"
	"github.com/eoghan2t9/Irongrid-DNS/internal/dnsserver"
	"github.com/eoghan2t9/Irongrid-DNS/internal/filter"
)

// TestMetricsShape verifies the Prometheus scrape response is well-formed
// text-exposition format (every metric line preceded by its HELP/TYPE
// comments) and carries the counters the dashboard's /api/stats also
// exposes. A local-only cache (no Redis) keeps the test free of a live
// Dragonfly server — L2 lines are expected to be absent in that case.
func TestMetricsShape(t *testing.T) {
	t.Parallel()
	h := &Handler{
		DNS:   dnsserver.NewHandler(filter.NewEngine(), nil, nil, nil, "nxdomain", 600, 5),
		Cache: cache.NewLocalOnly(time.Hour, time.Minute, 512, 0),
	}
	rr := httptest.NewRecorder()
	h.Metrics(t.Context(), rr)

	ct := rr.Header().Get("Content-Type")
	if !strings.HasPrefix(ct, "text/plain") {
		t.Fatalf("Content-Type = %q, want text/plain prefix", ct)
	}

	body := rr.Body.String()
	for _, want := range []string{
		"# HELP irongrid_queries_total",
		"# TYPE irongrid_queries_total counter",
		"irongrid_queries_total 0",
		"# HELP irongrid_cache_l1_hits_total",
		"irongrid_cache_l1_hits_total 0",
		"# HELP irongrid_latency_seconds",
		"irongrid_latency_seconds{quantile=\"0.5\"}",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("metrics output missing %q; got:\n%s", want, body)
		}
	}
	// No Redis client behind the local-only cache, so L2Stats fails and
	// those series must be omitted rather than emitted as zeros (which
	// would misreport "L2 is up but idle" instead of "L2 is absent").
	if strings.Contains(body, "irongrid_cache_l2_hits_total") {
		t.Fatalf("local-only cache should not emit L2 metrics; got:\n%s", body)
	}
}

// TestMetricsProtocolLabels verifies the per-protocol counter carries one
// labeled series per transport, matching h.DNS.Stats.ByProtocol.
func TestMetricsProtocolLabels(t *testing.T) {
	t.Parallel()
	h := &Handler{
		DNS:   dnsserver.NewHandler(filter.NewEngine(), nil, nil, nil, "nxdomain", 600, 5),
		Cache: cache.NewLocalOnly(time.Hour, time.Minute, 512, 0),
	}
	h.DNS.Stats.ByProtocol["udp"].Add(3)
	rr := httptest.NewRecorder()
	h.Metrics(t.Context(), rr)
	body := rr.Body.String()
	if !strings.Contains(body, `irongrid_queries_by_protocol_total{protocol="udp"} 3`) {
		t.Fatalf("metrics output missing udp protocol series; got:\n%s", body)
	}
}
