package api

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sort"
	"strconv"
	"strings"
)

// metrics renders a Prometheus text-exposition-format snapshot of the same
// counters /api/stats already computes from (cache L1/L2 hits, per-protocol
// traffic, latency percentiles, upstream circuit-breaker state, in-flight
// coalescing) — hand-rolled rather than pulling in the full
// prometheus/client_golang dependency tree (and its transitive
// protobuf/procfs/common packages) for what is, underneath, printing a
// handful of already-tracked int64s and float64s in a fixed text format.
//
// Deliberately lighter than /api/stats: it skips the query-log stream walk
// (StatsBundle) entirely, since a Prometheus scrape (typically every
// 10-15s) should never add load to Dragonfly for data that isn't
// itself a metric.
func (h *Handler) Metrics(ctx context.Context, w http.ResponseWriter) {
	var b strings.Builder

	writeCounter := func(name, help string, v int64) {
		fmt.Fprintf(&b, "# HELP %s %s\n# TYPE %s counter\n%s %d\n", name, help, name, name, v)
	}
	writeGauge := func(name, help string, v float64) {
		fmt.Fprintf(&b, "# HELP %s %s\n# TYPE %s gauge\n%s %s\n", name, help, name, name, formatMetricFloat(v))
	}

	s := h.DNS.Stats
	writeCounter("irongrid_queries_total", "Total DNS queries processed since restart.", s.Total.Load())
	writeCounter("irongrid_queries_blocked_total", "Queries blocked by policy.", s.Blocked.Load())
	writeCounter("irongrid_queries_allowed_total", "Queries allowed through.", s.Allowed.Load())
	writeCounter("irongrid_queries_cached_total", "Queries answered from cache.", s.Cached.Load())
	writeCounter("irongrid_query_errors_total", "Queries that ended in an error.", s.Errors.Load())
	writeCounter("irongrid_honeypot_hits_total", "Refused trap-domain hits (attack traffic).", s.Honeypot.Load())
	writeCounter("irongrid_doh_asn_header_total", "DoH responses carrying X-Irongrid-Client-ASN.", s.ASNHeader.Load())
	writeCounter("irongrid_udp_received_total", "UDP packets that reached userspace.", s.UDPReceived.Load())
	writeCounter("irongrid_udp_invalid_total", "UDP packets rejected before the shared handler.", s.UDPInvalid.Load())
	writeCounter("irongrid_udp_queue_drops_total", "UDP packets dropped for a full worker queue.", s.UDPQueueDrops.Load())
	writeCounter("irongrid_udp_completed_total", "UDP requests completed.", s.UDPCompleted.Load())
	writeCounter("irongrid_write_errors_total", "Response write failures.", s.WriteErrors.Load())
	writeCounter("irongrid_coalesce_flights_total", "Upstream resolutions issued through the in-flight request pool.", s.Flights.Load())
	writeCounter("irongrid_coalesce_merged_total", "Queries served by a shared in-flight resolution.", s.Merged.Load())

	protos := make([]string, 0, len(s.ByProtocol))
	for p := range s.ByProtocol {
		protos = append(protos, p)
	}
	sort.Strings(protos)
	fmt.Fprintf(&b, "# HELP irongrid_queries_by_protocol_total Queries by transport protocol.\n# TYPE irongrid_queries_by_protocol_total counter\n")
	for _, p := range protos {
		fmt.Fprintf(&b, "irongrid_queries_by_protocol_total{protocol=%s} %d\n", promLabelValue(p), s.ByProtocol[p].Load())
	}

	if h.Cache != nil {
		l1h, l1m := h.Cache.L1Counters()
		writeCounter("irongrid_cache_l1_hits_total", "L1 (in-process) cache hits since restart.", l1h)
		writeCounter("irongrid_cache_l1_misses_total", "L1 (in-process) cache misses since restart.", l1m)
		if ls, err := h.Cache.L2Stats(ctx); err == nil {
			writeCounter("irongrid_cache_l2_hits_total", "L2 (Dragonfly) cache hits since Dragonfly started.", ls.Hits)
			writeCounter("irongrid_cache_l2_misses_total", "L2 (Dragonfly) cache misses since Dragonfly started.", ls.Misses)
			writeCounter("irongrid_cache_l2_expired_total", "L2 keys expired since Dragonfly started.", ls.Expired)
			writeCounter("irongrid_cache_l2_evicted_total", "L2 keys evicted for memory pressure since Dragonfly started.", ls.Evicted)
			writeGauge("irongrid_cache_l2_used_bytes", "L2 memory currently in use.", float64(ls.UsedBytes))
			writeGauge("irongrid_cache_l2_max_bytes", "L2 configured memory budget.", float64(ls.MaxBytes))
			writeGauge("irongrid_cache_l2_keys", "L2 key count.", float64(ls.Keys))
		}
	}

	lat := h.DNS.LatencySummary()
	writeCounter("irongrid_latency_samples_total", "Queries counted in the latency histogram since restart.", lat.Count)
	fmt.Fprintf(&b, "# HELP irongrid_latency_seconds Estimated response-time quantile since restart (in-process histogram).\n# TYPE irongrid_latency_seconds gauge\n")
	fmt.Fprintf(&b, "irongrid_latency_seconds{quantile=\"0.5\"} %s\n", formatMetricFloat(lat.P50/1000))
	fmt.Fprintf(&b, "irongrid_latency_seconds{quantile=\"0.95\"} %s\n", formatMetricFloat(lat.P95/1000))
	fmt.Fprintf(&b, "irongrid_latency_seconds{quantile=\"0.99\"} %s\n", formatMetricFloat(lat.P99/1000))

	ups := h.DNS.UpstreamHealth()
	fmt.Fprintf(&b, "# HELP irongrid_upstream_available Whether the upstream's circuit breaker is currently closed (1) or open/cooling down (0).\n# TYPE irongrid_upstream_available gauge\n")
	fmt.Fprintf(&b, "# HELP irongrid_upstream_consecutive_fails Consecutive failures currently driving the upstream's circuit breaker.\n# TYPE irongrid_upstream_consecutive_fails gauge\n")
	for _, u := range ups {
		avail := 0
		if u.Available {
			avail = 1
		}
		labels := fmt.Sprintf("name=%s,transport=%s", promLabelValue(u.Name), promLabelValue(u.Transport))
		fmt.Fprintf(&b, "irongrid_upstream_available{%s} %d\n", labels, avail)
		fmt.Fprintf(&b, "irongrid_upstream_consecutive_fails{%s} %d\n", labels, u.Fails)
	}

	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	if _, err := io.WriteString(w, b.String()); err != nil {
		slog.Error("metrics write failed", "error", err)
	}
}

// formatMetricFloat renders v the way the Prometheus text format expects:
// no exponent notation (some older scrapers/parsers choke on it) and no
// trailing zeros.
func formatMetricFloat(v float64) string {
	return strconv.FormatFloat(v, 'f', -1, 64)
}

// promLabelValue quotes and escapes a label value per the Prometheus text
// exposition format (backslash, double-quote and newline must be escaped).
// Protocol and upstream names come from config, not raw user input, but
// escaping unconditionally is cheap and means a future label source can
// never produce an unparsable line.
func promLabelValue(v string) string {
	v = strings.ReplaceAll(v, `\`, `\\`)
	v = strings.ReplaceAll(v, `"`, `\"`)
	v = strings.ReplaceAll(v, "\n", `\n`)
	return `"` + v + `"`
}
