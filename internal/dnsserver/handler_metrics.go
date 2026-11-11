package dnsserver

import (
	"math/bits"
	"sync/atomic"
	"time"

	"github.com/eoghan2t9/Irongrid-DNS/internal/upstream"
)

// Handler metrics: latency histogram and upstream health summaries.

// latencyHist estimates response-time percentiles from a fixed set of
// millisecond buckets (powers of two, plus an overflow bucket), so the
// dashboard's Performance card gets p50/p95/p99 without scanning the query
// log or holding locks on the hot path — recording a query is one atomic add.
type latencyHist struct {
	// bucket i (i>=1) covers (2^(i-1), 2^i] ms; bucket 0 covers exactly 0ms
	// (a sub-millisecond response); the last bucket absorbs everything above
	// it.
	buckets [12]atomic.Int64
	total   atomic.Int64
}

func (h *latencyHist) record(d time.Duration) {
	i := bits.Len64(uint64(d.Milliseconds())) // 0 for 0ms; upper bound of bucket i is 2^i ms
	if i >= len(h.buckets) {
		i = len(h.buckets) - 1
	}
	h.buckets[i].Add(1)
	h.total.Add(1)
}

// pct returns the estimated response time (ms) at percentile p (0..100),
// or 0 when nothing has been recorded. Values are bucket upper bounds — an
// estimate, not an exact quantile.
func (h *latencyHist) pct(p float64) float64 {
	total := h.total.Load()
	if total == 0 {
		return 0
	}
	target := int64(float64(total) * p / 100)
	var seen int64
	last := -1 // highest bucket observed so far
	for i := range len(h.buckets) {
		n := h.buckets[i].Load()
		seen += n
		if n > 0 {
			last = i
		}
		if seen > target {
			if i == 0 {
				return 1
			}
			if i == len(h.buckets)-1 {
				return float64(int(1) << (i + 1)) // overflow: at least 2^(i+1) ms
			}
			return float64(int(1) << i)
		}
	}
	// Nothing crossed the target: either p == 100 (target == total, so the
	// top populated bucket is the answer) or the atomic snapshot caught
	// total just ahead of a concurrent record's bucket add. Estimate from
	// the highest populated bucket rather than a hardcoded overflow
	// constant, so a benign snapshot race can't paint a phantom 4s tail on
	// an otherwise fast server.
	if last <= 0 {
		return 1
	}
	if last == len(h.buckets)-1 {
		return float64(int(1) << (last + 1))
	}
	return float64(int(1) << last)
}

// LatencySummary is the dashboard Performance card's data: response-time
// percentiles (ms, estimated from the in-process histogram) since the
// process started.
type LatencySummary struct {
	Count int64   `json:"count"`
	P50   float64 `json:"p50"`
	P95   float64 `json:"p95"`
	P99   float64 `json:"p99"`
}

// LatencySummary returns the recorded percentiles since process start.
func (h *Handler) LatencySummary() LatencySummary {
	return LatencySummary{
		Count: h.latency.total.Load(),
		P50:   h.latency.pct(50),
		P95:   h.latency.pct(95),
		P99:   h.latency.pct(99),
	}
}

// UpstreamHealth is one upstream's circuit-breaker state for the dashboard's
// Upstreams card.
type UpstreamHealth struct {
	Name      string `json:"name"`
	Transport string `json:"transport"`
	// Fails is the consecutive-failure count driving the circuit breaker.
	Fails int64 `json:"fails"`
	// Available is false only while the circuit is open (circuitOpenFails+
	// consecutive failures inside the cooldown window).
	Available bool `json:"available"`
	// CooldownUntil is when an open circuit re-arms; nil when closed.
	CooldownUntil *time.Time `json:"cooldown_until,omitempty"`
	// Recursive reports whether this upstream resolves iteratively from the
	// root servers rather than forwarding.
	Recursive bool `json:"recursive"`
	// PoolHits/PoolMisses count how often a query reused a warm pooled or
	// persistent connection (TCP/DoT/UDP/DoQ) versus paid for a fresh dial,
	// since restart. Always zero for DoH (its connection pooling is Go's
	// own http.Transport, which doesn't expose per-request reuse counts)
	// and Recursive (no persistent upstream connection to reuse).
	PoolHits   int64 `json:"pool_hits"`
	PoolMisses int64 `json:"pool_misses"`
}

// UpstreamHealth snapshots the current upstream set's circuit state.
func (h *Handler) UpstreamHealth() []UpstreamHealth {
	ups := h.settings.Load().Upstreams
	out := make([]UpstreamHealth, 0, len(ups))
	for _, u := range ups {
		hits, misses := u.PoolStats()
		out = append(out, UpstreamHealth{
			Name:          u.Name(),
			Transport:     string(u.Transport),
			Fails:         u.Fails(),
			Available:     u.Available(),
			CooldownUntil: u.CooldownUntil(),
			Recursive:     u.Transport == upstream.Recursive,
			PoolHits:      hits,
			PoolMisses:    misses,
		})
	}
	return out
}
