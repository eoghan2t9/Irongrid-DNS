package querylog

import (
	"fmt"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
)

func entry(domain, action string) Entry {
	return Entry{
		Time: time.Now(), Client: "127.0.0.1", Domain: domain,
		Type: "A", Action: action, Upstream: "udp://1.1.1.1:53",
		ResponseTimeMS: 12, Rcode: 0, Answers: 1,
	}
}

// newTestLog starts an in-memory Redis-compatible server (miniredis) and
// returns a stream-backed Log pointing at it plus the server, so tests can
// recreate a Log over the same data (mimicking a restart).
func newTestLog(t *testing.T, retentionDays int) (*Log, *miniredis.Miniredis) {
	t.Helper()
	mr := miniredis.RunT(t)
	l, err := New(mr.Addr(), "", 0, retentionDays, 0)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = l.Close() })
	return l, mr
}

// waitFor polls until n entries are visible or the deadline passes (the
// writer flushes asynchronously).
func waitFor(t *testing.T, l *Log, n int) []Entry {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		entries, err := l.Query(t.Context(), n+10, 0, "", "", "", "")
		if err != nil {
			t.Fatalf("Query: %v", err)
		}
		if len(entries) >= n {
			return entries
		}
		if time.Now().After(deadline) {
			t.Fatalf("only %d of %d entries flushed in time", len(entries), n)
		}
		time.Sleep(25 * time.Millisecond)
	}
}

// TestEntryASNField verifies the per-entry ASN field (the server's own
// IP→ASN attribution) survives the JSON round-trip through the stream, and
// that entries recorded without one read back as 0.
func TestEntryASNField(t *testing.T) {
	t.Parallel()
	l, _ := newTestLog(t, 7)
	e := entry("asn-test.example", "allowed")
	e.ASN = 13335
	l.Record(e)
	if got := waitFor(t, l, 1); got[0].ASN != 13335 {
		t.Fatalf("ASN = %d, want 13335", got[0].ASN)
	}
	l.Record(entry("no-asn.example", "allowed"))
	for _, g := range waitFor(t, l, 2) {
		if g.Domain == "no-asn.example" && g.ASN != 0 {
			t.Fatalf("entry without ASN read back as %d, want 0", g.ASN)
		}
	}
}

// TestRecordFlushesOnClose verifies entries enqueued before Close are flushed
// to the stream — the final partial batch must not be lost at shutdown — and
// that a reopened log over the same server sees them.
func TestRecordFlushesOnClose(t *testing.T) {
	t.Parallel()
	mr := miniredis.RunT(t)
	l, err := New(mr.Addr(), "", 0, 30, 0)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	for range 10 {
		l.Record(entry("example.com.", "allowed"))
	}
	if err := l.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Reopen over the same (still running) server and count what persisted.
	r, err := New(mr.Addr(), "", 0, 30, 0)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer r.Close()
	entries, err := r.Query(t.Context(), 100, 0, "", "", "", "")
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(entries) != 10 {
		t.Fatalf("persisted %d entries, want 10", len(entries))
	}
	for _, e := range entries {
		if e.ID == "" {
			t.Fatal("entries read back from the stream must carry a stream ID")
		}
	}
}

// BenchmarkQueryLogRecord exercises the full hot-path call: Record's enqueue
// onto the bounded, drop-on-full entries channel (see logQueueCap) drained
// by the single runWriter goroutine, backed by a real miniredis instance so
// the writer actually flushes batches instead of hitting a nil client. Each
// parallel iteration logs a distinct domain, mirroring real traffic.
func BenchmarkQueryLogRecord(b *testing.B) {
	mr := miniredis.RunT(b)
	l, err := New(mr.Addr(), "", 0, 30, 0)
	if err != nil {
		b.Fatalf("New: %v", err)
	}
	b.Cleanup(func() { _ = l.Close() })

	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			l.Record(entry(fmt.Sprintf("bench-%d.example.com.", i), "allowed"))
			i++
		}
	})
}

// TestBatchFlush verifies queued entries are flushed without Close, via both
// the batch-size and the ticker paths.
func TestBatchFlush(t *testing.T) {
	t.Parallel()
	l, _ := newTestLog(t, 30)
	const n = logBatchSize + 50
	for range n {
		l.Record(entry("example.com.", "allowed"))
	}
	entries := waitFor(t, l, n)
	if len(entries) != n {
		t.Fatalf("flushed %d entries, want %d", len(entries), n)
	}
}

// TestQueryOrderAndFilters verifies newest-first ordering, the in-memory
// filters (action/qtype exact, domain substring) and pagination.
func TestQueryOrderAndFilters(t *testing.T) {
	t.Parallel()
	l, _ := newTestLog(t, 30)
	// Record in a distinct order so "newest first" is observable.
	l.Record(entry("aaa.com.", "allowed"))
	l.Record(entry("bbb.com.", "blocked"))
	l.Record(entry("ccc.com.", "allowed"))
	l.Record(entry("sub.bbb.com.", "blocked"))
	entries := waitFor(t, l, 4)

	if entries[0].Domain != "sub.bbb.com." || entries[3].Domain != "aaa.com." {
		t.Fatalf("expected newest-first order, got %q first / %q last",
			entries[0].Domain, entries[3].Domain)
	}

	blocked, err := l.Query(t.Context(), 100, 0, "blocked", "", "", "")
	if err != nil {
		t.Fatalf("Query blocked: %v", err)
	}
	if len(blocked) != 2 {
		t.Fatalf("blocked filter matched %d, want 2", len(blocked))
	}

	byDomain, err := l.Query(t.Context(), 100, 0, "", "bbb", "", "")
	if err != nil {
		t.Fatalf("Query domain: %v", err)
	}
	if len(byDomain) != 2 {
		t.Fatalf("domain substring matched %d, want 2 (bbb.com. + sub.bbb.com.)", len(byDomain))
	}

	// Pagination: offset 1, limit 2 over 4 entries -> the middle two.
	page, err := l.Query(t.Context(), 2, 1, "", "", "", "")
	if err != nil {
		t.Fatalf("Query page: %v", err)
	}
	if len(page) != 2 {
		t.Fatalf("page returned %d entries, want 2", len(page))
	}
	if page[0].Domain != entries[1].Domain || page[1].Domain != entries[2].Domain {
		t.Fatalf("pagination out of order: got %s,%s want %s,%s",
			page[0].Domain, page[1].Domain, entries[1].Domain, entries[2].Domain)
	}
}

// TestWalkStreamStrictBound verifies walkStream's scan bound is enforced
// inside the page: even when a single page holds more messages than the
// bound, exactly max messages are handed to the callback — the shared helper
// behind Query/Stats/Hourly/StatsBundle must never overshoot by a page.
func TestWalkStreamStrictBound(t *testing.T) {
	t.Parallel()
	l, _ := newTestLog(t, 30)
	for range 30 {
		l.Record(entry("a.com.", "allowed"))
	}
	waitFor(t, l, 30)

	// Bound of 10 with a page of 1000: the single page holds all 30
	// messages, yet the loop must see exactly 10.
	count := 0
	for _, err := range l.walkStream(t.Context(), true, "+", "-", 10, 1000) {
		if err != nil {
			t.Fatalf("walkStream: %v", err)
		}
		count++
	}
	if count != 10 {
		t.Fatalf("walkStream handed %d messages to the loop, want 10 (strict bound)", count)
	}

	// Breaking out of the loop also stops the walk early.
	stopped := 0
	for _, err := range l.walkStream(t.Context(), true, "+", "-", 1000, 1000) {
		if err != nil {
			t.Fatalf("walkStream early-exit: %v", err)
		}
		stopped++
		if stopped >= 3 {
			break
		}
	}
	if stopped != 3 {
		t.Fatalf("walkStream loop saw %d messages, want 3 (early exit)", stopped)
	}
}

// TestQueryNoMatch verifies a filter with no matches returns an empty (not
// nil) slice and walks the scan bound without error.
func TestQueryNoMatch(t *testing.T) {
	t.Parallel()
	l, _ := newTestLog(t, 30)
	l.Record(entry("aaa.com.", "allowed"))
	waitFor(t, l, 1)
	got, err := l.Query(t.Context(), 100, 0, "blocked", "", "", "")
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if got == nil || len(got) != 0 {
		t.Fatalf("no-match filter returned %v, want empty slice", got)
	}
}

// TestQueryClientFilter verifies the exact-match client (source IP) filter,
// the mechanism behind the dashboard's click-through top-clients rows.
func TestQueryClientFilter(t *testing.T) {
	t.Parallel()
	l, _ := newTestLog(t, 30)
	e1 := entry("a.com.", "allowed")
	e1.Client = "203.0.113.9"
	e2 := entry("b.com.", "allowed")
	e2.Client = "203.0.113.9"
	e3 := entry("c.com.", "blocked")
	e3.Client = "198.51.100.7"
	l.Record(e1)
	l.Record(e2)
	l.Record(e3)
	waitFor(t, l, 3)

	got, err := l.Query(t.Context(), 100, 0, "", "", "", "203.0.113.9")
	if err != nil {
		t.Fatalf("Query client: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("client filter matched %d, want 2", len(got))
	}
	for _, e := range got {
		if e.Client != "203.0.113.9" {
			t.Fatalf("client filter leaked entry from %s", e.Client)
		}
	}
	// Combined with another filter: exact action AND exact client.
	blocked, err := l.Query(t.Context(), 100, 0, "blocked", "", "", "203.0.113.9")
	if err != nil {
		t.Fatalf("Query client+action: %v", err)
	}
	if len(blocked) != 0 {
		t.Fatalf("combined filter matched %d, want 0", len(blocked))
	}
}

// TestHourly verifies the 24-slot per-hour series: the current hour counts
// the entries recorded so far, blocked entries are bucketed separately, and
// the series is always exactly 24 slots ending at the current hour.
func TestHourly(t *testing.T) {
	t.Parallel()
	l, _ := newTestLog(t, 30)
	l.Record(entry("ads.com.", "blocked"))
	l.Record(entry("ok.com.", "allowed"))
	waitFor(t, l, 2)

	hours, err := l.Hourly(t.Context(), time.Now().Add(-24*time.Hour))
	if err != nil {
		t.Fatalf("Hourly: %v", err)
	}
	if len(hours) != 24 {
		t.Fatalf("Hourly returned %d slots, want 24", len(hours))
	}
	// Slots are hourly and ordered oldest -> newest.
	for i := 1; i < len(hours); i++ {
		a, _ := time.Parse(time.RFC3339, hours[i-1].Hour)
		b, _ := time.Parse(time.RFC3339, hours[i].Hour)
		if b.Sub(a) != time.Hour {
			t.Fatalf("slot gap at %d: %s -> %s", i, hours[i-1].Hour, hours[i].Hour)
		}
	}
	// The newest slot is the current hour and holds both fresh entries.
	last := hours[len(hours)-1]
	want := time.Now().Truncate(time.Hour)
	if got, _ := time.Parse(time.RFC3339, last.Hour); !got.Equal(want) {
		t.Fatalf("last slot %s, want current hour %s", last.Hour, want.Format(time.RFC3339))
	}
	if last.Total != 2 || last.Blocked != 1 {
		t.Fatalf("current hour = total %d / blocked %d, want 2/1", last.Total, last.Blocked)
	}
	// All other slots are empty (zero-filled, not missing).
	for i := 0; i < len(hours)-1; i++ {
		if hours[i].Total != 0 || hours[i].Blocked != 0 {
			t.Fatalf("slot %d unexpectedly non-empty: %+v", i, hours[i])
		}
	}
}

// TestStats verifies the aggregate counters, average latency and top lists.
func TestStats(t *testing.T) {
	t.Parallel()
	l, _ := newTestLog(t, 30)
	before := time.Now()
	l.Record(entry("ads.example.com.", "blocked"))
	l.Record(entry("ads.example.com.", "blocked"))
	l.Record(entry("ok.example.com.", "allowed"))
	l.Record(entry("ok.example.com.", "cached"))
	waitFor(t, l, 4)

	stats, err := l.Stats(t.Context(), before.Add(-time.Minute))
	if err != nil {
		t.Fatalf("Stats: %v", err)
	}
	if stats["total"].(int64) != 4 {
		t.Fatalf("total = %v, want 4", stats["total"])
	}
	if stats["blocked"].(int64) != 2 || stats["allowed"].(int64) != 1 || stats["cached"].(int64) != 1 {
		t.Fatalf("counters = %v", stats)
	}
	if stats["avg_rt_ms"].(float64) != 12 {
		t.Fatalf("avg_rt_ms = %v, want 12", stats["avg_rt_ms"])
	}
	tb := stats["top_blocked"].([]TopDomain)
	if len(tb) != 1 || tb[0].Domain != "ads.example.com." || tb[0].Count != 2 {
		t.Fatalf("top_blocked = %v, want ads.example.com. x2", tb)
	}
	tc := stats["top_clients"].([]TopDomain)
	if len(tc) != 1 || tc[0].Count != 4 {
		t.Fatalf("top_clients = %v, want 127.0.0.1 x4", tc)
	}

	// A window entirely in the future counts nothing.
	future, err := l.Stats(t.Context(), time.Now().Add(time.Hour))
	if err != nil {
		t.Fatalf("Stats future: %v", err)
	}
	if future["total"].(int64) != 0 {
		t.Fatalf("future window total = %v, want 0", future["total"])
	}
}

// TestActiveDomains verifies the cache warmer's domain source: unique
// domains ordered by query count (ties alphabetical), only allowed/cached
// actions counting (blocked/error entries are excluded), a result cap, and
// an empty window.
func TestActiveDomains(t *testing.T) {
	t.Parallel()
	l, _ := newTestLog(t, 30)
	// a.com: 2 warmable hits (allowed + cached). b.com: blocked (excluded).
	// c.com: 1 allowed + 1 error (the error must not count).
	l.Record(entry("a.com.", "allowed"))
	l.Record(entry("b.com.", "blocked"))
	l.Record(entry("a.com.", "cached"))
	l.Record(entry("c.com.", "allowed"))
	l.Record(entry("c.com.", "error"))
	waitFor(t, l, 5)

	domains, err := l.ActiveDomains(t.Context(), time.Now().Add(-24*time.Hour), 0)
	if err != nil {
		t.Fatalf("ActiveDomains: %v", err)
	}
	want := []TopDomain{
		{Domain: "a.com.", Count: 2},
		{Domain: "c.com.", Count: 1},
	}
	if len(domains) != len(want) {
		t.Fatalf("ActiveDomains returned %v, want %v", domains, want)
	}
	for i := range want {
		if domains[i] != want[i] {
			t.Fatalf("ActiveDomains[%d] = %+v, want %+v", i, domains[i], want[i])
		}
	}

	// The cap keeps only the top-n by count (a.com is the busiest).
	top1, err := l.ActiveDomains(t.Context(), time.Now().Add(-24*time.Hour), 1)
	if err != nil {
		t.Fatalf("ActiveDomains capped: %v", err)
	}
	if len(top1) != 1 || top1[0].Domain != "a.com." {
		t.Fatalf("capped ActiveDomains = %v, want [a.com.]", top1)
	}

	// A window entirely in the future matches nothing.
	none, err := l.ActiveDomains(t.Context(), time.Now().Add(time.Hour), 0)
	if err != nil {
		t.Fatalf("ActiveDomains future: %v", err)
	}
	if none == nil || len(none) != 0 {
		t.Fatalf("future window ActiveDomains = %v, want empty slice", none)
	}
}

// TestActiveDomainsDisabled verifies the no-store path returns an empty slice.
func TestActiveDomainsDisabled(t *testing.T) {
	t.Parallel()
	l := NewDisabled(30)
	defer l.Close()
	domains, err := l.ActiveDomains(t.Context(), time.Now().Add(-time.Hour), 0)
	if err != nil {
		t.Fatalf("ActiveDomains: %v", err)
	}
	if len(domains) != 0 {
		t.Fatalf("disabled log returned %d domains, want 0", len(domains))
	}
}

// TestStatsCache verifies the aggregate TTL cache: a second call with the
// same (quantized) window is served from the cache — an entry recorded
// between the two calls is not reflected — while a different window
// recomputes fresh, and Clear invalidates the cache so a post-clear poll
// re-scans the (now empty) stream.
func TestStatsCache(t *testing.T) {
	t.Parallel()
	l, _ := newTestLog(t, 30)
	l.Record(entry("a.com.", "allowed"))
	waitFor(t, l, 1)

	since := time.Now().Add(-24 * time.Hour)
	first, err := l.Stats(t.Context(), since)
	if err != nil {
		t.Fatalf("Stats: %v", err)
	}
	if first["total"].(int64) != 1 {
		t.Fatalf("first total = %v, want 1", first["total"])
	}

	// Record two more entries and flush; the same window must still return
	// the cached total of 1 (no re-scan), proving the cache path was taken.
	l.Record(entry("b.com.", "blocked"))
	l.Record(entry("b.com.", "blocked"))
	waitFor(t, l, 3)
	second, err := l.Stats(t.Context(), since)
	if err != nil {
		t.Fatalf("Stats cached: %v", err)
	}
	if second["total"].(int64) != 1 {
		t.Fatalf("cached total = %v, want 1 (cache must not re-scan)", second["total"])
	}

	// A different window recomputes instead of reusing the cached value.
	future, err := l.Stats(t.Context(), time.Now().Add(time.Hour))
	if err != nil {
		t.Fatalf("Stats future: %v", err)
	}
	if future["total"].(int64) != 0 {
		t.Fatalf("future window total = %v, want 0", future["total"])
	}

	// Clear must invalidate the cache: the next poll re-scans the empty
	// stream rather than serving the pre-clear totals.
	if err := l.Clear(t.Context()); err != nil {
		t.Fatalf("Clear: %v", err)
	}
	after, err := l.Stats(t.Context(), since)
	if err != nil {
		t.Fatalf("Stats after clear: %v", err)
	}
	if after["total"].(int64) != 0 {
		t.Fatalf("post-clear total = %v, want 0 (cache must be invalidated)", after["total"])
	}
}

// TestHourlyCache verifies Hourly results are cached the same way: the second
// call with the same window returns the pre-recorded bucket totals.
func TestHourlyCache(t *testing.T) {
	t.Parallel()
	l, _ := newTestLog(t, 30)
	l.Record(entry("a.com.", "allowed"))
	waitFor(t, l, 1)

	since := time.Now().Add(-24 * time.Hour)
	first, err := l.Hourly(t.Context(), since)
	if err != nil {
		t.Fatalf("Hourly: %v", err)
	}
	if got := first[len(first)-1].Total; got != 1 {
		t.Fatalf("first current-hour total = %d, want 1", got)
	}

	// Two more entries flushed; the cached series (same window) must keep the
	// original bucket total of 1.
	l.Record(entry("b.com.", "blocked"))
	l.Record(entry("b.com.", "blocked"))
	waitFor(t, l, 3)
	second, err := l.Hourly(t.Context(), since)
	if err != nil {
		t.Fatalf("Hourly cached: %v", err)
	}
	if got := second[len(second)-1].Total; got != 1 {
		t.Fatalf("cached current-hour total = %d, want 1 (cache must not re-scan)", got)
	}
}

// TestStatsBundle verifies the rolling aggregate serves the dashboard's
// bundle live: the 24h block counts the entries in the 24 hours ending at
// the current hour, the today block only those since local midnight, and
// the hourly series ends at the current hour. A freshly flushed entry is
// reflected immediately (no TTL to wait out), a backdated entry is outside
// the window, and Clear resets the aggregate.
func TestStatsBundle(t *testing.T) {
	t.Parallel()
	l, _ := newTestLog(t, 30)
	l.Record(entry("new.example.com.", "allowed"))
	waitFor(t, l, 1)

	now := time.Now()
	since := now.Add(-24 * time.Hour)
	today := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())

	b, err := l.StatsBundle(t.Context(), since, today)
	if err != nil {
		t.Fatalf("StatsBundle: %v", err)
	}
	if b.Stats["total"].(int64) != 1 {
		t.Fatalf("24h total = %v, want 1", b.Stats["total"])
	}
	if b.Today["total"].(int64) != 1 {
		t.Fatalf("today total = %v, want 1", b.Today["total"])
	}
	if b.Today["blocked"].(int64) != 0 || b.Today["allowed"].(int64) != 1 {
		t.Fatalf("today counters = %v", b.Today)
	}
	if len(b.Hourly) != 24 {
		t.Fatalf("hourly slots = %d, want 24", len(b.Hourly))
	}
	if last := b.Hourly[len(b.Hourly)-1]; last.Total != 1 || last.Blocked != 0 {
		t.Fatalf("current-hour bucket = %+v, want total 1 / blocked 0", last)
	}
	if tc := b.Today["top_clients"].([]TopDomain); len(tc) != 1 || tc[0].Count != 1 {
		t.Fatalf("today top_clients = %v, want 127.0.0.1 x1", tc)
	}
	if tb := b.Today["top_blocked"].([]TopDomain); len(tb) != 0 {
		t.Fatalf("today top_blocked = %v, want empty", tb)
	}

	// Live: a freshly flushed entry is reflected on the next poll — the
	// rolling aggregate has no TTL to wait out.
	l.Record(entry("ads.example.com.", "blocked"))
	waitFor(t, l, 2)
	b2, err := l.StatsBundle(t.Context(), since, today)
	if err != nil {
		t.Fatalf("StatsBundle live: %v", err)
	}
	if b2.Stats["total"].(int64) != 2 || b2.Stats["blocked"].(int64) != 1 {
		t.Fatalf("live totals = %v, want total 2 / blocked 1", b2.Stats)
	}
	if tb := b2.Stats["top_blocked"].([]TopDomain); len(tb) != 1 || tb[0].Domain != "ads.example.com." || tb[0].Count != 1 {
		t.Fatalf("live top_blocked = %v, want ads.example.com. x1", tb)
	}

	// A backdated entry (25h ago) is outside the 24h window — the rolling
	// aggregate buckets by the recorded query time, so it is not counted.
	old := entry("old.example.com.", "blocked")
	old.Time = time.Now().Add(-25 * time.Hour)
	l.Record(old)
	waitFor(t, l, 3)
	b3, err := l.StatsBundle(t.Context(), since, today)
	if err != nil {
		t.Fatalf("StatsBundle backdated: %v", err)
	}
	if b3.Stats["total"].(int64) != 2 {
		t.Fatalf("24h total with backdated entry = %v, want 2 (outside window)", b3.Stats["total"])
	}

	// Clear must reset the aggregate so the next poll serves zeros.
	if err := l.Clear(t.Context()); err != nil {
		t.Fatalf("Clear: %v", err)
	}
	b4, err := l.StatsBundle(t.Context(), since, today)
	if err != nil {
		t.Fatalf("StatsBundle after clear: %v", err)
	}
	if b4.Stats["total"].(int64) != 0 || b4.Today["total"].(int64) != 0 {
		t.Fatalf("post-clear totals = %v / %v, want 0/0", b4.Stats["total"], b4.Today["total"])
	}
}

// TestStatsBundleNonstandardWindow verifies the walk fallback: a window
// other than the standard dashboard one (here: the last 6 hours) is served
// by the exact bounded walk, cached for repeated polls of the same window.
func TestStatsBundleNonstandardWindow(t *testing.T) {
	t.Parallel()
	l, _ := newTestLog(t, 30)
	l.Record(entry("a.example.com.", "allowed"))
	l.Record(entry("b.example.com.", "blocked"))
	waitFor(t, l, 2)

	now := time.Now()
	since := now.Add(-6 * time.Hour)
	today := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())

	b, err := l.StatsBundle(t.Context(), since, today)
	if err != nil {
		t.Fatalf("StatsBundle: %v", err)
	}
	if b.Stats["total"].(int64) != 2 || b.Stats["blocked"].(int64) != 1 {
		t.Fatalf("6h total = %v, want total 2 / blocked 1", b.Stats)
	}

	// A new entry flushed; the same window must still serve the cached
	// totals (the fallback keeps the walk's TTL-cache behavior).
	l.Record(entry("c.example.com.", "allowed"))
	waitFor(t, l, 3)
	b2, err := l.StatsBundle(t.Context(), since, today)
	if err != nil {
		t.Fatalf("StatsBundle cached: %v", err)
	}
	if b2.Stats["total"].(int64) != 2 {
		t.Fatalf("cached 6h total = %v, want 2 (cache must not re-scan)", b2.Stats["total"])
	}
}

// TestAggregateSeededAtStartup verifies a restarted log serves the last 24h
// from its seed walk: entries written to the stream before reopening are in
// the new log's aggregate without any fresh writes.
func TestAggregateSeededAtStartup(t *testing.T) {
	t.Parallel()
	mr := miniredis.RunT(t)
	l, err := New(mr.Addr(), "", 0, 30, 0)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	l.Record(entry("a.example.com.", "blocked"))
	l.Record(entry("b.example.com.", "allowed"))
	waitFor(t, l, 2)
	if err := l.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	l2, err := New(mr.Addr(), "", 0, 30, 0) // restart over the same stream
	if err != nil {
		t.Fatalf("New (restart): %v", err)
	}
	defer l2.Close()

	now := time.Now()
	b, err := l2.StatsBundle(t.Context(), now.Add(-24*time.Hour),
		time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location()))
	if err != nil {
		t.Fatalf("StatsBundle after restart: %v", err)
	}
	if b.Stats["total"].(int64) != 2 || b.Stats["blocked"].(int64) != 1 {
		t.Fatalf("seeded totals = %v, want total 2 / blocked 1", b.Stats)
	}
	if len(b.Hourly) != 24 {
		t.Fatalf("seeded hourly slots = %d, want 24", len(b.Hourly))
	}
}

// TestRollingAggRollover verifies entries age out of the window exactly:
// the oldest slot's contribution — including its top-N keys — is dropped
// from the running totals when the hour rolls.
func TestRollingAggRollover(t *testing.T) {
	t.Parallel()
	a := newRollingAgg()
	now := time.Now().Truncate(time.Hour)
	start := now.Add(-23 * time.Hour)
	mk := func(h time.Time, domain, action string) Entry {
		return Entry{Time: h.Add(time.Minute), Client: "10.0.0.1", Domain: domain, Action: action, ResponseTimeMS: 5}
	}
	a.add(mk(start, "old.com.", "blocked"))
	a.add(mk(now, "cur.com.", "allowed"))

	b := a.snapshot()
	if b.Stats["total"].(int64) != 2 || b.Stats["blocked"].(int64) != 1 {
		t.Fatalf("initial totals = %v, want total 2 / blocked 1", b.Stats)
	}

	// Roll one hour: the oldest slot (window start) ages out entirely.
	a.add(mk(now.Add(time.Hour), "next.com.", "cached"))
	b = a.snapshot()
	if b.Stats["total"].(int64) != 2 || b.Stats["blocked"].(int64) != 0 || b.Stats["cached"].(int64) != 1 {
		t.Fatalf("after roll totals = %v, want total 2 / blocked 0 / cached 1", b.Stats)
	}
	if tb := b.Stats["top_blocked"].([]TopDomain); len(tb) != 0 {
		t.Fatalf("after roll top_blocked = %v, want empty (old.com. aged out)", tb)
	}
	if tc := b.Stats["top_clients"].([]TopDomain); len(tc) != 1 || tc[0].Count != 2 {
		t.Fatalf("after roll top_clients = %v, want 10.0.0.1 x2", tc)
	}
	// The hourly series slid: the new current hour is at the end.
	if last := b.Hourly[len(b.Hourly)-1]; last.Total != 1 {
		t.Fatalf("rolled current-hour total = %d, want 1", last.Total)
	}
	if first := b.Hourly[0]; first.Total != 0 {
		t.Fatalf("rolled oldest-hour total = %d, want 0", first.Total)
	}
}

// TestRollingAggTodayReset verifies the today block resets at midnight: a
// write after midnight starts a fresh day, and a read after midnight with no
// intervening write does not serve yesterday's numbers.
func TestRollingAggTodayReset(t *testing.T) {
	t.Parallel()
	a := newRollingAgg()
	now := time.Now()
	a.add(Entry{Time: now, Client: "10.0.0.1", Domain: "a.com.", Action: "allowed"})
	if b := a.snapshot(); b.Today["total"].(int64) != 1 {
		t.Fatalf("today total = %v, want 1", b.Today["total"])
	}

	// A write after midnight: the today block resets and counts only the
	// new day's entry.
	nextDay := now.Add(24 * time.Hour).Add(time.Minute)
	a.add(Entry{Time: nextDay, Client: "10.0.0.1", Domain: "b.com.", Action: "blocked"})
	b := a.snapshot()
	if b.Today["total"].(int64) != 1 || b.Today["blocked"].(int64) != 1 || b.Today["allowed"].(int64) != 0 {
		t.Fatalf("post-midnight today = %v, want total 1 / blocked 1", b.Today)
	}

	// A read after another midnight with no writes in between must not
	// serve the previous day.
	a.resetTodayIfNeeded(nextDay.Add(24 * time.Hour))
	b = a.snapshot()
	if b.Today["total"].(int64) != 0 {
		t.Fatalf("quiet-midnight today total = %v, want 0", b.Today["total"])
	}
}

// TestRollingAggClear verifies Clear zeroes the aggregate and a subsequent
// write re-anchors the ring without double-counting.
func TestRollingAggClear(t *testing.T) {
	t.Parallel()
	a := newRollingAgg()
	now := time.Now()
	a.add(Entry{Time: now, Client: "10.0.0.1", Domain: "a.com.", Action: "blocked"})
	a.clear()
	b := a.snapshot()
	if b.Stats["total"].(int64) != 0 || b.Today["total"].(int64) != 0 {
		t.Fatalf("post-clear totals = %v / %v, want 0/0", b.Stats["total"], b.Today["total"])
	}
	a.add(Entry{Time: now, Client: "10.0.0.1", Domain: "b.com.", Action: "allowed"})
	b = a.snapshot()
	if b.Stats["total"].(int64) != 1 {
		t.Fatalf("post-clear write total = %v, want 1 (no double count)", b.Stats["total"])
	}
}

// TestStatsBundleDisabled verifies the no-store path returns zeroed blocks
// (the API's stats response still carries the expected shapes).
func TestStatsBundleDisabled(t *testing.T) {
	t.Parallel()
	l := NewDisabled(30)
	defer l.Close()
	now := time.Now()
	b, err := l.StatsBundle(t.Context(), now.Add(-24*time.Hour),
		time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location()))
	if err != nil {
		t.Fatalf("StatsBundle: %v", err)
	}
	if b.Stats["total"].(int64) != 0 || b.Today["total"].(int64) != 0 || len(b.Hourly) != 0 {
		t.Fatalf("disabled bundle = %+v, want zeros", b)
	}
}

// TestClear verifies the whole stream is deleted.
func TestClear(t *testing.T) {
	t.Parallel()
	l, _ := newTestLog(t, 30)
	for range 5 {
		l.Record(entry("example.com.", "allowed"))
	}
	waitFor(t, l, 5)
	if err := l.Clear(t.Context()); err != nil {
		t.Fatalf("Clear: %v", err)
	}
	entries, err := l.Query(t.Context(), 100, 0, "", "", "", "")
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("after Clear got %d entries, want 0", len(entries))
	}
}

// TestPruneKeepsFreshEntries verifies the retention trim runs without error
// and never removes entries younger than the window.
func TestPruneKeepsFreshEntries(t *testing.T) {
	t.Parallel()
	l, _ := newTestLog(t, 30)
	for range 5 {
		l.Record(entry("example.com.", "allowed"))
	}
	waitFor(t, l, 5)
	l.Prune(t.Context())
	entries, err := l.Query(t.Context(), 100, 0, "", "", "", "")
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(entries) != 5 {
		t.Fatalf("Prune removed fresh entries: %d remain, want 5", len(entries))
	}
}

// TestRecordAfterCloseIsSafe verifies Record never panics after Close.
func TestRecordAfterCloseIsSafe(t *testing.T) {
	t.Parallel()
	l, _ := newTestLog(t, 30)
	if err := l.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	l.Record(entry("example.com.", "allowed")) // must be a no-op, not a panic
}

// TestDisabledMode verifies NewDisabled records nothing and queries cleanly.
func TestDisabledMode(t *testing.T) {
	t.Parallel()
	l := NewDisabled(30)
	defer l.Close()
	l.Record(entry("example.com.", "allowed"))
	entries, err := l.Query(t.Context(), 100, 0, "", "", "", "")
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("disabled log returned %d entries, want 0", len(entries))
	}
	stats, err := l.Stats(t.Context(), time.Now().Add(-time.Hour))
	if err != nil {
		t.Fatalf("Stats: %v", err)
	}
	if stats["total"].(int64) != 0 {
		t.Fatalf("disabled log stats total = %v, want 0", stats["total"])
	}
}

// TestTopN exercises the bounded-heap top-k selection directly: descending
// count order, alphabetical tie-break, and — the case a heap-based
// selection can get wrong if the "worst kept" comparison is inverted — a
// three-way tie straddling the n-entry cutoff, where only the two
// alphabetically-first domains of the tied group must survive.
func TestTopN(t *testing.T) {
	t.Parallel()
	counts := map[string]int64{
		"z.example.com.": 5,
		"a.example.com.": 5, // ties with z at count 5; a sorts first
		"m.example.com.": 3, // three-way tie at count 3, cutoff lands inside it
		"b.example.com.": 3,
		"c.example.com.": 3,
		"only-one.com.":  1,
	}
	got := topN(counts, 4)
	want := []TopDomain{
		{Domain: "a.example.com.", Count: 5},
		{Domain: "z.example.com.", Count: 5},
		{Domain: "b.example.com.", Count: 3},
		{Domain: "c.example.com.", Count: 3},
	}
	if len(got) != len(want) {
		t.Fatalf("topN returned %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("topN[%d] = %+v, want %+v (full: %v)", i, got[i], want[i], got)
		}
	}

	if got := topN(counts, 0); len(got) != 0 {
		t.Fatalf("topN with n=0 = %v, want empty", got)
	}
	if got := topN(nil, 5); len(got) != 0 {
		t.Fatalf("topN of nil map = %v, want empty", got)
	}
	if got := topN(counts, 100); len(got) != len(counts) {
		t.Fatalf("topN with n > len(counts) returned %d entries, want %d", len(got), len(counts))
	}
}

// BenchmarkRecord measures the enqueue throughput of the async writer — the
// rate the DNS hot path can log at without ever blocking on a round trip.
func BenchmarkRecord(b *testing.B) {
	l := NewDisabled(30)
	for b.Loop() {
		l.Record(entry("bench.example.com.", "allowed"))
	}
	_ = l.Close()
}

// BenchmarkTopN sizes the win from the bounded-heap rewrite at a realistic
// distinct-domain count for a busy blocklist window (getStats calls this
// four times per /api/stats poll).
func BenchmarkTopN(b *testing.B) {
	counts := make(map[string]int64, 5000)
	for i := range 5000 {
		counts[fmt.Sprintf("domain-%d.example.com.", i)] = int64(i % 500)
	}
	for b.Loop() {
		topN(counts, 10)
	}
}
