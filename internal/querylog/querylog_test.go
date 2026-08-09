package querylog

import (
	"context"
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
		entries, err := l.Query(context.Background(), n+10, 0, "", "", "", "")
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

// TestRecordFlushesOnClose verifies entries enqueued before Close are flushed
// to the stream — the final partial batch must not be lost at shutdown — and
// that a reopened log over the same server sees them.
func TestRecordFlushesOnClose(t *testing.T) {
	mr := miniredis.RunT(t)
	l, err := New(mr.Addr(), "", 0, 30, 0)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	for i := 0; i < 10; i++ {
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
	entries, err := r.Query(context.Background(), 100, 0, "", "", "", "")
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

// TestBatchFlush verifies queued entries are flushed without Close, via both
// the batch-size and the ticker paths.
func TestBatchFlush(t *testing.T) {
	l, _ := newTestLog(t, 30)
	const n = logBatchSize + 50
	for i := 0; i < n; i++ {
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

	blocked, err := l.Query(context.Background(), 100, 0, "blocked", "", "", "")
	if err != nil {
		t.Fatalf("Query blocked: %v", err)
	}
	if len(blocked) != 2 {
		t.Fatalf("blocked filter matched %d, want 2", len(blocked))
	}

	byDomain, err := l.Query(context.Background(), 100, 0, "", "bbb", "", "")
	if err != nil {
		t.Fatalf("Query domain: %v", err)
	}
	if len(byDomain) != 2 {
		t.Fatalf("domain substring matched %d, want 2 (bbb.com. + sub.bbb.com.)", len(byDomain))
	}

	// Pagination: offset 1, limit 2 over 4 entries -> the middle two.
	page, err := l.Query(context.Background(), 2, 1, "", "", "", "")
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

// TestQueryNoMatch verifies a filter with no matches returns an empty (not
// nil) slice and walks the scan bound without error.
func TestQueryNoMatch(t *testing.T) {
	l, _ := newTestLog(t, 30)
	l.Record(entry("aaa.com.", "allowed"))
	waitFor(t, l, 1)
	got, err := l.Query(context.Background(), 100, 0, "blocked", "", "", "")
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

	got, err := l.Query(context.Background(), 100, 0, "", "", "", "203.0.113.9")
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
	blocked, err := l.Query(context.Background(), 100, 0, "blocked", "", "", "203.0.113.9")
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
	l, _ := newTestLog(t, 30)
	l.Record(entry("ads.com.", "blocked"))
	l.Record(entry("ok.com.", "allowed"))
	waitFor(t, l, 2)

	hours, err := l.Hourly(context.Background(), time.Now().Add(-24*time.Hour))
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
	l, _ := newTestLog(t, 30)
	before := time.Now()
	l.Record(entry("ads.example.com.", "blocked"))
	l.Record(entry("ads.example.com.", "blocked"))
	l.Record(entry("ok.example.com.", "allowed"))
	l.Record(entry("ok.example.com.", "cached"))
	waitFor(t, l, 4)

	stats, err := l.Stats(context.Background(), before.Add(-time.Minute))
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
	future, err := l.Stats(context.Background(), time.Now().Add(time.Hour))
	if err != nil {
		t.Fatalf("Stats future: %v", err)
	}
	if future["total"].(int64) != 0 {
		t.Fatalf("future window total = %v, want 0", future["total"])
	}
}

// TestStatsCache verifies the aggregate TTL cache: a second call with the
// same (quantized) window is served from the cache — an entry recorded
// between the two calls is not reflected — while a different window
// recomputes fresh, and Clear invalidates the cache so a post-clear poll
// re-scans the (now empty) stream.
func TestStatsCache(t *testing.T) {
	l, _ := newTestLog(t, 30)
	l.Record(entry("a.com.", "allowed"))
	waitFor(t, l, 1)

	since := time.Now().Add(-24 * time.Hour)
	first, err := l.Stats(context.Background(), since)
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
	second, err := l.Stats(context.Background(), since)
	if err != nil {
		t.Fatalf("Stats cached: %v", err)
	}
	if second["total"].(int64) != 1 {
		t.Fatalf("cached total = %v, want 1 (cache must not re-scan)", second["total"])
	}

	// A different window recomputes instead of reusing the cached value.
	future, err := l.Stats(context.Background(), time.Now().Add(time.Hour))
	if err != nil {
		t.Fatalf("Stats future: %v", err)
	}
	if future["total"].(int64) != 0 {
		t.Fatalf("future window total = %v, want 0", future["total"])
	}

	// Clear must invalidate the cache: the next poll re-scans the empty
	// stream rather than serving the pre-clear totals.
	if err := l.Clear(context.Background()); err != nil {
		t.Fatalf("Clear: %v", err)
	}
	after, err := l.Stats(context.Background(), since)
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
	l, _ := newTestLog(t, 30)
	l.Record(entry("a.com.", "allowed"))
	waitFor(t, l, 1)

	since := time.Now().Add(-24 * time.Hour)
	first, err := l.Hourly(context.Background(), since)
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
	second, err := l.Hourly(context.Background(), since)
	if err != nil {
		t.Fatalf("Hourly cached: %v", err)
	}
	if got := second[len(second)-1].Total; got != 1 {
		t.Fatalf("cached current-hour total = %d, want 1 (cache must not re-scan)", got)
	}
}

// TestStatsBundle verifies the single-walk aggregate: the 24h block counts
// every recorded entry, the today block only those since local midnight, and
// the hourly series ends at the current hour — plus the same TTL-cache and
// Clear-invalidation behavior as the standalone Stats/Hourly results.
func TestStatsBundle(t *testing.T) {
	l, _ := newTestLog(t, 30)
	// One entry 25h ago: inside the 24h window (written now, so its stream
	// ID is current) but always before today's midnight — 25h is more than
	// any time-of-day elapsed since midnight. One entry now.
	old := entry("old.example.com.", "blocked")
	old.Time = time.Now().Add(-25 * time.Hour)
	l.Record(old)
	l.Record(entry("new.example.com.", "allowed"))
	waitFor(t, l, 2)

	now := time.Now()
	since := now.Add(-24 * time.Hour)
	today := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())

	b, err := l.StatsBundle(context.Background(), since, today)
	if err != nil {
		t.Fatalf("StatsBundle: %v", err)
	}
	if b.Stats["total"].(int64) != 2 {
		t.Fatalf("24h total = %v, want 2", b.Stats["total"])
	}
	// The 25h-old entry is inside the 24h window but before today.
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
	// The today block's top lists are wired to the same walk.
	if tc := b.Today["top_clients"].([]TopDomain); len(tc) != 1 || tc[0].Count != 1 {
		t.Fatalf("today top_clients = %v, want 127.0.0.1 x1", tc)
	}
	if tb := b.Today["top_blocked"].([]TopDomain); len(tb) != 0 {
		t.Fatalf("today top_blocked = %v, want empty", tb)
	}

	// Cache: another entry flushed; the same (quantized) windows must still
	// serve the pre-existing totals without re-scanning.
	l.Record(entry("c.example.com.", "allowed"))
	waitFor(t, l, 3)
	b2, err := l.StatsBundle(context.Background(), since, today)
	if err != nil {
		t.Fatalf("StatsBundle cached: %v", err)
	}
	if b2.Stats["total"].(int64) != 2 {
		t.Fatalf("cached 24h total = %v, want 2 (cache must not re-scan)", b2.Stats["total"])
	}

	// Clear must invalidate the cache so the next poll re-scans the stream.
	if err := l.Clear(context.Background()); err != nil {
		t.Fatalf("Clear: %v", err)
	}
	b3, err := l.StatsBundle(context.Background(), since, today)
	if err != nil {
		t.Fatalf("StatsBundle after clear: %v", err)
	}
	if b3.Stats["total"].(int64) != 0 || b3.Today["total"].(int64) != 0 {
		t.Fatalf("post-clear totals = %v / %v, want 0/0", b3.Stats["total"], b3.Today["total"])
	}
}

// TestStatsBundleDisabled verifies the no-store path returns zeroed blocks
// (the API's stats response still carries the expected shapes).
func TestStatsBundleDisabled(t *testing.T) {
	l := NewDisabled(30)
	defer l.Close()
	now := time.Now()
	b, err := l.StatsBundle(context.Background(), now.Add(-24*time.Hour),
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
	l, _ := newTestLog(t, 30)
	for i := 0; i < 5; i++ {
		l.Record(entry("example.com.", "allowed"))
	}
	waitFor(t, l, 5)
	if err := l.Clear(context.Background()); err != nil {
		t.Fatalf("Clear: %v", err)
	}
	entries, err := l.Query(context.Background(), 100, 0, "", "", "", "")
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
	l, _ := newTestLog(t, 30)
	for i := 0; i < 5; i++ {
		l.Record(entry("example.com.", "allowed"))
	}
	waitFor(t, l, 5)
	l.Prune(context.Background())
	entries, err := l.Query(context.Background(), 100, 0, "", "", "", "")
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(entries) != 5 {
		t.Fatalf("Prune removed fresh entries: %d remain, want 5", len(entries))
	}
}

// TestRecordAfterCloseIsSafe verifies Record never panics after Close.
func TestRecordAfterCloseIsSafe(t *testing.T) {
	l, _ := newTestLog(t, 30)
	if err := l.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	l.Record(entry("example.com.", "allowed")) // must be a no-op, not a panic
}

// TestDisabledMode verifies NewDisabled records nothing and queries cleanly.
func TestDisabledMode(t *testing.T) {
	l := NewDisabled(30)
	defer l.Close()
	l.Record(entry("example.com.", "allowed"))
	entries, err := l.Query(context.Background(), 100, 0, "", "", "", "")
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("disabled log returned %d entries, want 0", len(entries))
	}
	stats, err := l.Stats(context.Background(), time.Now().Add(-time.Hour))
	if err != nil {
		t.Fatalf("Stats: %v", err)
	}
	if stats["total"].(int64) != 0 {
		t.Fatalf("disabled log stats total = %v, want 0", stats["total"])
	}
}

// BenchmarkRecord measures the enqueue throughput of the async writer — the
// rate the DNS hot path can log at without ever blocking on a round trip.
func BenchmarkRecord(b *testing.B) {
	l := NewDisabled(30)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		l.Record(entry("bench.example.com.", "allowed"))
	}
	b.StopTimer()
	_ = l.Close()
}
