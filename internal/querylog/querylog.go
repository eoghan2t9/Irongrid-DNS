// Package querylog stores every DNS request with its allow/block outcome in
// an append-only, time-ordered stream inside the embedded kvstore (BadgerDB).
// The stream shares the store with the DNS response cache: one data
// directory, no separate server to run. Entries are written asynchronously in
// batches so the DNS hot path never blocks on a disk write.
package querylog

import (
	"cmp"
	"container/heap"
	"context"
	"fmt"
	"iter"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/goccy/go-json"

	"github.com/eoghan2t9/Irongrid-DNS/internal/kvstore"
	"github.com/eoghan2t9/Irongrid-DNS/internal/safego"
	"github.com/eoghan2t9/Irongrid-DNS/internal/tuning"
)

// logQueueCap bounds the pending-entry queue. Serving never blocks on
// logging: once the queue is full, new entries are dropped — unlike the
// cache's write queue, this one has no synchronous fallback, so undersizing
// it on a busy box silently loses query-log history exactly when it's
// busiest. Derived from the tuned core count (tuning.ScaleByCores).
var logQueueCap = tuning.ScaleByCores(512, 8192, 131072)

const (
	// logBatchSize flushes the writer once this many entries have queued.
	logBatchSize = 256
	// logFlushInterval is the maximum age of a queued entry before the
	// writer flushes it in one batch.
	logFlushInterval = 100 * time.Millisecond
	// streamName is the kvstore stream holding every logged query. Stream IDs
	// are "<ms>-<seq>", so entries are time-ordered and the newest ID is also
	// the latest query.
	streamName = "log"
	// maxStreamEntries hard-caps the stream length so the log can never grow
	// unbounded on disk even if the hourly retention pruner is delayed.
	// 250k entries covers roughly a day or two of heavy traffic — well past
	// the dashboard's needs, and the retention pruner usually keeps it far
	// lower.
	maxStreamEntries = 250000
	// maxQueryScan bounds how far Query walks back when its filters match
	// nothing recent: worst case it reads this many stream entries before
	// giving up, so a pathological filter can't stall the API.
	maxQueryScan = 20000
	// maxStatsScan bounds how far the time-window stats walk. Beyond this
	// the counters under-report rather than burn CPU/bandwidth on the
	// dashboard's 10-second poll.
	maxStatsScan = 100000
	// maxWarmScan bounds the ActiveDomains walk used by the cache warmer.
	// It runs every warmer interval (default 15m), not on a 10s poll, and
	// a pass should see as much of the active set as the stream retains, so
	// it is the full stream cap rather than the stats poll's budget.
	maxWarmScan = maxStreamEntries

	// aggCacheTTL and aggCacheBucket back the Stats/Hourly/StatsBundle
	// result cache. Each /api/stats poll used to trigger up to three full
	// stream walks (24h stats, today stats, hourly); StatsBundle now serves
	// all three from ONE walk. A walk is bounded by maxStatsScan entries and
	// paged in 5000-entry round trips — still too expensive to repeat every
	// 10s. The cache reuses a result for aggCacheTTL across polls and
	// quantizes the window(s) to aggCacheBucket so consecutive polls (which
	// each pass a fresh time.Now()) share one entry: a value computed from
	// an equal-or-earlier since always covers the requested window, so
	// serving it is always correct.
	aggCacheTTL    = 30 * time.Second
	aggCacheBucket = 30 * time.Second
)

// Entry is a single logged query. ID is the stream ID, assigned on
// read; it is a stable unique key (the dashboard uses it as the React list
// key) rather than a monotonically increasing integer.
type Entry struct {
	ID     string    `json:"id"`
	Time   time.Time `json:"time"`
	Client string    `json:"client"`
	// Domain is stored lowercase: the DNS handler lowercases the qname
	// before recording, so filter matching and top-blocked keys can compare
	// directly without per-entry normalization.
	Domain         string `json:"domain"`
	Type           string `json:"type"`   // A, AAAA, TXT...
	Action         string `json:"action"` // "allowed", "blocked", "cached", "error"
	Reason         string `json:"reason"`
	Upstream       string `json:"upstream"`
	ResponseTimeMS int64  `json:"response_time_ms"`
	Rcode          int    `json:"rcode"`
	Answers        int    `json:"answers"`
	// ASN is the ASN the server attributed to the client at record time —
	// resolved locally from the configured ip2asn tables (geo_block
	// allow/block ASNs or a client group's asns), so it is the same
	// attribution the X-Irongrid-Client-ASN DoH header and the
	// asn-blocked/asn-allowed reasons use. 0 = the client's ISP is in none
	// of the configured ASN lists (the dashboard then falls back to its
	// external RIPEstat lookup). Omitted from JSON when unknown, so old
	// stored entries stay compatible.
	ASN uint32 `json:"asn,omitempty"`
}

// Log is a concurrency-safe query logger backed by a kvstore stream.
// Entries are enqueued and written by a single background goroutine in
// batches (one store transaction per flush), so per-query disk writes never
// sit on the DNS hot path.
type Log struct {
	stream    *kvstore.Stream
	retention time.Duration
	batchSize int

	entries chan Entry
	done    chan struct{}
	closed  atomic.Bool
	wg      sync.WaitGroup

	// lastFlushErr gates the flush-failure log line so a failing store
	// produces at most one line per minute instead of one every ~100ms.
	lastFlushErr atomic.Int64

	// agg is the writer-maintained rolling aggregate serving StatsBundle
	// (see rolling.go): polls read an O(1) in-memory snapshot instead of
	// re-walking the stream. nil for a disabled log (no backing store).
	agg *rollingAgg

	// statsCache/hourlyCache/bundleCache short-circuit repeated
	// dashboard polls — see the aggCache* constants. Zero values are ready
	// to use. The bundle cache backs only the walk fallback in
	// StatsBundle (non-standard windows); the rolling aggregate is served
	// live.
	statsCache  aggCache[map[string]any]
	hourlyCache aggCache[[]HourBucket]
	bundleCache aggCache[StatsBundle]
}

// New returns a stream-backed query log over an open kvstore. The store is
// shared with the DNS cache and owned by the caller: Close stops the writer but
// never closes it, so a cache reload can't pull the rug out from under the log.
// batchSize is the number of entries committed per flush; <= 0 uses the
// default.
func New(store *kvstore.Store, retentionDays, batchSize int) (*Log, error) {
	if store == nil {
		return nil, fmt.Errorf("querylog: a kvstore is required")
	}
	if err := store.Ping(); err != nil {
		return nil, fmt.Errorf("query log store unavailable: %w", err)
	}
	bs := logBatchSize
	if batchSize > 0 {
		bs = batchSize
	}
	l := &Log{
		stream:    store.Stream(streamName),
		retention: time.Duration(retentionDays) * 24 * time.Hour,
		batchSize: bs,
		entries:   make(chan Entry, logQueueCap),
		done:      make(chan struct{}),
		agg:       newRollingAgg(),
	}
	// Seed the aggregate from whatever the stream already holds (a restart
	// must keep showing the last 24h, not zeros until the window refills).
	// Runs before the writer starts, so the single-threaded add path never
	// races a live flush.
	l.seedAggregate(context.Background())
	l.wg.Go(l.runWriter)
	return l, nil
}

// NewDisabled returns a logger with no backing store: Record drops entries
// and Query/Stats return empty results. It exists for tests (and any caller
// that needs the full Log API without a kvstore); the writer
// goroutine is still started so Close behaves identically.
func NewDisabled(retentionDays int) *Log {
	l := &Log{
		retention: time.Duration(retentionDays) * 24 * time.Hour,
		entries:   make(chan Entry, logQueueCap),
		done:      make(chan struct{}),
	}
	l.wg.Go(l.runWriter)
	return l
}

// aggCache is a tiny TTL cache for one aggregate value. sinceKey is the
// `since` argument quantized to aggCacheBucket seconds, so near-identical
// windows (every poll passes a fresh time.Now()) share an entry. All methods
// are safe for concurrent use; the cached value itself is immutable once set
// (callers only read it, e.g. via JSON encoding).
type aggCache[T any] struct {
	mu       sync.Mutex
	sinceKey int64
	at       time.Time
	val      T
}

// get returns the cached value when it matches sinceKey and is still within
// aggCacheTTL.
func (c *aggCache[T]) get(sinceKey int64) (T, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.sinceKey != sinceKey || time.Since(c.at) > aggCacheTTL {
		var zero T
		return zero, false
	}
	return c.val, true
}

func (c *aggCache[T]) set(sinceKey int64, val T) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.sinceKey = sinceKey
	c.at = time.Now()
	c.val = val
}

// clear drops any cached value so the next call re-scans the stream (used by
// Clear: after the stream is deleted, a cached pre-clear result must not be
// served). sinceKey is set to -1 — unreachable for any real since (always
// Unix time, >= 0) — so the get's key check alone guarantees a miss.
func (c *aggCache[T]) clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.sinceKey = -1
	c.at = time.Time{}
}

// Record enqueues one query entry. It never blocks or slows query serving:
// the background writer batches entries and commits them in one batch. If the
// queue is full (or the log is closed), the entry is
// dropped — logging must never break DNS.
func (l *Log) Record(e Entry) {
	if l.closed.Load() {
		return
	}
	select {
	case l.entries <- e:
	default:
		// Queue full — drop rather than stall DNS serving.
	}
}

// runWriter drains the queue, flushing in batches of logBatchSize or every
// logFlushInterval, whichever comes first. Close() signals via l.done so the
// writer drains whatever is queued and flushes the final batch. The entries
// channel is deliberately never closed: Record may race Close and a send on
// a closed channel would panic.
func (l *Log) runWriter() {
	batch := make([]Entry, 0, l.batchSize)
	ticker := time.NewTicker(logFlushInterval)
	defer ticker.Stop()
	flush := func() {
		if len(batch) == 0 {
			return
		}
		l.writeBatch(batch)
		batch = batch[:0]
	}
	for {
		select {
		case e := <-l.entries:
			batch = append(batch, e)
			if len(batch) >= l.batchSize {
				flush()
			}
		case <-ticker.C:
			flush()
		case <-l.done:
			// Shutdown: drain everything still queued, then flush and exit.
			for {
				select {
				case e := <-l.entries:
					batch = append(batch, e)
					if len(batch) >= l.batchSize {
						flush()
					}
				default:
					flush()
					return
				}
			}
		}
	}
}

// writeBatch appends entries to the stream in one batch. Each entry is stored
// as a single JSON value so a read is a single Unmarshal. A failed flush logs
// the error and moves on — the log must never break DNS, and at most the last
// ~100ms of entries are at risk.
func (l *Log) writeBatch(entries []Entry) {
	if l.stream == nil || len(entries) == 0 {
		return
	}
	vals := make([][]byte, 0, len(entries))
	written := make([]Entry, 0, len(entries))
	for i := range entries {
		v, err := json.Marshal(&entries[i])
		if err != nil {
			continue
		}
		vals = append(vals, v)
		written = append(written, entries[i])
	}
	// Records expire on their own once past retention (plus an hour of slack
	// so the hourly pruner, not the TTL, is what normally removes them), and
	// the stream is length-capped so a delayed pruner can't let it grow
	// unbounded.
	var ttl time.Duration
	if l.retention > 0 {
		ttl = l.retention + time.Hour
	}
	if err := l.stream.Append(vals, ttl, maxStreamEntries); err != nil {
		// Rate-limited: a failing store would otherwise log every ~100ms.
		// The entries are dropped either way — logging must never break DNS.
		now := time.Now().UnixNano()
		last := l.lastFlushErr.Load()
		if last == 0 || now-last > int64(time.Minute) {
			l.lastFlushErr.Store(now)
			slog.Error("querylog stream flush failed", "error", err)
		}
		return
	}
	// The batch is durably in the stream: fold it into the rolling
	// aggregate so polls reflect it without re-walking. Only on success, so
	// the aggregate always equals the stream (a failed flush's entries are
	// in neither).
	if l.agg != nil {
		for i := range written {
			l.agg.add(written[i])
		}
	}
}

// seedAggregate rebuilds the rolling aggregate from the stream at startup
// (see New). Bounded by maxStatsScan like the old stats walk; under extreme
// volume the oldest entries are skipped rather than stalling boot. A walk
// failure is logged and the log keeps serving — the aggregate is a live
// view that self-heals as new entries land.
func (l *Log) seedAggregate(ctx context.Context) {
	if l.agg == nil {
		return
	}
	// Walk forward from an hour before the window so the far edge is
	// covered; addLocked skips anything older than the window itself.
	start := time.Now().Add(-25 * time.Hour).UnixMilli()
	for m, err := range l.walkStream(ctx, false, start, maxStatsScan) {
		if err != nil {
			slog.Error("querylog aggregate seed failed", "error", err)
			return
		}
		var e Entry
		if !entryFromMessage(&e, m) {
			continue
		}
		l.agg.add(e)
	}
}

// streamMsg is one record read from the stream: its ID and JSON payload. The
// payload is only valid until the next record is produced, so entryFromMessage
// must decode it immediately.
type streamMsg struct {
	ID    string
	Value []byte
}

// entryFromMessage decodes a stream message into an Entry. The message ID
// becomes the entry's stable ID; the payload is the JSON body stored at
// write time. ok is false for malformed messages, which are skipped.
func entryFromMessage(e *Entry, m streamMsg) bool {
	if m.ID == "" || len(m.Value) == 0 {
		return false
	}
	if err := json.Unmarshal(m.Value, e); err != nil {
		return false
	}
	e.ID = m.ID
	return true
}

// ctxCheckEvery is how many records a walk visits between context checks.
const ctxCheckEvery = 256

// walkStream returns an iterator over the stream's records with a timestamp of
// sinceMs or later (0 = from the beginning): oldest-first, or newest-first when
// reverse is set. Range-over-func stops the walk when the loop body breaks (the
// caller found what it needed), the stream is exhausted, max records have been
// scanned, the context is cancelled, or the store errors — the scan bound is
// strict. Every walk in this file shares this one shape; they differ only in
// direction, bounds and what the caller does per record. A yielded error is
// always the last value the iterator produces; callers must check it before
// using the message. Callers on a disabled log (nil stream) never reach here —
// the public methods guard first — but the guard is kept so the helper itself
// can't nil-deref.
func (l *Log) walkStream(ctx context.Context, reverse bool, sinceMs int64, max int) iter.Seq2[streamMsg, error] {
	return l.iterate(ctx, func(fn func(id string, val []byte) bool) error {
		return l.stream.Walk(reverse, sinceMs, max, fn)
	})
}

// walkBefore is walkStream's newest-first walk resumed strictly before the
// record beforeID (a cursor from QueryPage), at constant cost however deep the
// cursor is.
func (l *Log) walkBefore(ctx context.Context, beforeID string, max int) iter.Seq2[streamMsg, error] {
	return l.iterate(ctx, func(fn func(id string, val []byte) bool) error {
		return l.stream.WalkBefore(beforeID, 0, max, fn)
	})
}

// iterate adapts a stream walk (run) into the iterator shape every query uses:
// it checks the context periodically and yields any store or context error as
// the final value.
func (l *Log) iterate(ctx context.Context, run func(fn func(id string, val []byte) bool) error) iter.Seq2[streamMsg, error] {
	return func(yield func(streamMsg, error) bool) {
		if l.stream == nil {
			return
		}
		n := 0
		var stopErr error
		err := run(func(id string, val []byte) bool {
			n++
			if n%ctxCheckEvery == 0 {
				if stopErr = ctx.Err(); stopErr != nil {
					return false
				}
			}
			return yield(streamMsg{ID: id, Value: val}, nil)
		})
		if stopErr == nil {
			stopErr = err
		}
		if stopErr != nil {
			yield(streamMsg{}, stopErr)
		}
	}
}

// matchesFilter applies the query log filters (empty values are wildcards).
// The SQLite store did this in SQL; streams cannot filter server-side, so
// the same semantics are replicated here: action/qtype/client are exact
// matches and domain is a case-insensitive substring. client is the source
// IP exactly as recorded, so clicking a top client on the dashboard shows
// precisely that client's queries.
//
// domain is expected pre-lowercased by Query (the constant part of the
// substring check, hoisted out of the per-entry loop), and stored domains
// are lowercase too (see Entry.Domain), so the substring check compares
// directly — no per-entry ToLower.
func matchesFilter(e Entry, action, domainLower, qtype, client string) bool {
	if action != "" && e.Action != action {
		return false
	}
	if qtype != "" && !strings.EqualFold(e.Type, qtype) {
		return false
	}
	if domainLower != "" && !strings.Contains(e.Domain, domainLower) {
		return false
	}
	if client != "" && e.Client != client {
		return false
	}
	return true
}

// Query fetches recent entries with optional filters and pagination, newest
// first. Filters are applied in memory after reading from the stream,
// walking back from the newest entry until offset+limit matches are found or
// the scan bound is hit.
func (l *Log) Query(ctx context.Context, limit, offset int, action, domain, qtype, client string) ([]Entry, error) {
	if l.stream == nil {
		return nil, nil
	}
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	if offset < 0 {
		offset = 0
	}
	want := offset + limit
	// Hoist the constant lowercase of the domain filter out of the loop:
	// with the filter set, it would otherwise allocate once per entry walked.
	domainLower := strings.ToLower(domain)
	var matches []Entry
	// Walk newest-first, stopping as soon as the wanted page is full — the
	// old loop kept decoding the rest of the page it had already fetched, so
	// a default 100-row view decoded up to 1000 entries every request.
	for m, err := range l.walkStream(ctx, true, 0, maxQueryScan) {
		if err != nil {
			return nil, err
		}
		var e Entry
		if !entryFromMessage(&e, m) {
			continue
		}
		if matchesFilter(e, action, domainLower, qtype, client) {
			matches = append(matches, e)
			if len(matches) >= want {
				break // page full: no point scanning further
			}
		}
	}
	if len(matches) <= offset {
		return []Entry{}, nil
	}
	end := min(offset+limit, len(matches))
	return matches[offset:end], nil
}

// ErrBadCursor is returned by QueryPage for a cursor that is not a valid ID.
var ErrBadCursor = kvstore.ErrBadID

// QueryPage returns one page of up to limit entries matching the filters,
// newest first, resuming strictly before the cursor ID before ("" = start at
// the newest entry). next is the cursor for the following page, or "" when the
// log is exhausted.
//
// Unlike offset paging it never rescans what earlier pages covered, so every
// stored entry is reachable at constant cost per page. Each request examines at
// most maxQueryScan entries: a filter that matches sparsely can therefore come
// back short (even empty) with a non-empty next, meaning "keep going from here"
// rather than "no more matches". next is the last entry examined, not the last
// one returned, so the next page resumes exactly where this one stopped.
func (l *Log) QueryPage(ctx context.Context, limit int, before, action, domain, qtype, client string) (entries []Entry, next string, err error) {
	return l.queryPage(ctx, maxQueryScan, limit, before, action, domain, qtype, client)
}

// queryPage is QueryPage with the per-request scan bound as a parameter, so
// tests can exercise the bound without writing maxQueryScan entries.
func (l *Log) queryPage(ctx context.Context, scanMax, limit int, before, action, domain, qtype, client string) (entries []Entry, next string, err error) {
	entries = []Entry{}
	if l.stream == nil {
		return entries, "", nil
	}
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	domainLower := strings.ToLower(domain)

	var seq iter.Seq2[streamMsg, error]
	if before == "" {
		seq = l.walkStream(ctx, true, 0, scanMax)
	} else {
		seq = l.walkBefore(ctx, before, scanMax)
	}
	scanned, lastID, full := 0, "", false
	for m, werr := range seq {
		if werr != nil {
			return nil, "", werr
		}
		scanned++
		lastID = m.ID
		var e Entry
		if !entryFromMessage(&e, m) {
			continue
		}
		if matchesFilter(e, action, domainLower, qtype, client) {
			entries = append(entries, e)
			if len(entries) >= limit {
				full = true
				break
			}
		}
	}
	// More may remain if the page filled up, or the scan bound cut the walk
	// short before the stream ran out.
	if full || scanned >= scanMax {
		next = lastID
	}
	return entries, next, nil
}

// TopDomain is a domain (or client) with a count, used for the "top
// blocked" and "top clients" aggregates.
type TopDomain struct {
	Domain string `json:"domain"`
	Count  int64  `json:"count"`
}

// emptyStats returns a zeroed stats map with the exact value types the API's
// JSON consumers expect (int64 counters, float64 average, non-nil top lists).
func emptyStats() map[string]any {
	return map[string]any{
		"total": int64(0), "allowed": int64(0), "blocked": int64(0), "cached": int64(0),
		"avg_rt_ms": float64(0), "top_blocked": []TopDomain{}, "top_clients": []TopDomain{},
	}
}

// topDomainHeap is a min-heap over TopDomain ordered by "worseness" (the
// inverse of topN's output order): the root is always the weakest of the
// entries currently kept, so topN can evict it in O(log n) when a stronger
// candidate arrives instead of re-sorting everything.
type topDomainHeap []TopDomain

func (h topDomainHeap) Len() int { return len(h) }
func (h topDomainHeap) Less(i, j int) bool {
	if h[i].Count != h[j].Count {
		return h[i].Count < h[j].Count
	}
	return h[i].Domain > h[j].Domain // ties: alphabetically later is weaker
}
func (h topDomainHeap) Swap(i, j int) { h[i], h[j] = h[j], h[i] }
func (h *topDomainHeap) Push(x any)   { *h = append(*h, x.(TopDomain)) }
func (h *topDomainHeap) Pop() any {
	old := *h
	last := len(old) - 1
	x := old[last]
	*h = old[:last]
	return x
}

// topN returns the n entries with the highest counts, descending (ties
// broken alphabetically for determinism). counts can hold thousands of
// distinct domains/clients in a busy window and this runs on every
// dashboard poll (four times, for the 24h/today × blocked/clients splits),
// so it keeps a bounded size-n min-heap in a single pass over the map
// instead of sorting all of it — O(len(counts) log n) instead of
// O(len(counts) log len(counts)), with no full-slice sort allocation.
func topN(counts map[string]int64, n int) []TopDomain {
	if n <= 0 {
		return []TopDomain{}
	}
	h := make(topDomainHeap, 0, n)
	for d, c := range counts {
		cand := TopDomain{Domain: d, Count: c}
		if len(h) < n {
			heap.Push(&h, cand)
			continue
		}
		// h[0] is the weakest of the n entries kept so far; only replace it
		// when cand would rank ahead of it in the final descending order.
		if cand.Count > h[0].Count || (cand.Count == h[0].Count && cand.Domain < h[0].Domain) {
			h[0] = cand
			heap.Fix(&h, 0)
		}
	}
	out := []TopDomain(h)
	slices.SortFunc(out, func(a, b TopDomain) int {
		if c := cmp.Compare(b.Count, a.Count); c != 0 {
			return c
		}
		return cmp.Compare(a.Domain, b.Domain)
	})
	return out
}

// Stats returns aggregate counters for a time window by walking the stream
// entries recorded since. Stream auto-IDs embed the write timestamp, so the
// window maps directly to a minimum ID and the walk starts there. The scan
// is bounded (maxStatsScan): under extreme volume the counters under-report
// rather than stall the dashboard's poll.
func (l *Log) Stats(ctx context.Context, since time.Time) (map[string]any, error) {
	stats := emptyStats()
	if l.stream == nil {
		return stats, nil
	}
	// Serve a recent result for the same (quantized) window instead of
	// re-walking the stream: the dashboard polls every 10s, so polls within
	// one bucket share a single scan.
	sinceKey := since.Unix() / int64(aggCacheBucket/time.Second)
	if v, ok := l.statsCache.get(sinceKey); ok {
		return v, nil
	}
	var total, allowed, blocked, cached int64
	var rtSum float64
	blockedCnt := map[string]int64{}
	clientCnt := map[string]int64{}
	for m, err := range l.walkStream(ctx, false, since.UnixMilli(), maxStatsScan) {
		if err != nil {
			return nil, err
		}
		var e Entry
		if !entryFromMessage(&e, m) {
			continue
		}
		total++
		rtSum += float64(e.ResponseTimeMS)
		switch e.Action {
		case "allowed":
			allowed++
		case "blocked":
			blocked++
			blockedCnt[e.Domain]++
		case "cached":
			cached++
		}
		clientCnt[e.Client]++
	}
	if total > 0 {
		stats["avg_rt_ms"] = rtSum / float64(total)
	}
	stats["total"] = total
	stats["allowed"] = allowed
	stats["blocked"] = blocked
	stats["cached"] = cached
	stats["top_blocked"] = topN(blockedCnt, 10)
	stats["top_clients"] = topN(clientCnt, 10)
	l.statsCache.set(sinceKey, stats)
	return stats, nil
}

// HourBucket is one hour's query volume for the dashboard's 24h sparkline.
// Hour is the RFC3339 timestamp of the start of the bucket's hour.
type HourBucket struct {
	Hour    string `json:"hour"`
	Total   int64  `json:"total"`
	Blocked int64  `json:"blocked"`
}

// Hourly buckets query volume into the 24 one-hour slots ending at the
// current hour, oldest first, walking the stream newest-first so a scan
// bound (extreme volume) can only under-count the oldest hours, never the
// most recent ones. Empty hours are filled with zeros so the frontend always
// receives a fixed-length series.
func (l *Log) Hourly(ctx context.Context, since time.Time) ([]HourBucket, error) {
	out := []HourBucket{}
	if l.stream == nil {
		return out, nil
	}
	sinceKey := since.Unix() / int64(aggCacheBucket/time.Second)
	if v, ok := l.hourlyCache.get(sinceKey); ok {
		return v, nil
	}
	now := time.Now()
	endSlot := now.Truncate(time.Hour)
	startSlot := endSlot.Add(-23 * time.Hour)
	total := make([]int64, 24)
	blocked := make([]int64, 24)

	// Newest-first walk from "+" down to the since ID (inclusive), so the
	// current hour's bar is always complete even if the scan is bounded.
	for m, err := range l.walkStream(ctx, true, since.UnixMilli(), maxStatsScan) {
		if err != nil {
			return nil, err
		}
		var e Entry
		if !entryFromMessage(&e, m) {
			continue
		}
		idx := int(e.Time.Truncate(time.Hour).Sub(startSlot) / time.Hour)
		if idx < 0 || idx >= 24 {
			continue
		}
		total[idx]++
		if e.Action == "blocked" {
			blocked[idx]++
		}
	}
	for i := range 24 {
		out = append(out, HourBucket{
			Hour:    startSlot.Add(time.Duration(i) * time.Hour).Format(time.RFC3339),
			Total:   total[i],
			Blocked: blocked[i],
		})
	}
	l.hourlyCache.set(sinceKey, out)
	return out, nil
}

// StatsBundle is the dashboard's full aggregate set — the 24h stats, the
// since-midnight "today" stats and the 24-slot hourly series. The three
// blocks are just different projections of the same stream entries, so
// StatsBundle computes them in ONE walk instead of the three the dashboard
// poll used to perform.
type StatsBundle struct {
	Stats  map[string]any
	Today  map[string]any
	Hourly []HourBucket
}

// StatsBundle returns the dashboard's aggregate set. The standard window
// (24h ending at the current hour + since local midnight) is served live
// from the writer-maintained rolling aggregate in O(1) — no stream walk.
// Any other window falls back to the exact bounded walk (see
// statsBundleWalk), which is what Stats/Hourly have always done. since is
// the 24h window bound and today the since-midnight bound (local midnight,
// supplied by the caller — querylog doesn't know the server's timezone).
func (l *Log) StatsBundle(ctx context.Context, since, today time.Time) (*StatsBundle, error) {
	if l.stream == nil {
		return &StatsBundle{Stats: emptyStats(), Today: emptyStats(), Hourly: []HourBucket{}}, nil
	}
	// Fast path: the standard dashboard window, served live and uncached —
	// reads are O(1), so there is no reason to serve stale totals.
	if l.agg != nil && bundleWindowMatches(since, today) {
		l.agg.resetTodayIfNeeded(time.Now())
		b := l.agg.snapshot()
		return &b, nil
	}
	return l.statsBundleWalk(ctx, since, today)
}

// bundleWindowMatches reports whether since/today are the standard
// dashboard window the rolling aggregate serves: since ≈ now-24h and today
// ≈ local midnight. The tolerance covers the hour-aligned rolling window's
// boundary (see rolling.go) and any caller-computed "now" skew.
func bundleWindowMatches(since, today time.Time) bool {
	now := time.Now()
	d := now.Sub(since)
	if d < 23*time.Hour || d > 25*time.Hour {
		return false
	}
	return today.Sub(midnightOf(now)).Abs() < time.Minute
}

// statsBundleWalk computes the bundle with a single bounded walk of the
// stream: the 24h stats, the today stats and the 24-slot hourly series all
// come from one newest-first scan (bounded by maxStatsScan, so extreme
// volume can only under-count the oldest entries). The result is cached
// for aggCacheTTL keyed on both quantized windows; the cache serves any
// repeated poll with the same window without re-scanning.
func (l *Log) statsBundleWalk(ctx context.Context, since, today time.Time) (*StatsBundle, error) {
	// Key on both windows: today advances at local midnight, and serving a
	// pre-midnight "today" block just after midnight would be stale until
	// the next bucket (<= aggCacheBucket). Packing both Unix-bucket values
	// into one int64 is unambiguous while each fits in 32 bits (centuries).
	sinceKey := since.Unix() / int64(aggCacheBucket/time.Second)
	todayKey := today.Unix() / int64(aggCacheBucket/time.Second)
	cacheKey := (todayKey << 32) | sinceKey
	if v, ok := l.bundleCache.get(cacheKey); ok {
		return &v, nil
	}

	now := time.Now()
	endSlot := now.Truncate(time.Hour)
	startSlot := endSlot.Add(-23 * time.Hour)
	total := make([]int64, 24)
	blocked := make([]int64, 24)
	var total24, allowed24, blocked24, cached24 int64
	var todayTotal, todayAllowed, todayBlocked, todayCached int64
	var rtSum24, rtSumToday float64
	blockedCnt := map[string]int64{}
	clientCnt := map[string]int64{}
	todayBlockedCnt := map[string]int64{}
	todayClientCnt := map[string]int64{}

	// Newest-first walk from "+" down to the 24h bound (inclusive), same
	// shape as Hourly: a scan bound can only miss the oldest entries.
	for m, err := range l.walkStream(ctx, true, since.UnixMilli(), maxStatsScan) {
		if err != nil {
			return nil, err
		}
		var e Entry
		if !entryFromMessage(&e, m) {
			continue
		}
		total24++
		rtSum24 += float64(e.ResponseTimeMS)
		switch e.Action {
		case "allowed":
			allowed24++
		case "blocked":
			blocked24++
			blockedCnt[e.Domain]++
		case "cached":
			cached24++
		}
		clientCnt[e.Client]++
		if !e.Time.Before(today) {
			todayTotal++
			rtSumToday += float64(e.ResponseTimeMS)
			switch e.Action {
			case "allowed":
				todayAllowed++
			case "blocked":
				todayBlocked++
				todayBlockedCnt[e.Domain]++
			case "cached":
				todayCached++
			}
			todayClientCnt[e.Client]++
		}
		idx := int(e.Time.Truncate(time.Hour).Sub(startSlot) / time.Hour)
		if idx >= 0 && idx < 24 {
			total[idx]++
			if e.Action == "blocked" {
				blocked[idx]++
			}
		}
	}

	stats := emptyStats()
	if total24 > 0 {
		stats["avg_rt_ms"] = rtSum24 / float64(total24)
	}
	stats["total"] = total24
	stats["allowed"] = allowed24
	stats["blocked"] = blocked24
	stats["cached"] = cached24
	stats["top_blocked"] = topN(blockedCnt, 10)
	stats["top_clients"] = topN(clientCnt, 10)

	todayStats := emptyStats()
	if todayTotal > 0 {
		todayStats["avg_rt_ms"] = rtSumToday / float64(todayTotal)
	}
	todayStats["total"] = todayTotal
	todayStats["allowed"] = todayAllowed
	todayStats["blocked"] = todayBlocked
	todayStats["cached"] = todayCached
	todayStats["top_blocked"] = topN(todayBlockedCnt, 10)
	todayStats["top_clients"] = topN(todayClientCnt, 10)

	out := &StatsBundle{Stats: stats, Today: todayStats}
	for i := range 24 {
		out.Hourly = append(out.Hourly, HourBucket{
			Hour:    startSlot.Add(time.Duration(i) * time.Hour).Format(time.RFC3339),
			Total:   total[i],
			Blocked: blocked[i],
		})
	}
	l.bundleCache.set(cacheKey, *out)
	return out, nil
}

// ActiveDomains returns the unique domains recorded since, ordered by query
// count descending (ties alphabetical). limit caps the result (<= 0 = every
// domain in the window, bounded by the stream scan cap). Only "allowed" and
// "cached" actions count: blocked domains are re-blocked by the filter anyway
// (warming them would waste upstream traffic and leak the query), rewrites are
// answered locally without touching the cache, and errors have nothing to
// cache. This is the cache warmer's source of "currently active domains".
func (l *Log) ActiveDomains(ctx context.Context, since time.Time, limit int) ([]TopDomain, error) {
	if l.stream == nil {
		return []TopDomain{}, nil
	}
	counts := map[string]int64{}
	for m, err := range l.walkStream(ctx, false, since.UnixMilli(), maxWarmScan) {
		if err != nil {
			return nil, err
		}
		var e Entry
		if !entryFromMessage(&e, m) {
			continue
		}
		if e.Domain == "" {
			continue
		}
		switch e.Action {
		case "allowed", "cached":
			counts[e.Domain]++
		}
	}
	if len(counts) == 0 {
		return []TopDomain{}, nil
	}
	if limit <= 0 {
		limit = len(counts)
	}
	return topN(counts, limit), nil
}

// Clear deletes every record in the stream (the UI "clear log" action).
func (l *Log) Clear(ctx context.Context) error {
	if l.stream == nil {
		return nil
	}
	// Drop cached aggregates and reset the rolling aggregate too, or the
	// next poll would serve the pre-clear numbers.
	l.statsCache.clear()
	l.hourlyCache.clear()
	l.bundleCache.clear()
	if l.agg != nil {
		l.agg.clear()
	}
	return l.stream.Clear()
}

// Prune removes entries older than the retention window. The stream's
// time-ordered keys make "delete everything before cutoff" a single forward
// scan from the oldest record.
func (l *Log) Prune(context.Context) {
	if l.retention <= 0 || l.stream == nil {
		return
	}
	if _, err := l.stream.TrimBefore(time.Now().Add(-l.retention)); err != nil {
		slog.Error("querylog prune failed", "error", err)
	}
}

// StartPruner periodically prunes old entries.
func (l *Log) StartPruner(ctx context.Context) {
	go func() {
		defer safego.Recover("querylog pruner")
		t := time.NewTicker(time.Hour)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				l.Prune(ctx)
			}
		}
	}()
}

// Close stops the writer (flushing any pending entries). It does not close the
// kvstore, which the caller owns. Safe to call more than once.
func (l *Log) Close() error {
	if !l.closed.CompareAndSwap(false, true) {
		return nil
	}
	close(l.done) // writer drains the queue and flushes the final batch
	l.wg.Wait()
	return nil
}
