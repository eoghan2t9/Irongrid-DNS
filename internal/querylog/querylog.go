// Package querylog stores every DNS request with its allow/block outcome in
// a Dragonfly Redis Stream. The stream replaces the old SQLite database so
// the query log shares the same cache tier as DNS responses: one server to
// run, one place to look when diagnosing, and cheap sharing across multiple
// Irongrid instances. Entries are written asynchronously in batches so the
// DNS hot path never blocks on a round trip.
package querylog

import (
	"cmp"
	"container/heap"
	"context"
	"encoding/json"
	"fmt"
	"iter"
	"log/slog"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/redis/go-redis/v9"
)

const (
	// logQueueCap bounds the pending-entry queue. Serving never blocks on
	// logging: once the queue is full, new entries are dropped.
	logQueueCap = 8192
	// logBatchSize flushes the writer once this many entries have queued.
	logBatchSize = 256
	// logFlushInterval is the maximum age of a queued entry before the
	// writer flushes it in one pipelined round trip.
	logFlushInterval = 100 * time.Millisecond
	// streamKey is the single Dragonfly stream holding every logged query.
	// XADD auto-IDs are "<ms>-<seq>", so entries are time-ordered and the
	// newest ID is also the latest query.
	streamKey = "irongrid:log"
	// maxStreamEntries hard-caps the stream length so the log can never grow
	// unbounded in Dragonfly's cache mode (which evicts under memory
	// pressure) even if the hourly retention pruner is delayed. 250k entries
	// covers roughly a day or two of heavy traffic — well past the
	// dashboard's needs, and the retention pruner usually keeps it far lower.
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
	// queryPage is the fetch size for the interactive query-log walk: it
	// only ever needs up to a page of entries, so a small page keeps each
	// request's response small.
	queryPage = 1000
	// aggPage is the fetch size for the aggregate walks (Stats, Hourly,
	// StatsBundle): those scan deep into the stream (up to maxStatsScan
	// entries), so a bigger page means fewer round trips — 100k/5000 = 20
	// worst case, vs 100 at the old 1000-entry page.
	aggPage = 5000

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

// Entry is a single logged query. ID is the Dragonfly stream ID, assigned on
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

// Log is a concurrency-safe query logger backed by a Dragonfly stream.
// Entries are enqueued and written by a single background goroutine in
// pipelined batches (one round trip per flush), so per-query Redis traffic
// never sits on the DNS hot path.
type Log struct {
	client    *redis.Client
	retention time.Duration
	batchSize int

	entries chan Entry
	done    chan struct{}
	closed  atomic.Bool
	wg      sync.WaitGroup

	// lastFlushErr gates the flush-failure log line so a Dragonfly outage
	// produces at most one line per minute instead of one every ~100ms (the
	// writer flushes on a ticker even when the server is down).
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

// New connects to Dragonfly and returns a stream-backed query log. It shares
// the same endpoint as the DNS cache but owns its connection pool, so a
// cache reload (which closes and replaces the cache's client) can never kill
// the log. batchSize is the number of entries committed per pipelined flush;
// <= 0 uses the default.
func New(addr, password string, db, retentionDays, batchSize int) (*Log, error) {
	client := redis.NewClient(&redis.Options{
		Addr:         addr,
		Password:     password,
		DB:           db,
		DialTimeout:  5 * time.Second,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
	})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := client.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("dragonfly query log unreachable at %s: %w", addr, err)
	}
	bs := logBatchSize
	if batchSize > 0 {
		bs = batchSize
	}
	l := &Log{
		client:    client,
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
	l.seedAggregate(ctx)
	l.wg.Add(1)
	go l.runWriter()
	return l, nil
}

// NewDisabled returns a logger with no backing store: Record drops entries
// and Query/Stats return empty results. It exists for tests (and any caller
// that needs the full Log API without a Redis-compatible server); the writer
// goroutine is still started so Close behaves identically.
func NewDisabled(retentionDays int) *Log {
	l := &Log{
		retention: time.Duration(retentionDays) * 24 * time.Hour,
		entries:   make(chan Entry, logQueueCap),
		done:      make(chan struct{}),
	}
	l.wg.Add(1)
	go l.runWriter()
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
// the background writer batches entries and commits them in one pipelined
// round trip. If the queue is full (or the log is closed), the entry is
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
	defer l.wg.Done()
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

// writeBatch appends entries to the stream in a single pipelined round trip.
// Each entry is stored as one JSON field ("v") so a read is a single
// Unmarshal. A failed flush (Dragonfly down, connection reset) logs the
// error and moves on — the log must never break DNS, and at most the last
// ~100ms of entries are at risk.
func (l *Log) writeBatch(entries []Entry) {
	if l.client == nil || len(entries) == 0 {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	pipe := l.client.Pipeline()
	for i := range entries {
		v, err := json.Marshal(&entries[i])
		if err != nil {
			continue
		}
		pipe.XAdd(ctx, &redis.XAddArgs{Stream: streamKey, Values: map[string]any{"v": v}})
	}
	// Keep the stream bounded even if the hourly retention pruner is
	// delayed; in Dragonfly's cache mode an unbounded stream could otherwise
	// eat the whole 512MB budget.
	pipe.XTrimMaxLen(ctx, streamKey, maxStreamEntries)
	if _, err := pipe.Exec(ctx); err != nil {
		// Rate-limited: a down Dragonfly would otherwise log every ~100ms.
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
		for i := range entries {
			l.agg.add(entries[i])
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
	start := strconv.FormatInt(time.Now().Add(-25*time.Hour).UnixMilli(), 10) + "-0"
	for m, err := range l.walkStream(ctx, false, start, "+", maxStatsScan, aggPage) {
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

// entryFromMessage decodes a stream message into an Entry. The message ID
// becomes the entry's stable ID; the payload is the JSON body stored at
// write time. ok is false for malformed messages, which are skipped.
func entryFromMessage(e *Entry, m redis.XMessage) bool {
	if m.ID == "" {
		return false
	}
	raw, ok := m.Values["v"].(string)
	if !ok {
		return false
	}
	if err := json.Unmarshal([]byte(raw), e); err != nil {
		return false
	}
	e.ID = m.ID
	return true
}

// walkStream returns an iterator that pages through the stream from start
// towards stop (reverse for a newest-first walk, forward otherwise), yielding
// every message in range. Range-over-func stops the walk when the loop body
// breaks (the caller found what it needed), the stream is exhausted, max
// messages have been scanned, or a Redis error is yielded — the scan bound is
// strict, enforced inside the page so a single oversized page can't overshoot
// by up to page entries. The boundary message shared between consecutive
// pages is skipped (each page asks for page+1 messages so a short page proves
// exhaustion). Every walk in this file shares this one paging shape; they
// differ only in direction, bounds and what the caller does per message.
// Callers on a disabled log (nil client) never reach here — the public
// methods guard first — but the guard is kept so the helper itself can't
// nil-deref. A yielded error is always the last value the iterator produces;
// callers must check it before using the message.
func (l *Log) walkStream(ctx context.Context, reverse bool, start, stop string, max, page int) iter.Seq2[redis.XMessage, error] {
	return func(yield func(redis.XMessage, error) bool) {
		if l.client == nil {
			return
		}
		first := true
		scanned := 0
		for scanned < max {
			var (
				msgs []redis.XMessage
				err  error
			)
			if reverse {
				msgs, err = l.client.XRevRangeN(ctx, streamKey, start, stop, int64(page+1)).Result()
			} else {
				msgs, err = l.client.XRangeN(ctx, streamKey, start, stop, int64(page+1)).Result()
			}
			if err != nil {
				yield(redis.XMessage{}, err)
				return
			}
			begin := 0
			if !first && len(msgs) > 0 && msgs[0].ID == start {
				begin = 1
			}
			if len(msgs) <= begin {
				return
			}
			first = false
			for _, m := range msgs[begin:] {
				scanned++
				if !yield(m, nil) {
					return
				}
				if scanned >= max {
					return
				}
			}
			if len(msgs) <= page { // fewer than a full page: the stream is exhausted
				return
			}
			start = msgs[len(msgs)-1].ID
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
	if l.client == nil {
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
	for m, err := range l.walkStream(ctx, true, "+", "-", maxQueryScan, queryPage) {
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
	if l.client == nil {
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
	start := strconv.FormatInt(since.UnixMilli(), 10) + "-0"
	for m, err := range l.walkStream(ctx, false, start, "+", maxStatsScan, aggPage) {
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
	if l.client == nil {
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
	min := strconv.FormatInt(since.UnixMilli(), 10) + "-0"
	for m, err := range l.walkStream(ctx, true, "+", min, maxStatsScan, aggPage) {
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
	if l.client == nil {
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
	min := strconv.FormatInt(since.UnixMilli(), 10) + "-0"
	for m, err := range l.walkStream(ctx, true, "+", min, maxStatsScan, aggPage) {
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
	if l.client == nil {
		return []TopDomain{}, nil
	}
	counts := map[string]int64{}
	start := strconv.FormatInt(since.UnixMilli(), 10) + "-0"
	for m, err := range l.walkStream(ctx, false, start, "+", maxWarmScan, aggPage) {
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

// Clear deletes the entire stream (the UI "clear log" action).
func (l *Log) Clear(ctx context.Context) error {
	if l.client == nil {
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
	return l.client.Del(ctx, streamKey).Err()
}

// Prune removes entries older than the retention window. The stream's
// time-ordered IDs make "delete everything before cutoff" a single XTRIM
// MINID command.
func (l *Log) Prune(ctx context.Context) {
	if l.retention <= 0 || l.client == nil {
		return
	}
	cutoff := fmt.Sprintf("%d-0", time.Now().Add(-l.retention).UnixMilli())
	if err := l.client.XTrimMinID(ctx, streamKey, cutoff).Err(); err != nil {
		slog.Error("querylog prune failed", "error", err)
	}
}

// StartPruner periodically prunes old entries.
func (l *Log) StartPruner(ctx context.Context) {
	go func() {
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

// Close stops the writer (flushing any pending entries) and closes the
// connection pool. Safe to call more than once.
func (l *Log) Close() error {
	if !l.closed.CompareAndSwap(false, true) {
		return nil
	}
	close(l.done) // writer drains the queue and flushes the final batch
	l.wg.Wait()
	if l.client != nil {
		return l.client.Close()
	}
	return nil
}
