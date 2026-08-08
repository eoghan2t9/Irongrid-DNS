// Package querylog stores every DNS request with its allow/block outcome in
// a Dragonfly Redis Stream. The stream replaces the old SQLite database so
// the query log shares the same cache tier as DNS responses: one server to
// run, one place to look when diagnosing, and cheap sharing across multiple
// Irongrid instances. Entries are written asynchronously in batches so the
// DNS hot path never blocks on a round trip.
package querylog

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"sort"
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
)

// Entry is a single logged query. ID is the Dragonfly stream ID, assigned on
// read; it is a stable unique key (the dashboard uses it as the React list
// key) rather than a monotonically increasing integer.
type Entry struct {
	ID             string    `json:"id"`
	Time           time.Time `json:"time"`
	Client         string    `json:"client"`
	Domain         string    `json:"domain"`
	Type           string    `json:"type"`   // A, AAAA, TXT...
	Action         string    `json:"action"` // "allowed", "blocked", "cached", "error"
	Reason         string    `json:"reason"`
	Upstream       string    `json:"upstream"`
	ResponseTimeMS int64     `json:"response_time_ms"`
	Rcode          int       `json:"rcode"`
	Answers        int       `json:"answers"`
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
	}
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
			log.Printf("[querylog] stream flush failed: %v", err)
		}
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

// matchesFilter applies the query log filters (empty values are wildcards).
// The SQLite store did this in SQL; streams cannot filter server-side, so
// the same semantics are replicated here: action/qtype are exact matches
// and domain is a case-insensitive substring.
func matchesFilter(e Entry, action, domain, qtype string) bool {
	if action != "" && e.Action != action {
		return false
	}
	if qtype != "" && !strings.EqualFold(e.Type, qtype) {
		return false
	}
	if domain != "" && !strings.Contains(strings.ToLower(e.Domain), strings.ToLower(domain)) {
		return false
	}
	return true
}

// Query fetches recent entries with optional filters and pagination, newest
// first. Filters are applied in memory after reading from the stream,
// walking back from the newest entry until offset+limit matches are found or
// the scan bound is hit.
func (l *Log) Query(ctx context.Context, limit, offset int, action, domain, qtype string) ([]Entry, error) {
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
	var matches []Entry
	start := "+" // newest stream ID
	first := true
	scanned := 0
	for len(matches) < want && scanned < maxQueryScan {
		// Request one extra message: a page shorter than requested proves
		// the stream is exhausted, and (when continuing) the first message
		// is the already-consumed one, which we skip.
		const page = 1000
		msgs, err := l.client.XRevRangeN(ctx, streamKey, start, "-", page+1).Result()
		if err != nil {
			return nil, err
		}
		begin := 0
		if !first && len(msgs) > 0 && msgs[0].ID == start {
			begin = 1
		}
		if len(msgs) <= begin {
			break
		}
		first = false
		for _, m := range msgs[begin:] {
			scanned++
			var e Entry
			if !entryFromMessage(&e, m) {
				continue
			}
			if matchesFilter(e, action, domain, qtype) {
				matches = append(matches, e)
			}
		}
		if len(msgs) <= page { // fewer than a full page: the stream is exhausted
			break
		}
		start = msgs[len(msgs)-1].ID
	}
	if len(matches) <= offset {
		return []Entry{}, nil
	}
	end := offset + limit
	if end > len(matches) {
		end = len(matches)
	}
	return matches[offset:end], nil
}

// TopDomain is a domain (or client) with a count, used for the "top
// blocked" and "top clients" aggregates.
type TopDomain struct {
	Domain string `json:"domain"`
	Count  int64  `json:"count"`
}

// topN returns the n entries with the highest counts, descending (ties
// broken alphabetically for determinism).
func topN(counts map[string]int64, n int) []TopDomain {
	out := make([]TopDomain, 0, len(counts))
	for d, c := range counts {
		out = append(out, TopDomain{Domain: d, Count: c})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Domain < out[j].Domain
	})
	if len(out) > n {
		out = out[:n]
	}
	return out
}

// Stats returns aggregate counters for a time window by walking the stream
// entries recorded since. Stream auto-IDs embed the write timestamp, so the
// window maps directly to a minimum ID and the walk starts there. The scan
// is bounded (maxStatsScan): under extreme volume the counters under-report
// rather than stall the dashboard's poll.
func (l *Log) Stats(ctx context.Context, since time.Time) (map[string]any, error) {
	// int64 literals so every path (including the disabled no-store return)
	// yields the same value types the API's JSON consumers expect.
	stats := map[string]any{
		"total": int64(0), "allowed": int64(0), "blocked": int64(0), "cached": int64(0),
		"avg_rt_ms": float64(0), "top_blocked": []TopDomain{}, "top_clients": []TopDomain{},
	}
	if l.client == nil {
		return stats, nil
	}
	var total, allowed, blocked, cached int64
	var rtSum float64
	blockedCnt := map[string]int64{}
	clientCnt := map[string]int64{}
	start := strconv.FormatInt(since.UnixMilli(), 10) + "-0"
	first := true
	scanned := 0
	for scanned < maxStatsScan {
		const page = 1000
		msgs, err := l.client.XRangeN(ctx, streamKey, start, "+", page+1).Result()
		if err != nil {
			return nil, err
		}
		begin := 0
		if !first && len(msgs) > 0 && msgs[0].ID == start {
			begin = 1
		}
		if len(msgs) <= begin {
			break
		}
		first = false
		for _, m := range msgs[begin:] {
			scanned++
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
		if len(msgs) <= page {
			break
		}
		start = msgs[len(msgs)-1].ID
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
	return stats, nil
}

// Clear deletes the entire stream (the UI "clear log" action).
func (l *Log) Clear(ctx context.Context) error {
	if l.client == nil {
		return nil
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
		log.Printf("[querylog] prune failed: %v", err)
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
