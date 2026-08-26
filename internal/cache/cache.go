// Package cache provides the DNS response cache backed by Dragonfly
// (Redis protocol). Dragonfly is a hard dependency: the server refuses to
// start when it cannot be reached.
package cache

import (
	"context"
	"encoding/binary"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
	"github.com/redis/go-redis/v9"
)

// defaultLookupTimeout is the budget for the L2 (Dragonfly) read on the DNS
// hot path when the config leaves cache.lookup_timeout at 0. Dragonfly is an
// accelerator, not the source of truth: if it can't answer within this
// budget the query proceeds straight to the upstream instead of stalling
// behind a slow or down cache tier.
const defaultLookupTimeout = 150 * time.Millisecond

// l2Write is one queued L2 cache write: a key, its value and TTL. The hot
// path enqueues these and a single writer goroutine commits them to
// Dragonfly in pipelined batches, so a cache miss costs one channel send
// instead of a fresh goroutine plus one Redis round trip per write.
type l2Write struct {
	key string
	val []byte
	ttl time.Duration
}

const (
	// writeQueueCap bounds the pending-write queue. The enqueue path never
	// blocks on it: when the queue is full the write falls back to a
	// synchronous SET — batching is a throughput optimization, never a
	// reason to drop a cache entry.
	writeQueueCap = 8192
	// writeBatchSize flushes the writer once this many writes have queued.
	writeBatchSize = 256
	// writeFlushInterval is the maximum age of a queued write before the
	// writer commits it in one pipelined round trip. 20ms keeps writes
	// visible almost immediately while still coalescing bursts.
	writeFlushInterval = 20 * time.Millisecond
	// writeFlushTimeout bounds each pipelined flush so a stuck Dragonfly
	// can't wedge the writer goroutine.
	writeFlushTimeout = 2 * time.Second
)

// Cache is a two-layer response cache: a fast in-process L1 in front of the
// Dragonfly/Redis L2. The L2 is authoritative for the fleet (and survives
// restarts); the L1 makes local hits a pure map lookup.
type Cache struct {
	client      *redis.Client
	l1          *l1Cache // carries the serve-stale window (l1Cache.staleTTL)
	prefix      string
	ttl         time.Duration
	negativeTTL time.Duration
	// lookupTimeout bounds the L2 read on the lookup path (see
	// defaultLookupTimeout); 0 means the default. Set via SetLookupTimeout
	// (config live-apply, from the API goroutine) and read lock-free on the
	// hot path — an atomic keeps that race-free.
	lookupTimeout atomic.Int64 // nanoseconds

	// prefetch, when set, is invoked in the background for hot positive
	// entries near the end of their cache lifetime so the next query finds a
	// fresh answer instead of paying an upstream round trip. The handler
	// wires it to re-resolve via the current upstreams (see Handler.Refresh).
	//
	// EnablePrefetch must be called before the cache is published to serving
	// goroutines (it is: at construction, and before SetCache swaps a
	// replacement in) — the field is read lock-free on the lookup path.
	prefetch    func(ctx context.Context, q dns.Question)
	prefetching sync.Map // msgKey -> struct{}: one in-flight refresh per key

	// L2 write batching: Set/SetNegative enqueue their Dragonfly writes and
	// a single writer goroutine commits them in pipelined batches (see
	// runWriter), so the per-write cost on the miss path is one channel
	// send instead of a Dragonfly round trip. All nil for the LocalOnly
	// test cache (no L2, no writer).
	writes  chan l2Write
	wdone   chan struct{}
	wwg     sync.WaitGroup
	wclosed atomic.Bool
	// lastWriteErr rate-limits the batch-write failure log line so a down
	// Dragonfly can't spam the journal (the writer flushes on a ticker even
	// when nothing is queued).
	lastWriteErr atomic.Int64

	// l1Hits/l1Misses count lookups answered (or missed) by the in-process
	// L1 layer since process start, for the dashboard's cache card. They are
	// counted once per logical query (Get/Lookup/GetNegative), not per key
	// probed.
	l1Hits   atomic.Int64
	l1Misses atomic.Int64
}

// NewLocalOnly returns a Cache backed only by the in-process L1 layer, with
// no Dragonfly connection — for tests in other packages that need a working
// Cache without standing up a real Redis-compatible server. serveStale is
// the RFC 8767 stale window (0 disables serve-stale); prefetch is off until
// EnablePrefetch is called.
func NewLocalOnly(ttl, negativeTTL time.Duration, l1Entries int, serveStale time.Duration) *Cache {
	return &Cache{l1: newL1(l1Entries, serveStale), prefix: "irongrid:dns:", ttl: ttl, negativeTTL: negativeTTL}
}

// New connects to Dragonfly. It returns an error if the instance is
// unreachable, enforcing the hard dependency. l1Entries is the per-shard
// capacity of the in-process L1 cache; <= 0 disables the L1 layer. The
// "auto" sizing (config 0) is resolved at the call site via AutoPerShard,
// which needs the tuning package's memory detection. serveStale is how long
// an L1 entry remains answerable past its expiry (RFC 8767); 0 disables
// serve-stale.
func New(addr, password string, db int, ttl, negativeTTL, serveStale time.Duration, l1Entries int) (*Cache, error) {
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
		return nil, fmt.Errorf("dragonfly cache unreachable at %s: %w", addr, err)
	}

	// Sanity check that the connected server is actually Dragonfly or Redis.
	info, err := client.Info(ctx, "server").Result()
	if err != nil {
		return nil, fmt.Errorf("dragonfly cache info failed: %w", err)
	}
	slog.Info("cache connected", "server", summarizeServerInfo(info))

	var l1 *l1Cache
	if l1Entries > 0 {
		l1 = newL1(l1Entries, serveStale)
	}
	c := &Cache{
		client:      client,
		l1:          l1,
		prefix:      "irongrid:dns:",
		ttl:         ttl,
		negativeTTL: negativeTTL,
	}
	c.startWriter()
	return c, nil
}

// startWriter launches the batched L2 write goroutine. Only called when
// there is a real L2 (client != nil); the LocalOnly test cache has no
// writer, and its Set/SetNegative skip the L2 path entirely.
func (c *Cache) startWriter() {
	if c.client == nil {
		return
	}
	c.writes = make(chan l2Write, writeQueueCap)
	c.wdone = make(chan struct{})
	c.wwg.Go(c.runWriter)
}

// enqueueL2 queues a write for the batched writer, falling back to a direct
// synchronous SET when the writer hasn't started, is shutting down, or the
// queue is full — batching is an optimization and must never lose an entry.
func (c *Cache) enqueueL2(ctx context.Context, key string, val []byte, ttl time.Duration) {
	if c.client == nil {
		return
	}
	if c.writes == nil || c.wclosed.Load() {
		c.client.Set(ctx, key, val, ttl)
		return
	}
	select {
	case c.writes <- l2Write{key: key, val: val, ttl: ttl}:
	default:
		c.client.Set(ctx, key, val, ttl)
	}
}

// runWriter drains the write queue, committing batches of writeBatchSize or
// everything queued every writeFlushInterval, whichever comes first — one
// pipelined Dragonfly round trip per flush instead of one per write.
// Close() signals via wdone so the writer commits whatever is still queued
// before exiting. The writes channel is deliberately never closed: enqueueL2
// may race Close, and a send on a closed channel would panic.
func (c *Cache) runWriter() {
	batch := make([]l2Write, 0, writeBatchSize)
	ticker := time.NewTicker(writeFlushInterval)
	defer ticker.Stop()
	flush := func() {
		if len(batch) == 0 {
			return
		}
		c.writeBatchL2(batch)
		batch = batch[:0]
	}
	for {
		select {
		case w := <-c.writes:
			batch = append(batch, w)
			if len(batch) >= writeBatchSize {
				flush()
			}
		case <-ticker.C:
			flush()
		case <-c.wdone:
			// Shutdown: commit everything still queued, then exit.
			for {
				select {
				case w := <-c.writes:
					batch = append(batch, w)
					if len(batch) >= writeBatchSize {
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

// writeBatchL2 commits queued writes to Dragonfly in a single pipelined
// round trip. A failed flush drops the batch — the entries just re-warm on
// the next miss — and logs at most once a minute so a down cache tier can't
// spam the journal.
func (c *Cache) writeBatchL2(batch []l2Write) {
	if c.client == nil || len(batch) == 0 {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), writeFlushTimeout)
	defer cancel()
	pipe := c.client.Pipeline()
	for i := range batch {
		pipe.Set(ctx, batch[i].key, batch[i].val, batch[i].ttl)
	}
	if _, err := pipe.Exec(ctx); err != nil {
		now := time.Now().UnixNano()
		last := c.lastWriteErr.Load()
		if last == 0 || now-last > int64(time.Minute) {
			c.lastWriteErr.Store(now)
			slog.Error("cache L2 batch write failed", "entries", len(batch), "error", err)
		}
	}
}

func summarizeServerInfo(info string) string {
	server := strings.ToLower(info)
	switch {
	case strings.Contains(server, "dragonfly"):
		return "DragonflyDB"
	case strings.Contains(server, "redis_version"):
		return "Redis-compatible server"
	default:
		return "unknown Redis-protocol server"
	}
}

// Close stops the batched writer (committing whatever is queued) and then
// terminates the connection pool. Safe to call more than once: the CAS
// guarantees only the first caller shuts the writer down, and enqueueL2
// racing the shutdown sees wclosed and falls back to a direct synchronous
// SET instead of sending on a channel the writer has stopped draining.
func (c *Cache) Close() error {
	if c.writes != nil && c.wclosed.CompareAndSwap(false, true) {
		close(c.wdone)
		c.wwg.Wait()
	}
	if c.client != nil {
		return c.client.Close()
	}
	return nil
}

// Ping returns an error if the cache is not reachable right now.
func (c *Cache) Ping(ctx context.Context) error { return c.client.Ping(ctx).Err() }

// Stats returns basic usage counters for the dashboard.
func (c *Cache) Stats(ctx context.Context) (map[string]string, error) {
	info, err := c.client.Info(ctx, "stats").Result()
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	for line := range strings.SplitSeq(info, "\n") {
		line = strings.TrimSpace(line)
		if i := strings.Index(line, ":"); i > 0 {
			out[strings.TrimSpace(line[:i])] = strings.TrimSpace(line[i+1:])
		}
	}
	return out, nil
}

// L2Stats is a snapshot of Dragonfly's cumulative keyspace counters plus its
// current memory and key count. Hits/misses/expired/evicted are cumulative
// since the Dragonfly process started, not since this Irongrid process.
type L2Stats struct {
	Hits      int64
	Misses    int64
	Expired   int64
	Evicted   int64
	UsedBytes int64
	MaxBytes  int64
	Keys      int64
}

// L2Stats fetches the live Dragonfly INFO counters and DBSIZE.
func (c *Cache) L2Stats(ctx context.Context) (L2Stats, error) {
	var s L2Stats
	if c.client == nil {
		return s, fmt.Errorf("no L2 cache")
	}
	info, err := c.client.Info(ctx).Result()
	if err != nil {
		return s, err
	}
	fields := map[string]*int64{
		"keyspace_hits":   &s.Hits,
		"keyspace_misses": &s.Misses,
		"expired_keys":    &s.Expired,
		"evicted_keys":    &s.Evicted,
		"used_memory":     &s.UsedBytes,
		"maxmemory":       &s.MaxBytes,
	}
	for line := range strings.SplitSeq(info, "\n") {
		line = strings.TrimSpace(line)
		if i := strings.Index(line, ":"); i > 0 {
			if dst, ok := fields[strings.TrimSpace(line[:i])]; ok {
				if v, err := strconv.ParseInt(strings.TrimSpace(line[i+1:]), 10, 64); err == nil {
					*dst = v
				}
			}
		}
	}
	if n, err := c.client.DBSize(ctx).Result(); err == nil {
		s.Keys = n
	}
	return s, nil
}

// L1Counters returns the in-process cache layer's hit/miss counts since
// process start (both zero when the L1 layer is disabled).
func (c *Cache) L1Counters() (hits, misses int64) {
	return c.l1Hits.Load(), c.l1Misses.Load()
}

// SetLookupTimeout hot-swaps the L2 read budget (config live-apply); <= 0
// restores the built-in default.
func (c *Cache) SetLookupTimeout(d time.Duration) {
	c.lookupTimeout.Store(int64(d))
}

// budget returns the effective L2 read budget for the lookup path.
func (c *Cache) budget() time.Duration {
	if d := time.Duration(c.lookupTimeout.Load()); d > 0 {
		return d
	}
	return defaultLookupTimeout
}

// ---- key handling ----

// keyHash is a fast, deterministic 64-bit fingerprint of a question. It must
// stay deterministic across processes and restarts since Dragonfly is a
// shared L2 cache for the whole fleet — unlike hash/maphash's per-process
// random seed, FNV-1a gives every instance the same key for the same query.
// SHA-256 bought nothing here (this is a private cache namespace, not
// adversarial input) and cost real CPU on every single query; hashing the
// name byte-by-byte also skips the strings.ToLower + concatenation
// allocations the old key built on every call.
func keyHash(q dns.Question) uint64 {
	const (
		offset64 = 14695981039346656037
		prime64  = 1099511628211
	)
	h := uint64(offset64)
	for i := 0; i < len(q.Name); i++ {
		b := q.Name[i]
		if b >= 'A' && b <= 'Z' {
			b += 'a' - 'A'
		}
		h = (h ^ uint64(b)) * prime64
	}
	h = (h ^ uint64(q.Qtype)) * prime64
	h = (h ^ uint64(q.Qclass)) * prime64
	return h
}

func (c *Cache) msgKey(h uint64) string {
	return c.prefix + "ans:" + strconv.FormatUint(h, 16)
}

func (c *Cache) negKey(h uint64) string {
	return c.prefix + "neg:" + strconv.FormatUint(h, 16)
}

// ttlOffsets walks a packed DNS message and returns the byte offset (relative
// to msg) of the TTL field of every Answer-section RR. The raw serve path
// uses these offsets to rebase TTLs in place on a private copy of the bytes,
// which is what lets a cache hit skip Unpack entirely. Returns nil when the
// message is malformed or has no answers (negative entries never call this —
// their TTLs are not rebased). Runs only off the hot path (cache writes and
// L2-miss re-warms).
func ttlOffsets(msg []byte) []uint32 {
	if len(msg) < 12 {
		return nil
	}
	qd := int(binary.BigEndian.Uint16(msg[4:6]))
	an := int(binary.BigEndian.Uint16(msg[6:8]))
	if an == 0 {
		return nil
	}
	off := 12
	// Skip the question section: QNAME (never compressed in a message we
	// packed, but handle a pointer defensively) + qtype + qclass.
	for range qd {
		n, ok := skipPackedName(msg, off)
		if !ok || n+4 > len(msg) {
			return nil
		}
		off = n + 4
	}
	out := make([]uint32, 0, an)
	for range an {
		n, ok := skipPackedName(msg, off)
		// type(2) + class(2) + ttl(4) + rdlength(2) = 10 bytes after the name.
		if !ok || n+10 > len(msg) {
			return nil
		}
		// TTL field starts after the name and the 2-byte type + 2-byte class.
		out = append(out, uint32(n+4))
		rdlen := int(binary.BigEndian.Uint16(msg[n+8 : n+10]))
		off = n + 10 + rdlen
		if off > len(msg) {
			return nil
		}
	}
	return out
}

// skipPackedName returns the offset just past the name starting at off: a
// run of length-prefixed labels terminated by a zero byte, or a 2-byte
// compression pointer (0xC0-prefixed). ok is false when the walk runs off
// the end of the message.
func skipPackedName(msg []byte, off int) (int, bool) {
	for {
		if off >= len(msg) {
			return 0, false
		}
		b := msg[off]
		switch {
		case b&0xC0 == 0xC0: // compression pointer: 2 bytes total
			if off+2 > len(msg) {
				return 0, false
			}
			return off + 2, true
		case b == 0: // terminal zero label
			return off + 1, true
		default: // label: length byte + label bytes
			off += 1 + int(b)
			if off > len(msg) {
				return 0, false
			}
		}
	}
}

// ---- positive answers ----

// cacheEntryPrefix marks the stored value format: an 8-byte big-endian store
// timestamp followed by the packed DNS message. The timestamp lets reads
// rebase record TTLs to their remaining lifetime.
const cacheEntryPrefixLen = 8

// Get returns a cached response for q, or nil when absent/expired. The L1
// memory cache is consulted first; L2 (Dragonfly) only on an L1 miss, and a
// hit is then re-warmed into L1.
func (c *Cache) Get(ctx context.Context, q dns.Question) *dns.Msg {
	return c.getPositive(ctx, keyHash(q))
}

func (c *Cache) getPositive(ctx context.Context, h uint64) *dns.Msg {
	if c.l1 == nil {
		if raw, ok := c.l2Get(ctx, c.msgKey(h)); ok {
			return unpackEntry(raw, time.Now())
		}
		return nil
	}
	now := time.Now()
	if raw, _, stale, _, ok := c.l1.get(h, false, now); ok && !stale {
		c.l1Hits.Add(1)
		return unpackEntry(raw, now)
	}
	c.l1Misses.Add(1)
	raw, ok := c.l2Get(ctx, c.msgKey(h))
	if !ok {
		return nil
	}
	c.l1.set(h, false, raw, c.ttl, now, ttlOffsets(raw[cacheEntryPrefixLen:]))
	return unpackEntry(raw, now)
}

// LookupResult is the outcome of a cache lookup. Raw is nil on a miss.
//
// Raw holds the stored packed DNS response (without the 8-byte store
// timestamp prefix), so a hit can be served straight off the wire without
// decoding it into a *dns.Msg — the handler patches the query ID (bytes
// 0-1) and, for positive entries, rebases answer TTLs at TTLOffsets in a
// private copy. Negative reports whether Raw is a cached NXDOMAIN/NODATA/
// empty answer; Stale means the entry has expired but is still within its
// serve-stale window: the caller should attempt re-resolution first and only
// answer from it when that fails (RFC 8767 stale-while-error). StoredAt is
// the store timestamp (Unix seconds) for positive entries, the reference for
// TTL rebasing.
//
// Msg() decodes Raw into a *dns.Msg with TTLs rebased to their remaining
// lifetime. Call it at most once per result (each call allocates a fresh
// message); the fast path never needs it.
type LookupResult struct {
	Raw        []byte
	Negative   bool
	Stale      bool
	StoredAt   int64
	TTLOffsets []uint32
}

// Msg decodes Raw into a *dns.Msg, rebasing positive-entry TTLs to their
// remaining lifetime exactly like the pre-raw Lookup did. Returns nil for a
// miss or a corrupt entry. The message is freshly allocated and safe to
// recycle by the caller (nothing in the cache retains it).
func (res LookupResult) Msg() *dns.Msg {
	if len(res.Raw) == 0 {
		return nil
	}
	if res.Negative {
		return unpackNegative(res.Raw)
	}
	buf := make([]byte, cacheEntryPrefixLen+len(res.Raw))
	binary.BigEndian.PutUint64(buf[:cacheEntryPrefixLen], uint64(res.StoredAt))
	copy(buf[cacheEntryPrefixLen:], res.Raw)
	return unpackEntry(buf, time.Now())
}

// prefetchLead is how close to expiry a served positive entry must be before
// a background refresh is scheduled — a fraction of the cache TTL, capped so
// hour-long TTLs don't spawn refreshes half an hour early.
func (c *Cache) prefetchLead() time.Duration {
	lead := max(min(c.ttl/5, 2*time.Minute), time.Second)
	return lead
}

// prefetchTimeout bounds each background refresh so a stalled upstream can't
// leak goroutines that outlive their usefulness.
const prefetchTimeout = 15 * time.Second

// EnablePrefetch installs the callback used to refresh hot entries in the
// background before they expire (nil disables prefetching). The handler wires
// this to re-resolve via the current upstreams.
//
// Call it before the cache is handed to serving goroutines: the prefetch
// field is read without a lock on the lookup path.
func (c *Cache) EnablePrefetch(fn func(ctx context.Context, q dns.Question)) {
	c.prefetch = fn
}

// maybePrefetch schedules a background refresh when a served entry is within
// its prefetch lead of expiry. Positive entries use prefetchLead (a fraction
// of the positive TTL); negative entries use negPrefetchLead (a fraction of
// the much shorter negative TTL) so short-lived negatives don't spawn a
// refresh on every single hit. At most one refresh is in flight per question
// hash (prefetching sync.Map), and the goroutine is fully best-effort — a
// failure just leaves the now-stale entry to serve-stale or upstream on the
// next miss.
func (c *Cache) maybePrefetch(q dns.Question, h uint64, remaining time.Duration, neg bool) {
	if c.prefetch == nil || remaining <= 0 {
		return
	}
	lead := c.prefetchLead()
	if neg {
		lead = c.negPrefetchLead()
	}
	if remaining > lead {
		return
	}
	if _, loaded := c.prefetching.LoadOrStore(h, struct{}{}); loaded {
		return
	}
	go func() {
		defer c.prefetching.Delete(h)
		ctx, cancel := context.WithTimeout(context.Background(), prefetchTimeout)
		defer cancel()
		c.prefetch(ctx, q)
	}()
}

// negPrefetchLead is the negative-entry equivalent of prefetchLead, derived
// from the negative TTL instead of the positive one: a lead sized against the
// (typically hours-long) positive TTL would be longer than most negative
// entries' whole lifetime, firing a refresh on every hit.
func (c *Cache) negPrefetchLead() time.Duration {
	lead := max(c.negativeTTL/5, time.Second)
	return lead
}

// Lookup checks both the positive and negative entries for q, hashing the
// question once and reusing it for both. It is the DNS hot path, so L1
// (in-process, no network) is probed without allocating anything — no key
// string, no context, and — on a hit — no dns.Msg decode either: the stored
// packed bytes are returned as-is (LookupResult.Raw) so the handler can
// patch the ID and TTLs and write them straight to the client. Only when
// nothing fresh is found locally does this touch L2, and then it fetches
// both keys in a single Redis MGET (instead of two sequential GETs) bounded
// by the configured lookup budget — a domain this instance has never seen
// before (an L1 miss on both) would otherwise pay for two round trips to
// Dragonfly before the query ever reaches upstream.
//
// A fresh positive hit near the end of its lifetime also schedules a
// background prefetch so the next query finds a warm entry (see
// maybePrefetch).
//
// Expired-but-still-stale L1 entries (RFC 8767) are never treated as fresh:
// they count as an L1 miss and — if L2 holds anything for the question — a
// fresh L2 entry wins over the stale one. Only when neither layer has fresh
// data is the stale entry reported (LookupResult.Stale) so the handler can
// answer from it if re-resolution fails.
func (c *Cache) Lookup(q dns.Question) LookupResult {
	h := keyHash(q)
	now := time.Now()

	var stale LookupResult

	if c.l1 != nil {
		posRaw, posRemaining, posStale, posOff, posOK := c.l1.get(h, false, now)
		if posOK && !posStale {
			c.l1Hits.Add(1)
			c.maybePrefetch(q, h, posRemaining, false)
			return positiveResult(posRaw, posOff)
		}
		negRaw, negRemaining, negStale, _, negOK := c.l1.get(h, true, now)
		if negOK && !negStale {
			c.l1Hits.Add(1)
			// Prefetch NXDOMAIN and NODATA negatives (stable, legitimate
			// answers — the classic repeat case is a stale AAAA probe for an
			// A-only domain, which is NODATA: NOERROR with no answers) but
			// never SERVFAIL ones: those are failure-cache entries written
			// during an upstream outage, and refreshing them would re-probe
			// the failing upstream on every query instead of letting the
			// failure cache absorb the retries. Blocked domains never reach
			// the cache at all, so this can't leak a blocked lookup upstream.
			if rcodeOf(negRaw) != dns.RcodeServerFailure {
				c.maybePrefetch(q, h, negRemaining, true)
			}
			return LookupResult{Raw: negRaw, Negative: true}
		}
		// Nothing fresh: a stale pos or neg entry (already probed above — no
		// need to re-fetch it) is the RFC 8767 fallback for when L2 and the
		// upstream both fail.
		switch {
		case posOK && posStale:
			stale = positiveResult(posRaw, posOff)
			stale.Stale = true
		case negOK && negStale:
			stale = LookupResult{Raw: negRaw, Negative: true, Stale: true}
		}
		c.l1Misses.Add(1)
	}
	if c.client == nil {
		return stale
	}
	// L1 miss: one MGET to Dragonfly for both keys. The budget context is
	// created only here — never on the hit path — so a slow or down cache
	// tier can't stall the query beyond the budget.
	ctx, cancel := context.WithTimeout(context.Background(), c.budget())
	defer cancel()
	vals, err := c.client.MGet(ctx, c.msgKey(h), c.negKey(h)).Result()
	if err != nil {
		return stale
	}
	posRaw, negRaw, ok := decodeMGetResult(vals)
	if !ok {
		return stale
	}
	if posRaw != nil {
		if len(posRaw) <= cacheEntryPrefixLen {
			return stale
		}
		// Compute the TTL offsets here (off the hot path — this is the miss
		// path) so this hit and every later L1 hit can serve the raw bytes.
		off := ttlOffsets(posRaw[cacheEntryPrefixLen:])
		if c.l1 != nil {
			c.l1.set(h, false, posRaw, c.ttl, now, off)
		}
		return positiveResult(posRaw, off)
	}
	if negRaw != nil {
		if c.l1 != nil {
			// A fresh negative supersedes any stale positive in L1 so the
			// stale one can't keep shadowing the neg key on later lookups.
			c.l1.del(h, false)
			c.l1.set(h, true, negRaw, c.negativeTTL, now, nil)
		}
		return LookupResult{Raw: negRaw, Negative: true}
	}
	return stale
}

// positiveResult builds a positive LookupResult from stored bytes that carry
// the 8-byte store-timestamp prefix. off may be nil (an L2-sourced hit on
// the first miss); the entry is still served, the handler just falls back to
// the decoded-message path when it needs TTL rebasing.
func positiveResult(posRaw []byte, off []uint32) LookupResult {
	if len(posRaw) <= cacheEntryPrefixLen {
		return LookupResult{}
	}
	return LookupResult{
		Raw:        posRaw[cacheEntryPrefixLen:],
		StoredAt:   int64(binary.BigEndian.Uint64(posRaw[:cacheEntryPrefixLen])),
		TTLOffsets: off,
	}
}

// rcodeOf returns the header rcode (lower 4 bits of byte 3) of a packed
// message, or SERVFAIL for a malformed/too-short one. All cached negatives
// are NOERROR/NXDOMAIN/SERVFAIL — well under the 16 rcode values the header
// byte can express — so the extended-rcode bits in the OPT TTL never matter
// here.
func rcodeOf(raw []byte) int {
	if len(raw) < 4 {
		return dns.RcodeServerFailure
	}
	return int(raw[3] & 0x0F)
}

// Fresh reports whether q is already answered by a fresh (positive or
// negative) entry in either cache layer. Unlike Lookup it does not count the
// probe in the L1 hit/miss counters and does not schedule a background
// prefetch. It exists for the cache warmer's freshness probe: warming
// traffic must not skew the dashboard's cache hit-rate cards, and a
// near-expiry entry should be refreshed by the warmer (or prefetch) rather
// than have the probe itself trigger a refresh and then get skipped.
func (c *Cache) Fresh(q dns.Question) bool {
	h := keyHash(q)
	now := time.Now()
	if c.l1 != nil {
		if raw, _, stale, _, ok := c.l1.get(h, false, now); ok && !stale && len(raw) > 0 {
			return true
		}
		if raw, _, stale, _, ok := c.l1.get(h, true, now); ok && !stale && len(raw) > 0 {
			return true
		}
	}
	if c.client == nil {
		return false
	}
	// L1 miss: one budgeted MGET for both keys, exactly like Lookup — a
	// present L2 key is fresh by construction (Redis expires it at its TTL).
	ctx, cancel := context.WithTimeout(context.Background(), c.budget())
	defer cancel()
	vals, err := c.client.MGet(ctx, c.msgKey(h), c.negKey(h)).Result()
	if err != nil {
		return false
	}
	for _, v := range vals {
		if v != nil {
			return true
		}
	}
	return false
}

// decodeMGetResult interprets the [positive, negative] result of an MGET
// against the two keys for one question, as go-redis returns it: a present
// key comes back as a string, a missing key as nil. ok is false when
// neither key was present, or the result didn't have the expected shape.
func decodeMGetResult(vals []any) (posRaw, negRaw []byte, ok bool) {
	if len(vals) != 2 {
		return nil, nil, false
	}
	if s, isStr := vals[0].(string); isStr {
		return []byte(s), nil, true
	}
	if s, isStr := vals[1].(string); isStr {
		return nil, []byte(s), true
	}
	return nil, nil, false
}

// l2Get fetches raw bytes from Dragonfly/Redis. A nil client (unit tests)
// is a clean miss.
func (c *Cache) l2Get(ctx context.Context, key string) ([]byte, bool) {
	if c.client == nil {
		return nil, false
	}
	raw, err := c.client.Get(ctx, key).Bytes()
	return raw, err == nil
}

// unpackEntry decodes a stored positive entry (8-byte store timestamp +
// packed DNS message) and rebases answer TTLs to the remaining lifetime
// (floor at 1 so clients don't cache a zero-TTL answer as immortal). now is
// the same clock read the caller already took for the cache probe, so a hit
// doesn't pay for a second time.Now().
func unpackEntry(raw []byte, now time.Time) *dns.Msg {
	if len(raw) <= cacheEntryPrefixLen {
		return nil
	}
	stored := int64(binary.BigEndian.Uint64(raw[:cacheEntryPrefixLen]))
	m := new(dns.Msg)
	if err := m.Unpack(raw[cacheEntryPrefixLen:]); err != nil {
		return nil
	}
	elapsed := now.Unix() - stored
	for _, rr := range m.Answer {
		if elapsed > 0 && rr.Header().Ttl > uint32(elapsed) {
			rr.Header().Ttl -= uint32(elapsed)
		} else {
			rr.Header().Ttl = 1
		}
	}
	return m
}

// Set stores a positive response for q. capTTL of zero means the configured
// default cap (cache.ttl) applies; the stored TTL is the minimum of the
// record TTLs and that cap. The entry goes to L1 immediately and L2 for the
// fleet.
func (c *Cache) Set(ctx context.Context, q dns.Question, m *dns.Msg, capTTL time.Duration) {
	if m == nil || len(m.Answer) == 0 {
		return
	}
	var min = ^uint32(0)
	for _, rr := range m.Answer {
		if rr.Header().Ttl < min {
			min = rr.Header().Ttl
		}
	}
	ttl := time.Duration(min) * time.Second
	if capTTL <= 0 {
		capTTL = c.ttl
	}
	if capTTL > 0 && ttl > capTTL {
		ttl = capTTL
	}
	if ttl <= 0 {
		return
	}
	// Compress before packing so the stored bytes match what the handler
	// would send on the wire. m.SetReply(m) used to sit here too, but
	// calling it with the message as its own argument is a no-op for every
	// field except Rcode, which it unconditionally forces to NOERROR — a
	// CNAME chain that legitimately terminates in NXDOMAIN (RFC 2308) has a
	// non-empty Answer and a non-success Rcode, and that call silently
	// cached it as a successful answer for every future hit.
	m.Compress = true
	packed, err := m.Pack()
	if err != nil {
		return
	}
	buf := make([]byte, cacheEntryPrefixLen+len(packed))
	now := time.Now()
	binary.BigEndian.PutUint64(buf[:cacheEntryPrefixLen], uint64(now.Unix()))
	copy(buf[cacheEntryPrefixLen:], packed)
	h := keyHash(q)
	if c.l1 != nil {
		// Record the Answer-TTL offsets once here (off the hot path) so
		// every L1 hit can rebase TTLs on the raw bytes without unpacking.
		c.l1.set(h, false, buf, ttl, now, ttlOffsets(packed))
	}
	c.enqueueL2(ctx, c.msgKey(h), buf, ttl)
}

// ---- negative answers ----

// SetNegative caches an empty (NXDOMAIN/NOERROR/SERVFAIL) result briefly so
// repeated blocked or failing queries are cheap. A zero ttl uses the
// configured negative TTL.
func (c *Cache) SetNegative(ctx context.Context, q dns.Question, m *dns.Msg, ttl time.Duration) {
	if m == nil || len(m.Answer) != 0 {
		return
	}
	if ttl <= 0 {
		ttl = c.negativeTTL
	}
	if ttl <= 0 {
		return
	}
	raw, err := m.Pack()
	if err != nil {
		return
	}
	h := keyHash(q)
	now := time.Now()
	if c.l1 != nil {
		c.l1.set(h, true, raw, ttl, now, nil)
	}
	c.enqueueL2(ctx, c.negKey(h), raw, ttl)
}

// GetNegative returns a cached empty response, if any (L1 first, then L2).
func (c *Cache) GetNegative(ctx context.Context, q dns.Question) *dns.Msg {
	return c.getNegative(ctx, keyHash(q))
}

func (c *Cache) getNegative(ctx context.Context, h uint64) *dns.Msg {
	if c.l1 == nil {
		if raw, ok := c.l2Get(ctx, c.negKey(h)); ok {
			return unpackNegative(raw)
		}
		return nil
	}
	now := time.Now()
	if raw, _, stale, _, ok := c.l1.get(h, true, now); ok && !stale {
		c.l1Hits.Add(1)
		return unpackNegative(raw)
	}
	c.l1Misses.Add(1)
	raw, ok := c.l2Get(ctx, c.negKey(h))
	if !ok {
		return nil
	}
	c.l1.set(h, true, raw, c.negativeTTL, now, nil)
	return unpackNegative(raw)
}

// unpackNegative decodes a stored negative entry (no TTL rebasing needed;
// the Redis expiry already bounds it).
func unpackNegative(raw []byte) *dns.Msg {
	m := new(dns.Msg)
	if err := m.Unpack(raw); err != nil {
		return nil
	}
	return m
}

// FlushAll clears every cached entry in L1 and L2 (used by the UI "clear
// cache" action).
func (c *Cache) FlushAll(ctx context.Context) (int64, error) {
	if c.l1 != nil {
		c.l1.flush()
	}
	if c.client == nil {
		return 0, nil
	}
	var n int64
	iter := c.client.Scan(ctx, 0, c.prefix+"*", 1000).Iterator()
	for iter.Next(ctx) {
		n += c.client.Del(ctx, iter.Val()).Val()
	}
	return n, iter.Err()
}
