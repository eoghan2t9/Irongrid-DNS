// Package cache provides the DNS response cache backed by Dragonfly
// (Redis protocol). Dragonfly is a hard dependency: the server refuses to
// start when it cannot be reached.
package cache

import (
	"context"
	"encoding/binary"
	"fmt"
	"log"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
	"github.com/redis/go-redis/v9"
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
// capacity of the in-process L1 cache; <= 0 disables the L1 layer. serveStale
// is how long an L1 entry remains answerable past its expiry (RFC 8767); 0
// disables serve-stale.
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
	log.Printf("[cache] connected: %s", summarizeServerInfo(info))

	var l1 *l1Cache
	if l1Entries > 0 {
		l1 = newL1(l1Entries, serveStale)
	}
	return &Cache{
		client:      client,
		l1:          l1,
		prefix:      "irongrid:dns:",
		ttl:         ttl,
		negativeTTL: negativeTTL,
	}, nil
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

// Close terminates the connection pool.
func (c *Cache) Close() error { return c.client.Close() }

// Ping returns an error if the cache is not reachable right now.
func (c *Cache) Ping(ctx context.Context) error { return c.client.Ping(ctx).Err() }

// Stats returns basic usage counters for the dashboard.
func (c *Cache) Stats(ctx context.Context) (map[string]string, error) {
	info, err := c.client.Info(ctx, "stats").Result()
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	for _, line := range strings.Split(info, "\n") {
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
	for _, line := range strings.Split(info, "\n") {
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
	key := c.msgKey(h)
	if c.l1 == nil {
		if raw, ok := c.l2Get(ctx, key); ok {
			return unpackEntry(raw)
		}
		return nil
	}
	now := time.Now()
	if raw, _, stale, ok := c.l1.get(key, now); ok && !stale {
		c.l1Hits.Add(1)
		return unpackEntry(raw)
	}
	c.l1Misses.Add(1)
	raw, ok := c.l2Get(ctx, key)
	if !ok {
		return nil
	}
	c.l1.set(key, raw, c.ttl, now)
	return unpackEntry(raw)
}

// LookupResult is the outcome of a cache lookup. Msg is nil on a miss.
// Negative reports whether the entry is a cached NXDOMAIN/empty answer.
// Stale means the entry has expired but is still within its serve-stale
// window: the caller should attempt re-resolution first and only answer
// from it when that fails (RFC 8767 stale-while-error).
type LookupResult struct {
	Msg      *dns.Msg
	Negative bool
	Stale    bool
}

// prefetchLead is how close to expiry a served positive entry must be before
// a background refresh is scheduled — a fraction of the cache TTL, capped so
// hour-long TTLs don't spawn refreshes half an hour early.
func (c *Cache) prefetchLead() time.Duration {
	lead := c.ttl / 5
	if lead > 2*time.Minute {
		lead = 2 * time.Minute
	}
	if lead < time.Second {
		lead = time.Second
	}
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

// maybePrefetch schedules a background refresh when a served positive entry is
// within prefetchLead of its expiry. At most one refresh is in flight per key
// (prefetching sync.Map), and the goroutine is fully best-effort — a failure
// just leaves the now-stale entry to serve-stale or upstream on the next miss.
func (c *Cache) maybePrefetch(q dns.Question, remaining time.Duration) {
	if c.prefetch == nil || remaining <= 0 || remaining > c.prefetchLead() {
		return
	}
	key := c.msgKey(keyHash(q))
	if _, loaded := c.prefetching.LoadOrStore(key, struct{}{}); loaded {
		return
	}
	go func() {
		defer c.prefetching.Delete(key)
		ctx, cancel := context.WithTimeout(context.Background(), prefetchTimeout)
		defer cancel()
		c.prefetch(ctx, q)
	}()
}

// Lookup checks both the positive and negative entries for q, hashing the
// question once and reusing it for both. L1 (in-process, no network) is
// checked for each first; only when nothing fresh is found locally does
// this touch L2, and then it fetches both keys in a single Redis MGET
// instead of two sequential GETs — a domain this instance has never seen
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
func (c *Cache) Lookup(ctx context.Context, q dns.Question) LookupResult {
	h := keyHash(q)
	posKey := c.msgKey(h)
	negKey := c.negKey(h)
	now := time.Now()

	var staleMsg *dns.Msg
	var staleNeg bool

	if c.l1 != nil {
		if raw, remaining, stale, ok := c.l1.get(posKey, now); ok && !stale {
			c.l1Hits.Add(1)
			c.maybePrefetch(q, remaining)
			return LookupResult{Msg: unpackEntry(raw)}
		} else if raw, _, stale, ok := c.l1.get(negKey, now); ok && !stale {
			c.l1Hits.Add(1)
			return LookupResult{Msg: unpackNegative(raw), Negative: true}
		}
		// Nothing fresh: remember a stale entry (pos or neg) as the
		// RFC 8767 fallback for when L2 and the upstream both fail.
		if raw, _, _, ok := c.l1.get(posKey, now); ok {
			staleMsg = unpackEntry(raw)
		} else if raw, _, _, ok := c.l1.get(negKey, now); ok {
			staleMsg = unpackNegative(raw)
			staleNeg = true
		}
		c.l1Misses.Add(1)
	}
	if c.client == nil {
		if staleMsg != nil {
			return LookupResult{Msg: staleMsg, Negative: staleNeg, Stale: true}
		}
		return LookupResult{}
	}
	vals, err := c.client.MGet(ctx, posKey, negKey).Result()
	if err != nil {
		if staleMsg != nil {
			return LookupResult{Msg: staleMsg, Negative: staleNeg, Stale: true}
		}
		return LookupResult{}
	}
	posRaw, negRaw, ok := decodeMGetResult(vals)
	if !ok {
		if staleMsg != nil {
			return LookupResult{Msg: staleMsg, Negative: staleNeg, Stale: true}
		}
		return LookupResult{}
	}
	if posRaw != nil {
		if c.l1 != nil {
			c.l1.set(posKey, posRaw, c.ttl, now)
		}
		return LookupResult{Msg: unpackEntry(posRaw)}
	}
	if negRaw != nil {
		if c.l1 != nil {
			// A fresh negative supersedes any stale positive in L1 so the
			// stale one can't keep shadowing the neg key on later lookups.
			c.l1.del(posKey)
			c.l1.set(negKey, negRaw, c.negativeTTL, now)
		}
		return LookupResult{Msg: unpackNegative(negRaw), Negative: true}
	}
	if staleMsg != nil {
		return LookupResult{Msg: staleMsg, Negative: staleNeg, Stale: true}
	}
	return LookupResult{}
}

// decodeMGetResult interprets the [positive, negative] result of an MGET
// against the two keys for one question, as go-redis returns it: a present
// key comes back as a string, a missing key as nil. ok is false when
// neither key was present, or the result didn't have the expected shape.
func decodeMGetResult(vals []interface{}) (posRaw, negRaw []byte, ok bool) {
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
// (floor at 1 so clients don't cache a zero-TTL answer as immortal).
func unpackEntry(raw []byte) *dns.Msg {
	if len(raw) <= cacheEntryPrefixLen {
		return nil
	}
	stored := int64(binary.BigEndian.Uint64(raw[:cacheEntryPrefixLen]))
	m := new(dns.Msg)
	if err := m.Unpack(raw[cacheEntryPrefixLen:]); err != nil {
		return nil
	}
	elapsed := time.Now().Unix() - stored
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
	var min uint32 = ^uint32(0)
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
	// Normalize the answer to a canonical form before caching.
	m.SetReply(m)
	m.Compress = true
	packed, err := m.Pack()
	if err != nil {
		return
	}
	buf := make([]byte, cacheEntryPrefixLen+len(packed))
	now := time.Now()
	binary.BigEndian.PutUint64(buf[:cacheEntryPrefixLen], uint64(now.Unix()))
	copy(buf[cacheEntryPrefixLen:], packed)
	key := c.msgKey(keyHash(q))
	if c.l1 != nil {
		c.l1.set(key, buf, ttl, now)
	}
	if c.client != nil {
		c.client.Set(ctx, key, buf, ttl)
	}
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
	key := c.negKey(keyHash(q))
	now := time.Now()
	if c.l1 != nil {
		c.l1.set(key, raw, ttl, now)
	}
	if c.client != nil {
		c.client.Set(ctx, key, raw, ttl)
	}
}

// GetNegative returns a cached empty response, if any (L1 first, then L2).
func (c *Cache) GetNegative(ctx context.Context, q dns.Question) *dns.Msg {
	return c.getNegative(ctx, keyHash(q))
}

func (c *Cache) getNegative(ctx context.Context, h uint64) *dns.Msg {
	key := c.negKey(h)
	if c.l1 == nil {
		if raw, ok := c.l2Get(ctx, key); ok {
			return unpackNegative(raw)
		}
		return nil
	}
	now := time.Now()
	if raw, _, stale, ok := c.l1.get(key, now); ok && !stale {
		c.l1Hits.Add(1)
		return unpackNegative(raw)
	}
	c.l1Misses.Add(1)
	raw, ok := c.l2Get(ctx, key)
	if !ok {
		return nil
	}
	c.l1.set(key, raw, c.negativeTTL, now)
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
