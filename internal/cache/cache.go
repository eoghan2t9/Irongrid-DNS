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
	"time"

	"github.com/miekg/dns"
	"github.com/redis/go-redis/v9"
)

// Cache is a two-layer response cache: a fast in-process L1 in front of the
// Dragonfly/Redis L2. The L2 is authoritative for the fleet (and survives
// restarts); the L1 makes local hits a pure map lookup.
type Cache struct {
	client      *redis.Client
	l1          *l1Cache
	prefix      string
	ttl         time.Duration
	negativeTTL time.Duration
}

// NewLocalOnly returns a Cache backed only by the in-process L1 layer, with
// no Dragonfly connection — for tests in other packages that need a working
// Cache without standing up a real Redis-compatible server.
func NewLocalOnly(ttl, negativeTTL time.Duration, l1Entries int) *Cache {
	return &Cache{l1: newL1(l1Entries), prefix: "irongrid:dns:", ttl: ttl, negativeTTL: negativeTTL}
}

// New connects to Dragonfly. It returns an error if the instance is
// unreachable, enforcing the hard dependency. l1Entries is the per-shard
// capacity of the in-process L1 cache; <= 0 disables the L1 layer.
func New(addr, password string, db int, ttl, negativeTTL time.Duration, l1Entries int) (*Cache, error) {
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
		l1 = newL1(l1Entries)
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
	if raw, ok := c.l1.get(key, now); ok {
		return unpackEntry(raw)
	}
	raw, ok := c.l2Get(ctx, key)
	if !ok {
		return nil
	}
	c.l1.set(key, raw, c.ttl, now)
	return unpackEntry(raw)
}

// Lookup checks both the positive and negative entries for q, hashing the
// question once and reusing it for both. L1 (in-process, no network) is
// checked for each first; only when both miss locally does this touch L2,
// and then it fetches both keys in a single Redis MGET instead of two
// sequential GETs — a domain this instance has never seen before (an L1
// miss on both) would otherwise pay for two round trips to Dragonfly before
// the query ever reaches upstream.
//
// This does mean a query where L2 alone holds a fresher positive answer
// than a stale negative one already warmed into L1 could occasionally
// return the stale negative — the original sequential Get-then-GetNegative
// always fully resolved positive (L1 and L2) before ever considering
// negative. Both entries existing at once is already a rare, transient
// state (a domain flipping between answering and NXDOMAIN across queries),
// and every cache entry is TTL-bounded regardless, so this is an acceptable
// trade for skipping a real network round trip on the much more common
// full-miss case. negative reports which kind of entry matched when msg is
// non-nil.
func (c *Cache) Lookup(ctx context.Context, q dns.Question) (msg *dns.Msg, negative bool) {
	h := keyHash(q)
	posKey := c.msgKey(h)
	negKey := c.negKey(h)
	now := time.Now()

	if c.l1 != nil {
		if raw, ok := c.l1.get(posKey, now); ok {
			return unpackEntry(raw), false
		}
		if raw, ok := c.l1.get(negKey, now); ok {
			return unpackNegative(raw), true
		}
	}
	if c.client == nil {
		return nil, false
	}
	vals, err := c.client.MGet(ctx, posKey, negKey).Result()
	if err != nil {
		return nil, false
	}
	posRaw, negRaw, ok := decodeMGetResult(vals)
	if !ok {
		return nil, false
	}
	if posRaw != nil {
		if c.l1 != nil {
			c.l1.set(posKey, posRaw, c.ttl, now)
		}
		return unpackEntry(posRaw), false
	}
	if c.l1 != nil {
		c.l1.set(negKey, negRaw, c.negativeTTL, now)
	}
	return unpackNegative(negRaw), true
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
	if raw, ok := c.l1.get(key, now); ok {
		return unpackNegative(raw)
	}
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
