// Package cache provides the DNS response cache backed by Dragonfly
// (Redis protocol). Dragonfly is a hard dependency: the server refuses to
// start when it cannot be reached.
package cache

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"log"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/redis/go-redis/v9"
)

// Cache is a thin, type-safe wrapper around a Dragonfly connection.
type Cache struct {
	client      *redis.Client
	prefix      string
	ttl         time.Duration
	negativeTTL time.Duration
}

// New connects to Dragonfly. It returns an error if the instance is
// unreachable, enforcing the hard dependency.
func New(addr, password string, db int, ttl, negativeTTL time.Duration) (*Cache, error) {
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

	return &Cache{
		client:      client,
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

func (c *Cache) msgKey(q dns.Question) string {
	h := sha256.Sum256([]byte(strings.ToLower(q.Name) + "|" + strconv.Itoa(int(q.Qtype)) + "|" + strconv.Itoa(int(q.Qclass))))
	return c.prefix + "ans:" + hex.EncodeToString(h[:])
}

func (c *Cache) negKey(q dns.Question) string {
	h := sha256.Sum256([]byte(strings.ToLower(q.Name) + "|" + strconv.Itoa(int(q.Qtype)) + "|" + strconv.Itoa(int(q.Qclass))))
	return c.prefix + "neg:" + hex.EncodeToString(h[:])
}

// ---- positive answers ----

// cacheEntryPrefix marks the stored value format: an 8-byte big-endian store
// timestamp followed by the packed DNS message. The timestamp lets Get rebase
// record TTLs to their remaining lifetime.
const cacheEntryPrefixLen = 8

// Get returns a cached response for q, or nil when absent/expired.
func (c *Cache) Get(ctx context.Context, q dns.Question) *dns.Msg {
	raw, err := c.client.Get(ctx, c.msgKey(q)).Bytes()
	if err != nil || len(raw) <= cacheEntryPrefixLen {
		return nil
	}
	stored := int64(binary.BigEndian.Uint64(raw[:cacheEntryPrefixLen]))
	m := new(dns.Msg)
	if err := m.Unpack(raw[cacheEntryPrefixLen:]); err != nil {
		return nil
	}
	// Rebase TTLs to the remaining lifetime (floor at 1 so clients don't
	// cache a zero-TTL answer as immortal).
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
// record TTLs and that cap.
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
	binary.BigEndian.PutUint64(buf[:cacheEntryPrefixLen], uint64(time.Now().Unix()))
	copy(buf[cacheEntryPrefixLen:], packed)
	c.client.Set(ctx, c.msgKey(q), buf, ttl)
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
	c.client.Set(ctx, c.negKey(q), raw, ttl)
}

// GetNegative returns a cached empty response, if any.
func (c *Cache) GetNegative(ctx context.Context, q dns.Question) *dns.Msg {
	raw, err := c.client.Get(ctx, c.negKey(q)).Bytes()
	if err != nil {
		return nil
	}
	m := new(dns.Msg)
	if err := m.Unpack(raw); err != nil {
		return nil
	}
	return m
}

// FlushAll clears every cached entry (used by the UI "clear cache" action).
func (c *Cache) FlushAll(ctx context.Context) (int64, error) {
	var n int64
	iter := c.client.Scan(ctx, 0, c.prefix+"*", 1000).Iterator()
	for iter.Next(ctx) {
		n += c.client.Del(ctx, iter.Val()).Val()
	}
	return n, iter.Err()
}

