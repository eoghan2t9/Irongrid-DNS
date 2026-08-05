package cache

import (
	"sync"
	"time"
)

// L1 is a small in-process, TTL-based response cache layered in front of the
// Dragonfly/Redis L2. Cache hits become a single sharded map lookup instead
// of a network round-trip to Redis — the same design CoreDNS uses (fast
// in-memory cache, optional shared L2). It is purely an accelerator: entries
// are never authoritative and losing it is harmless (it just re-warms from
// L2).
const (
	l1Shards      = 256
	l1CapPerShard = 512 // bounds memory: 256*512 = 131k entries max
)

// l1Entry stores the packed response (with the 8-byte store-timestamp prefix
// for positive entries) plus its expiry so reads can rebase TTLs.
type l1Entry struct {
	raw     []byte
	expires time.Time
}

type l1Shard struct {
	mu sync.RWMutex
	m  map[string]l1Entry
}

type l1Cache struct {
	shards [l1Shards]*l1Shard
}

func newL1() *l1Cache {
	c := &l1Cache{}
	for i := range c.shards {
		c.shards[i] = &l1Shard{m: make(map[string]l1Entry, 16)}
	}
	return c
}

// shard picks the shard for a key with FNV-1a (cheap, decent spread).
func (c *l1Cache) shard(key string) *l1Shard {
	var h uint32 = 2166136261
	for i := 0; i < len(key); i++ {
		h ^= uint32(key[i])
		h *= 16777619
	}
	return c.shards[h&(l1Shards-1)]
}

// get returns the stored raw bytes for key, or ok=false on miss/expiry.
// Expired entries are evicted lazily on read.
func (c *l1Cache) get(key string, now time.Time) ([]byte, bool) {
	s := c.shard(key)
	s.mu.RLock()
	e, ok := s.m[key]
	s.mu.RUnlock()
	if !ok {
		return nil, false
	}
	if !now.Before(e.expires) {
		c.del(key)
		return nil, false
	}
	return e.raw, true
}

// set stores raw under key with a TTL. When a shard is at capacity the
// oldest-arbitrary entry (map iteration order) is evicted so memory stays
// bounded under high query cardinality.
func (c *l1Cache) set(key string, raw []byte, ttl time.Duration, now time.Time) {
	if ttl <= 0 || len(raw) == 0 {
		return
	}
	s := c.shard(key)
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.m) >= l1CapPerShard {
		for k := range s.m {
			delete(s.m, k)
			break
		}
	}
	s.m[key] = l1Entry{raw: raw, expires: now.Add(ttl)}
}

func (c *l1Cache) del(key string) {
	s := c.shard(key)
	s.mu.Lock()
	delete(s.m, key)
	s.mu.Unlock()
}

// flush drops every entry (used by the UI "clear cache" action).
func (c *l1Cache) flush() {
	for _, s := range c.shards {
		s.mu.Lock()
		s.m = make(map[string]l1Entry, 16)
		s.mu.Unlock()
	}
}
