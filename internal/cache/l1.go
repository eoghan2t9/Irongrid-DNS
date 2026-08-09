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
const l1Shards = 256

// l1Key identifies a cached entry: the 64-bit question fingerprint (keyHash)
// plus whether it is the negative variant. Keying by the hash — rather than
// by the L2 key strings the old code built and re-hashed — keeps the lookup
// path allocation-free: a hit is one shard mask, one map lookup and nothing
// else. Collisions share the same domain as the L2 keys (both derive from
// the same 64-bit hash), so this is no weaker than the previous scheme.
type l1Key struct {
	h   uint64
	neg bool
}

// l1Entry stores the packed response (with the 8-byte store-timestamp prefix
// for positive entries) plus its expiry so reads can rebase TTLs. staleUntil
// extends the entry's life beyond expiry so RFC 8767-style serve-stale can
// answer from it during an upstream outage; the stale window only ever keeps
// data that was previously cached locally — Dragonfly expires its copies at
// the same TTL, so an expired L1 entry is never stale-able again after this
// window passes and the next cold miss just resolves upstream.
type l1Entry struct {
	raw        []byte
	expires    time.Time
	staleUntil time.Time // expires + staleTTL; serves stale before this
}

type l1Shard struct {
	mu sync.RWMutex
	m  map[l1Key]l1Entry
}

type l1Cache struct {
	shards   [l1Shards]*l1Shard
	cap      int           // per-shard entry cap (0 = unlimited)
	staleTTL time.Duration // how long past expiry entries remain stale-servable
}

// newL1 creates the sharded cache with a per-shard entry capacity and the
// serve-stale window applied to every stored entry (0 disables serve-stale).
func newL1(capPerShard int, staleTTL time.Duration) *l1Cache {
	c := &l1Cache{cap: capPerShard, staleTTL: staleTTL}
	for i := range c.shards {
		c.shards[i] = &l1Shard{m: make(map[l1Key]l1Entry, 16)}
	}
	return c
}

// shard picks the shard for a key hash. FNV-1a's low bits are well
// distributed, so masking is enough — and it avoids re-hashing a key string
// (the previous scheme scanned the whole key on every probe).
func (c *l1Cache) shard(h uint64) *l1Shard {
	return c.shards[h&(l1Shards-1)]
}

// get returns the stored raw bytes for the question hash. The three outcomes
// are:
//   - ok=true, stale=false: a fresh hit, remaining is the time left on the
//     cache lifetime (used for prefetch decisions);
//   - ok=true, stale=true: the entry has expired but is still within its
//     serve-stale window (remaining is 0) — the caller may serve it if
//     re-resolution fails;
//   - ok=false: a miss; entries past their stale window are evicted lazily.
func (c *l1Cache) get(h uint64, neg bool, now time.Time) (raw []byte, remaining time.Duration, stale bool, ok bool) {
	key := l1Key{h: h, neg: neg}
	s := c.shard(h)
	s.mu.RLock()
	e, ok := s.m[key]
	s.mu.RUnlock()
	if !ok {
		return nil, 0, false, false
	}
	if now.Before(e.expires) {
		return e.raw, e.expires.Sub(now), false, true
	}
	if now.Before(e.staleUntil) {
		return e.raw, 0, true, true
	}
	c.del(h, neg)
	return nil, 0, false, false
}

// set stores raw under the question hash with a TTL. When a shard is at
// capacity the oldest-arbitrary entry (map iteration order) is evicted so
// memory stays bounded under high query cardinality.
func (c *l1Cache) set(h uint64, neg bool, raw []byte, ttl time.Duration, now time.Time) {
	if ttl <= 0 || len(raw) == 0 {
		return
	}
	key := l1Key{h: h, neg: neg}
	s := c.shard(h)
	s.mu.Lock()
	defer s.mu.Unlock()
	if c.cap > 0 && len(s.m) >= c.cap {
		for k := range s.m {
			delete(s.m, k)
			break
		}
	}
	s.m[key] = l1Entry{raw: raw, expires: now.Add(ttl), staleUntil: now.Add(ttl + c.staleTTL)}
}

func (c *l1Cache) del(h uint64, neg bool) {
	key := l1Key{h: h, neg: neg}
	s := c.shard(h)
	s.mu.Lock()
	delete(s.m, key)
	s.mu.Unlock()
}

// flush drops every entry (used by the UI "clear cache" action).
func (c *l1Cache) flush() {
	for _, s := range c.shards {
		s.mu.Lock()
		s.m = make(map[l1Key]l1Entry, 16)
		s.mu.Unlock()
	}
}
