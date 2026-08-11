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
	// queue tracks insertion order so a full shard evicts the oldest-inserted
	// entry instead of an arbitrary one (map iteration order). Entries that
	// were deleted/expired linger as dead slots until they reach the head;
	// compact() bounds that growth. Never appended when cap == 0.
	queue []l1Key
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

// L1 auto-sizing: when cache.l1_entries is left at 0 ("auto"), AutoPerShard
// picks a per-shard entry cap from the process's memory ceiling so a 512 MiB
// Pi and a 64 GiB server get proportionally sized in-process caches instead
// of one fixed default.
const (
	// l1MemoryFraction is the share of the detected memory ceiling the L1
	// cache may occupy. The Go heap (GOMEMLIMIT) already reserves most of the
	// ceiling; L1 stays a modest slice of that so it accelerates without
	// crowding out the resolver's working set or the query log.
	l1MemoryFraction = 0.025
	// l1AvgEntryBytes is a rough all-in cost estimate per cached entry
	// (packed message + Go map/queue overhead), used to convert the memory
	// budget into an entry count.
	l1AvgEntryBytes = 512
	// l1AutoDefault is the fallback per-shard cap when the memory ceiling
	// can't be detected (non-Linux, or no cgroup and no /proc/meminfo).
	l1AutoDefault = 2048
	// l1AutoFloor/l1AutoCap bound the auto result: a tiny box never gets a
	// uselessly small cache, and a huge one can't balloon the eviction queue
	// overhead.
	l1AutoFloor = 128
	l1AutoCap   = 16384
)

// AutoPerShard returns the per-shard L1 entry cap that keeps the whole
// cache within l1MemoryFraction of memBytes. memKnown=false (memory
// undetectable) returns l1AutoDefault.
func AutoPerShard(memBytes uint64, memKnown bool) int {
	if !memKnown {
		return l1AutoDefault
	}
	perShard := int(uint64(float64(memBytes)*l1MemoryFraction) / l1AvgEntryBytes / l1Shards)
	if perShard < l1AutoFloor {
		return l1AutoFloor
	}
	if perShard > l1AutoCap {
		return l1AutoCap
	}
	return perShard
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

// set stores raw under the question hash with a TTL. Each shard keeps an
// insertion-order queue, so a full shard evicts the oldest-inserted entry
// rather than whichever map entry Go happens to iterate first — the old
// scheme could evict a hot domain while cold entries lingered. Memory stays
// bounded under high query cardinality.
func (c *l1Cache) set(h uint64, neg bool, raw []byte, ttl time.Duration, now time.Time) {
	if ttl <= 0 || len(raw) == 0 {
		return
	}
	key := l1Key{h: h, neg: neg}
	s := c.shard(h)
	s.mu.Lock()
	defer s.mu.Unlock()
	if c.cap > 0 {
		if _, exists := s.m[key]; !exists {
			s.m[key] = l1Entry{raw: raw, expires: now.Add(ttl), staleUntil: now.Add(ttl + c.staleTTL)}
			s.queue = append(s.queue, key)
			s.evictToCap(c.cap)
			// Dead queue slots (deleted/expired keys) accumulate as the map
			// churns; compact once they double the map so the queue's memory
			// stays bounded. Amortized O(1) per set.
			if len(s.queue) > 2*c.cap {
				s.compact()
			}
			return
		}
		// Overwrite keeps the key's original queue position (insertion
		// order). Re-appending on overwrite would be worse, not better: a
		// hot key refreshed every TTL would accumulate duplicate queue
		// entries, pushing itself to the head and making itself MORE
		// evictable — plus every duplicate is a map probe under the shard
		// lock during compaction. First-seen order is the cheap, stable
		// approximation; the L2-hit re-warm path re-sets the same key in
		// place without churning the queue.
	}
	s.m[key] = l1Entry{raw: raw, expires: now.Add(ttl), staleUntil: now.Add(ttl + c.staleTTL)}
}

// evictToCap pops queue entries until the shard map is at or under cap.
// Dead slots (keys already deleted) are popped without shrinking the map —
// delete is a no-op for them — so only popping a live entry frees capacity
// and the loop advances. Called with the shard lock held.
func (s *l1Shard) evictToCap(cap int) {
	for len(s.m) > cap && len(s.queue) > 0 {
		k := s.queue[0]
		s.queue = s.queue[1:]
		delete(s.m, k)
	}
}

// compact rebuilds the queue with only live entries, preserving insertion
// order. Called when the queue grows past 2×cap so stale slots from deleted
// entries can't grow without bound. Called with the shard lock held.
func (s *l1Shard) compact() {
	keep := s.queue[:0]
	for _, k := range s.queue {
		if _, ok := s.m[k]; ok {
			keep = append(keep, k)
		}
	}
	s.queue = keep
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
		s.queue = nil
		s.mu.Unlock()
	}
}
