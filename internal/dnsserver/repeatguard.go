package dnsserver

import (
	"sync"
	"time"

	"github.com/eoghan2t9/Irongrid-DNS/internal/shardutil"
)

// Repeat-query flood guard: a client that resolves the *same* domain over
// and over at a rapid pace looks like it's using this resolver to flood or
// DDoS that domain (or its authoritative infrastructure) rather than
// browsing normally — real browsing sessions move between many different
// names, and Irongrid's own cache already answers genuine repeat lookups
// for a popular name without the client needing to re-query at all. The
// guard tracks one "streak" per client: the domain it last queried, how
// many times in a row, and when the streak started. A different qname (or
// a stale window) always resets the streak to 1, so ordinary multi-domain
// browsing never approaches the threshold; a client hammering one name
// racks it up fast.
//
// Unlike NXGuard (which aggregates to a /24 or /64 prefix because a
// random-subdomain flood is often spread over many sources), this guard
// keys on the exact client IP: it's about one source's behavior, not a
// distributed pattern. And unlike NXGuard/RateLimiter, which auto-block
// internally once tripped, RepeatGuard only ever *detects* the pattern
// (NoteQuery) — the handler decides how long a block should last via
// ForceBlock, because that decision depends on transport trust (a query's
// source is spoofable over plain UDP) which the guard itself has no way to
// know.
const rqShards = 64

// rqMaxPerShard bounds memory the same way rlMaxPerShard/nxMaxPerShard do: a
// spoofed-source flood must not be able to grow this map without bound —
// that would turn the defense itself into a memory-exhaustion vector.
const rqMaxPerShard = 4096

// rqIdleEvict is how long a client can go quiet before its entry is
// reclaimed.
const rqIdleEvict = 10 * time.Minute

// RepeatGuard is a sharded per-client same-domain-streak counter with a
// fail-closed cooldown, mirroring NXGuard's shape.
type RepeatGuard struct {
	shards [rqShards]*rqShard

	// threshold is how many consecutive queries for the same domain within
	// window trip the guard; window is how long a streak may accumulate.
	threshold int
	window    time.Duration
}

type rqShard struct {
	mu      sync.Mutex
	entries map[string]*rqEntry
}

type rqEntry struct {
	// qname, count and firstSeen track the client's current same-domain
	// streak: only queries for qname within window of firstSeen count
	// toward threshold, so alternating between two domains (or a slow
	// trickle of repeats) never accumulates into a trip.
	qname     string
	count     int
	firstSeen time.Time
	// blockedUntil zero means the client is not currently blocked.
	blockedUntil time.Time
}

// NewRepeatGuard builds a guard that reports a trip once a client queries
// the same domain threshold times within window. Threshold is floored at 2
// (a single repeat can never be a "flood") and window falls back to a sane
// default, mirroring NewNXGuard's defensive clamping.
func NewRepeatGuard(threshold int, window time.Duration) *RepeatGuard {
	if threshold < 2 {
		threshold = 2
	}
	if window <= 0 {
		window = 10 * time.Second
	}
	g := &RepeatGuard{threshold: threshold, window: window}
	for i := range g.shards {
		g.shards[i] = &rqShard{entries: make(map[string]*rqEntry, 64)}
	}
	return g
}

func (g *RepeatGuard) shard(client string) *rqShard {
	return g.shards[shardutil.FNV1a(client)&(rqShards-1)]
}

// Allow reports whether a query from client may proceed. It is a read-only
// check run at the top of the handler, before any real work — a blocked
// client is refused exactly like a rate-limited client. An empty client (no
// address available) is always allowed.
func (g *RepeatGuard) Allow(client string) bool {
	if client == "" {
		return true
	}
	s := g.shard(client)
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.entries[client]
	if !ok || e.blockedUntil.IsZero() {
		return true
	}
	return time.Now().After(e.blockedUntil)
}

// NoteQuery records a query for qname from client and reports whether this
// call just crossed the threshold — the handler should then decide (based
// on transport trust) whether and for how long to call ForceBlock. The
// *triggering* query itself is never refused here; only subsequent queries
// are, via Allow, once ForceBlock has been applied.
func (g *RepeatGuard) NoteQuery(client, qname string) bool {
	if client == "" || qname == "" {
		return false
	}
	s := g.shard(client)
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.entries[client]
	if !ok {
		evictRQLocked(s, now)
		s.entries[client] = &rqEntry{qname: qname, count: 1, firstSeen: now}
		return false
	}
	if e.qname != qname || now.Sub(e.firstSeen) > g.window {
		e.qname = qname
		e.count = 1
		e.firstSeen = now
		e.blockedUntil = time.Time{}
		return false
	}
	e.count++
	return e.count >= g.threshold
}

// ForceBlock puts client under a block for d. Called by the handler once
// NoteQuery reports a trip, with d chosen from the transport-trust-gated
// duration (the full configured BlockFor for a verified source, a bounded
// UDPBlockFor otherwise) — this guard never picks its own duration, since it
// has no way to know how much a given source should be trusted.
func (g *RepeatGuard) ForceBlock(client string, d time.Duration) {
	if client == "" || d <= 0 {
		return
	}
	s := g.shard(client)
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.entries[client]
	if !ok {
		evictRQLocked(s, now)
		e = &rqEntry{firstSeen: now}
		s.entries[client] = e
	}
	e.blockedUntil = now.Add(d)
	e.qname = ""
	e.count = 0
	e.firstSeen = now
}

// evictRQLocked keeps a shard's entry map under rqMaxPerShard, mirroring
// evictLocked/evictNXLocked: idle entries go first, then least-recently-
// seen until the shard is back under the cap. Caller holds s.mu.
func evictRQLocked(s *rqShard, now time.Time) {
	if len(s.entries) < rqMaxPerShard {
		return
	}
	for k, e := range s.entries {
		if now.Sub(e.firstSeen) > rqIdleEvict {
			delete(s.entries, k)
		}
	}
	for len(s.entries) >= rqMaxPerShard {
		var oldest string
		var oldestSeen time.Time
		for k, e := range s.entries {
			if oldest == "" || e.firstSeen.Before(oldestSeen) {
				oldest, oldestSeen = k, e.firstSeen
			}
		}
		delete(s.entries, oldest)
	}
}
