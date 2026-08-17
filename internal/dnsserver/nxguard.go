package dnsserver

import (
	"net"
	"sync"
	"time"

	"github.com/eoghan2t9/Irongrid-DNS/internal/shardutil"
)

// NXDOMAIN flood guard: throttles random-subdomain (a.k.a. "water torture")
// attacks, where a client fires unique random labels under a victim domain —
// every one is a cache miss that costs an upstream round trip and fills the
// negative cache, and per-IP rate limiting barely helps because the traffic
// is spread over many sources or churned IPv6 privacy addresses. The guard
// counts NXDOMAIN *responses* per client prefix (IPv4 /24, IPv6 /64) and,
// once a prefix produces Threshold NXDOMAINs within Window, refuses every
// query from that prefix for BlockFor. Counting responses rather than
// queries is what makes it a flood guard: a legit client resolving a few
// missing names occasionally never trips it, while a random-subdomain flood
// racks up NXDOMAINs far faster than any real workload.

// nxShards bounds lock contention, mirroring the rate limiter.
const nxShards = 64

// nxMaxPerShard bounds memory the same way rlMaxPerShard does: a spoofed-
// prefix flood must not be able to grow this map without bound — that would
// turn the defense itself into a memory-exhaustion vector.
const nxMaxPerShard = 4096

// nxIdleEvict is how long a prefix can go quiet before its entry is
// reclaimed.
const nxIdleEvict = 10 * time.Minute

// NXGuard is a sharded per-prefix NXDOMAIN response counter with a
// fail-closed cooldown. Built once from config; config reloads swap the
// whole guard rather than mutating a live one (see BuildNXGuard).
type NXGuard struct {
	shards [nxShards]*nxShard

	// threshold is how many NXDOMAIN responses within window (counting from
	// the first in the burst) trip the block; window is how long a burst is
	// allowed to accumulate; blockFor is the cooldown after tripping.
	threshold int
	window    time.Duration
	blockFor  time.Duration
}

type nxShard struct {
	mu      sync.Mutex
	entries map[string]*nxEntry
}

type nxEntry struct {
	// count and firstSeen bound the sliding window: only NXDOMAINs within
	// window of firstSeen count toward the threshold, so a slow trickle of
	// missing names never accumulates into a block.
	count     int
	firstSeen time.Time
	// blockedUntil zero means the prefix is not currently blocked.
	blockedUntil time.Time
}

// NewNXGuard builds a guard allowing up to threshold NXDOMAIN responses per
// prefix within window before refusing the prefix for blockFor. Threshold is
// floored at 1 and blockFor at a minute (same defensive clamping the rate
// limiter uses).
func NewNXGuard(threshold int, window, blockFor time.Duration) *NXGuard {
	if threshold < 1 {
		threshold = 1
	}
	if window <= 0 {
		window = 30 * time.Second
	}
	if blockFor <= 0 {
		blockFor = time.Minute
	}
	g := &NXGuard{threshold: threshold, window: window, blockFor: blockFor}
	for i := range g.shards {
		g.shards[i] = &nxShard{entries: make(map[string]*nxEntry, 64)}
	}
	return g
}

func (g *NXGuard) shard(prefix string) *nxShard {
	return g.shards[shardutil.FNV1a(prefix)&(nxShards-1)]
}

// Allow reports whether a query from prefix may proceed. It is a read-only
// check run at the top of the handler, before any real work — a blocked
// prefix is refused (UDP: silent drop; streams: REFUSED) exactly like a
// rate-limited client. An empty prefix (no address available) is always
// allowed.
func (g *NXGuard) Allow(prefix string) bool {
	if prefix == "" {
		return true
	}
	s := g.shard(prefix)
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.entries[prefix]
	if !ok || e.blockedUntil.IsZero() {
		return true
	}
	return now.After(e.blockedUntil)
}

// NoteNX records an NXDOMAIN response served to prefix. Called by the
// handler wherever a genuine NXDOMAIN is produced (upstream answer or
// negative cache hit) — never for blocked responses, which are also NXDOMAIN
// under the default block_response but are legitimate traffic. Once the
// threshold is reached within the window, the prefix is blocked for blockFor
// and the counter resets so a fresh burst after the cooldown is needed to
// re-trip.
func (g *NXGuard) NoteNX(prefix string) {
	if prefix == "" {
		return
	}
	s := g.shard(prefix)
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.entries[prefix]
	if !ok {
		evictNXLocked(s, now)
		e = &nxEntry{count: 1, firstSeen: now}
		s.entries[prefix] = e
	} else {
		// A stale firstSeen starts a fresh window; an expired block is cleared
		// at the same time so a formerly abusive prefix isn't re-blocked by
		// leftover counts.
		if now.Sub(e.firstSeen) > g.window {
			e.count = 0
			e.firstSeen = now
			e.blockedUntil = time.Time{}
		}
		e.count++
	}
	// Threshold check shared by both paths (a fresh entry counts as its first
	// NXDOMAIN, so a threshold of 1 trips immediately). The block resets the
	// counter so a fresh burst after the cooldown is needed to re-trip.
	if e.count >= g.threshold && e.blockedUntil.IsZero() {
		e.blockedUntil = now.Add(g.blockFor)
		e.count = 0
		e.firstSeen = now
	}
}

// evictNXLocked keeps a shard's entry map under nxMaxPerShard, mirroring the
// rate limiter's evictLocked: idle entries go first, then least-recently-
// seen until the shard is back under the cap. The map size must never be
// attacker-controlled. Caller holds s.mu.
func evictNXLocked(s *nxShard, now time.Time) {
	if len(s.entries) < nxMaxPerShard {
		return
	}
	for k, e := range s.entries {
		if now.Sub(e.firstSeen) > nxIdleEvict {
			delete(s.entries, k)
		}
	}
	for len(s.entries) >= nxMaxPerShard {
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

// clientPrefix aggregates a client IP to the prefix the NXDOMAIN guard keys
// on: the full /24 for IPv4, the /64 for IPv6. Aggregating is what makes the
// guard effective against address churn (IPv6 privacy extensions) and
// distributed floods from one netblock, at the cost of a whole prefix being
// throttled together — acceptable for a temporary, auto-expiring cooldown.
func clientPrefix(ip string) string {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return ip
	}
	if v4 := parsed.To4(); v4 != nil {
		return v4.Mask(net.CIDRMask(24, 32)).String()
	}
	return parsed.Mask(net.CIDRMask(64, 128)).String()
}
