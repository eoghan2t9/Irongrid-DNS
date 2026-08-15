package dnsserver

import (
	"sort"
	"sync"
	"time"
)

// rlShards controls lock contention: each client IP hashes to one shard, so
// concurrent queries from different clients rarely block each other.
const rlShards = 64

// rlMaxPerShard bounds memory: a public listener hit by many distinct (or
// spoofed) source IPs must not let this map grow without bound — that would
// turn the defense itself into a memory-exhaustion vector.
const rlMaxPerShard = 4096

// rlIdleEvict is how long an IP can go quiet before its bucket is reclaimed.
const rlIdleEvict = 10 * time.Minute

type rlBucket struct {
	tokens   float64
	lastSeen time.Time

	// Auto-block bookkeeping: violations are rate-limit rejections; once
	// they reach the configured threshold (within blockFor of the first),
	// the client is blocked until blockedUntil. blockedUntil zero means the
	// bucket is not currently blocked.
	violations   int
	firstViol    time.Time
	blockedUntil time.Time

	// Lifetime stats shown on the dashboard's blocked-clients list: queries
	// is every Allow call seen from this client, blocks is how many times
	// the auto-block has tripped, firstSeen when the bucket was created.
	// They survive unblocking (that's the "history") and are only cleared
	// when the bucket is evicted.
	queries   int64
	blocks    int
	firstSeen time.Time
}

type rlShard struct {
	mu      sync.Mutex
	buckets map[string]*rlBucket
}

// RateLimiter is a per-client-IP token bucket. It exists to blunt abuse (a
// compromised LAN device, or a public listener being used for DNS
// amplification) rather than to be a precise traffic shaper. When auto-block
// is enabled it also fails closed on repeat offenders: a client that keeps
// tripping the limit is refused entirely for a cooldown window.
type RateLimiter struct {
	shards [rlShards]*rlShard
	qps    float64
	burst  float64

	autoBlock  bool
	blockAfter int
	blockFor   time.Duration
}

// NewRateLimiter builds a limiter allowing qps sustained queries/sec and up
// to burst queries in a short spike, per client IP.
func NewRateLimiter(qps, burst int) *RateLimiter {
	if qps < 1 {
		qps = 1
	}
	if burst < qps {
		burst = qps
	}
	rl := &RateLimiter{qps: float64(qps), burst: float64(burst)}
	for i := range rl.shards {
		rl.shards[i] = &rlShard{buckets: make(map[string]*rlBucket, 64)}
	}
	return rl
}

// SetAutoBlock enables the fail2ban-style layer: a client whose rejections
// reach after (counting only violations within blockFor of the first) is
// refused for blockFor. Set once at construction; config reloads swap the
// whole limiter rather than mutating a live one.
func (rl *RateLimiter) SetAutoBlock(after int, blockFor time.Duration) {
	if after < 1 {
		after = 1
	}
	if blockFor <= 0 {
		blockFor = time.Minute
	}
	rl.autoBlock = true
	rl.blockAfter = after
	rl.blockFor = blockFor
}

// shard picks a shard for key with FNV-1a (cheap, decent spread) — same
// scheme cache.l1Cache uses for the same reason.
func (rl *RateLimiter) shard(key string) *rlShard {
	var h uint32 = 2166136261
	for i := 0; i < len(key); i++ {
		h ^= uint32(key[i])
		h *= 16777619
	}
	return rl.shards[h&(rlShards-1)]
}

// Allow reports whether client may proceed, consuming one token if so. An
// empty client (transport gave us no address) is always allowed — there is
// nothing to key a bucket on. A client currently under an auto-block is
// refused regardless of how many tokens it has accumulated.
func (rl *RateLimiter) Allow(client string) bool {
	if client == "" {
		return true
	}
	s := rl.shard(client)
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	b, ok := s.buckets[client]
	if !ok {
		evictLocked(s, now)
		s.buckets[client] = &rlBucket{tokens: rl.burst - 1, lastSeen: now, queries: 1, firstSeen: now}
		return true
	}
	elapsed := now.Sub(b.lastSeen).Seconds()
	b.lastSeen = now
	b.queries++
	if !b.blockedUntil.IsZero() {
		if now.Before(b.blockedUntil) {
			return false
		}
		// Cooldown over: give the client a clean slate (fresh bucket) so a
		// formerly abusive IP isn't stuck with a near-empty token bucket.
		b.blockedUntil = time.Time{}
		b.violations = 0
		b.firstViol = time.Time{}
		b.tokens = rl.burst
	}
	b.tokens += elapsed * rl.qps
	if b.tokens > rl.burst {
		b.tokens = rl.burst
	}
	if b.tokens < 1 {
		rl.recordViolationLocked(b, now)
		return false
	}
	b.tokens--
	return true
}

// evictLocked keeps a shard's bucket map under rlMaxPerShard: idle buckets
// go first, and if everyone is still active (a spoofed-IP flood keeps every
// lastSeen fresh), least-recently-seen buckets are dropped until the shard
// is back under the cap. The map size must never be attacker-controlled —
// that would turn the defense itself into a memory-exhaustion vector. (The
// trade-off: a blocked bucket can be evicted under extreme pressure and its
// cooldown forgotten — acceptable for a blunt abuse defense, and the client
// is re-blocked on the next burst of violations.) Caller holds s.mu.
func evictLocked(s *rlShard, now time.Time) {
	if len(s.buckets) < rlMaxPerShard {
		return
	}
	for k, e := range s.buckets {
		if now.Sub(e.lastSeen) > rlIdleEvict {
			delete(s.buckets, k)
		}
	}
	for len(s.buckets) >= rlMaxPerShard {
		var oldest string
		var oldestSeen time.Time
		for k, e := range s.buckets {
			if oldest == "" || e.lastSeen.Before(oldestSeen) {
				oldest, oldestSeen = k, e.lastSeen
			}
		}
		delete(s.buckets, oldest)
	}
}

// ForceBlock puts client under an auto-block for d without waiting for
// violations to accumulate — the DNS handler uses it when a honeypot hit
// over plain UDP (a spoofable source that must never earn a permanent
// firewall drop) needs the source dropped at the DNS layer for a bounded
// window. The block is temporary by construction: it expires after d like a
// violation-triggered block, is visible in BlockedList, and can be lifted
// early with Unblock.
func (rl *RateLimiter) ForceBlock(client string, d time.Duration) {
	if client == "" || d <= 0 {
		return
	}
	s := rl.shard(client)
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	b, ok := s.buckets[client]
	if !ok {
		evictLocked(s, now)
		b = &rlBucket{lastSeen: now, firstSeen: now}
		s.buckets[client] = b
	}
	b.blockedUntil = now.Add(d)
	b.violations = 0
	b.firstViol = time.Time{}
	b.blocks++
	b.lastSeen = now
}

// recordViolationLocked counts a rate-limit rejection toward the auto-block
// threshold. The caller holds the shard lock. Violations only count while
// they accumulate within blockFor of the first, mirroring the login guard's
// sliding window — an IP that occasionally spikes (say, once an hour) is
// throttled but never blocked.
func (rl *RateLimiter) recordViolationLocked(b *rlBucket, now time.Time) {
	if !rl.autoBlock {
		return
	}
	if b.firstViol.IsZero() || now.Sub(b.firstViol) > rl.blockFor {
		b.firstViol = now
		b.violations = 1
	} else {
		b.violations++
	}
	if b.violations >= rl.blockAfter {
		b.blockedUntil = now.Add(rl.blockFor)
		b.violations = 0
		b.firstViol = time.Time{}
		b.blocks++
	}
}

// Blocked reports whether client is currently under an auto-block and, if
// so, when it expires.
func (rl *RateLimiter) Blocked(client string) (bool, time.Time) {
	if client == "" {
		return false, time.Time{}
	}
	s := rl.shard(client)
	s.mu.Lock()
	defer s.mu.Unlock()
	if b, ok := s.buckets[client]; ok && !b.blockedUntil.IsZero() && time.Now().Before(b.blockedUntil) {
		return true, b.blockedUntil
	}
	return false, time.Time{}
}

// BlockedClient is one entry of the currently-blocked snapshot served to the
// dashboard. Queries/Blocks/FirstSeen are lifetime stats since the client's
// bucket was created, so the list doubles as a block history.
type BlockedClient struct {
	IP           string    `json:"ip"`
	BlockedUntil time.Time `json:"blocked_until"`
	Queries      int64     `json:"queries"`
	Blocks       int       `json:"blocks"`
	FirstSeen    time.Time `json:"first_seen"`
}

// BlockedList returns every client currently under an auto-block, newest
// expiry first.
func (rl *RateLimiter) BlockedList() []BlockedClient {
	now := time.Now()
	var out []BlockedClient
	for _, s := range rl.shards {
		s.mu.Lock()
		for ip, b := range s.buckets {
			if !b.blockedUntil.IsZero() && now.Before(b.blockedUntil) {
				out = append(out, BlockedClient{
					IP: ip, BlockedUntil: b.blockedUntil,
					Queries: b.queries, Blocks: b.blocks, FirstSeen: b.firstSeen,
				})
			}
		}
		s.mu.Unlock()
	}
	sort.Slice(out, func(i, j int) bool { return out[i].BlockedUntil.After(out[j].BlockedUntil) })
	return out
}

// Unblock clears client's auto-block (and abuse history) and resets its token
// bucket, so the dashboard's "unblock" button actually admits the client
// right away instead of leaving it over-limit and immediately throttled.
func (rl *RateLimiter) Unblock(client string) {
	if client == "" {
		return
	}
	s := rl.shard(client)
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	if b, ok := s.buckets[client]; ok {
		b.blockedUntil = time.Time{}
		b.violations = 0
		b.firstViol = time.Time{}
		b.tokens = rl.burst
		b.lastSeen = now
	}
}
