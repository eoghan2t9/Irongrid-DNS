package api

import (
	"sync"
	"time"

	"github.com/eoghan2t9/Irongrid-DNS/internal/shardutil"
)

// apiRateShards controls lock contention: each client IP hashes to one
// shard, mirroring dnsserver.RateLimiter and LoginGuard.
const apiRateShards = 64

// apiRateMaxPerShard bounds memory the same way the DNS rate limiter and
// login guard do — the map must never grow without bound under a flood of
// distinct source IPs.
const apiRateMaxPerShard = 4096

// apiRateIdleEvict is how long a client can go quiet before its bucket is
// reclaimed.
const apiRateIdleEvict = 10 * time.Minute

// apiRateQPS and apiRateBurst are deliberately generous: LoginGuard already
// throttles failed *login* attempts, so this limiter only needs to catch a
// runaway loop (a buggy frontend build, a stuck retry, a compromised
// session) after authentication — not shape normal dashboard traffic. The
// busiest legitimate pattern is a handful of concurrent polls every 5-10s
// across open tabs/views, nowhere near this budget.
const (
	apiRateQPS   = 25
	apiRateBurst = 60
)

type apiRateBucket struct {
	tokens   float64
	lastSeen time.Time
}

type apiRateShard struct {
	mu      sync.Mutex
	buckets map[string]*apiRateBucket
}

// APIRateLimiter is a per-client-IP token bucket guarding authenticated
// REST API traffic (everything under /api/, after authorize succeeds).
// Unlike dnsserver.RateLimiter it never auto-blocks: a 429 with Retry-After
// is enough insurance here, and permanently locking out an admin session
// over a burst would be worse than the problem it prevents.
type APIRateLimiter struct {
	shards [apiRateShards]*apiRateShard
}

// NewAPIRateLimiter returns a limiter with no clients tracked yet.
func NewAPIRateLimiter() *APIRateLimiter {
	l := &APIRateLimiter{}
	for i := range l.shards {
		l.shards[i] = &apiRateShard{buckets: make(map[string]*apiRateBucket, 64)}
	}
	return l
}

func (l *APIRateLimiter) shard(key string) *apiRateShard {
	return l.shards[shardutil.FNV1a(key)&(apiRateShards-1)]
}

// Allow reports whether client may make one more API request right now,
// consuming a token if so. An empty client is always allowed — there is
// nothing to key a bucket on.
func (l *APIRateLimiter) Allow(client string) bool {
	if client == "" {
		return true
	}
	s := l.shard(client)
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	b, ok := s.buckets[client]
	if !ok {
		if len(s.buckets) >= apiRateMaxPerShard {
			evictIdleLocked(s, now)
		}
		s.buckets[client] = &apiRateBucket{tokens: apiRateBurst - 1, lastSeen: now}
		return true
	}
	elapsed := now.Sub(b.lastSeen).Seconds()
	b.lastSeen = now
	b.tokens += elapsed * apiRateQPS
	if b.tokens > apiRateBurst {
		b.tokens = apiRateBurst
	}
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// evictIdleLocked drops buckets idle past apiRateIdleEvict to keep the shard
// under apiRateMaxPerShard. Caller holds s.mu.
func evictIdleLocked(s *apiRateShard, now time.Time) {
	for k, e := range s.buckets {
		if now.Sub(e.lastSeen) > apiRateIdleEvict {
			delete(s.buckets, k)
		}
	}
}
