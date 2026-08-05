package dnsserver

import (
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
}

type rlShard struct {
	mu      sync.Mutex
	buckets map[string]*rlBucket
}

// RateLimiter is a per-client-IP token bucket. It exists to blunt abuse (a
// compromised LAN device, or a public listener being used for DNS
// amplification) rather than to be a precise traffic shaper.
type RateLimiter struct {
	shards [rlShards]*rlShard
	qps    float64
	burst  float64
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
// nothing to key a bucket on.
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
		if len(s.buckets) >= rlMaxPerShard {
			for k, e := range s.buckets {
				if now.Sub(e.lastSeen) > rlIdleEvict {
					delete(s.buckets, k)
				}
			}
		}
		s.buckets[client] = &rlBucket{tokens: rl.burst - 1, lastSeen: now}
		return true
	}
	elapsed := now.Sub(b.lastSeen).Seconds()
	b.lastSeen = now
	b.tokens += elapsed * rl.qps
	if b.tokens > rl.burst {
		b.tokens = rl.burst
	}
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}
