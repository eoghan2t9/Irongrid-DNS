package dnsserver

import (
	"fmt"
	"testing"
	"time"
)

func TestRateLimiterAllowsUpToBurst(t *testing.T) {
	// qps=1 (1 token/sec) keeps refill-per-statement negligible, so the
	// "immediately denied" assertion below isn't sensitive to ordinary
	// scheduling jitter between two back-to-back calls.
	rl := NewRateLimiter(1, 3)
	for i := range 3 {
		if !rl.Allow("1.2.3.4") {
			t.Fatalf("request %d should be allowed within burst", i)
		}
	}
	if rl.Allow("1.2.3.4") {
		t.Fatal("4th immediate request should exceed the burst of 3")
	}
}

func TestRateLimiterRefillsOverTime(t *testing.T) {
	// NewRateLimiter clamps burst up to at least qps (same invariant
	// config.Validate enforces), so burst=qps=5 here rather than a smaller
	// burst that would silently get clamped up.
	rl := NewRateLimiter(5, 5) // refills at 5/s (200ms/token)
	for i := range 5 {
		if !rl.Allow("5.6.7.8") {
			t.Fatalf("request %d should be allowed within the burst of 5", i)
		}
	}
	if rl.Allow("5.6.7.8") {
		t.Fatal("6th immediate request should be denied (burst exhausted)")
	}
	// Comfortably longer than the 200ms/token refill time so this isn't
	// flaky under a loaded/virtualized scheduler.
	time.Sleep(350 * time.Millisecond)
	if !rl.Allow("5.6.7.8") {
		t.Fatal("request after refill window should be allowed")
	}
}

func TestRateLimiterPerClientIndependent(t *testing.T) {
	rl := NewRateLimiter(10, 1)
	if !rl.Allow("10.0.0.1") {
		t.Fatal("client A's first request should be allowed")
	}
	if !rl.Allow("10.0.0.2") {
		t.Fatal("client B is a different bucket and should not be affected by A's usage")
	}
}

func TestRateLimiterEmptyClientAlwaysAllowed(t *testing.T) {
	rl := NewRateLimiter(1, 1)
	for range 5 {
		if !rl.Allow("") {
			t.Fatal("an empty client key (unidentifiable) must never be throttled")
		}
	}
}

func TestRateLimiterAutoBlockTriggersAndExpires(t *testing.T) {
	rl := NewRateLimiter(1, 1)
	rl.SetAutoBlock(3, 100*time.Millisecond)

	// Hammer past the 3-violation threshold.
	for range 10 {
		rl.Allow("1.2.3.4")
	}
	if blocked, until := rl.Blocked("1.2.3.4"); !blocked {
		t.Fatal("expected 1.2.3.4 to be auto-blocked after repeated violations")
	} else if until.IsZero() || time.Until(until) <= 0 {
		t.Fatalf("blockedUntil %v is not in the future", until)
	}
	if list := rl.BlockedList(); len(list) != 1 || list[0].IP != "1.2.3.4" {
		t.Fatalf("BlockedList = %+v, want exactly [1.2.3.4]", list)
	} else {
		// Lifetime stats: every Allow call counted, exactly one block
		// triggered, and the bucket has existed since the first query.
		if list[0].Queries != 10 {
			t.Errorf("Queries = %d, want 10", list[0].Queries)
		}
		if list[0].Blocks != 1 {
			t.Errorf("Blocks = %d, want 1", list[0].Blocks)
		}
		if list[0].FirstSeen.IsZero() || list[0].FirstSeen.After(time.Now()) {
			t.Errorf("FirstSeen %v is not a sensible past timestamp", list[0].FirstSeen)
		}
	}

	// During the cooldown, Allow always refuses even after time passes.
	time.Sleep(50 * time.Millisecond)
	if rl.Allow("1.2.3.4") {
		t.Fatal("blocked client was allowed mid-cooldown")
	}
	if blocked, _ := rl.Blocked("1.2.3.4"); !blocked {
		t.Fatal("Blocked turned false before the cooldown elapsed")
	}

	// After the cooldown, the client starts fresh and is allowed again.
	time.Sleep(80 * time.Millisecond)
	if !rl.Allow("1.2.3.4") {
		t.Fatal("client still refused after the cooldown expired")
	}
	if blocked, _ := rl.Blocked("1.2.3.4"); blocked {
		t.Fatal("Blocked still true after expiry")
	}
}

func TestRateLimiterAutoBlockIsPerClient(t *testing.T) {
	rl := NewRateLimiter(1, 1)
	rl.SetAutoBlock(3, time.Minute)
	for range 10 {
		rl.Allow("9.9.9.9")
	}
	if blocked, _ := rl.Blocked("9.9.9.9"); !blocked {
		t.Fatal("9.9.9.9 should be blocked")
	}
	if !rl.Allow("1.1.1.1") {
		t.Fatal("an unrelated client must not be affected by another's block")
	}
}

func TestRateLimiterUnblock(t *testing.T) {
	rl := NewRateLimiter(1, 1)
	rl.SetAutoBlock(3, time.Hour)
	for range 10 {
		rl.Allow("5.5.5.5")
	}
	if blocked, _ := rl.Blocked("5.5.5.5"); !blocked {
		t.Fatal("5.5.5.5 should be blocked")
	}
	rl.Unblock("5.5.5.5")
	if blocked, _ := rl.Blocked("5.5.5.5"); blocked {
		t.Fatal("5.5.5.5 still blocked after Unblock")
	}
	if !rl.Allow("5.5.5.5") {
		t.Fatal("an unblocked client is still refused")
	}
	// The lifetime stats survive unblocking — they are the block history.
	rl.Allow("5.5.5.5") // one more query
	if blocked, _ := rl.Blocked("5.5.5.5"); blocked {
		t.Fatal("client re-blocked by leftover state after Unblock")
	}
	s := rl.shard("5.5.5.5")
	s.mu.Lock()
	b := s.buckets["5.5.5.5"]
	s.mu.Unlock()
	if b == nil {
		t.Fatal("bucket missing after Unblock")
	}
	if b.queries != 12 {
		t.Errorf("Queries = %d after unblock, want 12 (10 before + 2 after)", b.queries)
	}
	if b.blocks != 1 {
		t.Errorf("Blocks = %d, want 1 — the block history must survive Unblock", b.blocks)
	}
	if b.firstSeen.IsZero() {
		t.Error("FirstSeen must survive Unblock")
	}
}

func TestRateLimiterSparseViolationsDoNotBlock(t *testing.T) {
	// Violations that only occur far apart (one per window) are throttled
	// but must never accumulate into a block — an IP that spikes once in a
	// while is not a hammerer.
	rl := NewRateLimiter(1, 1)
	rl.SetAutoBlock(3, 20*time.Millisecond)
	for range 3 {
		rl.Allow("7.7.7.7") // consume the burst
		rl.Allow("7.7.7.7") // violation
		time.Sleep(25 * time.Millisecond)
	}
	if blocked, _ := rl.Blocked("7.7.7.7"); blocked {
		t.Fatal("sparse violations must not trigger the auto-block")
	}
}

// sameShard returns two distinct client keys that hash to the same shard, so
// tests can drive one shard past rlMaxPerShard deterministically.
func sameShard(t *testing.T, rl *RateLimiter) (string, string) {
	t.Helper()
	a := "203.0.113.1"
	for i := range 10000 {
		b := fmt.Sprintf("203.0.113.%d", i+2)
		if rl.shard(b) == rl.shard(a) {
			return a, b
		}
	}
	t.Fatal("could not find two clients hashing to the same shard")
	return "", ""
}

func TestRateLimiterShardCapPrefersIdleEviction(t *testing.T) {
	rl := NewRateLimiter(1000, 1000) // generous limits: nothing is throttled
	a, b := sameShard(t, rl)
	s := rl.shard(a)
	now := time.Now()
	s.mu.Lock()
	s.buckets = make(map[string]*rlBucket, rlMaxPerShard+1)
	for i := range rlMaxPerShard {
		s.buckets[fmt.Sprintf("198.51.100.%d", i)] = &rlBucket{tokens: 1, lastSeen: now}
	}
	// One entry went quiet long ago: it must be the one evicted to make
	// room, not a live client.
	s.buckets["198.51.100.0"].lastSeen = now.Add(-2 * rlIdleEvict)
	s.mu.Unlock()

	if !rl.Allow(b) {
		t.Fatal("a new client was refused although an idle bucket was evictable")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if n := len(s.buckets); n != rlMaxPerShard {
		t.Fatalf("shard holds %d buckets, want exactly %d", n, rlMaxPerShard)
	}
	if _, ok := s.buckets["198.51.100.0"]; ok {
		t.Fatal("the idle bucket should have been evicted, not a live one")
	}
	if _, ok := s.buckets[b]; !ok {
		t.Fatal("the new client's bucket is missing")
	}
}

func TestRateLimiterShardCapHoldsUnderActiveFlood(t *testing.T) {
	// Every bucket is active (fresh lastSeen) — the scenario a spoofed-IP
	// flood creates. The cap must still hold: no idle entries to evict means
	// least-recently-seen entries get dropped instead.
	rl := NewRateLimiter(1000, 1000)
	_, b := sameShard(t, rl)
	s := rl.shard(b)
	now := time.Now()
	s.mu.Lock()
	s.buckets = make(map[string]*rlBucket, rlMaxPerShard+1)
	for i := range rlMaxPerShard {
		s.buckets[fmt.Sprintf("198.51.100.%d", i)] = &rlBucket{tokens: 1, lastSeen: now}
	}
	s.mu.Unlock()

	if !rl.Allow(b) {
		t.Fatal("a new client was refused although eviction should have made room")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if n := len(s.buckets); n != rlMaxPerShard {
		t.Fatalf("shard grew to %d buckets under active flood, cap is %d", n, rlMaxPerShard)
	}
	if _, ok := s.buckets[b]; !ok {
		t.Fatal("the new client's bucket is missing")
	}
}
