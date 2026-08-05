package dnsserver

import (
	"testing"
	"time"
)

func TestRateLimiterAllowsUpToBurst(t *testing.T) {
	// qps=1 (1 token/sec) keeps refill-per-statement negligible, so the
	// "immediately denied" assertion below isn't sensitive to ordinary
	// scheduling jitter between two back-to-back calls.
	rl := NewRateLimiter(1, 3)
	for i := 0; i < 3; i++ {
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
	for i := 0; i < 5; i++ {
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
	for i := 0; i < 5; i++ {
		if !rl.Allow("") {
			t.Fatal("an empty client key (unidentifiable) must never be throttled")
		}
	}
}
