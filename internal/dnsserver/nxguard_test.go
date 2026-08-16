package dnsserver

import (
	"net"
	"testing"
	"time"
)

func TestNXGuardAllowsUnderThreshold(t *testing.T) {
	g := NewNXGuard(5, time.Minute, time.Minute)
	for i := 0; i < 4; i++ {
		if !g.Allow("192.168.1.0") {
			t.Fatalf("Allow before threshold (%d NXDOMAINs) must succeed", i+1)
		}
		g.NoteNX("192.168.1.0")
	}
	if !g.Allow("192.168.1.0") {
		t.Fatal("Allow with 4 of 5 NXDOMAINs must still succeed")
	}
}

func TestNXGuardBlocksAtThreshold(t *testing.T) {
	g := NewNXGuard(5, time.Minute, time.Minute)
	for i := 0; i < 5; i++ {
		g.NoteNX("192.168.1.0")
	}
	if g.Allow("192.168.1.0") {
		t.Fatal("Allow must fail once the threshold is reached")
	}
	// Other prefixes are unaffected.
	if !g.Allow("10.0.0.0") {
		t.Fatal("a different prefix must not be blocked by another prefix's flood")
	}
}

func TestNXGuardExpiresAfterBlockFor(t *testing.T) {
	g := NewNXGuard(2, time.Minute, 100*time.Millisecond)
	g.NoteNX("192.168.1.0")
	g.NoteNX("192.168.1.0")
	if g.Allow("192.168.1.0") {
		t.Fatal("Allow must fail while the cooldown is active")
	}
	time.Sleep(150 * time.Millisecond)
	if !g.Allow("192.168.1.0") {
		t.Fatal("Allow must succeed after the cooldown elapses")
	}
}

func TestNXGuardSlidingWindowResets(t *testing.T) {
	// NXDOMAINs spread beyond the window must not accumulate toward the
	// threshold: two bursts of 2 within 10ms of each other, 50ms apart, with a
	// 20ms window — each burst individually stays under threshold 3.
	g := NewNXGuard(3, 20*time.Millisecond, time.Minute)
	g.NoteNX("192.168.1.0")
	g.NoteNX("192.168.1.0")
	time.Sleep(50 * time.Millisecond)
	g.NoteNX("192.168.1.0")
	g.NoteNX("192.168.1.0")
	if !g.Allow("192.168.1.0") {
		t.Fatal("sparse NXDOMAIN bursts must not trip the guard")
	}
}

func TestNXGuardEmptyPrefixAllowed(t *testing.T) {
	g := NewNXGuard(1, time.Minute, time.Minute)
	g.NoteNX("") // must not panic or count
	if !g.Allow("") {
		t.Fatal("empty prefix must always be allowed")
	}
	// An empty-prefix note must not have leaked into any real bucket: a fresh
	// real prefix is still allowed.
	if !g.Allow("10.0.0.0") {
		t.Fatal("a fresh real prefix must be allowed")
	}
	// A real prefix with the threshold reached is blocked, independently of
	// the empty-prefix no-ops above.
	g.NoteNX("10.0.0.0")
	if g.Allow("10.0.0.0") {
		t.Fatal("a real prefix at its threshold must be blocked")
	}
}

func TestClientPrefixAggregation(t *testing.T) {
	// IPv4 aggregates to /24.
	if p := clientPrefix("192.168.1.77"); p != "192.168.1.0" {
		t.Fatalf("v4 prefix = %q, want 192.168.1.0", p)
	}
	// IPv6 aggregates to /64.
	if p := clientPrefix("2001:db8:1234:5678:9abc:def0:1234:5678"); p != "2001:db8:1234:5678::" {
		t.Fatalf("v6 prefix = %q, want 2001:db8:1234:5678::", p)
	}
	// A /64-churning IPv6 attacker maps to one guard entry.
	if clientPrefix("2001:db8:1234:5678:aaaa:bbbb:cccc:dddd") != clientPrefix("2001:db8:1234:5678:1111:2222:3333:4444") {
		t.Fatal("two addresses in the same /64 must share a guard entry")
	}
	// Unparseable input is passed through unchanged.
	if p := clientPrefix("garbage"); p != "garbage" {
		t.Fatalf("unparseable prefix = %q, want passthrough", p)
	}
}

func TestNXGuardShardCapHolds(t *testing.T) {
	// A flood of distinct prefixes must not grow the map without bound — the
	// same invariant the rate limiter's shard cap enforces. Fill one shard
	// past the cap and verify evictNXLocked brings it back under.
	s := &nxShard{entries: make(map[string]*nxEntry, nxMaxPerShard+1)}
	now := time.Now()
	for i := 0; i < nxMaxPerShard+1; i++ {
		s.entries[uniqueIP4(i)] = &nxEntry{count: 1, firstSeen: now}
	}
	evictNXLocked(s, now)
	if len(s.entries) >= nxMaxPerShard {
		t.Fatalf("shard still holds %d entries, want < %d", len(s.entries), nxMaxPerShard)
	}
	// Idle entries are reclaimed first: give every entry an old firstSeen and
	// confirm eviction drops them over live ones.
	s = &nxShard{entries: make(map[string]*nxEntry, nxMaxPerShard+1)}
	for i := 0; i < nxMaxPerShard+1; i++ {
		s.entries[uniqueIP4(i)] = &nxEntry{count: 1, firstSeen: now.Add(-time.Hour)}
	}
	evictNXLocked(s, now)
	if len(s.entries) >= nxMaxPerShard {
		t.Fatalf("idle eviction left %d entries, want < %d", len(s.entries), nxMaxPerShard)
	}
}

// uniqueIP4 returns a distinct IPv4 string for i: each value lands in its own
// /24 (10.a.b.c with a,b,c derived from i), so the /24 aggregation in
// clientPrefix produces distinct guard keys.
func uniqueIP4(i int) string {
	return net.IPv4(10, byte(i>>16), byte(i>>8), byte(i)).String()
}
