package dnsserver

import (
	"testing"
	"testing/synctest"
	"time"
)

func TestRepeatGuardAllowsUnderThreshold(t *testing.T) {
	g := NewRepeatGuard(5, time.Minute)
	for i := range 4 {
		if g.NoteQuery("192.168.1.10", "example.com") {
			t.Fatalf("NoteQuery tripped before threshold (%d queries)", i+1)
		}
	}
	if !g.Allow("192.168.1.10") {
		t.Fatal("Allow with 4 of 5 same-domain queries must still succeed")
	}
}

func TestRepeatGuardTripsAtThreshold(t *testing.T) {
	g := NewRepeatGuard(5, time.Minute)
	tripped := false
	for range 5 {
		if g.NoteQuery("192.168.1.10", "example.com") {
			tripped = true
		}
	}
	if !tripped {
		t.Fatal("NoteQuery must report a trip once the threshold is reached")
	}
	// NoteQuery only detects the flood — the client is not blocked until the
	// handler calls ForceBlock.
	if !g.Allow("192.168.1.10") {
		t.Fatal("Allow must still succeed before ForceBlock is called")
	}
	g.ForceBlock("192.168.1.10", time.Minute)
	if g.Allow("192.168.1.10") {
		t.Fatal("Allow must fail once ForceBlock has been applied")
	}
	// A different client is unaffected.
	if !g.Allow("10.0.0.5") {
		t.Fatal("a different client must not be blocked by another client's flood")
	}
}

func TestRepeatGuardDifferentDomainResetsStreak(t *testing.T) {
	g := NewRepeatGuard(3, time.Minute)
	// Alternating between two domains never accumulates a streak, no matter
	// how many total queries are sent — this is what makes it a
	// *same*-domain flood guard rather than a second general rate limiter.
	tripped := false
	for range 10 {
		if g.NoteQuery("192.168.1.10", "a.example.com") {
			tripped = true
		}
		if g.NoteQuery("192.168.1.10", "b.example.com") {
			tripped = true
		}
	}
	if tripped {
		t.Fatal("alternating between two domains must never trip the guard")
	}
}

func TestRepeatGuardBlockExpires(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		g := NewRepeatGuard(2, time.Minute)
		g.ForceBlock("192.168.1.10", 100*time.Millisecond)
		if g.Allow("192.168.1.10") {
			t.Fatal("Allow must fail while the block is active")
		}
		time.Sleep(150 * time.Millisecond)
		if !g.Allow("192.168.1.10") {
			t.Fatal("Allow must succeed after the block expires")
		}
	})
}

func TestRepeatGuardSlidingWindowResets(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		// A streak spread beyond the window must not accumulate: two bursts
		// of 2 for the same domain, 50ms apart, with a 20ms window — each
		// burst individually stays under threshold 3.
		g := NewRepeatGuard(3, 20*time.Millisecond)
		g.NoteQuery("192.168.1.10", "example.com")
		g.NoteQuery("192.168.1.10", "example.com")
		time.Sleep(50 * time.Millisecond)
		tripped := g.NoteQuery("192.168.1.10", "example.com")
		tripped = g.NoteQuery("192.168.1.10", "example.com") || tripped
		if tripped {
			t.Fatal("a same-domain streak spread beyond the window must not trip the guard")
		}
	})
}

func TestRepeatGuardEmptyInputsNoOp(t *testing.T) {
	g := NewRepeatGuard(1, time.Minute)
	if g.NoteQuery("", "example.com") {
		t.Fatal("an empty client must never trip the guard")
	}
	if g.NoteQuery("192.168.1.10", "") {
		t.Fatal("an empty qname must never trip the guard")
	}
	if !g.Allow("") {
		t.Fatal("an empty client must always be allowed")
	}
	g.ForceBlock("", time.Minute)
	if !g.Allow("") {
		t.Fatal("ForceBlock on an empty client must be a no-op")
	}
}

func TestRepeatGuardThresholdFloor(t *testing.T) {
	// Threshold is floored at 2 — a single repeat can never be a "flood".
	g := NewRepeatGuard(0, time.Minute)
	if g.threshold != 2 {
		t.Fatalf("threshold = %d, want floored to 2", g.threshold)
	}
}

func TestRepeatGuardShardCapHolds(t *testing.T) {
	// A flood of distinct clients must not grow the map without bound —
	// the same invariant NXGuard/RateLimiter's shard caps enforce.
	s := &rqShard{entries: make(map[string]*rqEntry, rqMaxPerShard+1)}
	now := time.Now()
	for i := range rqMaxPerShard + 1 {
		s.entries[uniqueIP4(i)] = &rqEntry{count: 1, firstSeen: now}
	}
	evictRQLocked(s, now)
	if len(s.entries) >= rqMaxPerShard {
		t.Fatalf("shard still holds %d entries, want < %d", len(s.entries), rqMaxPerShard)
	}
	// Idle entries are reclaimed first.
	s = &rqShard{entries: make(map[string]*rqEntry, rqMaxPerShard+1)}
	for i := range rqMaxPerShard + 1 {
		s.entries[uniqueIP4(i)] = &rqEntry{count: 1, firstSeen: now.Add(-time.Hour)}
	}
	evictRQLocked(s, now)
	if len(s.entries) >= rqMaxPerShard {
		t.Fatalf("idle eviction left %d entries, want < %d", len(s.entries), rqMaxPerShard)
	}
}
