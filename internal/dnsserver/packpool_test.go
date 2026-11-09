package dnsserver

import "testing"

// TestPackBufPoolRoundTrip verifies a buffer survives get/put and comes back
// at full capacity, ready for reuse.
func TestPackBufPoolRoundTrip(t *testing.T) {
	buf := getPackBuf()
	if len(buf) != cap(buf) {
		t.Fatalf("len(buf) = %d, want == cap(buf) = %d", len(buf), cap(buf))
	}
	if cap(buf) < udpMaxPacketSize {
		t.Fatalf("cap(buf) = %d, want >= udpMaxPacketSize = %d", cap(buf), udpMaxPacketSize)
	}
	putPackBuf(buf)

	buf2 := getPackBuf()
	if len(buf2) != cap(buf2) {
		t.Fatalf("len(buf2) = %d, want == cap(buf2) = %d", len(buf2), cap(buf2))
	}
}

// TestPackBufPoolGrows verifies putting back a larger buffer than the pool's
// starting size (as happens when PackBuffer had to grow for an oversized
// message) is preserved for the next Get — the pool self-tunes up, it
// doesn't clamp back down to udpMaxPacketSize.
func TestPackBufPoolGrows(t *testing.T) {
	big := make([]byte, udpMaxPacketSize*4)
	// sync.Pool gives no retention guarantee: a GC can clear the pool at any
	// time, and under -race the runtime GCs often. So instead of seeding
	// once and hoping, re-seed on every iteration — each cycle puts a big
	// buffer and pulls one item out, so a cleared pool is immediately
	// restocked and every subsequent Get has a large buffer to find. Any
	// small buffer drawn is put back, so the pool can only drift toward big.
	for range 100 {
		putPackBuf(big)
		got := getPackBuf()
		if cap(got) >= udpMaxPacketSize*4 {
			putPackBuf(got)
			return
		}
		putPackBuf(got)
	}
	t.Fatal("pool never returned the larger buffer — put did not preserve capacity")
}

// TestPackBufPoolNoAllocs pins the steady-state cost of a get/put cycle at
// zero heap allocations. putPackBuf used to Put(&buf), which moves the slice
// header to the heap on every call — one allocation per DoH/DoQ/raw-cache
// response.
func TestPackBufPoolNoAllocs(t *testing.T) {
	// Warm the pools so the measurement is steady state.
	for range 8 {
		putPackBuf(getPackBuf())
	}
	if n := testing.AllocsPerRun(1000, func() {
		putPackBuf(getPackBuf())
	}); n != 0 {
		t.Fatalf("get/put cycle allocated %v times, want 0", n)
	}
}
