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
	putPackBuf(big)

	// This Get isn't guaranteed to return the exact buffer just put back
	// (sync.Pool makes no such promise), but across a few tries at least one
	// should, since nothing else is contending for the pool in this test.
	found := false
	for i := 0; i < 50; i++ {
		got := getPackBuf()
		if cap(got) >= udpMaxPacketSize*4 {
			found = true
			putPackBuf(got)
			break
		}
		putPackBuf(got)
	}
	if !found {
		t.Fatal("pool never returned the larger buffer — put did not preserve capacity")
	}
}
