//go:build aix || darwin || dragonfly || freebsd || linux || netbsd || openbsd || zos

package tuning

import (
	"net"
	"testing"
	"time"
)

// TestReuseportListeners verifies that several SO_REUSEPORT sockets can bind
// one UDP address at once (the kernel load-balances incoming datagrams across
// them) and that a datagram sent to the shared address is received by one of
// them — the property the multi-socket DNS listener relies on.
func TestReuseportListeners(t *testing.T) {
	lc := &net.ListenConfig{Control: ReuseportControl}
	first, err := lc.ListenPacket(t.Context(), "udp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("SO_REUSEPORT unavailable here: %v", err)
	}
	defer first.Close()
	addr := first.LocalAddr().String()

	const extra = 3
	rest := make([]net.PacketConn, 0, extra)
	defer func() {
		for _, pc := range rest {
			_ = pc.Close()
		}
	}()
	for i := range extra {
		pc, err := lc.ListenPacket(t.Context(), "udp", addr)
		if err != nil {
			t.Fatalf("reuseport bind %d on %s: %v", i+1, addr, err)
		}
		rest = append(rest, pc)
	}

	// A datagram sent to the shared address is picked up by exactly one of
	// the sockets (the kernel's hash chooses the destination).
	dst, err := net.Dial("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer dst.Close()
	if _, err := dst.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}

	all := append([]net.PacketConn{first}, rest...)
	got := make(chan net.PacketConn, 1)
	done := make(chan struct{})
	defer close(done)
	for _, pc := range all {
		go func(pc net.PacketConn) {
			buf := make([]byte, 64)
			_ = pc.SetReadDeadline(time.Now().Add(3 * time.Second))
			if n, _, err := pc.ReadFrom(buf); err == nil && n > 0 {
				select {
				case got <- pc:
				case <-done:
				}
			}
		}(pc)
	}
	select {
	case <-got:
		// received by exactly one socket — good enough for the property the
		// listener relies on; the other readers simply time out.
	case <-time.After(4 * time.Second):
		t.Fatal("no socket received the datagram")
	}
}
