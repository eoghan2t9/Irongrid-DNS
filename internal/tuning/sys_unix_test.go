//go:build !windows

package tuning

import (
	"net"
	"testing"

	"golang.org/x/sys/unix"
)

// TestRaiseFileLimit verifies the raise is monotonic, never exceeds the hard
// limit, and is clamped to maxFileLimit when the hard limit is unbounded.
func TestRaiseFileLimit(t *testing.T) {
	var before unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_NOFILE, &before); err != nil {
		t.Fatalf("getrlimit: %v", err)
	}
	raiseFileLimit()
	var after unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_NOFILE, &after); err != nil {
		t.Fatalf("getrlimit: %v", err)
	}
	if after.Cur < before.Cur {
		t.Errorf("soft limit lowered: %d -> %d", before.Cur, after.Cur)
	}
	if after.Max != unix.RLIM_INFINITY && after.Cur > after.Max {
		t.Errorf("soft limit %d exceeds hard limit %d", after.Cur, after.Max)
	}
	if after.Max == unix.RLIM_INFINITY && after.Cur > maxFileLimit {
		t.Errorf("soft limit %d exceeds clamp %d", after.Cur, maxFileLimit)
	}
}

// TestSoftLimitCandidates verifies the preferred target comes first and the
// list is deduplicated.
func TestSoftLimitCandidates(t *testing.T) {
	t.Parallel()
	// Unbounded hard limit (the common macOS case): maxFileLimit first, then
	// the fallbacks — all unique (the first entry dedupes against maxFileLimit).
	got := softLimitCandidates(unix.RLIM_INFINITY)
	if len(got) != 3 || got[0] != maxFileLimit {
		t.Fatalf("infinity candidates = %v, want first = %d", got, maxFileLimit)
	}
	seen := map[uint64]bool{}
	for _, c := range got {
		if seen[c] {
			t.Errorf("duplicate candidate %d in %v", c, got)
		}
		seen[c] = true
	}
	// Finite hard limit below the cap: the hard limit is tried first.
	if got := softLimitCandidates(1 << 16); got[0] != 1<<16 {
		t.Errorf("finite candidates = %v, want first = 65536", got)
	}
}

// TestSetSocketBufferSizes verifies the setsockopt path works on a real
// socket. It only asserts no error: the kernel may clamp the granted size
// (Linux caps at net.core.rmem_max without privileges; macOS at its sockbuf
// ceiling), so reading back an exact value would be flaky.
func TestSetSocketBufferSizes(t *testing.T) {
	t.Parallel()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	raw, err := pc.(*net.UDPConn).SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	if err := raw.Control(func(fd uintptr) {
		if serr := setSocketBufferSizes(fd); serr != nil {
			t.Errorf("setSocketBufferSizes: %v", serr)
		}
	}); err != nil {
		t.Fatal(err)
	}
}

// TestStatusSnapshot verifies Status reports the fd limits and runtime
// settings sanely (the dashboard feeds on this).
func TestStatusSnapshot(t *testing.T) {
	t.Parallel()
	st := Status()
	if st.SocketBuffer != SocketBufferSize {
		t.Errorf("SocketBuffer = %d, want %d", st.SocketBuffer, SocketBufferSize)
	}
	if st.GOMAXPROCS < 1 {
		t.Errorf("GOMAXPROCS = %d, want >= 1", st.GOMAXPROCS)
	}
	// On Unix the fd limits must be present and the soft limit may never
	// exceed a finite hard limit.
	if st.FDSoft == nil || st.FDHard == nil {
		t.Fatal("fd limits not reported on unix")
	}
	if *st.FDHard != ^uint64(0) && *st.FDSoft > *st.FDHard {
		t.Errorf("soft %d > hard %d", *st.FDSoft, *st.FDHard)
	}
}

// TestListenConfigServes verifies the Control hook doesn't break ordinary
// listening (the hook runs on every socket the ListenConfig creates).
func TestListenConfigServes(t *testing.T) {
	t.Parallel()
	ln, err := ListenConfig().Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial tuned listener: %v", err)
	}
	_ = conn.Close()
}
