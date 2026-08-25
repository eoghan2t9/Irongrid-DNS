package installer

import (
	"bytes"
	"net"
	"strings"
	"testing"
	"time"
)

// fakeRedis starts a TCP listener that answers every PING with +PONG, and
// returns its address. It is what redisPing/EnsureDragonfly probe.
func fakeRedis(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(5 * time.Second))
				buf := make([]byte, 64)
				if _, err := c.Read(buf); err != nil {
					return
				}
				_, _ = c.Write([]byte("+PONG\r\n"))
			}(conn)
		}
	}()
	return ln.Addr().String()
}

func TestRedisPing(t *testing.T) {
	t.Parallel()
	addr := fakeRedis(t)
	if !redisPing(addr) {
		t.Fatalf("redisPing(%s) = false, want true", addr)
	}
	// Closed port must not answer.
	if redisPing("127.0.0.1:1") {
		t.Fatal("redisPing on closed port = true, want false")
	}
	// Unparseable address must not panic and must be false.
	if redisPing("not-an-address") {
		t.Fatal("redisPing on bad address = true, want false")
	}
}

func TestSplitHostPort(t *testing.T) {
	t.Parallel()
	cases := []struct{ in, host, port string }{
		{"localhost:6379", "localhost", "6379"},
		{"127.0.0.1:6380", "127.0.0.1", "6380"},
		{"dragonfly:6379", "dragonfly", "6379"},
		{"localhost", "localhost", "6379"},
		{"", "", "6379"},
	}
	for _, c := range cases {
		h, p := splitHostPort(c.in)
		if h != c.host || p != c.port {
			t.Errorf("splitHostPort(%q) = (%q, %q), want (%q, %q)", c.in, h, p, c.host, c.port)
		}
	}
}

func TestEnsureDragonflyAlreadyRunning(t *testing.T) {
	t.Parallel()
	addr := fakeRedis(t)
	var out bytes.Buffer
	if err := EnsureDragonfly(addr, &out); err != nil {
		t.Fatalf("EnsureDragonfly with running cache: %v", err)
	}
	if !strings.Contains(out.String(), "already running") {
		t.Errorf("expected 'already running' notice, got: %q", out.String())
	}
}

func TestEnsureDragonflyNonLocalAddr(t *testing.T) {
	t.Parallel()
	// A non-local address must be left alone (no download, no docker).
	var out bytes.Buffer
	err := EnsureDragonfly("dragonfly:6379", &out)
	if err != nil {
		t.Fatalf("non-local addr should not error, got: %v", err)
	}
	if !strings.Contains(out.String(), "not local") {
		t.Errorf("expected 'not local' notice, got: %q", out.String())
	}
}

func TestExtractDragonflyBinaryMissing(t *testing.T) {
	t.Parallel()
	// A tarball without the expected binary must error, not panic.
	gz := []byte{0x1f, 0x8b} // truncated gzip header
	if _, err := extractDragonflyBinary(bytes.NewReader(gz), "x86_64"); err == nil {
		t.Fatal("expected error for invalid tarball")
	}
}
