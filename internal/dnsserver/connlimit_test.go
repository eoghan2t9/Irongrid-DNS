package dnsserver

import (
	"net"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestConnLimiterCapsPerIP(t *testing.T) {
	cl := newConnLimiter(2)
	if !cl.acquire("1.2.3.4") || !cl.acquire("1.2.3.4") {
		t.Fatal("first two acquisitions within the cap must succeed")
	}
	if cl.acquire("1.2.3.4") {
		t.Fatal("third acquisition past the cap must fail")
	}
	// Other IPs are unaffected.
	if !cl.acquire("5.6.7.8") {
		t.Fatal("a different IP must not be limited by another IP's cap")
	}
	cl.release("1.2.3.4")
	if !cl.acquire("1.2.3.4") {
		t.Fatal("release must free a slot for the same IP")
	}
}

func TestConnLimiterDisabled(t *testing.T) {
	cl := newConnLimiter(0) // unlimited
	for i := 0; i < 1000; i++ {
		if !cl.acquire("1.2.3.4") {
			t.Fatalf("unlimited limiter rejected acquisition %d", i)
		}
	}
}

func TestConnLimiterReleaseIdempotent(t *testing.T) {
	cl := newConnLimiter(1)
	// Releasing without an acquire (or twice) must not corrupt the count: the
	// slot should still be free for a fresh acquire.
	cl.release("1.2.3.4")
	cl.release("1.2.3.4")
	if !cl.acquire("1.2.3.4") {
		t.Fatal("limiter must recover from stray releases")
	}
}

// startLimitedTCPServer runs a real miekg/dns TCP server over a limitListener
// capped at max connections per client IP, answering every query with an A
// record. Returns the listen address.
func startLimitedTCPServer(t *testing.T, max int) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	srv := &dns.Server{
		Net:          "tcp",
		Listener:     &limitListener{Listener: ln, lim: newConnLimiter(max)},
		ReadTimeout:  2 * time.Second,
		WriteTimeout: 2 * time.Second,
		Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
			m := new(dns.Msg)
			m.SetReply(r)
			m.Answer = append(m.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
				A:   net.ParseIP("1.2.3.4"),
			})
			_ = w.WriteMsg(m)
		}),
	}
	go func() { _ = srv.ActivateAndServe() }()
	t.Cleanup(func() { _ = srv.Shutdown() })
	return ln.Addr().String()
}

// queryTCP performs one DNS query over TCP and reports whether it got an
// answer (true) or the connection was refused/rejected (false).
func queryTCP(t *testing.T, addr string) bool {
	t.Helper()
	c := &dns.Client{Net: "tcp", Timeout: 3 * time.Second}
	m := new(dns.Msg)
	m.SetQuestion("example.com.", dns.TypeA)
	_, _, err := c.Exchange(m, addr)
	return err == nil
}

func TestLimitListenerRejectsOverCap(t *testing.T) {
	addr := startLimitedTCPServer(t, 1)

	// Open a raw TCP connection and hold it without sending a query — a
	// slowloris-style flood connection — so the single per-IP slot stays
	// occupied (the whole point of the cap: connection count, not queries).
	holder, err := net.DialTimeout("tcp", addr, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	// A second concurrent connection from the same IP (127.0.0.1) exceeds the
	// cap and is refused at accept — the query never gets a reply.
	if queryTCP(t, addr) {
		t.Fatal("connection past the cap must be rejected")
	}
	// Release the holder: the slot frees and a new connection is accepted.
	_ = holder.Close()
	// Wait for the release to propagate through the accept loop.
	deadline := time.Now().Add(2 * time.Second)
	for {
		if queryTCP(t, addr) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("after the holder closes, the slot must be free")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestLimitListenerNoCapPassesThrough(t *testing.T) {
	addr := startLimitedTCPServer(t, 0) // unlimited
	for i := 0; i < 3; i++ {
		if !queryTCP(t, addr) {
			t.Fatalf("unlimited listener must answer connection %d", i)
		}
	}
}

func TestLimitListenerConcurrentCapsPerIP(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	cl := newConnLimiter(1)
	limited := &limitListener{Listener: ln, lim: cl}

	// Hold one live connection open, then verify a second concurrent
	// connection is rejected while the first still holds the slot.
	var first net.Conn
	accepted := make(chan net.Conn, 2)
	var acceptWG sync.WaitGroup
	acceptWG.Add(1)
	go func() {
		defer acceptWG.Done()
		for {
			c, err := limited.Accept()
			if err != nil {
				return
			}
			accepted <- c
		}
	}()
	defer func() {
		if first != nil {
			_ = first.Close()
		}
	}()

	c1, err := net.DialTimeout("tcp", ln.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c1.Close()
	first = <-accepted // accept loop hands it over
	if _, ok := first.(*trackedConn); !ok {
		t.Fatalf("first conn is %T, want *trackedConn", first)
	}

	// Second connection from the same source: rejected while the first is
	// open. net.DialTimeout succeeds at the TCP level (the handshake happens
	// in the kernel); the rejection is visible on the accepted side.
	c2, err := net.DialTimeout("tcp", ln.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c2.Close()
	select {
	case c := <-accepted:
		if _, ok := c.(rejectedConn); !ok {
			t.Fatalf("over-cap conn is %T, want rejectedConn", c)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("accept loop never returned the over-cap connection")
	}
}
