package dnsserver

import (
	"net"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/eoghan2t9/Irongrid-DNS/internal/filter"
)

// TestUDPServerWorkerPool verifies the worker-pool UDP listener serves real
// datagrams end to end: queries through the socket get answered from the
// handler, including under a concurrent burst that exceeds the worker count
// (the jobs channel absorbs the overflow).
func TestUDPServerWorkerPool(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	// Answer from a local DNS record so the response is deterministic and
	// exercises the full serve() pipeline (rewrite → write).
	engine := filter.NewEngine()
	h := NewHandler(engine, nil, nil, nil, "nxdomain", 600, 5*time.Second)
	rw := filter.NewRewriter()
	rw.Set([]filter.RewriteSpec{{Domain: "pool.test", Type: "A", Value: "192.168.1.10", TTL: 300}})
	h.SetRewriter(rw)

	srv := newUDPServer(pc, h, udpWorkersPerSocket())
	go func() { _ = srv.Serve() }()
	t.Cleanup(srv.Close)

	addr := pc.LocalAddr().String()
	c := &dns.Client{Net: "udp", Timeout: 2 * time.Second}
	query := func() {
		m := new(dns.Msg)
		m.SetQuestion("pool.test.", dns.TypeA)
		resp, _, err := c.Exchange(m, addr)
		if err != nil {
			t.Fatalf("exchange: %v", err)
		}
		if len(resp.Answer) != 1 {
			t.Fatalf("answers = %d, want 1 (rcode %d)", len(resp.Answer), resp.Rcode)
		}
		if a, ok := resp.Answer[0].(*dns.A); !ok || a.A.String() != "192.168.1.10" {
			t.Fatalf("answer = %v, want A 192.168.1.10", resp.Answer[0])
		}
	}

	// Warm up, then throw a burst of concurrent queries at the pool.
	query()
	const clients = 32
	const each = 5
	var wg sync.WaitGroup
	for i := 0; i < clients; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < each; j++ {
				query()
			}
		}()
	}
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("concurrent burst did not complete in time")
	}
}

// TestUDPServerWorkerPoolShutdown verifies Close terminates the read loop
// and workers: Serve returns and the socket is released, so the address can
// be rebound immediately.
func TestUDPServerWorkerPoolShutdown(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := pc.LocalAddr().String()
	engine := filter.NewEngine()
	srv := newUDPServer(pc, NewHandler(engine, nil, nil, nil, "nxdomain", 600, 5*time.Second), udpWorkersPerSocket())
	go func() { _ = srv.Serve() }()

	srv.Close()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		rebound, err := net.ListenPacket("udp", addr)
		if err == nil {
			rebound.Close()
			return // address released: the old listener is fully gone
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("UDP listener did not release its address after Close")
}
