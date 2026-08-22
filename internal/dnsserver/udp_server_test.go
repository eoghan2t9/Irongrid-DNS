package dnsserver

import (
	"context"
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

	srv := newUDPServer(pc, h, h.Stats, udpWorkersPerSocket())
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
	for range clients {
		wg.Go(func() {
			for range each {
				query()
			}
		})
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
	h := NewHandler(engine, nil, nil, nil, "nxdomain", 600, 5*time.Second)
	srv := newUDPServer(pc, h, h.Stats, udpWorkersPerSocket())
	go func() { _ = srv.Serve() }()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		t.Fatalf("shutdown: %v", err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		rebound, err := net.ListenPacket("udp", addr)
		if err == nil {
			rebound.Close()
			return // address released: the old listener is fully gone
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("UDP listener did not release its address after Shutdown")
}

type blockingDNSHandler struct {
	entered chan struct{}
	release chan struct{}
}

func (h *blockingDNSHandler) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	select {
	case h.entered <- struct{}{}:
	default:
	}
	<-h.release
	m := new(dns.Msg)
	m.SetReply(r)
	_ = w.WriteMsg(m)
}

// TestUDPServerOverloadIsMeasured verifies a blocked handler cannot stop the
// socket reader. Once the bounded queue fills, later datagrams are rejected
// and counted, then accepted work drains during shutdown.
func TestUDPServerOverloadIsMeasured(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	stats := newStats()
	h := &blockingDNSHandler{
		entered: make(chan struct{}, 1),
		release: make(chan struct{}),
	}
	srv := newUDPServer(pc, h, stats, 1)
	serveDone := make(chan error, 1)
	go func() { serveDone <- srv.Serve() }()

	client, err := net.Dial("udp", pc.LocalAddr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()
	m := new(dns.Msg)
	m.SetQuestion("overload.test.", dns.TypeA)
	wire, err := m.Pack()
	if err != nil {
		t.Fatalf("pack: %v", err)
	}
	const packets = 16
	for range packets {
		if _, err := client.Write(wire); err != nil {
			t.Fatalf("write: %v", err)
		}
	}

	select {
	case <-h.entered:
	case <-time.After(2 * time.Second):
		t.Fatal("worker did not enter handler")
	}
	deadline := time.Now().Add(2 * time.Second)
	for stats.UDPReceived.Load() < packets && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if got := stats.UDPReceived.Load(); got != packets {
		t.Fatalf("UDPReceived = %d, want %d", got, packets)
	}
	if got := stats.UDPQueueDrops.Load(); got == 0 {
		t.Fatal("UDPQueueDrops = 0, want overload drops")
	}

	shutdownDone := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		shutdownDone <- srv.Shutdown(ctx)
	}()
	select {
	case err := <-shutdownDone:
		t.Fatalf("shutdown returned before accepted work drained: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	close(h.release)
	if err := <-shutdownDone; err != nil {
		t.Fatalf("shutdown: %v", err)
	}
	if err := <-serveDone; err != nil {
		t.Fatalf("serve: %v", err)
	}
	wantCompleted := stats.UDPReceived.Load() - stats.UDPQueueDrops.Load()
	if got := stats.UDPCompleted.Load(); got != wantCompleted {
		t.Fatalf("UDPCompleted = %d, want %d", got, wantCompleted)
	}
}
