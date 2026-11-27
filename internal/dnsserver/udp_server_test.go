package dnsserver

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
	"codeberg.org/miekg/dns/rdata"

	"github.com/eoghan2t9/Irongrid-DNS/internal/cache"
	"github.com/eoghan2t9/Irongrid-DNS/internal/dnsname"
	"github.com/eoghan2t9/Irongrid-DNS/internal/filter"
	"github.com/eoghan2t9/Irongrid-DNS/internal/upstream"
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
	c := dns.NewClient()
	query := func() {
		m := new(dns.Msg)
		dnsutil.SetQuestion(m, "pool.test.", dns.TypeA)
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		resp, _, err := c.Exchange(ctx, m, "udp", addr)
		if err != nil {
			t.Fatalf("exchange: %v", err)
		}
		if len(resp.Answer) != 1 {
			t.Fatalf("answers = %d, want 1 (rcode %d)", len(resp.Answer), resp.Rcode)
		}
		if a, ok := resp.Answer[0].(*dns.A); !ok || a.A.Addr.String() != "192.168.1.10" {
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

func (h *blockingDNSHandler) ServeDNS(_ context.Context, w dns.ResponseWriter, r *dns.Msg) {
	select {
	case h.entered <- struct{}{}:
	default:
	}
	<-h.release
	m := new(dns.Msg)
	dnsname.SetReply(m, r)
	_ = m.Pack()
	_, _ = w.Write(m.Data)
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
	dnsutil.SetQuestion(m, "overload.test.", dns.TypeA)
	if err := m.Pack(); err != nil {
		t.Fatalf("pack: %v", err)
	}
	wire := m.Data
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

// TestUDPServerWriteSingle verifies writeSingle — the per-message fallback
// batchWriter uses when sendmmsg stops short of attempting a queued write
// (see batchWriter's doc comment) — delivers the bytes to the intended
// destination on its own, independent of any batch. This is the retry path
// that keeps one flaky destination from taking down unrelated replies
// queued behind it in the same sendmmsg batch.
func TestUDPServerWriteSingle(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer pc.Close()
	h := NewHandler(filter.NewEngine(), nil, nil, nil, "nxdomain", 600, 5*time.Second)
	srv := newUDPServer(pc, h, h.Stats, 1)

	client, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen client: %v", err)
	}
	defer client.Close()
	clientAddr, ok := client.LocalAddr().(*net.UDPAddr)
	if !ok {
		t.Fatalf("client addr = %T, want *net.UDPAddr", client.LocalAddr())
	}

	want := []byte("writeSingle payload")
	req := &udpWriteReq{b: want, addr: clientAddr, res: make(chan error, 1)}
	if err := srv.writeSingle(req); err != nil {
		t.Fatalf("writeSingle: %v", err)
	}

	if err := client.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}
	buf := make([]byte, 64)
	n, _, err := client.ReadFrom(buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if got := string(buf[:n]); got != string(want) {
		t.Fatalf("received %q, want %q", got, want)
	}
}

// TestUDPServerServeStaleRaceNoPoolCorruption verifies that when serve-stale's
// grace timer fires on a UDP query and ServeDNS returns while the background
// upstream resolution is still running, recycling req (reqPool) and w
// (udpWriterPool) in the UDP worker does not race with or panic the background
// goroutines.
func TestUDPServerServeStaleRaceNoPoolCorruption(t *testing.T) {
	// Slow upstream that takes longer than staleGrace(1s) = 500ms, then fails.
	upPC, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen upstream: %v", err)
	}
	defer upPC.Close()
	upDone := make(chan struct{})
	defer close(upDone)
	go func() {
		buf := make([]byte, 512)
		for {
			_, _, rerr := upPC.ReadFrom(buf)
			if rerr != nil {
				return
			}
			// Never reply: force the background resolution to wait out the
			// 1s upstream timeout after staleGrace (500ms) has already returned.
		}
	}()

	c := cache.NewLocalOnly(10*time.Millisecond, time.Minute, 64, 5*time.Minute)
	q := dnsname.Question{Name: "stale-race.example.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
	seed := new(dns.Msg)
	dnsutil.SetQuestion(seed, q.Name, q.Qtype)
	seed.Response = true
	seed.Answer = append(seed.Answer, &dns.A{
		Hdr: dns.Header{Name: q.Name, Class: dns.ClassINET, TTL: 1},
		A:   rdata.A{Addr: netip.MustParseAddr("1.2.3.4")},
	})
	c.Set(t.Context(), q, seed, 10*time.Millisecond)
	time.Sleep(25 * time.Millisecond) // expire into the serve-stale window

	h := NewHandler(filter.NewEngine(), c, []*upstream.Upstream{
		{Transport: upstream.UDP, Addr: upPC.LocalAddr().String()},
	}, nil, "nxdomain", 600, 1*time.Second)

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := newUDPServer(pc, h, h.Stats, 2)
	done := make(chan error, 1)
	go func() { done <- srv.Serve() }()
	defer func() {
		srv.Close()
		_ = <-done
	}()

	cl := &upstream.Upstream{Transport: upstream.UDP, Addr: pc.LocalAddr().String()}
	req := new(dns.Msg)
	dnsutil.SetQuestion(req, q.Name, q.Qtype)
	resp, err := cl.Query(t.Context(), req)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if len(resp.Answer) == 0 {
		t.Fatalf("expected stale answer, got empty response")
	}

	// Immediately send another query so the worker reuses reqPool/udpWriterPool
	// while the first query's background resolution is still in flight.
	req2 := new(dns.Msg)
	dnsutil.SetQuestion(req2, "other.example.", dns.TypeA)
	ctx2, cancel2 := context.WithTimeout(t.Context(), 200*time.Millisecond)
	_, _ = cl.Query(ctx2, req2)
	cancel2()

	// Wait for the background stale-race resolution (1s timeout) to finish.
	time.Sleep(1100 * time.Millisecond)
}
