package dnsserver

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/miekg/dns"

	"github.com/eoghan2t9/Irongrid-DNS/internal/cache"
	"github.com/eoghan2t9/Irongrid-DNS/internal/filter"
	"github.com/eoghan2t9/Irongrid-DNS/internal/geoip"
	"github.com/eoghan2t9/Irongrid-DNS/internal/querylog"
	"github.com/eoghan2t9/Irongrid-DNS/internal/upstream"
)

// startUDPTestServer runs a tiny UDP DNS server on a random loopback port
// that answers every query with an A record of ip (after delay).
func startUDPTestServer(t *testing.T, ip string, delay time.Duration) string {
	t.Helper()
	mux := dns.NewServeMux()
	mux.HandleFunc(".", func(w dns.ResponseWriter, r *dns.Msg) {
		if delay > 0 {
			time.Sleep(delay)
		}
		m := new(dns.Msg)
		m.SetReply(r)
		m.Answer = append(m.Answer, &dns.A{
			Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
			A:   net.ParseIP(ip),
		})
		_ = w.WriteMsg(m)
	})
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := &dns.Server{PacketConn: pc, Handler: mux}
	go func() { _ = srv.ActivateAndServe() }()
	t.Cleanup(func() { _ = srv.Shutdown() })
	return pc.LocalAddr().String()
}

// fakeWriter implements dns.ResponseWriter for direct handler invocation. ip
// overrides the client source address (nil = 127.0.0.1) so tests can exercise
// per-client behaviour like rate-limit auto-blocks and geo-blocking.
type fakeWriter struct {
	msg *dns.Msg
	ip  net.IP
}

func (f *fakeWriter) LocalAddr() net.Addr { return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 53} }
func (f *fakeWriter) RemoteAddr() net.Addr {
	ip := f.ip
	if ip == nil {
		ip = net.IPv4(127, 0, 0, 1)
	}
	return &net.UDPAddr{IP: ip, Port: 12345}
}
func (f *fakeWriter) WriteMsg(m *dns.Msg) error {
	// Copy, not alias: a real WriteMsg implementation packs m into its own
	// []byte synchronously and never touches m again (see msgpool.go) — the
	// handler is therefore free to recycle m immediately after this call
	// returns. Aliasing here would make fw.msg vulnerable to exactly that
	// recycling, which a real consumer never observes.
	f.msg = m.Copy()
	return nil
}

// Write receives the raw packed bytes the handler's pack-once fast path
// sends (a real transport writes them to the wire verbatim), so unpacking
// them into f.msg mirrors what a real client receives. A malformed payload
// leaves f.msg nil rather than failing the write.
func (f *fakeWriter) Write(b []byte) (int, error) {
	m := new(dns.Msg)
	if err := m.Unpack(b); err == nil {
		f.msg = m
	}
	return len(b), nil
}
func (f *fakeWriter) Close() error          { return nil }
func (f *fakeWriter) TsigStatus() error     { return nil }
func (f *fakeWriter) TsigTimersOnly(b bool) {}
func (f *fakeWriter) Hijack()               {}

// TestHandlerUpstreamQuerySingleOPT verifies the query forwarded to an
// upstream carries exactly one EDNS OPT record even when the client sent its
// own — the handler must replace (not append to) the client's OPT. A query
// with two OPTs is malformed (RFC 6891 §6.1.1) and strict resolvers like
// Quad9 reject it with FORMERR, surfacing to the client as a resolution
// failure.
func TestHandlerUpstreamQuerySingleOPT(t *testing.T) {
	var mu sync.Mutex
	optCounts := []int{}
	mux := dns.NewServeMux()
	mux.HandleFunc(".", func(w dns.ResponseWriter, r *dns.Msg) {
		n := 0
		for _, rr := range r.Extra {
			if rr.Header().Rrtype == dns.TypeOPT {
				n++
			}
		}
		mu.Lock()
		optCounts = append(optCounts, n)
		mu.Unlock()
		m := new(dns.Msg)
		m.SetReply(r)
		_ = w.WriteMsg(m)
	})
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &dns.Server{PacketConn: pc, Handler: mux}
	go func() { _ = srv.ActivateAndServe() }()
	t.Cleanup(func() { _ = srv.Shutdown() })

	h := NewHandler(filter.NewEngine(), nil, []*upstream.Upstream{
		{Transport: upstream.UDP, Addr: pc.LocalAddr().String()},
	}, nil, "nxdomain", 600, 5*time.Second)

	m := new(dns.Msg)
	m.SetQuestion("example.com.", dns.TypeA)
	m.SetEdns0(1232, false) // client advertises its own EDNS, like dig/browsers
	fw := &fakeWriter{}
	h.ServeDNS(fw, m)

	mu.Lock()
	defer mu.Unlock()
	if len(optCounts) == 0 {
		t.Fatal("upstream never received the query")
	}
	for i, n := range optCounts {
		if n != 1 {
			t.Fatalf("upstream query %d carried %d OPT records, want exactly 1 (two OPTs is a FORMERR for strict resolvers)", i, n)
		}
	}
}

// startUDPCountingServer runs a UDP DNS server that answers with an A record
// of ip and increments count per query received — lets a test assert an
// upstream was never consulted.
func startUDPCountingServer(t *testing.T, ip string, count *atomic.Int32) string {
	t.Helper()
	mux := dns.NewServeMux()
	mux.HandleFunc(".", func(w dns.ResponseWriter, r *dns.Msg) {
		count.Add(1)
		m := new(dns.Msg)
		m.SetReply(r)
		m.Answer = append(m.Answer, &dns.A{
			Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
			A:   net.ParseIP(ip),
		})
		_ = w.WriteMsg(m)
	})
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := &dns.Server{PacketConn: pc, Handler: mux}
	go func() { _ = srv.ActivateAndServe() }()
	t.Cleanup(func() { _ = srv.Shutdown() })
	return pc.LocalAddr().String()
}

// startSERVFAILServer runs a UDP DNS server that answers every query with
// SERVFAIL — a "working but failing" upstream for failover tests.
func startSERVFAILServer(t *testing.T) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Rcode = dns.RcodeServerFailure
		_ = w.WriteMsg(m)
	})}
	go func() { _ = srv.ActivateAndServe() }()
	t.Cleanup(func() { _ = srv.Shutdown() })
	return pc.LocalAddr().String()
}

// TestHandlerSequentialUpstreamFailover verifies the sequential strategy
// fails over: a primary that answers SERVFAIL is skipped and the backup's
// real answer is returned (under the default race strategy the first SERVFAIL
// response would win instead).
func TestHandlerSequentialUpstreamFailover(t *testing.T) {
	servfailAddr := startSERVFAILServer(t)
	okAddr := startUDPTestServer(t, "1.1.1.1", 0)
	h := NewHandler(filter.NewEngine(), nil, []*upstream.Upstream{
		{Transport: upstream.UDP, Addr: servfailAddr},
		{Transport: upstream.UDP, Addr: okAddr},
	}, nil, "nxdomain", 600, 5*time.Second)
	h.SetUpstreamMode(UpstreamModeSequential)

	m := new(dns.Msg)
	m.SetQuestion("example.com.", dns.TypeA)
	fw := &fakeWriter{}
	h.ServeDNS(fw, m)

	if fw.msg == nil || len(fw.msg.Answer) == 0 {
		t.Fatalf("rcode=%v, no answers — failover did not reach the backup", fw.msg)
	}
	a, ok := fw.msg.Answer[0].(*dns.A)
	if !ok || !a.A.Equal(net.ParseIP("1.1.1.1")) {
		t.Fatalf("answer = %v, want 1.1.1.1 (backup after primary SERVFAIL)", fw.msg.Answer)
	}
}

// TestHandlerSequentialUpstreamStopsAtFirstSuccess verifies the sequential
// strategy prefers the first healthy upstream in list order: when the primary
// answers, the backup must never be consulted (failover does not
// load-balance).
func TestHandlerSequentialUpstreamStopsAtFirstSuccess(t *testing.T) {
	var backupHits atomic.Int32
	primaryAddr := startUDPTestServer(t, "2.2.2.2", 0)
	backupAddr := startUDPCountingServer(t, "1.1.1.1", &backupHits)
	h := NewHandler(filter.NewEngine(), nil, []*upstream.Upstream{
		{Transport: upstream.UDP, Addr: primaryAddr},
		{Transport: upstream.UDP, Addr: backupAddr},
	}, nil, "nxdomain", 600, 5*time.Second)
	h.SetUpstreamMode(UpstreamModeSequential)

	m := new(dns.Msg)
	m.SetQuestion("example.com.", dns.TypeA)
	fw := &fakeWriter{}
	h.ServeDNS(fw, m)

	if fw.msg == nil || len(fw.msg.Answer) == 0 {
		t.Fatalf("no answer: %v", fw.msg)
	}
	a, ok := fw.msg.Answer[0].(*dns.A)
	if !ok || !a.A.Equal(net.ParseIP("2.2.2.2")) {
		t.Fatalf("answer = %v, want 2.2.2.2 (the listed primary)", fw.msg.Answer)
	}
	if hits := backupHits.Load(); hits != 0 {
		t.Fatalf("backup upstream was consulted %d times, want 0 (failover must stop at the first success)", hits)
	}
}

// TestRaceUpstreamsFastestWins verifies the concurrent forward path returns
// the fastest upstream's answer even when it is listed after a slow one
// (sequential forwarding would take the slow path's full delay).
func TestRaceUpstreamsFastestWins(t *testing.T) {
	slowAddr := startUDPTestServer(t, "2.2.2.2", 400*time.Millisecond)
	fastAddr := startUDPTestServer(t, "1.1.1.1", 0)
	h := NewHandler(filter.NewEngine(), nil, []*upstream.Upstream{
		{Transport: upstream.UDP, Addr: slowAddr},
		{Transport: upstream.UDP, Addr: fastAddr},
	}, nil, "nxdomain", 600, 5*time.Second)

	m := new(dns.Msg)
	m.SetQuestion("example.com.", dns.TypeA)
	fw := &fakeWriter{}
	start := time.Now()
	h.ServeDNS(fw, m)
	elapsed := time.Since(start)

	if fw.msg == nil {
		t.Fatal("no response written")
	}
	if len(fw.msg.Answer) == 0 {
		t.Fatalf("rcode=%d, no answers — racing likely failed", fw.msg.Rcode)
	}
	a, ok := fw.msg.Answer[0].(*dns.A)
	if !ok {
		t.Fatalf("answer type %T", fw.msg.Answer[0])
	}
	if !a.A.Equal(net.ParseIP("1.1.1.1")) {
		t.Fatalf("answer = %s, want 1.1.1.1 (fast upstream)", a.A)
	}
	if elapsed > 300*time.Millisecond {
		t.Fatalf("answered in %s — upstreams were not raced (sequential slow-first)", elapsed)
	}
}

// TestHandlerCoalescesConcurrentIdenticalQueries verifies the in-flight
// request pool: N concurrent queries for the same question collapse into a
// single upstream round trip, every waiter still receives a correct answer,
// and each response carries its own message ID (a shared ID would be silently
// dropped by the UDP clients as a spoofed/mismatched reply).
func TestHandlerCoalescesConcurrentIdenticalQueries(t *testing.T) {
	var hits atomic.Int32
	var ednsSize atomic.Int32
	mux := dns.NewServeMux()
	mux.HandleFunc(".", func(w dns.ResponseWriter, r *dns.Msg) {
		hits.Add(1)
		// Record the EDNS UDP payload the outgoing query advertises (must be
		// the Flag Day 2020 1232, not the old 4096).
		for _, rr := range r.Extra {
			if opt, ok := rr.(*dns.OPT); ok {
				ednsSize.Store(int32(opt.UDPSize()))
			}
		}
		// Keep the response in flight long enough for every goroutine below
		// to join the shared resolution instead of starting its own (500ms
		// so a slowly-scheduled goroutine under CI load still joins).
		time.Sleep(500 * time.Millisecond)
		m := new(dns.Msg)
		m.SetReply(r)
		m.Answer = append(m.Answer, &dns.A{
			Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
			A:   net.ParseIP("1.2.3.4"),
		})
		_ = w.WriteMsg(m)
	})
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := &dns.Server{PacketConn: pc, Handler: mux}
	go func() { _ = srv.ActivateAndServe() }()
	t.Cleanup(func() { _ = srv.Shutdown() })

	h := NewHandler(filter.NewEngine(), nil, []*upstream.Upstream{
		{Transport: upstream.UDP, Addr: pc.LocalAddr().String()},
	}, nil, "nxdomain", 600, 5*time.Second)

	const n = 8
	var wg sync.WaitGroup
	fws := make([]*fakeWriter, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			fw := &fakeWriter{}
			fws[i] = fw
			m := new(dns.Msg)
			m.SetQuestion("example.com.", dns.TypeA)
			m.Id = uint16(1000 + i)
			h.ServeDNS(fw, m)
		}(i)
	}
	wg.Wait()

	if got := hits.Load(); got != 1 {
		t.Fatalf("upstream received %d queries, want 1 (burst coalesced into one round trip)", got)
	}
	for i, fw := range fws {
		if fw.msg == nil || len(fw.msg.Answer) == 0 {
			t.Fatalf("waiter %d got no answer (rcode=%v)", i, fw.msg)
		}
		a, ok := fw.msg.Answer[0].(*dns.A)
		if !ok || !a.A.Equal(net.ParseIP("1.2.3.4")) {
			t.Fatalf("waiter %d answer = %v, want 1.2.3.4", i, fw.msg.Answer[0])
		}
		if fw.msg.Id != uint16(1000+i) {
			t.Fatalf("waiter %d response Id = %d, want %d (IDs must not be shared)", i, fw.msg.Id, 1000+i)
		}
	}

	// The pool's counters: exactly one real upstream resolution (the
	// leader's) for the whole burst, and every caller — leader included,
	// per singleflight's Shared semantics — counted as served by a shared
	// flight (saved round trips = merged - flights = 7).
	if got := h.Stats.Flights.Load(); got != 1 {
		t.Fatalf("flights = %d, want 1 (the burst resolved upstream exactly once)", got)
	}
	if got := h.Stats.Merged.Load(); got != n {
		t.Fatalf("merged = %d, want %d (every caller of the shared flight is counted)", got, n)
	}
	// The outgoing upstream query advertises the 1232-byte EDNS payload.
	if got := ednsSize.Load(); got != 1232 {
		t.Fatalf("outgoing upstream query advertises EDNS %d bytes, want 1232", got)
	}
}

// TestHandlerCoalescesMergedFailure verifies the failure side of the request
// pool: when the leader's resolution fails (here an upstream that answers
// SERVFAIL), every waiter of the burst receives the same failure instead of
// each re-querying the upstream.
func TestHandlerCoalescesMergedFailure(t *testing.T) {
	var hits atomic.Int32
	mux := dns.NewServeMux()
	mux.HandleFunc(".", func(w dns.ResponseWriter, r *dns.Msg) {
		hits.Add(1)
		time.Sleep(300 * time.Millisecond) // keep the burst joined
		m := new(dns.Msg)
		m.SetReply(r)
		m.Rcode = dns.RcodeServerFailure
		_ = w.WriteMsg(m)
	})
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := &dns.Server{PacketConn: pc, Handler: mux}
	go func() { _ = srv.ActivateAndServe() }()
	t.Cleanup(func() { _ = srv.Shutdown() })

	h := NewHandler(filter.NewEngine(), nil, []*upstream.Upstream{
		{Transport: upstream.UDP, Addr: pc.LocalAddr().String()},
	}, nil, "nxdomain", 600, 5*time.Second)

	const n = 4
	var wg sync.WaitGroup
	fws := make([]*fakeWriter, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			fw := &fakeWriter{}
			fws[i] = fw
			m := new(dns.Msg)
			m.SetQuestion("example.com.", dns.TypeA)
			h.ServeDNS(fw, m)
		}(i)
	}
	wg.Wait()

	if got := hits.Load(); got != 1 {
		t.Fatalf("upstream received %d queries, want 1 (failure coalesced too)", got)
	}
	for i, fw := range fws {
		if fw.msg == nil || fw.msg.Rcode != dns.RcodeServerFailure {
			t.Fatalf("waiter %d got rcode=%v, want SERVFAIL (shared failure)", i, fw.msg)
		}
	}
}

// TestHandlerCoalescesBackgroundResolutions verifies the background
// resolution path (cache prefetch + cache warmer) shares the same in-flight
// request pool as live queries: concurrent refreshes of the same question
// hit the upstream once instead of once per refresh.
func TestHandlerCoalescesBackgroundResolutions(t *testing.T) {
	var hits atomic.Int32
	mux := dns.NewServeMux()
	mux.HandleFunc(".", func(w dns.ResponseWriter, r *dns.Msg) {
		hits.Add(1)
		time.Sleep(300 * time.Millisecond) // keep the burst joined
		m := new(dns.Msg)
		m.SetReply(r)
		m.Answer = append(m.Answer, &dns.A{
			Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
			A:   net.ParseIP("5.6.7.8"),
		})
		_ = w.WriteMsg(m)
	})
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := &dns.Server{PacketConn: pc, Handler: mux}
	go func() { _ = srv.ActivateAndServe() }()
	t.Cleanup(func() { _ = srv.Shutdown() })

	c := cache.NewLocalOnly(6*time.Hour, time.Minute, 4096, 5*time.Minute)
	h := NewHandler(filter.NewEngine(), c, []*upstream.Upstream{
		{Transport: upstream.UDP, Addr: pc.LocalAddr().String()},
	}, nil, "nxdomain", 600, 5*time.Second)

	const n = 4
	q := dns.Question{Name: "example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			h.Refresh(ctx, q)
		}()
	}
	wg.Wait()

	if got := hits.Load(); got != 1 {
		t.Fatalf("upstream received %d background resolutions, want 1 (coalesced)", got)
	}
}

// TestHandlerDoesNotCoalesceDistinctQuestions verifies the request pool keys
// on the full question: concurrent queries for different domains each reach
// the upstream rather than sharing a resolution.
func TestHandlerDoesNotCoalesceDistinctQuestions(t *testing.T) {
	var hits atomic.Int32
	mux := dns.NewServeMux()
	mux.HandleFunc(".", func(w dns.ResponseWriter, r *dns.Msg) {
		hits.Add(1)
		time.Sleep(100 * time.Millisecond) // keep the window open so they'd overlap if merged
		m := new(dns.Msg)
		m.SetReply(r)
		_ = w.WriteMsg(m)
	})
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := &dns.Server{PacketConn: pc, Handler: mux}
	go func() { _ = srv.ActivateAndServe() }()
	t.Cleanup(func() { _ = srv.Shutdown() })

	h := NewHandler(filter.NewEngine(), nil, []*upstream.Upstream{
		{Transport: upstream.UDP, Addr: pc.LocalAddr().String()},
	}, nil, "nxdomain", 600, 5*time.Second)

	const n = 4
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			m := new(dns.Msg)
			m.SetQuestion(fmt.Sprintf("host%d.example.com.", i), dns.TypeA)
			h.ServeDNS(&fakeWriter{}, m)
		}(i)
	}
	wg.Wait()

	if got := hits.Load(); got != n {
		t.Fatalf("upstream received %d queries, want %d (distinct questions must not coalesce)", got, n)
	}
}

// TestCoalesceEligible verifies which queries may join the in-flight pool:
// plain recursive lookups only — meta queries (ANY/AXFR...), RD=0 probes,
// CD-set queries and messages carrying TSIG or other non-OPT additional
// records resolve on their own because their answers are not interchangeable.
func TestCoalesceEligible(t *testing.T) {
	plain := new(dns.Msg)
	plain.SetQuestion("example.com.", dns.TypeA)
	plain.RecursionDesired = true
	if !coalesceEligible(plain) {
		t.Fatal("plain A query should be eligible for coalescing")
	}

	noRD := new(dns.Msg)
	noRD.SetQuestion("example.com.", dns.TypeA)
	noRD.RecursionDesired = false
	if coalesceEligible(noRD) {
		t.Fatal("RD=0 query must not coalesce")
	}

	cd := new(dns.Msg)
	cd.SetQuestion("example.com.", dns.TypeA)
	cd.RecursionDesired = true
	cd.CheckingDisabled = true
	if coalesceEligible(cd) {
		t.Fatal("CD-set query must not coalesce")
	}

	anyQ := new(dns.Msg)
	anyQ.SetQuestion("example.com.", dns.TypeANY)
	anyQ.RecursionDesired = true
	if coalesceEligible(anyQ) {
		t.Fatal("meta (ANY) query must not coalesce")
	}

	multi := new(dns.Msg)
	multi.SetQuestion("example.com.", dns.TypeA)
	multi.RecursionDesired = true
	multi.Question = append(multi.Question, dns.Question{Name: "other.example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET})
	if coalesceEligible(multi) {
		t.Fatal("multi-question message must not coalesce (only the first question is keyed)")
	}

	tsig := new(dns.Msg)
	tsig.SetQuestion("example.com.", dns.TypeA)
	tsig.RecursionDesired = true
	tsig.Extra = append(tsig.Extra, &dns.TSIG{
		Hdr:        dns.RR_Header{Name: "key.example.com.", Rrtype: dns.TypeTSIG, Class: dns.ClassANY, Ttl: 0},
		Algorithm:  dns.HmacSHA256,
		TimeSigned: uint64(time.Now().Unix()),
	})
	if coalesceEligible(tsig) {
		t.Fatal("TSIG-carrying query must not coalesce")
	}
}

// TestHandlerTruncatesOversizedUDPResponse verifies client-facing response
// sizing (RFC 1035 §4.2.1, RFC 6891): a UDP client whose advertised buffer —
// 512 bytes for a legacy client without EDNS — is smaller than the answer
// receives a truncated response with the TC bit set, so it retries over TCP,
// instead of an oversized datagram that many stacks silently drop. A client
// with a large EDNS buffer keeps the full answer, and stream transports
// (TCP/DoT/DoH/DoQ) are never truncated.
func TestHandlerTruncatesOversizedUDPResponse(t *testing.T) {
	// A realistic recursive upstream: UDP + TCP on the same port, honoring
	// the query's advertised EDNS payload — an answer bigger than the buffer
	// goes out truncated (TC) over UDP so the forwarder falls back to TCP
	// for the full answer, exactly like Cloudflare/Quad9 behave.
	mux := dns.NewServeMux()
	mux.HandleFunc(".", func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		for i := 0; i < 8; i++ {
			m.Answer = append(m.Answer, &dns.TXT{
				Hdr: dns.RR_Header{Name: fmt.Sprintf("txt%d.example.com.", i), Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 60},
				// RFC 1035 caps each TXT character-string at 255 bytes, so real
				// large TXT records split content across strings: 240 + 160
				// chars = 400 per record, ~3.4 KB across all eight.
				Txt: []string{strings.Repeat("0123456789abcdef", 15), strings.Repeat("0123456789abcdef", 10)},
			})
		}
		if _, isUDP := w.RemoteAddr().(*net.UDPAddr); isUDP {
			if size := clientUDPSize(r); m.Len() > size {
				m.Truncate(size)
			}
		}
		_ = w.WriteMsg(m)
	})
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	host, port, err := net.SplitHostPort(pc.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", net.JoinHostPort(host, port))
	if err != nil {
		t.Fatal(err)
	}
	srvUDP := &dns.Server{PacketConn: pc, Handler: mux}
	srvTCP := &dns.Server{Listener: ln, Handler: mux}
	go func() { _ = srvUDP.ActivateAndServe() }()
	go func() { _ = srvTCP.ActivateAndServe() }()
	t.Cleanup(func() {
		_ = srvUDP.Shutdown()
		_ = srvTCP.Shutdown()
	})

	// A cache makes the handler's second query take the cache-hit path, so
	// the test covers write(w, hit.Msg, ...) — a message unpacked from the
	// stored wire form, not a fresh upstream response — and verifies the
	// truncated copy never poisons the shared entry.
	c := cache.NewLocalOnly(time.Hour, time.Minute, 1024, 0)
	h := NewHandler(filter.NewEngine(), c, []*upstream.Upstream{
		{Transport: upstream.UDP, Addr: pc.LocalAddr().String()},
	}, nil, "nxdomain", 600, 5*time.Second)

	// The 8 x 400-char TXT answer is ~3.4 KB — well over 512 even compressed,
	// comfortably under a 4096-byte EDNS buffer.
	legacy := new(dns.Msg)
	legacy.SetQuestion("example.com.", dns.TypeTXT)
	q := legacy.Question[0]

	assertTruncated := func(fw *fakeWriter, label string) {
		t.Helper()
		if fw.msg == nil || len(fw.msg.Answer) == 0 {
			t.Fatalf("%s: no answer (rcode=%v)", label, fw.msg)
		}
		if !fw.msg.Truncated {
			t.Fatalf("%s: TC bit not set (wire %d bytes)", label, fw.msg.Len())
		}
		if n := fw.msg.Len(); n > dns.MinMsgSize {
			t.Fatalf("%s: received a %d-byte UDP response, want <= %d", label, n, dns.MinMsgSize)
		}
	}

	// Legacy client, cache miss: truncated with TC over UDP.
	fw := &fakeWriter{}
	h.ServeDNS(fw, legacy)
	assertTruncated(fw, "legacy client (upstream path)")

	// The cache must hold the FULL untruncated answer: the truncation runs
	// on a copy, never on resp, so a small-buffer client can't poison the
	// shared entry. The cache write is a background goroutine, so poll.
	var hit *dns.Msg
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		hit = c.Get(context.Background(), q)
		if hit != nil {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if hit == nil || len(hit.Answer) != 8 {
		answers := 0
		if hit != nil {
			answers = len(hit.Answer)
		}
		t.Fatalf("cache lost records to truncation: %d answers, want 8", answers)
	}

	// Same legacy client again — now a cache hit, still truncated for it.
	fwHit := &fakeWriter{}
	h.ServeDNS(fwHit, legacy)
	assertTruncated(fwHit, "legacy client (cache-hit path)")

	// A client advertising a 4096-byte EDNS buffer keeps the full answer.
	big := new(dns.Msg)
	big.SetQuestion("example.com.", dns.TypeTXT)
	big.SetEdns0(4096, false)
	fw2 := &fakeWriter{}
	h.ServeDNS(fw2, big)
	if fw2.msg == nil || len(fw2.msg.Answer) != 8 {
		t.Fatalf("4096-buffer client got %d answers, want all 8 (msg=%v)", len(fw2.msg.Answer), fw2.msg)
	}
	if fw2.msg.Truncated {
		t.Fatal("4096-buffer client: TC set unexpectedly")
	}

	// Stream transports have no datagram limit: the TCP path delivers the
	// full untruncated answer to the same 512-byte (no-EDNS) client. serve()
	// copies the request before forwarding, so reusing legacy here is safe.
	fw3 := &fakeWriter{}
	h.ServeDNSWithProto(fw3, legacy, "tcp")
	if fw3.msg == nil || fw3.msg.Truncated || len(fw3.msg.Answer) != 8 {
		t.Fatalf("TCP client: expected the full untruncated answer, got %v", fw3.msg)
	}
}

// TestHandlerRewriteShortCircuitsUpstream verifies a matching local DNS
// record answers directly without ever touching the upstream — proven by
// pointing Upstreams at nothing reachable and confirming the query still
// succeeds instantly with the rewritten answer.
func TestHandlerRewriteShortCircuitsUpstream(t *testing.T) {
	h := NewHandler(filter.NewEngine(), nil, nil, nil, "nxdomain", 600, 5*time.Second)
	rw := filter.NewRewriter()
	rw.Set([]filter.RewriteSpec{{Domain: "nas.home", Type: "A", Value: "192.168.1.10", TTL: 300}})
	h.SetRewriter(rw)

	m := new(dns.Msg)
	m.SetQuestion("nas.home.", dns.TypeA)
	fw := &fakeWriter{}
	h.ServeDNS(fw, m)

	if fw.msg == nil || len(fw.msg.Answer) != 1 {
		t.Fatalf("expected one rewritten answer, got %v", fw.msg)
	}
	a, ok := fw.msg.Answer[0].(*dns.A)
	if !ok || a.A.String() != "192.168.1.10" {
		t.Fatalf("unexpected answer: %v", fw.msg.Answer[0])
	}
}

// TestHandlerRateLimitDropsUDPOverLimit verifies a client that exceeds its
// burst gets no UDP response at all (dropped, not REFUSED — see the
// amplification-abuse comment in serve()).
func TestHandlerRateLimitDropsUDPOverLimit(t *testing.T) {
	addr := startUDPTestServer(t, "1.1.1.1", 0)
	h := NewHandler(filter.NewEngine(), nil, []*upstream.Upstream{{Transport: upstream.UDP, Addr: addr}}, nil, "nxdomain", 600, 5*time.Second)
	h.SetRateLimiter(NewRateLimiter(1, 1))

	q := func() *dns.Msg {
		m := new(dns.Msg)
		m.SetQuestion("example.com.", dns.TypeA)
		return m
	}
	fw1 := &fakeWriter{}
	h.ServeDNS(fw1, q())
	if fw1.msg == nil {
		t.Fatal("first query should be allowed and answered")
	}
	fw2 := &fakeWriter{}
	h.ServeDNS(fw2, q())
	if fw2.msg != nil {
		t.Fatalf("second query within the same burst window should be dropped, got %v", fw2.msg)
	}
}

// TestHandlerRateLimitRefusesConnectionOriented verifies non-UDP protocols
// get a REFUSED response instead of a silent drop when rate-limited (no
// amplification risk over a connection-oriented transport).
func TestHandlerRateLimitRefusesConnectionOriented(t *testing.T) {
	h := NewHandler(filter.NewEngine(), nil, nil, nil, "nxdomain", 600, 5*time.Second)
	h.SetRateLimiter(NewRateLimiter(1, 1))

	q := func() *dns.Msg {
		m := new(dns.Msg)
		m.SetQuestion("example.com.", dns.TypeA)
		return m
	}
	fw1 := &fakeWriter{}
	h.ServeDNSWithProto(fw1, q(), "tcp")
	fw2 := &fakeWriter{}
	h.ServeDNSWithProto(fw2, q(), "tcp")
	if fw2.msg == nil || fw2.msg.Rcode != dns.RcodeRefused {
		t.Fatalf("expected REFUSED for a rate-limited TCP query, got %v", fw2.msg)
	}
}

// TestHandlerAutoBlockedClientDroppedOnUDP verifies a client under an
// auto-block gets no UDP response at all (same silent-drop path as ordinary
// over-limit handling).
func TestHandlerAutoBlockedClientDroppedOnUDP(t *testing.T) {
	addr := startUDPTestServer(t, "1.1.1.1", 0)
	h := NewHandler(filter.NewEngine(), nil, []*upstream.Upstream{{Transport: upstream.UDP, Addr: addr}}, nil, "nxdomain", 600, 5*time.Second)
	rl := NewRateLimiter(1, 1)
	rl.SetAutoBlock(3, time.Hour)
	h.SetRateLimiter(rl)

	q := func() *dns.Msg {
		m := new(dns.Msg)
		m.SetQuestion("example.com.", dns.TypeA)
		return m
	}
	// Hammer the same client until the auto-block trips.
	for i := 0; i < 10; i++ {
		h.ServeDNS(&fakeWriter{}, q())
	}
	if blocked, _ := rl.Blocked("127.0.0.1"); !blocked {
		t.Fatal("client not auto-blocked after hammering")
	}
	fw := &fakeWriter{}
	h.ServeDNS(fw, q())
	if fw.msg != nil {
		t.Fatalf("auto-blocked UDP client got a response, want a silent drop: %v", fw.msg)
	}
}

// TestHandlerAutoBlockedClientRefusedOnTCP verifies connection-oriented
// transports get REFUSED while a client is under an auto-block.
func TestHandlerAutoBlockedClientRefusedOnTCP(t *testing.T) {
	h := NewHandler(filter.NewEngine(), nil, nil, nil, "nxdomain", 600, 5*time.Second)
	rl := NewRateLimiter(1, 1)
	rl.SetAutoBlock(3, time.Hour)
	h.SetRateLimiter(rl)

	q := func() *dns.Msg {
		m := new(dns.Msg)
		m.SetQuestion("example.com.", dns.TypeA)
		return m
	}
	for i := 0; i < 10; i++ {
		h.ServeDNSWithProto(&fakeWriter{}, q(), "tcp")
	}
	if blocked, _ := rl.Blocked("127.0.0.1"); !blocked {
		t.Fatal("client not auto-blocked after hammering")
	}
	fw := &fakeWriter{}
	h.ServeDNSWithProto(fw, q(), "tcp")
	if fw.msg == nil || fw.msg.Rcode != dns.RcodeRefused {
		t.Fatalf("expected REFUSED for an auto-blocked TCP client, got %v", fw.msg)
	}
}

// TestHandlerGeoBlockedClientRefusedEveryTransport verifies a client whose
// IP falls in a blocked country gets REFUSED on UDP as well as TCP (geo
// blocking's configured action is REFUSED everywhere), and that an
// allowlisted IP passes untouched.
func TestHandlerGeoBlockedClientRefusedEveryTransport(t *testing.T) {
	addr := startUDPTestServer(t, "1.1.1.1", 0)
	h := NewHandler(filter.NewEngine(), nil, []*upstream.Upstream{{Transport: upstream.UDP, Addr: addr}}, nil, "nxdomain", 600, 5*time.Second)

	tbl, err := geoip.LoadTable([]byte("93.0.0.0/8\n"), nil)
	if err != nil {
		t.Fatalf("LoadTable: %v", err)
	}
	b := geoip.NewBlocker()
	if err := b.SetConfig([]string{"RU"}, nil); err != nil {
		t.Fatalf("SetConfig: %v", err)
	}
	b.AddTable("RU", tbl)
	h.SetGeo(b)

	q := func() *dns.Msg {
		m := new(dns.Msg)
		m.SetQuestion("example.com.", dns.TypeA)
		return m
	}
	client := &fakeWriter{ip: net.ParseIP("93.184.0.1")}
	h.ServeDNS(client, q()) // UDP: REFUSED too, unlike rate limiting's silent drop
	if client.msg == nil || client.msg.Rcode != dns.RcodeRefused {
		t.Fatalf("geo-blocked UDP client: expected REFUSED, got %v", client.msg)
	}
	client2 := &fakeWriter{ip: net.ParseIP("93.184.0.1")}
	h.ServeDNSWithProto(client2, q(), "tcp")
	if client2.msg == nil || client2.msg.Rcode != dns.RcodeRefused {
		t.Fatalf("geo-blocked TCP client: expected REFUSED, got %v", client2.msg)
	}

	// A client outside the blocked ranges is served normally.
	direct := &fakeWriter{}
	h.ServeDNS(direct, q())
	if direct.msg == nil || len(direct.msg.Answer) == 0 {
		t.Fatalf("non-blocked client should get a normal answer, got %v", direct.msg)
	}

	// Allowlisting an IP inside the blocked country lets it through.
	b2 := geoip.NewBlocker()
	if err := b2.SetConfig([]string{"RU"}, []string{"93.184.0.1"}); err != nil {
		t.Fatalf("SetConfig: %v", err)
	}
	b2.AddTable("RU", tbl)
	h.SetGeo(b2)
	allowed := &fakeWriter{ip: net.ParseIP("93.184.0.1")}
	h.ServeDNS(allowed, q())
	if allowed.msg == nil || len(allowed.msg.Answer) == 0 {
		t.Fatalf("allowlisted client was geo-blocked, got %v", allowed.msg)
	}
}

// TestHandlerIPBannerAndHoneypot verifies the client-IP banner refuses
// blocked clients (configured IPs/CIDRs), and that querying a honeypot
// domain auto-blocks the client (firing the banner's OnBlock callback so the
// firewall can drop it) and refuses the query — after which the client is
// refused on every domain. Auto-blocking only fires over connection-oriented
// transports: a spoofable UDP source must never be able to permanently block
// an innocent victim (see the serve() comment), so UDP honeypot queries are
// silently dropped (never answered — replying would amplify a spoofed
// packet) and leave the client unblocked.
func TestHandlerIPBannerAndHoneypot(t *testing.T) {
	addr := startUDPTestServer(t, "1.1.1.1", 0)
	h := NewHandler(filter.NewEngine(), nil, []*upstream.Upstream{{Transport: upstream.UDP, Addr: addr}}, nil, "nxdomain", 600, 5*time.Second)

	var autoBlocked []string
	banner := geoip.NewBanner("", nil, []string{"38.11.106.3"}, []string{"trap.example.com"})
	banner.OnBlock = func(ip string) { autoBlocked = append(autoBlocked, ip) }
	h.SetIPBanner(banner)

	q := func(name string) *dns.Msg {
		m := new(dns.Msg)
		m.SetQuestion(name, dns.TypeA)
		return m
	}
	// A configured block IP gets REFUSED like a geo-blocked country.
	blocked := &fakeWriter{ip: net.ParseIP("38.11.106.3")}
	h.ServeDNS(blocked, q("example.com."))
	if blocked.msg == nil || blocked.msg.Rcode != dns.RcodeRefused {
		t.Fatalf("banner-blocked client: expected REFUSED, got %v", blocked.msg)
	}
	// A honeypot query over UDP is silently dropped (no answer — replying
	// to a spoofable source would amplify it) and must NOT auto-block: UDP
	// sources can be spoofed, so trusting one would let an attacker block an
	// innocent victim with a single spoofed packet.
	udpClient := &fakeWriter{ip: net.ParseIP("203.0.113.9")}
	h.ServeDNS(udpClient, q("trap.example.com."))
	if udpClient.msg != nil {
		t.Fatalf("UDP honeypot query: expected a silent drop, got %v", udpClient.msg)
	}
	if len(autoBlocked) != 0 {
		t.Fatalf("UDP honeypot query auto-blocked the client: %v", autoBlocked)
	}
	// The UDP queryer stays unblocked: a normal query still resolves.
	udpAgain := &fakeWriter{ip: net.ParseIP("203.0.113.9")}
	h.ServeDNS(udpAgain, q("example.com."))
	if udpAgain.msg == nil || len(udpAgain.msg.Answer) == 0 {
		t.Fatalf("UDP honeypot queryer should still resolve normal domains, got %v", udpAgain.msg)
	}
	// The same honeypot query over TCP (a real handshake, so the source is
	// genuine) auto-blocks the client and is itself refused.
	client := &fakeWriter{ip: net.ParseIP("203.0.113.9")}
	h.ServeDNSWithProto(client, q("trap.example.com."), "tcp")
	if client.msg == nil || client.msg.Rcode != dns.RcodeRefused {
		t.Fatalf("TCP honeypot query: expected REFUSED, got %v", client.msg)
	}
	if len(autoBlocked) != 1 || autoBlocked[0] != "203.0.113.9" {
		t.Fatalf("OnBlock fired %v, want [203.0.113.9]", autoBlocked)
	}
	// Subdomain floods are the classic DDoS shape: a trap configured as
	// "trap.example.com" must catch random labels under it too, auto-blocking
	// the client over a real handshake.
	sub := &fakeWriter{ip: net.ParseIP("198.51.100.42")}
	h.ServeDNSWithProto(sub, q("rand-9f2a.trap.example.com."), "tcp")
	if sub.msg == nil || sub.msg.Rcode != dns.RcodeRefused {
		t.Fatalf("TCP subdomain honeypot query: expected REFUSED, got %v", sub.msg)
	}
	if len(autoBlocked) != 2 || autoBlocked[1] != "198.51.100.42" {
		t.Fatalf("OnBlock fired %v, want [203.0.113.9 198.51.100.42]", autoBlocked)
	}
	// Subdomain over UDP is silently dropped but never auto-blocks
	// (spoofable source).
	udpSub := &fakeWriter{ip: net.ParseIP("198.51.100.99")}
	h.ServeDNS(udpSub, q("rand-7e1a.trap.example.com."))
	if udpSub.msg != nil {
		t.Fatalf("UDP subdomain honeypot query: expected a silent drop, got %v", udpSub.msg)
	}
	if len(autoBlocked) != 2 {
		t.Fatalf("UDP subdomain honeypot query auto-blocked the client: %v", autoBlocked)
	}
	// The auto-blocked client is now refused on a normal domain too.
	again := &fakeWriter{ip: net.ParseIP("203.0.113.9")}
	h.ServeDNS(again, q("example.com."))
	if again.msg == nil || again.msg.Rcode != dns.RcodeRefused {
		t.Fatalf("auto-blocked client on a normal domain: expected REFUSED, got %v", again.msg)
	}
	// Unrelated clients are untouched.
	ok := &fakeWriter{}
	h.ServeDNS(ok, q("example.com."))
	if ok.msg == nil || len(ok.msg.Answer) == 0 {
		t.Fatalf("unrelated client should get a normal answer, got %v", ok.msg)
	}
}

// TestHandlerAllowlistedClientNotHoneypotBlocked verifies the end-to-end
// guarantee behind the allowlist: an allowlisted client that queries a
// honeypot domain over a trusted transport is refused (honeypots are never
// answered) but is NOT auto-blocked — it keeps resolving normal domains, and
// the banner's OnBlock never fires so the firewall is never told to drop it.
// The same query from a non-allowlisted client auto-blocks as usual.
func TestHandlerAllowlistedClientNotHoneypotBlocked(t *testing.T) {
	addr := startUDPTestServer(t, "1.1.1.1", 0)
	h := NewHandler(filter.NewEngine(), nil, []*upstream.Upstream{{Transport: upstream.UDP, Addr: addr}}, nil, "nxdomain", 600, 5*time.Second)
	var autoBlocked []string
	banner := geoip.NewBanner("", []string{"203.0.113.9"}, nil, []string{"trap.example.com"})
	banner.OnBlock = func(ip string) { autoBlocked = append(autoBlocked, ip) }
	h.SetIPBanner(banner)

	q := func(name string) *dns.Msg {
		m := new(dns.Msg)
		m.SetQuestion(name, dns.TypeA)
		return m
	}
	// Honeypot query over TCP from the allowlisted client: refused, not blocked.
	fw := &fakeWriter{ip: net.ParseIP("203.0.113.9")}
	h.ServeDNSWithProto(fw, q("trap.example.com."), "tcp")
	if fw.msg == nil || fw.msg.Rcode != dns.RcodeRefused {
		t.Fatalf("honeypot query: expected REFUSED, got %v", fw.msg)
	}
	if len(autoBlocked) != 0 {
		t.Fatalf("allowlisted client was auto-blocked: %v", autoBlocked)
	}
	if b := h.CurrentIPBanner(); b != nil && b.Blocked("203.0.113.9") {
		t.Fatal("allowlisted client reported blocked after honeypot query")
	}
	// A normal query from the allowlisted client still resolves.
	ok := &fakeWriter{ip: net.ParseIP("203.0.113.9")}
	h.ServeDNS(ok, q("example.com."))
	if ok.msg == nil || len(ok.msg.Answer) == 0 {
		t.Fatalf("allowlisted client's normal query failed: %v", ok.msg)
	}
	// Control: the same honeypot query from a non-allowlisted client auto-blocks.
	ctrl := &fakeWriter{ip: net.ParseIP("198.51.100.42")}
	h.ServeDNSWithProto(ctrl, q("trap.example.com."), "tcp")
	if len(autoBlocked) != 1 || autoBlocked[0] != "198.51.100.42" {
		t.Fatalf("control client OnBlock fired %v, want [198.51.100.42]", autoBlocked)
	}
}

// TestHandlerHoneypotNotLogged verifies that honeypot hits — the apex and
// random subdomains under the trap — are never written to the query log, while
// a normal query is logged as usual. Honeypot traffic is attack traffic; the
// dashboard surfaces auto-blocked clients via /api/geo/blocked instead.
func TestHandlerHoneypotNotLogged(t *testing.T) {
	addr := startUDPTestServer(t, "1.1.1.1", 0)
	// The query log now lives in a Dragonfly stream; miniredis provides the
	// in-process Redis-compatible store so the log is real and queryable.
	mr := miniredis.RunT(t)
	ql, err := querylog.New(mr.Addr(), "", 0, 30, 0)
	if err != nil {
		t.Fatalf("querylog: %v", err)
	}
	defer ql.Close()
	h := NewHandler(filter.NewEngine(), nil, []*upstream.Upstream{{Transport: upstream.UDP, Addr: addr}}, ql, "nxdomain", 600, 5*time.Second)
	banner := geoip.NewBanner("", nil, nil, []string{"trap.example.com"})
	h.SetIPBanner(banner)

	q := func(name string) *dns.Msg {
		m := new(dns.Msg)
		m.SetQuestion(name, dns.TypeA)
		return m
	}
	// Honeypot hits (apex over UDP, random subdomain over UDP) are silently
	// dropped and must not reach the log.
	for _, name := range []string{"trap.example.com.", "rand-9f2a.trap.example.com."} {
		fw := &fakeWriter{ip: net.ParseIP("203.0.113.9")}
		h.ServeDNS(fw, q(name))
		if fw.msg != nil {
			t.Fatalf("honeypot query %s: expected a silent drop, got %v", name, fw.msg)
		}
	}
	// A normal query is served and logged as usual.
	ok := &fakeWriter{}
	h.ServeDNS(ok, q("example.com."))
	if ok.msg == nil || len(ok.msg.Answer) == 0 {
		t.Fatalf("control query failed: %v", ok.msg)
	}

	// The async log writer flushes on a 100ms ticker; poll briefly.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		entries, err := ql.Query(context.Background(), 100, 0, "", "", "", "")
		if err != nil {
			t.Fatalf("query log read: %v", err)
		}
		if len(entries) == 1 && entries[0].Domain == "example.com" {
			return // only the control query was logged
		}
		if len(entries) > 1 || (len(entries) == 1 && entries[0].Domain != "example.com") {
			t.Fatalf("honeypot traffic reached the query log: %+v", entries)
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatal("control query never appeared in the log")
}

// TestHandlerHoneypotTrustUDP verifies the opt-in trust_udp flag: normally a
// plain-UDP honeypot hit is silently dropped and never auto-blocks its source
// (UDP can be spoofed, so trusting it would let an attacker block an innocent
// victim). With TrustUDP set, the UDP source is auto-blocked too (permanently
// — persisted + firewall drop) — an operator choice for trusted networks.
func TestHandlerHoneypotTrustUDP(t *testing.T) {
	addr := startUDPTestServer(t, "1.1.1.1", 0)
	h := NewHandler(filter.NewEngine(), nil, []*upstream.Upstream{{Transport: upstream.UDP, Addr: addr}}, nil, "nxdomain", 600, 5*time.Second)
	banner := geoip.NewBanner("", nil, nil, []string{"trap.example.com"})
	var autoBlocked []string
	banner.OnBlock = func(ip string) { autoBlocked = append(autoBlocked, ip) }
	h.SetIPBanner(banner)
	h.SetTrustUDP(true)

	q := func(name string) *dns.Msg {
		m := new(dns.Msg)
		m.SetQuestion(name, dns.TypeA)
		return m
	}
	fw := &fakeWriter{ip: net.ParseIP("203.0.113.9")}
	h.ServeDNS(fw, q("trap.example.com."))
	if fw.msg != nil {
		t.Fatalf("UDP honeypot query with trust_udp: expected a silent drop, got %v", fw.msg)
	}
	if len(autoBlocked) != 1 || autoBlocked[0] != "203.0.113.9" {
		t.Fatalf("trust_udp OnBlock fired %v, want [203.0.113.9]", autoBlocked)
	}
	// The auto-blocked client is now refused on a normal domain too.
	again := &fakeWriter{ip: net.ParseIP("203.0.113.9")}
	h.ServeDNS(again, q("example.com."))
	if again.msg == nil || again.msg.Rcode != dns.RcodeRefused {
		t.Fatalf("trust_udp auto-blocked client on a normal domain: expected REFUSED, got %v", again.msg)
	}
}

// TestHandlerHoneypotUDPBoundedBlock verifies the honeypot_udp_block knob:
// a plain-UDP honeypot hit is silently dropped (never answered) and its
// source is auto-blocked via the rate limiter for a bounded window — not the
// banner's permanent block (a UDP source can be spoofed, so a single spoofed
// packet must not be able to block a victim forever). The blocked source is
// dropped at the DNS layer (its UDP queries get no answer), shows up on the
// dashboard's blocked-clients list with an expiry, and can be unblocked
// early. Trusted transports still earn the permanent banner block regardless
// of the knob.
func TestHandlerHoneypotUDPBoundedBlock(t *testing.T) {
	addr := startUDPTestServer(t, "1.1.1.1", 0)
	h := NewHandler(filter.NewEngine(), nil, []*upstream.Upstream{{Transport: upstream.UDP, Addr: addr}}, nil, "nxdomain", 600, 5*time.Second)
	banner := geoip.NewBanner("", nil, nil, []string{"trap.example.com"})
	var autoBlocked []string
	banner.OnBlock = func(ip string) { autoBlocked = append(autoBlocked, ip) }
	h.SetIPBanner(banner)
	h.SetRateLimiter(NewRateLimiter(10, 10))
	h.SetHoneypotUDPBlock(10 * time.Minute)

	q := func(name string) *dns.Msg {
		m := new(dns.Msg)
		m.SetQuestion(name, dns.TypeA)
		return m
	}
	// A UDP honeypot hit is silently dropped and never reaches the banner
	// (no permanent block, no OnBlock).
	fw := &fakeWriter{ip: net.ParseIP("203.0.113.9")}
	h.ServeDNS(fw, q("trap.example.com."))
	if fw.msg != nil {
		t.Fatalf("UDP honeypot query with honeypot_udp_block: expected a silent drop, got %v", fw.msg)
	}
	if len(autoBlocked) != 0 {
		t.Fatalf("honeypot_udp_block triggered a permanent banner block: %v", autoBlocked)
	}
	// The source is under a bounded rate-limiter block instead, visible on
	// the dashboard's blocked-clients list with an expiry.
	var blocked []BlockedClient
	for _, c := range h.BlockedClients() {
		if c.IP == "203.0.113.9" {
			blocked = append(blocked, c)
		}
	}
	if len(blocked) != 1 {
		t.Fatalf("BlockedClients = %+v, want one bounded block for 203.0.113.9", h.BlockedClients())
	}
	if expiry := time.Until(blocked[0].BlockedUntil); expiry > 10*time.Minute || expiry <= 9*time.Minute {
		t.Fatalf("block expiry = %v, want ~10m", expiry)
	}
	// While blocked, the source's normal UDP queries are dropped too — the
	// flood stops at the DNS layer.
	dropped := &fakeWriter{ip: net.ParseIP("203.0.113.9")}
	h.ServeDNS(dropped, q("example.com."))
	if dropped.msg != nil {
		t.Fatalf("bounded-blocked UDP client on a normal domain: expected a silent drop, got %v", dropped.msg)
	}
	// Unblocking early admits the client again.
	h.UnblockClient("203.0.113.9")
	ok := &fakeWriter{ip: net.ParseIP("203.0.113.9")}
	h.ServeDNS(ok, q("example.com."))
	if ok.msg == nil || len(ok.msg.Answer) == 0 {
		t.Fatalf("unblocked client should resolve normal domains again, got %v", ok.msg)
	}
	// Control: a TCP honeypot hit from a different client still earns the
	// permanent banner block — the knob only affects plain UDP.
	tcpClient := &fakeWriter{ip: net.ParseIP("198.51.100.42")}
	h.ServeDNSWithProto(tcpClient, q("trap.example.com."), "tcp")
	if tcpClient.msg == nil || tcpClient.msg.Rcode != dns.RcodeRefused {
		t.Fatalf("TCP honeypot query: expected REFUSED, got %v", tcpClient.msg)
	}
	if len(autoBlocked) != 1 || autoBlocked[0] != "198.51.100.42" {
		t.Fatalf("TCP honeypot OnBlock fired %v, want [198.51.100.42]", autoBlocked)
	}
}

// TestHandlerDNSSECRejectsUnauthenticated verifies that with DNSSEC required,
// an upstream answer lacking the AD bit is rejected as SERVFAIL rather than
// passed through.
func TestHandlerDNSSECRejectsUnauthenticated(t *testing.T) {
	addr := startUDPTestServer(t, "1.1.1.1", 0) // test server never sets AD
	h := NewHandler(filter.NewEngine(), nil, []*upstream.Upstream{{Transport: upstream.UDP, Addr: addr}}, nil, "nxdomain", 600, 5*time.Second)
	h.SetDNSSEC(true, true)

	m := new(dns.Msg)
	m.SetQuestion("example.com.", dns.TypeA)
	fw := &fakeWriter{}
	h.ServeDNS(fw, m)

	if fw.msg == nil || fw.msg.Rcode != dns.RcodeServerFailure {
		t.Fatalf("expected SERVFAIL for an unauthenticated answer under require_ad, got %v", fw.msg)
	}
}

// startCNAMETestServer runs a tiny UDP DNS server that answers every query
// with a CNAME from owner to target plus an A record for target.
func startCNAMETestServer(t *testing.T, owner, target, targetIP string) string {
	t.Helper()
	mux := dns.NewServeMux()
	mux.HandleFunc(".", func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Answer = append(m.Answer,
			&dns.CNAME{Hdr: dns.RR_Header{Name: owner, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 60}, Target: target},
			&dns.A{Hdr: dns.RR_Header{Name: target, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.ParseIP(targetIP)},
		)
		_ = w.WriteMsg(m)
	})
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := &dns.Server{PacketConn: pc, Handler: mux}
	go func() { _ = srv.ActivateAndServe() }()
	t.Cleanup(func() { _ = srv.Shutdown() })
	return pc.LocalAddr().String()
}

// TestHandlerCNAMECloakingProtection verifies that a query resolving through
// a CNAME to a blocklisted domain is blocked even though the originally
// queried name is on no list — and that it's a no-op when the toggle is off
// or when no hop in the chain is blocklisted.
func TestHandlerCNAMECloakingProtection(t *testing.T) {
	const owner = "sub.example.com."
	const target = "tracker.ads.net."

	t.Run("blocked when enabled and target is blocklisted", func(t *testing.T) {
		addr := startCNAMETestServer(t, owner, target, "203.0.113.5")
		e := filter.NewEngine()
		e.SetUserLists([]string{"tracker.ads.net"}, nil)
		e.Compile()
		h := NewHandler(e, nil, []*upstream.Upstream{{Transport: upstream.UDP, Addr: addr}}, nil, "nxdomain", 600, 5*time.Second)
		h.SetCNAMECloakingProtection(true)

		m := new(dns.Msg)
		m.SetQuestion(owner, dns.TypeA)
		fw := &fakeWriter{}
		h.ServeDNS(fw, m)

		if fw.msg == nil || fw.msg.Rcode != dns.RcodeNameError {
			t.Fatalf("expected NXDOMAIN for a CNAME-cloaked tracker, got %v", fw.msg)
		}
	})

	t.Run("passes through when disabled", func(t *testing.T) {
		addr := startCNAMETestServer(t, owner, target, "203.0.113.5")
		e := filter.NewEngine()
		e.SetUserLists([]string{"tracker.ads.net"}, nil)
		e.Compile()
		h := NewHandler(e, nil, []*upstream.Upstream{{Transport: upstream.UDP, Addr: addr}}, nil, "nxdomain", 600, 5*time.Second)
		// SetCNAMECloakingProtection not called: off by default.

		m := new(dns.Msg)
		m.SetQuestion(owner, dns.TypeA)
		fw := &fakeWriter{}
		h.ServeDNS(fw, m)

		if fw.msg == nil || len(fw.msg.Answer) == 0 {
			t.Fatalf("expected the CNAME+A answer to pass through with protection off, got %v", fw.msg)
		}
	})

	t.Run("unaffected when no hop is blocklisted", func(t *testing.T) {
		addr := startCNAMETestServer(t, owner, target, "203.0.113.5")
		e := filter.NewEngine() // nothing blocklisted
		h := NewHandler(e, nil, []*upstream.Upstream{{Transport: upstream.UDP, Addr: addr}}, nil, "nxdomain", 600, 5*time.Second)
		h.SetCNAMECloakingProtection(true)

		m := new(dns.Msg)
		m.SetQuestion(owner, dns.TypeA)
		fw := &fakeWriter{}
		h.ServeDNS(fw, m)

		if fw.msg == nil || len(fw.msg.Answer) == 0 {
			t.Fatalf("expected the CNAME+A answer to pass through when no hop is blocklisted, got %v", fw.msg)
		}
	})
}

// TestRaceUpstreamsAllFail verifies an all-failures case returns promptly
// instead of stalling until the full timeout.
func TestRaceUpstreamsAllFail(t *testing.T) {
	// Bind a port then release it: dialing it now fails immediately.
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	deadAddr := pc.LocalAddr().String()
	pc.Close()

	m := new(dns.Msg)
	m.SetQuestion("example.com.", dns.TypeA)
	start := time.Now()
	resp, _, err := raceUpstreams(context.Background(), []*upstream.Upstream{
		{Transport: upstream.UDP, Addr: deadAddr},
		{Transport: upstream.UDP, Addr: deadAddr},
	}, m)
	if err == nil || resp != nil {
		t.Fatalf("expected an error, got resp=%v err=%v", resp, err)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("all-fail took %s, want a prompt failure", elapsed)
	}
}

// TestHandlerCacheWriteDoesNotBlockResponse verifies the response is written
// to the client without waiting for the cache write to land, and that the
// answer still ends up cached shortly after (the async write actually runs,
// and — since it hands the cache a copy rather than resp itself — running
// concurrently with WriteMsg's own packing of resp doesn't race either;
// `go test -race` covers that property).
func TestHandlerCacheWriteDoesNotBlockResponse(t *testing.T) {
	addr := startUDPTestServer(t, "1.1.1.1", 0)
	c := cache.NewLocalOnly(time.Hour, time.Minute, 512, 0)
	h := NewHandler(filter.NewEngine(), c, []*upstream.Upstream{
		{Transport: upstream.UDP, Addr: addr},
	}, nil, "nxdomain", 600, 5*time.Second)

	m := new(dns.Msg)
	m.SetQuestion("example.com.", dns.TypeA)
	q := m.Question[0]
	fw := &fakeWriter{}
	h.ServeDNS(fw, m)

	if fw.msg == nil || len(fw.msg.Answer) == 0 {
		t.Fatalf("expected an answer, got %v", fw.msg)
	}

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if got := c.Get(context.Background(), q); got != nil {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("cached entry never appeared after the response was written")
}

// TestHandlerCacheHitPoolConcurrency hammers the cache-hit path (the
// highest-value site pooled via msgPool/getMsg/putMsg) from many goroutines
// at once. A single-threaded test can't exercise cross-goroutine pool
// reuse; this gives `go test -race` a real chance to catch a Get/Put
// correctness bug (a response written from a message another goroutine has
// already recycled, or a race on the pooled object itself) while also
// asserting every response is still well-formed.
func TestHandlerCacheHitPoolConcurrency(t *testing.T) {
	addr := startUDPTestServer(t, "203.0.113.7", 0)
	c := cache.NewLocalOnly(time.Hour, time.Minute, 512, 0)
	h := NewHandler(filter.NewEngine(), c, []*upstream.Upstream{
		{Transport: upstream.UDP, Addr: addr},
	}, nil, "nxdomain", 600, 5*time.Second)

	// Prime the cache with one real resolution, then wait until it's
	// actually visible in the cache before firing concurrent queries — a
	// query that instead falls through to live upstream resolution hands
	// its (deliberately unpooled) resp to a background cache-write
	// goroutine and keeps no synchronization with the caller, so reading
	// that response after ServeDNS returns would itself race the
	// goroutine — a pre-existing characteristic of the write path (see the
	// "resp is deliberately never put into msgPool" comment in handler.go),
	// not something this test is meant to exercise. Waiting for the cache
	// to converge, exactly like TestHandlerCacheWriteDoesNotBlockResponse
	// does, keeps every concurrent query on the pooled cache-hit path.
	primeQ := dns.Question{Name: "pool-concurrency.example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
	prime := new(dns.Msg)
	prime.SetQuestion(primeQ.Name, primeQ.Qtype)
	primeFW := &fakeWriter{}
	h.ServeDNS(primeFW, prime)
	if primeFW.msg == nil || len(primeFW.msg.Answer) == 0 {
		t.Fatalf("priming query failed: %v", primeFW.msg)
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if got := c.Get(context.Background(), primeQ); got != nil {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}

	const goroutines = 32
	const perGoroutine = 50
	var wg sync.WaitGroup
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < perGoroutine; j++ {
				m := new(dns.Msg)
				m.SetQuestion("pool-concurrency.example.com.", dns.TypeA)
				fw := &fakeWriter{}
				h.ServeDNS(fw, m)
				if fw.msg == nil || fw.msg.Rcode != dns.RcodeSuccess {
					t.Errorf("unexpected response: %v", fw.msg)
					return
				}
				if len(fw.msg.Answer) != 1 {
					t.Errorf("expected exactly 1 answer RR, got %d: %v", len(fw.msg.Answer), fw.msg)
					return
				}
				a, ok := fw.msg.Answer[0].(*dns.A)
				if !ok || a.A.String() != "203.0.113.7" {
					t.Errorf("unexpected answer RR: %v", fw.msg.Answer[0])
					return
				}
			}
		}()
	}
	wg.Wait()
}

// TestHandlerServeStale verifies RFC 8767 serve-stale end to end: an answer
// cached from a healthy upstream is still served — from the expired entry —
// once the upstream dies, instead of SERVFAIL. The stale answer is fast (the
// dead upstream's timeout is not waited out) and its TTLs are capped low so
// clients don't cache the stale data.
func TestHandlerServeStale(t *testing.T) {
	addr := startUDPTestServer(t, "1.1.1.1", 0)
	c := cache.NewLocalOnly(300*time.Millisecond, time.Minute, 512, 5*time.Second)
	h := NewHandler(filter.NewEngine(), c, []*upstream.Upstream{
		{Transport: upstream.UDP, Addr: addr},
	}, nil, "nxdomain", 600, 5*time.Second)

	q := func() *dns.Msg {
		m := new(dns.Msg)
		m.SetQuestion("example.com.", dns.TypeA)
		return m
	}
	// Populate the cache from a healthy upstream.
	fw := &fakeWriter{}
	h.ServeDNS(fw, q())
	if fw.msg == nil || len(fw.msg.Answer) == 0 {
		t.Fatalf("expected a fresh answer, got %v", fw.msg)
	}

	// Let the entry expire into its serve-stale window, then kill the
	// upstream so re-resolution fails and the handler must answer from the
	// expired entry.
	time.Sleep(400 * time.Millisecond)
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	deadAddr := pc.LocalAddr().String()
	pc.Close()
	h.SetUpstreams([]*upstream.Upstream{{Transport: upstream.UDP, Addr: deadAddr}})

	start := time.Now()
	fw2 := &fakeWriter{}
	h.ServeDNS(fw2, q())
	if fw2.msg == nil || len(fw2.msg.Answer) == 0 {
		t.Fatalf("expected a stale answer, got %v", fw2.msg)
	}
	if a, ok := fw2.msg.Answer[0].(*dns.A); !ok || !a.A.Equal(net.ParseIP("1.1.1.1")) {
		t.Fatalf("stale answer = %v, want 1.1.1.1", fw2.msg.Answer[0])
	}
	if ttl := fw2.msg.Answer[0].Header().Ttl; ttl > staleServeTTL {
		t.Fatalf("stale answer TTL = %d, want <= %d so clients don't cache it", ttl, staleServeTTL)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("stale answer took %s — the dead upstream's timeout was waited out", elapsed)
	}
	// The failed re-resolution must NOT have negatively cached the SERVFAIL:
	// a fresh negative would shadow the serve-stale entry on the next query,
	// and the whole point of serve-stale is that the last known good answer
	// keeps winning while re-resolution fails.
	if res := c.Lookup(q().Question[0]); res.Msg() != nil && res.Negative {
		t.Fatalf("failure was negatively cached despite a serve-stale entry: %v", res.Msg())
	}
}

// TestHandlerFailureNegativelyCached verifies that a resolution failure with
// no cached data (upstream unreachable, no serve-stale entry) is negatively
// cached: the retry within the negative TTL answers instantly from cache
// instead of re-paying the full per-query timeout — the property that turns
// a dead-zone outage (e.g. the NTP-pool incident) from 5s per retry into a
// one-time cost per negative-TTL window.
func TestHandlerFailureNegativelyCached(t *testing.T) {
	// Bind a port then release it: dialing it now fails immediately.
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	deadAddr := pc.LocalAddr().String()
	pc.Close()

	// The cache's own negative TTL is an hour, but the failure-cache knob is
	// 100ms: if SetFailureTTL were ignored (falling back to negative_ttl) the
	// entry would outlive the disappearance check below, so that check proves
	// the custom TTL actually reached the cache.
	c := cache.NewLocalOnly(time.Hour, time.Hour, 512, 0)
	h := NewHandler(filter.NewEngine(), c, []*upstream.Upstream{
		{Transport: upstream.UDP, Addr: deadAddr},
	}, nil, "nxdomain", 600, 5*time.Second)
	h.SetFailureTTL(100 * time.Millisecond)

	q := func() *dns.Msg {
		m := new(dns.Msg)
		m.SetQuestion("example.com.", dns.TypeA)
		return m
	}
	fw := &fakeWriter{}
	h.ServeDNS(fw, q())
	if fw.msg == nil || fw.msg.Rcode != dns.RcodeServerFailure {
		t.Fatalf("expected SERVFAIL, got %v", fw.msg)
	}

	// The failure is written asynchronously, like a positive answer; it must
	// land promptly (the check interval stays well inside the 100ms TTL).
	question := fw.msg.Question[0]
	appeared := false
	for i := 0; i < 40; i++ {
		if res := c.Lookup(question); res.Msg() != nil {
			if !res.Negative {
				t.Fatalf("expected a negative cache entry, got positive %v", res.Msg())
			}
			if res.Msg().Rcode != dns.RcodeServerFailure {
				t.Fatalf("cached rcode = %d, want SERVFAIL", res.Msg().Rcode)
			}
			appeared = true
			break
		}
		time.Sleep(2 * time.Millisecond)
	}
	if !appeared {
		t.Fatal("negative entry never appeared after the failure")
	}

	// ...and it must expire at the configured 100ms failure TTL rather than
	// linger for the 1h negative TTL.
	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		if c.Lookup(question).Msg() == nil {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("negative entry outlived the configured failure_ttl — knob ignored?")
}

// TestHandlerSingleUpstreamCooldownFastFail verifies the circuit breaker end
// to end: a single upstream that has failed 3 times in a row is skipped
// immediately (fail fast into SERVFAIL) instead of letting every query wait
// out the full timeout against a dead server.
func TestHandlerSingleUpstreamCooldownFastFail(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	deadAddr := pc.LocalAddr().String()
	pc.Close()

	h := NewHandler(filter.NewEngine(), nil, []*upstream.Upstream{
		{Transport: upstream.UDP, Addr: deadAddr},
	}, nil, "nxdomain", 600, 5*time.Second)
	q := func() *dns.Msg {
		m := new(dns.Msg)
		m.SetQuestion("example.com.", dns.TypeA)
		return m
	}
	// Trip the circuit: connection-refused on loopback fails fast.
	for i := 0; i < 3; i++ {
		fw := &fakeWriter{}
		h.ServeDNS(fw, q())
		if fw.msg == nil || fw.msg.Rcode != dns.RcodeServerFailure {
			t.Fatalf("failure %d: expected SERVFAIL, got %v", i+1, fw.msg)
		}
	}
	// Circuit open: the next query must fail immediately via the cooldown
	// skip rather than attempting (and timing out against) the upstream.
	start := time.Now()
	fw := &fakeWriter{}
	h.ServeDNS(fw, q())
	if fw.msg == nil || fw.msg.Rcode != dns.RcodeServerFailure {
		t.Fatalf("cooldown query: expected SERVFAIL, got %v", fw.msg)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("cooldown query took %s — expected an immediate fail-fast", elapsed)
	}
}

// TestCapTTL verifies the serve-stale TTL cap applies across every section
// (Answer, Ns, Extra) while leaving the OPT pseudo-record untouched — its
// TTL field carries extended-rcode/DO flags, not a lifetime.
func TestCapTTL(t *testing.T) {
	m := new(dns.Msg)
	m.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: "a.example.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 3600}, A: net.ParseIP("1.2.3.4")}}
	m.Ns = []dns.RR{&dns.SOA{Hdr: dns.RR_Header{Name: "example.", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 3600}}}
	m.Extra = []dns.RR{
		&dns.TXT{Hdr: dns.RR_Header{Name: "b.example.", Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 7200}, Txt: []string{"x"}},
	}
	opt := new(dns.OPT)
	opt.Hdr.Name = "."
	opt.Hdr.Rrtype = dns.TypeOPT
	opt.Hdr.Class = 4096
	opt.SetDo(true)
	opt.Hdr.Ttl = 0x00008000 // extended rcode + version + DO flag bits
	m.Extra = append(m.Extra, opt)

	capTTL(m, 30)

	if got := m.Answer[0].Header().Ttl; got != 30 {
		t.Errorf("answer TTL = %d, want 30", got)
	}
	if got := m.Ns[0].Header().Ttl; got != 30 {
		t.Errorf("Ns (SOA) TTL = %d, want 30 so clients don't cache stale negatives long", got)
	}
	if got := m.Extra[0].Header().Ttl; got != 30 {
		t.Errorf("Extra TTL = %d, want 30", got)
	}
	if !opt.Do() {
		t.Error("OPT DO flag was corrupted by capTTL")
	}
	if got := opt.Hdr.Ttl; got != 0x00008000 {
		t.Errorf("OPT TTL/flags = %#x, want untouched 0x00008000", got)
	}
}

// startNXDOMAINServer runs a UDP DNS server that answers every query with
// NXDOMAIN — the response a random-subdomain flood elicits.
func startNXDOMAINServer(t *testing.T) string {
	t.Helper()
	mux := dns.NewServeMux()
	mux.HandleFunc(".", func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Rcode = dns.RcodeNameError
		_ = w.WriteMsg(m)
	})
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := &dns.Server{PacketConn: pc, Handler: mux}
	go func() { _ = srv.ActivateAndServe() }()
	t.Cleanup(func() { _ = srv.Shutdown() })
	return pc.LocalAddr().String()
}

// TestHandlerNXGuardBlocksFlood verifies the NXDOMAIN flood guard end to end
// through the handler: a client whose random-subdomain burst reaches the
// threshold gets its queries refused (silent UDP drop) until the cooldown
// elapses.
func TestHandlerNXGuardBlocksFlood(t *testing.T) {
	upAddr := startNXDOMAINServer(t)
	h := NewHandler(filter.NewEngine(), nil, []*upstream.Upstream{
		{Transport: upstream.UDP, Addr: upAddr},
	}, nil, "nxdomain", 600, 5*time.Second)
	// Threshold 2: two NXDOMAIN responses trip the guard.
	h.SetNXGuard(NewNXGuard(2, time.Minute, time.Minute))

	ask := func() *dns.Msg {
		m := new(dns.Msg)
		// Random subdomain so every query is a cache miss -> upstream NXDOMAIN.
		m.SetQuestion(fmt.Sprintf("rand%d.example.com.", time.Now().UnixNano()), dns.TypeA)
		fw := &fakeWriter{}
		h.ServeDNS(fw, m)
		return fw.msg
	}

	// First two queries get real NXDOMAIN answers and count toward the guard.
	for i := 0; i < 2; i++ {
		if resp := ask(); resp == nil || resp.Rcode != dns.RcodeNameError {
			t.Fatalf("query %d: want NXDOMAIN, got %v", i+1, resp)
		}
	}
	// The burst tripped the threshold: the third query is silently dropped
	// (no response at all, matching the rate limiter's UDP drop).
	if resp := ask(); resp != nil {
		t.Fatalf("query past the guard threshold must be dropped, got %v", resp)
	}
	// A different client prefix is unaffected.
	m := new(dns.Msg)
	m.SetQuestion(fmt.Sprintf("other%d.example.com.", time.Now().UnixNano()), dns.TypeA)
	fw := &fakeWriter{ip: net.IPv4(10, 9, 8, 7)}
	h.ServeDNS(fw, m)
	if fw.msg == nil || fw.msg.Rcode != dns.RcodeNameError {
		t.Fatalf("a different client must still be answered, got %v", fw.msg)
	}
}

// BenchmarkHandlerUpstreamMiss measures the cache-miss path — the one that
// matters under load and in a flood: filter decision, rate limiter, EDNS
// rewrite, upstream round trip, compression and the write. Distinct names
// keep every iteration a genuine miss (no singleflight merging). This is the
// benchmark the PGO profile is collected from, so the profile reflects the
// real query path rather than the cache fast path alone.
func BenchmarkHandlerUpstreamMiss(b *testing.B) {
	// A real UDP upstream over loopback, answering with an A record — the
	// same shape the test helpers use, but benchmark-compatible (Cleanup on
	// *testing.B).
	mux := dns.NewServeMux()
	mux.HandleFunc(".", func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Answer = append(m.Answer, &dns.A{
			Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
			A:   net.ParseIP("1.2.3.4"),
		})
		_ = w.WriteMsg(m)
	})
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		b.Fatal(err)
	}
	srv := &dns.Server{PacketConn: pc, Handler: mux}
	go func() { _ = srv.ActivateAndServe() }()
	b.Cleanup(func() { _ = srv.Shutdown() })

	h := NewHandler(filter.NewEngine(), nil, []*upstream.Upstream{
		{Transport: upstream.UDP, Addr: pc.LocalAddr().String()},
	}, nil, "nxdomain", 600, 5*time.Second)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		m := new(dns.Msg)
		// 1024 distinct names so b.N > 1024 still mostly misses.
		m.SetQuestion(fmt.Sprintf("bench%d.example.com.", i%1024), dns.TypeA)
		fw := &fakeWriter{}
		h.ServeDNS(fw, m)
		if fw.msg == nil {
			b.Fatal("no response")
		}
	}
}

// BenchmarkHandlerCacheHit measures the whole served-cache-hit pipeline:
// question hashing, filter decision, L1 cache lookup and the raw-byte write
// path (no Unpack, no re-Pack). The fake writer unpacks the bytes it
// receives like a real client stack would, so the handler-side savings are
// what moves the needle, not the sink.
func BenchmarkHandlerCacheHit(b *testing.B) {
	c := cache.NewLocalOnly(time.Hour, time.Minute, 512, 0)
	h := NewHandler(filter.NewEngine(), c, nil, nil, "nxdomain", 600, 5*time.Second)
	m := new(dns.Msg)
	m.SetQuestion("example.com.", dns.TypeA)
	h.ServeDNS(&fakeWriter{}, m) // warm the cache (async write; poll)
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if c.Lookup(m.Question[0]).Msg() != nil {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if c.Lookup(m.Question[0]).Msg() == nil {
		b.Fatal("cache not warmed")
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		fw := &fakeWriter{}
		h.ServeDNS(fw, m)
		if fw.msg == nil {
			b.Fatal("no response")
		}
	}
}

// TestHandlerIPBlockGated verifies the answer-IP blocking path still blocks
// through the HasIPRules gate: an engine holding an IP rule blocks an
// upstream answer whose address matches.
func TestHandlerIPBlockGated(t *testing.T) {
	upAddr := startUDPTestServer(t, "1.2.3.4", 0)
	engine := filter.NewEngine()
	if _, err := engine.LoadList("ip", "ip list", []byte("1.2.3.4\n")); err != nil {
		t.Fatalf("load list: %v", err)
	}
	engine.Compile()
	if !engine.HasIPRules() {
		t.Fatal("engine with an IP rule must report HasIPRules")
	}
	h := NewHandler(engine, nil, []*upstream.Upstream{{Transport: upstream.UDP, Addr: upAddr}}, nil, "nxdomain", 600, 5*time.Second)
	m := new(dns.Msg)
	m.SetQuestion("example.com.", dns.TypeA)
	fw := &fakeWriter{}
	h.ServeDNS(fw, m)
	if fw.msg == nil || fw.msg.Rcode != dns.RcodeNameError {
		t.Fatalf("expected the IP-blocked answer to be NXDOMAIN, got %v", fw.msg)
	}
}
