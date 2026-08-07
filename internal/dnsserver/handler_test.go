package dnsserver

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/eoghan2t9/Irongrid-DNS/internal/cache"
	"github.com/eoghan2t9/Irongrid-DNS/internal/filter"
	"github.com/eoghan2t9/Irongrid-DNS/internal/geoip"
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
		w.WriteMsg(m)
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
	f.msg = m
	return nil
}
func (f *fakeWriter) Write(b []byte) (int, error) { return len(b), nil }
func (f *fakeWriter) Close() error                { return nil }
func (f *fakeWriter) TsigStatus() error           { return nil }
func (f *fakeWriter) TsigTimersOnly(b bool)       {}
func (f *fakeWriter) Hijack()                     {}

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
// refused on every domain.
func TestHandlerIPBannerAndHoneypot(t *testing.T) {
	addr := startUDPTestServer(t, "1.1.1.1", 0)
	h := NewHandler(filter.NewEngine(), nil, []*upstream.Upstream{{Transport: upstream.UDP, Addr: addr}}, nil, "nxdomain", 600, 5*time.Second)

	var autoBlocked []string
	banner := geoip.NewBanner("", []string{"38.11.106.3"}, []string{"trap.example.com"})
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
	// A honeypot query auto-blocks its client and is itself refused.
	client := &fakeWriter{ip: net.ParseIP("203.0.113.9")}
	h.ServeDNS(client, q("trap.example.com."))
	if client.msg == nil || client.msg.Rcode != dns.RcodeRefused {
		t.Fatalf("honeypot query: expected REFUSED, got %v", client.msg)
	}
	if len(autoBlocked) != 1 || autoBlocked[0] != "203.0.113.9" {
		t.Fatalf("OnBlock fired %v, want [203.0.113.9]", autoBlocked)
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
	c := cache.NewLocalOnly(time.Hour, time.Minute, 512)
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
