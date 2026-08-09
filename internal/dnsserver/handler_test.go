package dnsserver

import (
	"context"
	"net"
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
// refused on every domain. Auto-blocking only fires over connection-oriented
// transports: a spoofable UDP source must never be able to permanently block
// an innocent victim (see the serve() comment), so UDP honeypot queries are
// refused but leave the client unblocked.
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
	// A honeypot query over UDP is refused but must NOT auto-block: UDP
	// sources can be spoofed, so trusting one would let an attacker block an
	// innocent victim with a single spoofed packet.
	udpClient := &fakeWriter{ip: net.ParseIP("203.0.113.9")}
	h.ServeDNS(udpClient, q("trap.example.com."))
	if udpClient.msg == nil || udpClient.msg.Rcode != dns.RcodeRefused {
		t.Fatalf("UDP honeypot query: expected REFUSED, got %v", udpClient.msg)
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
	// Subdomain over UDP is refused but never auto-blocks (spoofable source).
	udpSub := &fakeWriter{ip: net.ParseIP("198.51.100.99")}
	h.ServeDNS(udpSub, q("rand-7e1a.trap.example.com."))
	if udpSub.msg == nil || udpSub.msg.Rcode != dns.RcodeRefused {
		t.Fatalf("UDP subdomain honeypot query: expected REFUSED, got %v", udpSub.msg)
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
	// Honeypot hits (apex over UDP, random subdomain over UDP) are refused
	// and must not reach the log.
	for _, name := range []string{"trap.example.com.", "rand-9f2a.trap.example.com."} {
		fw := &fakeWriter{ip: net.ParseIP("203.0.113.9")}
		h.ServeDNS(fw, q(name))
		if fw.msg == nil || fw.msg.Rcode != dns.RcodeRefused {
			t.Fatalf("honeypot query %s: expected REFUSED, got %v", name, fw.msg)
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
// plain-UDP honeypot hit is refused but never auto-blocks its source (UDP can
// be spoofed, so trusting it would let an attacker block an innocent victim).
// With TrustUDP set, the UDP source is auto-blocked too — an operator choice
// for trusted networks.
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
	if fw.msg == nil || fw.msg.Rcode != dns.RcodeRefused {
		t.Fatalf("UDP honeypot query with trust_udp: expected REFUSED, got %v", fw.msg)
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
