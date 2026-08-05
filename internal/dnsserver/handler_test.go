package dnsserver

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/eoghan2t9/Irongrid-DNS/internal/filter"
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

// fakeWriter implements dns.ResponseWriter for direct handler invocation.
type fakeWriter struct{ msg *dns.Msg }

func (f *fakeWriter) LocalAddr() net.Addr { return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 53} }
func (f *fakeWriter) RemoteAddr() net.Addr {
	return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345}
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
