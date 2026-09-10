package dnsserver

import (
	"context"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/eoghan2t9/Irongrid-DNS/internal/filter"
	"github.com/eoghan2t9/Irongrid-DNS/internal/upstream"
	"github.com/miekg/dns"
)

// startCountingUDPTestServer runs a tiny UDP DNS server that answers every
// query with a minimal A record and records how many queries it received
// plus the qname/qtype of the last one.
func startCountingUDPTestServer(t *testing.T) (addr string, count *atomic.Int64, lastQname *atomic.Value) {
	t.Helper()
	count = &atomic.Int64{}
	lastQname = &atomic.Value{}
	mux := dns.NewServeMux()
	mux.HandleFunc(".", func(w dns.ResponseWriter, r *dns.Msg) {
		count.Add(1)
		lastQname.Store(r.Question[0].Name)
		m := new(dns.Msg)
		m.SetReply(r)
		m.Answer = append(m.Answer, &dns.A{
			Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
			A:   net.ParseIP("93.184.216.34"),
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
	return pc.LocalAddr().String(), count, lastQname
}

func TestProbeUpstreamsDisabledByDefault(t *testing.T) {
	addr, count, _ := startCountingUDPTestServer(t)
	h := NewHandler(filter.NewEngine(), nil, []*upstream.Upstream{{Transport: upstream.UDP, Addr: addr}}, nil, "nxdomain", 600, 5*time.Second)

	h.probeUpstreams(context.Background())
	time.Sleep(100 * time.Millisecond)

	if got := count.Load(); got != 0 {
		t.Fatalf("upstream_health disabled: expected 0 probe queries, got %d", got)
	}
}

func TestProbeUpstreamsSendsCanaryWhenEnabled(t *testing.T) {
	addr, count, lastQname := startCountingUDPTestServer(t)
	h := NewHandler(filter.NewEngine(), nil, []*upstream.Upstream{{Transport: upstream.UDP, Addr: addr}}, nil, "nxdomain", 600, 5*time.Second)
	h.SetUpstreamHealthCheck(true)

	h.probeUpstreams(context.Background())
	deadline := time.Now().Add(2 * time.Second)
	for count.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}

	if got := count.Load(); got != 1 {
		t.Fatalf("upstream_health enabled: expected exactly 1 probe query, got %d", got)
	}
	if got, _ := lastQname.Load().(string); got != upstreamHealthCheckDomain {
		t.Fatalf("probe queried %q, want %q", got, upstreamHealthCheckDomain)
	}
}
