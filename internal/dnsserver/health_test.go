package dnsserver

import (
	"context"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
	"codeberg.org/miekg/dns/rdata"
	"github.com/eoghan2t9/Irongrid-DNS/internal/filter"
	"github.com/eoghan2t9/Irongrid-DNS/internal/upstream"
)

// startCountingUDPTestServer runs a tiny UDP DNS server that answers every
// query with a minimal A record and records how many queries it received
// plus the qname/qtype of the last one.
func startCountingUDPTestServer(t *testing.T) (addr string, count *atomic.Int64, lastQname *atomic.Value) {
	t.Helper()
	count = &atomic.Int64{}
	lastQname = &atomic.Value{}
	handler := dns.HandlerFunc(func(_ context.Context, w dns.ResponseWriter, r *dns.Msg) {
		count.Add(1)
		qname := r.Question[0].Header().Name
		lastQname.Store(qname)
		m := new(dns.Msg)
		dnsutil.SetReply(m, r)
		m.Answer = append(m.Answer, &dns.A{
			Hdr: dns.Header{Name: qname, Class: dns.ClassINET, TTL: 60},
			A:   rdata.A{Addr: netip.MustParseAddr("93.184.216.34")},
		})
		_, _ = m.WriteTo(w)
	})
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	started := make(chan struct{})
	srv := &dns.Server{PacketConn: pc, Handler: handler, NotifyStartedFunc: func(context.Context) { close(started) }}
	go func() { _ = srv.ListenAndServe() }()
	<-started
	t.Cleanup(func() { srv.Shutdown(context.Background()) })
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
