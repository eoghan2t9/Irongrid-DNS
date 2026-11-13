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

// TestHandlerRandomizesUpstreamQueryIDButRestoresClientID verifies the
// serve() cache-poisoning hardening: the transaction ID sent to the
// upstream is no longer the client's own ID (see upstreamQuery.Id = dns.Id()
// in handler.go), yet the response handed back to the client always carries
// the client's original ID — a client that sees a mismatched ID silently
// discards the answer, so this is a correctness requirement, not just a
// nice-to-have.
func TestHandlerRandomizesUpstreamQueryIDButRestoresClientID(t *testing.T) {
	var upstreamSawID atomic.Uint32
	handler := dns.HandlerFunc(func(_ context.Context, w dns.ResponseWriter, r *dns.Msg) {
		upstreamSawID.Store(uint32(r.ID))
		m := new(dns.Msg)
		dnsutil.SetReply(m, r) // echoes r.ID back, exactly like a real resolver
		m.Answer = append(m.Answer, &dns.A{
			Hdr: dns.Header{Name: r.Question[0].Header().Name, Class: dns.ClassINET, TTL: 60},
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
	addr := pc.LocalAddr().String()

	h := NewHandler(filter.NewEngine(), nil, []*upstream.Upstream{{Transport: upstream.UDP, Addr: addr}}, nil, "nxdomain", 600, 5*time.Second)

	m := new(dns.Msg)
	dnsutil.SetQuestion(m, "example.com.", dns.TypeA)
	const clientID = 0xBEEF
	m.ID = clientID

	fw := &fakeWriter{}
	h.ServeDNS(context.Background(), fw, m)

	if fw.msg == nil {
		t.Fatal("expected a response, got none")
	}
	if fw.msg.ID != clientID {
		t.Fatalf("client-visible response ID = 0x%X, want 0x%X (client's own ID)", fw.msg.ID, clientID)
	}
	if upstreamSawID.Load() == clientID {
		t.Fatalf("upstream saw the client's own ID (0x%X) unchanged — expected a randomized per-hop ID", clientID)
	}
}
