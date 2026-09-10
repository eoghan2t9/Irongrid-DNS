package dnsserver

import (
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/eoghan2t9/Irongrid-DNS/internal/filter"
	"github.com/eoghan2t9/Irongrid-DNS/internal/upstream"
	"github.com/miekg/dns"
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
	mux := dns.NewServeMux()
	mux.HandleFunc(".", func(w dns.ResponseWriter, r *dns.Msg) {
		upstreamSawID.Store(uint32(r.Id))
		m := new(dns.Msg)
		m.SetReply(r) // echoes r.Id back, exactly like a real resolver
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
	addr := pc.LocalAddr().String()

	h := NewHandler(filter.NewEngine(), nil, []*upstream.Upstream{{Transport: upstream.UDP, Addr: addr}}, nil, "nxdomain", 600, 5*time.Second)

	m := new(dns.Msg)
	m.SetQuestion("example.com.", dns.TypeA)
	const clientID = 0xBEEF
	m.Id = clientID

	fw := &fakeWriter{}
	h.ServeDNS(fw, m)

	if fw.msg == nil {
		t.Fatal("expected a response, got none")
	}
	if fw.msg.Id != clientID {
		t.Fatalf("client-visible response ID = 0x%X, want 0x%X (client's own ID)", fw.msg.Id, clientID)
	}
	if upstreamSawID.Load() == clientID {
		t.Fatalf("upstream saw the client's own ID (0x%X) unchanged — expected a randomized per-hop ID", clientID)
	}
}
