package dnsserver

import (
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/eoghan2t9/Irongrid-DNS/internal/filter"
	"github.com/eoghan2t9/Irongrid-DNS/internal/upstream"
)

// TestConditionalRoutes verifies that a per-domain route sends matching
// queries (exact domain AND every subdomain) to its own upstream set while
// everything else uses the global forwarders — and that the longest matching
// route wins when routes overlap.
func TestConditionalRoutes(t *testing.T) {
	var globalHits, routeHits, deepHits atomic.Int32
	globalAddr := startUDPCountingServer(t, "203.0.113.7", &globalHits)
	routeAddr := startUDPCountingServer(t, "198.51.100.9", &routeHits)
	deepAddr := startUDPCountingServer(t, "192.0.2.44", &deepHits)

	h := NewHandler(filter.NewEngine(), nil, []*upstream.Upstream{
		{Transport: upstream.UDP, Addr: globalAddr},
	}, nil, "nxdomain", 600, 5*time.Second)
	routes, err := ParseRoutes([]RouteSpec{
		{Domain: "lan", Upstreams: []string{"udp://" + routeAddr}},
		{Domain: "deep.lan", Upstreams: []string{"udp://" + deepAddr}},
	})
	if err != nil {
		t.Fatal(err)
	}
	h.SetUpstreamRoutes(routes)

	query := func(name string, qtype uint16) *dns.Msg {
		m := new(dns.Msg)
		m.SetQuestion(name, qtype)
		fw := &fakeWriter{}
		h.ServeDNS(fw, m)
		return fw.msg
	}

	// A name under the route domain (subdomain of lan) goes to the route.
	if msg := query("printer.lan.", dns.TypeA); msg == nil || len(msg.Answer) != 1 {
		t.Fatalf("printer.lan: no answer (route hits=%d)", routeHits.Load())
	} else if a := msg.Answer[0].(*dns.A); !a.A.Equal(net.ParseIP("198.51.100.9")) {
		t.Fatalf("printer.lan answered %v, want the route's 198.51.100.9", a.A)
	}
	// The exact route domain itself also routes.
	query("lan.", dns.TypeA)
	// Everything else uses the global forwarders.
	query("example.com.", dns.TypeA)
	query("sub.lan.example.com.", dns.TypeA)

	if routeHits.Load() != 2 {
		t.Fatalf("route hits = %d, want 2 (printer.lan + lan)", routeHits.Load())
	}
	if globalHits.Load() != 2 {
		t.Fatalf("global hits = %d, want 2 (example.com + sub.lan.example.com)", globalHits.Load())
	}
	if deepHits.Load() != 0 {
		t.Fatalf("deep route hit for non-matching names = %d, want 0", deepHits.Load())
	}

	// Longest match wins: x.deep.lan is under BOTH lan and deep.lan.
	query("x.deep.lan.", dns.TypeA)
	if deepHits.Load() != 1 {
		t.Fatalf("deep route hits = %d, want 1 (longest match)", deepHits.Load())
	}
	if routeHits.Load() != 2 {
		t.Fatalf("route hits after deep query = %d, want unchanged 2", routeHits.Load())
	}

	// A bad route spec (unsupported scheme) fails ParseRoutes, and because
	// SetUpstreamRoutes was never called with it the previous routes remain
	// live.
	if _, err := ParseRoutes([]RouteSpec{{Domain: "lan", Upstreams: []string{"ftp://1.2.3.4"}}}); err == nil {
		t.Fatal("bad route spec accepted")
	}
	query("printer.lan.", dns.TypeA)
	if routeHits.Load() != 3 {
		t.Fatalf("route hits after failed parse = %d, want 3 (old routes still live)", routeHits.Load())
	}
}
