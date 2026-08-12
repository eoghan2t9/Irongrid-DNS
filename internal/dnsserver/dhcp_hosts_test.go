package dnsserver

import (
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/eoghan2t9/Irongrid-DNS/internal/filter"
	"github.com/eoghan2t9/Irongrid-DNS/internal/upstream"
)

// fakeDHCPResolver implements DHCPHostResolver with a fixed hostname map.
type fakeDHCPResolver struct {
	hosts map[string][]net.IP
}

func (f *fakeDHCPResolver) LookupHost(name string) ([]net.IP, bool) {
	// Mirror the real server: strip the trailing dot, lowercase, and peel
	// the configured .lan domain suffix (printer.lan -> printer).
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	name = strings.TrimSuffix(name, ".lan")
	ips, ok := f.hosts[name]
	return ips, ok
}

// TestDHCPHostnameResolution verifies that a DHCP-registered client hostname
// resolves locally (Pi-hole style: bare name AND name.domain) without ever
// touching an upstream, and that unknown names fall through to the upstream.
func TestDHCPHostnameResolution(t *testing.T) {
	var upstreamHits atomic.Int32
	// An upstream that answers every query — used to prove the DHCP hook
	// short-circuits before the upstream for known hostnames.
	upAddr := startUDPCountingServer(t, "203.0.113.7", &upstreamHits)
	h := NewHandler(filter.NewEngine(), nil, []*upstream.Upstream{
		{Transport: upstream.UDP, Addr: upAddr},
	}, nil, "nxdomain", 600, 5*time.Second)

	h.DHCPHosts = &fakeDHCPResolver{
		hosts: map[string][]net.IP{
			"printer": {net.ParseIP("192.168.1.50")},
			"nas":     {net.ParseIP("fd00::50")},
		},
	}

	// Bare hostname, A query.
	m := new(dns.Msg)
	m.SetQuestion("printer.", dns.TypeA)
	fw := &fakeWriter{}
	h.ServeDNS(fw, m)
	if fw.msg == nil || len(fw.msg.Answer) != 1 {
		t.Fatalf("printer A: got %d answers, want 1 (upstream hits=%d)", len(fw.msg.Answer), upstreamHits.Load())
	}
	if a, ok := fw.msg.Answer[0].(*dns.A); !ok || !a.A.Equal(net.ParseIP("192.168.1.50")) {
		t.Fatalf("printer A = %v, want 192.168.1.50", fw.msg.Answer[0])
	}

	// Hostname with domain suffix, A query.
	m2 := new(dns.Msg)
	m2.SetQuestion("printer.lan.", dns.TypeA)
	fw2 := &fakeWriter{}
	h.ServeDNS(fw2, m2)
	if len(fw2.msg.Answer) != 1 {
		t.Fatalf("printer.lan A: got %d answers, want 1", len(fw2.msg.Answer))
	}
	if a, ok := fw2.msg.Answer[0].(*dns.A); !ok || !a.A.Equal(net.ParseIP("192.168.1.50")) {
		t.Fatalf("printer.lan A = %v, want 192.168.1.50", fw2.msg.Answer[0])
	}

	// IPv6 hostname, AAAA query.
	m3 := new(dns.Msg)
	m3.SetQuestion("nas.lan.", dns.TypeAAAA)
	fw3 := &fakeWriter{}
	h.ServeDNS(fw3, m3)
	if len(fw3.msg.Answer) != 1 {
		t.Fatalf("nas.lan AAAA: got %d answers, want 1", len(fw3.msg.Answer))
	}
	if aaaa, ok := fw3.msg.Answer[0].(*dns.AAAA); !ok || !aaaa.AAAA.Equal(net.ParseIP("fd00::50")) {
		t.Fatalf("nas.lan AAAA = %v, want fd00::50", fw3.msg.Answer[0])
	}

	// Unknown hostname falls through to the upstream.
	hitsBefore := upstreamHits.Load()
	m4 := new(dns.Msg)
	m4.SetQuestion("something.else.", dns.TypeA)
	fw4 := &fakeWriter{}
	h.ServeDNS(fw4, m4)
	if upstreamHits.Load() == hitsBefore {
		t.Fatal("unknown hostname did not reach the upstream")
	}
	if len(fw4.msg.Answer) != 1 {
		t.Fatalf("fall-through A: got %d answers, want 1", len(fw4.msg.Answer))
	}
}

// TestDHCPHostnameDoesNotLeakToAAAAForV4Only verifies that a v4-only
// hostname answers an A query but not AAAA.
func TestDHCPHostnameDoesNotLeakToAAAAForV4Only(t *testing.T) {
	var upstreamHits atomic.Int32
	upAddr := startUDPCountingServer(t, "203.0.113.7", &upstreamHits)
	h := NewHandler(filter.NewEngine(), nil, []*upstream.Upstream{
		{Transport: upstream.UDP, Addr: upAddr},
	}, nil, "nxdomain", 600, 5*time.Second)
	h.DHCPHosts = &fakeDHCPResolver{
		hosts: map[string][]net.IP{
			"printer": {net.ParseIP("192.168.1.50")},
		},
	}

	// AAAA for a v4-only hostname: the resolver returns a v4 address, so the
	// handler must answer NODATA (no AAAA) instead of leaking the A.
	m := new(dns.Msg)
	m.SetQuestion("printer.", dns.TypeAAAA)
	fw := &fakeWriter{}
	h.ServeDNS(fw, m)
	if fw.msg == nil {
		t.Fatal("no response")
	}
	if len(fw.msg.Answer) != 0 {
		t.Fatalf("AAAA for v4-only hostname answered with %d records", len(fw.msg.Answer))
	}
	if fw.msg.Rcode != dns.RcodeSuccess {
		t.Fatalf("AAAA for v4-only hostname rcode = %d, want NOERROR (NODATA)", fw.msg.Rcode)
	}
}
