package dnsserver

import (
	"net"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/eoghan2t9/Irongrid-DNS/internal/filter"
)

func ddrQuery(t *testing.T, h *Handler, qtype uint16) *dns.Msg {
	t.Helper()
	m := new(dns.Msg)
	m.SetQuestion("_dns.resolver.arpa.", qtype)
	fw := &fakeWriter{}
	h.ServeDNS(fw, m)
	if fw.msg == nil {
		t.Fatal("no response")
	}
	return fw.msg
}

func TestDDRAnswersSVCBForEveryEncryptedTransport(t *testing.T) {
	// No upstreams: the query must be answered locally, never forwarded.
	h := NewHandler(filter.NewEngine(), nil, nil, nil, "nxdomain", 600, 5*time.Second)
	h.SetDDR(NewDDRConfig("dns.example.net", "0.0.0.0:853", "0.0.0.0:443", "0.0.0.0:443", "0.0.0.0:8853", "/dns-query"))

	resp := ddrQuery(t, h, dns.TypeSVCB)
	if resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("rcode = %s", dns.RcodeToString[resp.Rcode])
	}
	// DoH+DoH3 share a record (same port), then DoT, then DoQ.
	if len(resp.Answer) != 3 {
		t.Fatalf("want 3 SVCB records, got %d: %v", len(resp.Answer), resp.Answer)
	}
	byAlpn := map[string]*dns.SVCB{}
	for _, rr := range resp.Answer {
		s, ok := rr.(*dns.SVCB)
		if !ok {
			t.Fatalf("not SVCB: %T", rr)
		}
		if s.Target != "dns.example.net." {
			t.Errorf("target = %q", s.Target)
		}
		var alpn []string
		for _, kv := range s.Value {
			if a, ok := kv.(*dns.SVCBAlpn); ok {
				alpn = a.Alpn
			}
		}
		byAlpn[strings.Join(alpn, ",")] = s
	}
	doh, dot, doq := byAlpn["h2,h3"], byAlpn["dot"], byAlpn["doq"]
	if doh == nil || dot == nil || doq == nil {
		t.Fatalf("missing transport record: %v", byAlpn)
	}
	if !(doh.Priority < dot.Priority && dot.Priority < doq.Priority) {
		t.Errorf("priorities not ordered DoH<DoT<DoQ: %d %d %d", doh.Priority, dot.Priority, doq.Priority)
	}
	// Default ports are omitted; the non-default DoQ port is stated.
	port := func(s *dns.SVCB) int {
		for _, kv := range s.Value {
			if p, ok := kv.(*dns.SVCBPort); ok {
				return int(p.Port)
			}
		}
		return 0
	}
	if port(doh) != 0 || port(dot) != 0 {
		t.Errorf("default ports should be omitted: doh=%d dot=%d", port(doh), port(dot))
	}
	if port(doq) != 8853 {
		t.Errorf("doq port = %d, want 8853", port(doq))
	}
	// dohpath only on the HTTPS-based record, as an RFC 6570 template.
	var path string
	for _, kv := range doh.Value {
		if p, ok := kv.(*dns.SVCBDoHPath); ok {
			path = p.Template
		}
	}
	if path != "/dns-query{?dns}" {
		t.Errorf("dohpath = %q", path)
	}
	// The address the query arrived on is hinted.
	var hint net.IP
	for _, kv := range dot.Value {
		if h4, ok := kv.(*dns.SVCBIPv4Hint); ok && len(h4.Hint) == 1 {
			hint = h4.Hint[0]
		}
	}
	if !hint.Equal(net.IPv4(127, 0, 0, 1)) {
		t.Errorf("ipv4hint = %v, want the local address", hint)
	}
	// SvcParams must be in ascending key order and survive the wire.
	packed, err := resp.Pack()
	if err != nil {
		t.Fatalf("pack: %v", err)
	}
	var back dns.Msg
	if err := back.Unpack(packed); err != nil {
		t.Fatalf("unpack: %v", err)
	}
	if len(back.Answer) != 3 {
		t.Fatalf("round trip lost records: %d", len(back.Answer))
	}
}

func TestDDRWithoutConfigIsNODATANotForwarded(t *testing.T) {
	h := NewHandler(filter.NewEngine(), nil, nil, nil, "nxdomain", 600, 5*time.Second)
	for _, qt := range []uint16{dns.TypeSVCB, dns.TypeA, dns.TypeAAAA} {
		resp := ddrQuery(t, h, qt)
		if resp.Rcode != dns.RcodeSuccess || len(resp.Answer) != 0 {
			t.Errorf("type %d: want NOERROR/NODATA, got %s with %d answers", qt, dns.RcodeToString[resp.Rcode], len(resp.Answer))
		}
	}
}

func TestDDROtherTypesAreNODATA(t *testing.T) {
	h := NewHandler(filter.NewEngine(), nil, nil, nil, "nxdomain", 600, 5*time.Second)
	h.SetDDR(NewDDRConfig("dns.example.net", "0.0.0.0:853", "", "", "", ""))
	if resp := ddrQuery(t, h, dns.TypeA); resp.Rcode != dns.RcodeSuccess || len(resp.Answer) != 0 {
		t.Fatalf("A query: want NODATA, got %v", resp)
	}
	if resp := ddrQuery(t, h, dns.TypeSVCB); len(resp.Answer) != 1 {
		t.Fatalf("DoT-only should give one record, got %d", len(resp.Answer))
	}
}

func TestNewDDRConfigRejectsEmpty(t *testing.T) {
	if NewDDRConfig("", "0.0.0.0:853", "", "", "", "") != nil {
		t.Error("no host must advertise nothing")
	}
	if NewDDRConfig("dns.example.net", "", "", "", "", "") != nil {
		t.Error("no encrypted listener must advertise nothing")
	}
	c := NewDDRConfig("DNS.Example.Net.", "bad", ":853", "", "", "")
	if c == nil || c.Host != "dns.example.net" || c.DoT != 0 || c.DoH != 853 || c.DoHPath != "/dns-query" {
		t.Errorf("unexpected config: %+v", c)
	}
}
