package dnsplan

import (
	"errors"
	"net"
	"reflect"
	"strings"
	"testing"
)

var allProtocols = Endpoint{Host: "DNS.Example.com.", DoT: 853, DoQ: 853, DoH: 443, DoHPath: "/dns-query"}

func byType(ws []Want, typ string) []Want {
	var out []Want
	for _, w := range ws {
		if w.Type == typ {
			out = append(out, w)
		}
	}
	return out
}

func TestBuildPublishesAddressesDiscoveryAndHTTPS(t *testing.T) {
	t.Parallel()
	ws := Build(allProtocols, []string{"192.0.2.10"}, []string{"2001:db8::10"}, true)

	if a := byType(ws, "A"); len(a) != 1 || a[0].Name != "dns.example.com" || a[0].Content != "192.0.2.10" {
		t.Errorf("A = %+v, want one record for the normalised hostname", a)
	}
	if a := byType(ws, "AAAA"); len(a) != 1 || a[0].Content != "2001:db8::10" {
		t.Errorf("AAAA = %+v", a)
	}

	svcb := byType(ws, "SVCB")
	if len(svcb) != 3 {
		t.Fatalf("SVCB records = %d, want DoH, DoT and DoQ: %+v", len(svcb), svcb)
	}
	// Same order, ALPNs and parameters the server answers for DDR.
	wantValues := []string{
		`alpn="h2" ipv4hint="192.0.2.10" ipv6hint="2001:db8::10" dohpath="/dns-query{?dns}"`,
		`alpn="dot" ipv4hint="192.0.2.10" ipv6hint="2001:db8::10"`,
		`alpn="doq" ipv4hint="192.0.2.10" ipv6hint="2001:db8::10"`,
	}
	for i, w := range svcb {
		if w.Name != "_dns.dns.example.com" || w.Priority != i+1 || w.Target != "dns.example.com" || w.Value() != wantValues[i] {
			t.Errorf("SVCB[%d] = prio %d target %q name %q value %q; want prio %d value %q", i, w.Priority, w.Target, w.Name, w.Value(), i+1, wantValues[i])
		}
	}

	https := byType(ws, "HTTPS")
	if len(https) != 1 || https[0].Name != "dns.example.com" || https[0].Priority != 1 || https[0].Target != "." ||
		https[0].Value() != `alpn="h2" ipv4hint="192.0.2.10" ipv6hint="2001:db8::10"` {
		t.Errorf("HTTPS = %+v", https)
	}
}

func TestBuildFollowsTheEnabledListeners(t *testing.T) {
	t.Parallel()
	// Non-default ports are published; a transport that is off is not.
	ws := Build(Endpoint{Host: "dns.example.com", DoT: 8853, DoH: 8443, DoH3: 8443}, []string{"192.0.2.10"}, nil, true)
	svcb := byType(ws, "SVCB")
	if len(svcb) != 2 {
		t.Fatalf("SVCB = %+v, want DoH(+H3) and DoT only", svcb)
	}
	if svcb[0].Params["alpn"] != "h2,h3" || svcb[0].Params["port"] != "8443" {
		t.Errorf("DoH record = %v, want h2,h3 on 8443 sharing one record", svcb[0].Params)
	}
	if svcb[1].Params["alpn"] != "dot" || svcb[1].Params["port"] != "8853" {
		t.Errorf("DoT record = %v", svcb[1].Params)
	}
	if byType(ws, "AAAA") != nil {
		t.Error("an AAAA record was planned without an IPv6 address")
	}
	if byType(ws, "HTTPS") != nil {
		t.Error("an HTTPS record was planned for a port other than 443, where it would be wrong")
	}

	// A separate HTTP/3 port gets its own discovery record.
	sep := Build(Endpoint{Host: "dns.example.com", DoH: 443, DoH3: 8443}, nil, nil, false)
	if s := byType(sep, "SVCB"); len(s) != 2 || s[1].Params["alpn"] != "h3" || s[1].Params["port"] != "8443" {
		t.Errorf("separate DoH3 = %+v", s)
	}
	if got := Build(Endpoint{Host: "dns.example.com"}, []string{"192.0.2.1"}, nil, true); len(byType(got, "SVCB")) != 0 || len(byType(got, "HTTPS")) != 0 {
		t.Errorf("records planned with no encrypted protocol: %+v", got)
	}
	if Build(Endpoint{}, []string{"192.0.2.1"}, nil, true) != nil {
		t.Error("a plan was built without a hostname")
	}
}

func TestHTTPSRecordCanBeSkippedAndAdvertisesH3Only3WhenEnabled(t *testing.T) {
	t.Parallel()
	if len(byType(Build(allProtocols, []string{"192.0.2.1"}, nil, false), "HTTPS")) != 0 {
		t.Error("an HTTPS record was planned although it was switched off")
	}
	ep := allProtocols
	ep.DoH3 = 443
	h := byType(Build(ep, []string{"192.0.2.1"}, nil, true), "HTTPS")
	if len(h) != 1 || h[0].Params["alpn"] != "h2,h3" {
		t.Errorf("HTTPS with DoH3 on 443 = %+v, want h2,h3", h)
	}
}

func TestParseSVCBToleratesQuotingOrderAndHintFormatting(t *testing.T) {
	t.Parallel()
	p, target, kv, ok := ParseSVCB(`1 dns.example.com. dohpath="/dns-query{?dns}" ipv4hint="192.0.2.2,192.0.2.1" alpn=h2`)
	if !ok || p != 1 || target != "dns.example.com." {
		t.Fatalf("parsed = %d %q ok=%v", p, target, ok)
	}
	want := map[string]string{"alpn": "h2", "ipv4hint": "192.0.2.1,192.0.2.2", "dohpath": "/dns-query{?dns}"}
	if !reflect.DeepEqual(kv, want) {
		t.Errorf("params = %v, want %v", kv, want)
	}
	for _, bad := range []string{"", "1", "x host alpn=h2", "-1 host"} {
		if _, _, _, ok := ParseSVCB(bad); ok {
			t.Errorf("ParseSVCB(%q) accepted garbage", bad)
		}
	}
}

func a(ip string) Have { return Have{ID: "a-" + ip, Type: "A", Name: "dns.example.com", Content: ip} }
func item(t *testing.T, items []Item, state State) Item {
	t.Helper()
	for _, it := range items {
		if it.State == state {
			return it
		}
	}
	t.Fatalf("no %s item in %+v", state, items)
	return Item{}
}

func TestDiffAddressesCreateOKAndUpdateInPlaceWhenTheIPChanges(t *testing.T) {
	t.Parallel()
	ep := Endpoint{Host: "dns.example.com", DoT: 853}
	wants := Build(ep, []string{"192.0.2.10"}, nil, false)[:1] // just the A record

	// Nothing there: create.
	if it := item(t, Diff(wants, nil), StateMissing); it.Action != ActionCreate || it.Have != nil {
		t.Errorf("missing = %+v", it)
	}
	// Already right: nothing to do.
	if it := item(t, Diff(wants, []Have{a("192.0.2.10")}), StateOK); it.Action != ActionNone {
		t.Errorf("ok = %+v", it)
	}
	// The server's address changed: the existing record is updated in place,
	// not duplicated and not deleted.
	items := Diff(wants, []Have{a("198.51.100.7")})
	if len(items) != 1 || items[0].State != StateDiffers || items[0].Action != ActionUpdate || items[0].Have.ID != "a-198.51.100.7" {
		t.Errorf("changed IP = %+v, want one in-place update", items)
	}
	// A proxied address record is the right IP but the wrong kind.
	px := a("192.0.2.10")
	px.Proxied = true
	if it := item(t, Diff(wants, []Have{px}), StateDiffers); it.Action != ActionUpdate || !strings.Contains(it.Detail, "proxied") {
		t.Errorf("proxied = %+v", it)
	}
	// Extra addresses are reported for deletion but never matched away.
	items = Diff(wants, []Have{a("192.0.2.10"), a("203.0.113.9")})
	if e := item(t, items, StateExtra); e.Action != ActionDelete || e.Have.Content != "203.0.113.9" {
		t.Errorf("extra = %+v", e)
	}
	if item(t, items, StateOK).Want.Content != "192.0.2.10" {
		t.Error("the correct address was not recognised alongside the extra one")
	}
}

func TestDiffTreatsEquivalentIPv6SpellingsAsTheSame(t *testing.T) {
	t.Parallel()
	wants := []Want{{Type: "AAAA", Name: "dns.example.com", Content: "2001:db8::10"}}
	have := []Have{{ID: "x", Type: "AAAA", Name: "DNS.example.com.", Content: "2001:0db8:0000:0000:0000:0000:0000:0010"}}
	if it := item(t, Diff(wants, have), StateOK); it.Action != ActionNone {
		t.Errorf("= %+v", it)
	}
}

func TestDiffNeverTouchesANameThatHasACNAME(t *testing.T) {
	t.Parallel()
	wants := Build(allProtocols, []string{"192.0.2.10"}, nil, true)
	have := []Have{{ID: "c", Type: "CNAME", Name: "dns.example.com", Content: "tunnel.cfargotunnel.com", Proxied: true}}
	for _, it := range Diff(wants, have) {
		// Only the records that live at the CNAME's own name are blocked; the
		// discovery records sit under _dns.<host>, a different name.
		if it.Want.Name == "dns.example.com" && (it.State != StateConflict || it.Action != ActionNone) {
			t.Errorf("at the CNAME's name %s was %s/%s, want conflict and no action", it.Want.Type, it.State, it.Action)
		}
		if it.Want.Name == "_dns.dns.example.com" && it.State != StateMissing {
			t.Errorf("the discovery record %s was %s, want it unaffected by the CNAME", it.Want.Type, it.State)
		}
	}
	if n := len(Diff(wants, have)); n != len(wants) {
		t.Errorf("%d items for %d wanted records", n, len(wants))
	}
}

func TestDiffSVCBMatchesByPrioritySemantically(t *testing.T) {
	t.Parallel()
	wants := Build(allProtocols, []string{"192.0.2.10"}, nil, false)
	svcb := byType(wants, "SVCB")

	// What Cloudflare returns: other key order, quotes, trailing dot.
	have := []Have{
		{ID: "doh", Type: "SVCB", Name: "_dns.dns.example.com", Content: `1 dns.example.com. dohpath="/dns-query{?dns}" alpn="h2" ipv4hint="192.0.2.10"`},
		{ID: "dot", Type: "SVCB", Name: "_dns.dns.example.com", Content: `2 dns.example.com. alpn="dot" ipv4hint="198.51.100.1"`}, // stale hint
		{ID: "old", Type: "SVCB", Name: "_dns.dns.example.com", Content: `9 dns.example.com. alpn="h3"`},                          // no longer advertised
	}
	items := Diff(svcb, have)
	by := map[State][]Item{}
	for _, it := range items {
		by[it.State] = append(by[it.State], it)
	}
	if len(by[StateOK]) != 1 || by[StateOK][0].Have.ID != "doh" {
		t.Errorf("ok = %+v, want the reordered but equivalent DoH record", by[StateOK])
	}
	if len(by[StateDiffers]) != 1 || by[StateDiffers][0].Have.ID != "dot" || by[StateDiffers][0].Action != ActionUpdate {
		t.Errorf("differs = %+v, want the DoT record updated in place", by[StateDiffers])
	}
	if len(by[StateMissing]) != 1 || by[StateMissing][0].Want.Params["alpn"] != "doq" {
		t.Errorf("missing = %+v, want the DoQ record created", by[StateMissing])
	}
	if len(by[StateExtra]) != 1 || by[StateExtra][0].Have.ID != "old" || by[StateExtra][0].Action != ActionDelete {
		t.Errorf("extra = %+v, want the stale priority-9 record flagged", by[StateExtra])
	}
}

func TestHTTPSTargetDotMatchesRegardlessOfSpelling(t *testing.T) {
	t.Parallel()
	wants := byType(Build(allProtocols, []string{"192.0.2.10"}, nil, true), "HTTPS")
	have := []Have{{ID: "h", Type: "HTTPS", Name: "dns.example.com", Content: `1 . alpn="h2" ipv4hint="192.0.2.10"`}}
	if it := item(t, Diff(wants, have), StateOK); it.Action != ActionNone {
		t.Errorf("= %+v", it)
	}
}

func TestPublicAddressClassification(t *testing.T) {
	t.Parallel()
	for ip, want := range map[string]bool{
		"192.0.2.10": true, "8.8.8.8": true,
		"10.1.2.3": false, "172.16.0.5": false, "192.168.1.1": false, "127.0.0.1": false,
		"169.254.1.1": false, "100.64.0.1": false, "100.127.255.254": false, "100.128.0.1": true,
	} {
		if got := Public4(net.ParseIP(ip)); got != want {
			t.Errorf("Public4(%s) = %v, want %v", ip, got, want)
		}
	}
	for ip, want := range map[string]bool{"2001:db8::1": true, "2606:4700::1": true, "fd00::1": false, "fe80::1": false, "::1": false} {
		if got := Public6(net.ParseIP(ip)); got != want {
			t.Errorf("Public6(%s) = %v, want %v", ip, got, want)
		}
	}
}

type fakeConn struct {
	net.Conn
	local net.Addr
}

func (f fakeConn) LocalAddr() net.Addr { return f.local }
func (f fakeConn) Close() error        { return nil }

func TestDetectPublicUsesTheRouteSourceAddressAndReportsNATAsAbsent(t *testing.T) {
	old := dial
	defer func() { dial = old }()

	dial = func(network, _ string) (net.Conn, error) {
		switch network {
		case "udp4":
			return fakeConn{local: &net.UDPAddr{IP: net.ParseIP("192.0.2.10")}}, nil
		default:
			return fakeConn{local: &net.UDPAddr{IP: net.ParseIP("2001:db8::10")}}, nil
		}
	}
	if v4, v6 := DetectPublic(); v4 != "192.0.2.10" || v6 != "2001:db8::10" {
		t.Errorf("DetectPublic = %q, %q", v4, v6)
	}

	// Behind NAT the local address is private: not reported as the public one.
	dial = func(network, _ string) (net.Conn, error) {
		if network == "udp4" {
			return fakeConn{local: &net.UDPAddr{IP: net.ParseIP("10.0.0.5")}}, nil
		}
		return nil, errors.New("no IPv6 route")
	}
	if v4, v6 := DetectPublic(); v4 != "" || v6 != "" {
		t.Errorf("DetectPublic behind NAT = %q, %q, want neither", v4, v6)
	}
}
