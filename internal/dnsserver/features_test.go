package dnsserver

import (
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/eoghan2t9/Irongrid-DNS/internal/filter"
)

// TestDNSCookies verifies RFC 7873 server cookies end to end through the
// handler: a query carrying a COOKIE option gets its client cookie echoed
// with the handler's HMAC server cookie appended; a query carrying a forged
// server cookie is answered BADCOOKIE (with the correct cookie so the client
// can retry) instead of being processed; and nothing is minted when the
// feature is off.
func TestDNSCookies(t *testing.T) {
	h := NewHandler(filter.NewEngine(), nil, nil, nil, "nxdomain", 600, 5*time.Second)
	h.SetCookies(true)

	clientCookie := "1234567890abcdef" // 8 bytes, hex
	newQuery := func(cookie string) *dns.Msg {
		q := new(dns.Msg)
		q.SetQuestion("example.com.", dns.TypeA)
		if cookie != "" {
			opt := new(dns.OPT)
			opt.Hdr.Name = "."
			opt.Hdr.Rrtype = dns.TypeOPT
			opt.SetUDPSize(4096)
			opt.Option = append(opt.Option, &dns.EDNS0_COOKIE{Code: dns.EDNS0COOKIE, Cookie: cookie})
			q.Extra = append(q.Extra, opt)
		}
		return q
	}

	// 1. Valid client cookie → the response echoes it plus an 8-byte server
	//    cookie (32 hex chars total) that matches the handler's own
	//    generator for this client IP.
	w := &fakeWriter{}
	h.ServeDNSWithProto(w, newQuery(clientCookie), "udp")
	if w.msg == nil {
		t.Fatal("no response")
	}
	sc := h.serverCookie("127.0.0.1", clientCookie)
	if want := clientCookie + sc; requestCookieValue(w.msg) != want {
		t.Fatalf("response cookie %q != expected %q", requestCookieValue(w.msg), want)
	}
	if got := requestCookieValue(w.msg); len(got) != 2*clientCookieHexLen {
		t.Fatalf("response cookie length %d, want %d (client + server)", len(got), 2*clientCookieHexLen)
	}

	// 2. Forged server cookie → BADCOOKIE, correct cookie attached so the
	//    client can retry with it.
	w2 := &fakeWriter{}
	h.ServeDNSWithProto(w2, newQuery(clientCookie+"deadbeefdeadbeef"), "udp")
	if w2.msg == nil {
		t.Fatal("no BADCOOKIE response")
	}
	if w2.msg.Rcode != dns.RcodeBadCookie {
		t.Fatalf("forged cookie: rcode %d, want BADCOOKIE (%d)", w2.msg.Rcode, dns.RcodeBadCookie)
	}
	if got := requestCookieValue(w2.msg); got != clientCookie+sc {
		t.Fatalf("BADCOOKIE response cookie %q != correct %q", got, clientCookie+sc)
	}

	// 3. Feature off → no server cookie minted at all.
	h.SetCookies(false)
	w3 := &fakeWriter{}
	h.ServeDNSWithProto(w3, newQuery(clientCookie), "udp")
	if w3.msg == nil {
		t.Fatal("no response")
	}
	if got := requestCookieValue(w3.msg); got != "" {
		t.Fatalf("cookies disabled but response carried cookie %q", got)
	}
}

// TestEDNSPadding verifies RFC 7830 padding: with padding enabled, responses
// on the encrypted transports carry an EDNS0_PADDING option that lands the
// packed length on a 128-byte boundary, while plain UDP responses are never
// padded (padding would inflate datagrams toward the client's buffer limit
// without hiding anything — the length leaks either way).
func TestEDNSPadding(t *testing.T) {
	h := NewHandler(filter.NewEngine(), nil, nil, nil, "nxdomain", 600, 5*time.Second)
	h.SetPadding(true)

	hasPadding := func(m *dns.Msg) bool {
		opt := m.IsEdns0()
		if opt == nil {
			return false
		}
		for _, o := range opt.Option {
			if o.Option() == dns.EDNS0PADDING {
				return true
			}
		}
		return false
	}

	// DoH (encrypted stream transport) → padded to a 128-byte multiple.
	w := &fakeWriter{}
	q := new(dns.Msg)
	q.SetQuestion("example.com.", dns.TypeA)
	h.ServeDNSFromContext(w, q, "127.0.0.1", "doh")
	if w.msg == nil {
		t.Fatal("no DoH response")
	}
	if !hasPadding(w.msg) {
		t.Fatal("no EDNS0_PADDING option in padded response")
	}
	packed, err := w.msg.Pack()
	if err != nil {
		t.Fatalf("pack padded response: %v", err)
	}
	if len(packed)%128 != 0 {
		t.Fatalf("padded response length %d is not a multiple of 128", len(packed))
	}

	// Plain UDP → no padding option.
	w2 := &fakeWriter{}
	q2 := new(dns.Msg)
	q2.SetQuestion("example.com.", dns.TypeA)
	h.ServeDNSWithProto(w2, q2, "udp")
	if w2.msg == nil {
		t.Fatal("no UDP response")
	}
	if hasPadding(w2.msg) {
		t.Fatal("UDP response carried an EDNS0_PADDING option")
	}

	// Padding off → no padding option on encrypted transports either.
	h.SetPadding(false)
	w3 := &fakeWriter{}
	q3 := new(dns.Msg)
	q3.SetQuestion("example.com.", dns.TypeA)
	h.ServeDNSFromContext(w3, q3, "127.0.0.1", "doh")
	if w3.msg == nil {
		t.Fatal("no DoH response")
	}
	if hasPadding(w3.msg) {
		t.Fatal("padding disabled but EDNS0_PADDING still present")
	}
}

// TestCookieAndPadCopyInvariant guards the copy semantics that keep per-client
// decorations out of shared messages: attachCookie and padMessage must never
// mutate the message they are given (the success path hands that same message
// to the background cache writer right after the write).
func TestCookieAndPadCopyInvariant(t *testing.T) {
	m := new(dns.Msg)
	m.SetQuestion("example.com.", dns.TypeA)

	c := attachCookie(m, "1234567890abcdef1234567890abcdef")
	if requestCookieValue(c) == "" {
		t.Fatal("copy did not carry the cookie")
	}
	if requestCookieValue(m) != "" {
		t.Fatal("attachCookie mutated its input")
	}

	p := padMessage(m, 128)
	if p.IsEdns0() == nil {
		t.Fatal("padded copy has no OPT")
	}
	if m.IsEdns0() != nil {
		t.Fatal("padMessage mutated its input")
	}
}
