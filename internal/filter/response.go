package filter

import (
	"net/netip"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
	"codeberg.org/miekg/dns/rdata"
)

// BuildBlockResponse crafts the response a blocked query receives.
// mode is one of "nxdomain", "refused", or a literal IP address ("0.0.0.0").
// The request's message ID and question are preserved via SetReply so the
// client accepts the answer.
func BuildBlockResponse(req *dns.Msg, mode string, ttl uint32) *dns.Msg {
	if req == nil || len(req.Question) == 0 {
		return nil
	}
	q := req.Question[0]
	m := dnsutil.SetReply(new(dns.Msg), req)
	m.RecursionAvailable = true

	switch mode {
	case "refused":
		m.Rcode = dns.RcodeRefused
		return m
	case "nxdomain", "":
		m.Rcode = dns.RcodeNameError
		return m
	default:
		// Mode is an IP literal: answer A/AAAA with the blackhole address.
		ip, err := netip.ParseAddr(mode)
		if err != nil {
			m.Rcode = dns.RcodeRefused
			return m
		}
		m.Rcode = dns.RcodeSuccess
		rr := blockAnswerRR(q, ip, ttl)
		if rr != nil {
			m.Answer = append(m.Answer, rr)
		}
		return m
	}
}

// blockAnswerRR synthesizes an answer for the requested type. A v4 blackhole
// answers A records and maps AAAA queries to :: (and vice versa) so both
// address families are always blackholed regardless of the configured IP.
func blockAnswerRR(q dns.RR, ip netip.Addr, ttl uint32) dns.RR {
	qtype := dns.RRToType(q)
	hdr := dns.Header{Name: q.Header().Name, Class: q.Header().Class, TTL: ttl}
	v4 := ip.Is4()
	switch {
	case qtype == dns.TypeA && v4:
		return &dns.A{Hdr: hdr, A: rdata.A{Addr: ip}}
	case qtype == dns.TypeA && !v4:
		return &dns.A{Hdr: hdr, A: rdata.A{Addr: netip.IPv4Unspecified()}}
	case qtype == dns.TypeAAAA && !v4:
		return &dns.AAAA{Hdr: hdr, AAAA: rdata.AAAA{Addr: ip}}
	case qtype == dns.TypeAAAA && v4:
		return &dns.AAAA{Hdr: hdr, AAAA: rdata.AAAA{Addr: netip.IPv6Unspecified()}}
	}
	return nil
}
