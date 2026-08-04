package filter

import (
	"net"

	"github.com/miekg/dns"
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
	m := new(dns.Msg)
	m.SetReply(req)
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
		ip := net.ParseIP(mode)
		if ip == nil {
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
func blockAnswerRR(q dns.Question, ip net.IP, ttl uint32) dns.RR {
	hdr := dns.RR_Header{Name: q.Name, Rrtype: q.Qtype, Class: q.Qclass, Ttl: ttl}
	v4 := ip.To4() != nil
	switch {
	case q.Qtype == dns.TypeA && v4:
		return &dns.A{Hdr: hdr, A: ip.To4()}
	case q.Qtype == dns.TypeA && !v4:
		return &dns.A{Hdr: hdr, A: net.IPv4zero.To4()}
	case q.Qtype == dns.TypeAAAA && !v4:
		return &dns.AAAA{Hdr: hdr, AAAA: ip}
	case q.Qtype == dns.TypeAAAA && v4:
		return &dns.AAAA{Hdr: hdr, AAAA: net.IPv6zero}
	}
	return nil
}
