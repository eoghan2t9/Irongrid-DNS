package dnsname

import "codeberg.org/miekg/dns"

// SetReply turns m into a reply to the request r and returns m. It copies the
// ID, opcode and question from r, plus (for a query) the RecursionDesired,
// CheckingDisabled and Security (DO) bits; the rcode is success, the Z bits are
// cleared and every other section of m is resliced to length zero. r is never
// modified and r's Data buffer is not copied.
//
// This is the behaviour of the dnsutil.SetReply(m, r) that codeberg.org/miekg/dns
// shipped until v0.6.133. Later releases replaced it with dnsutil.SetReply(m),
// which converts the request into its own reply in place — not usable here,
// where handlers keep reading the request after building a reply from it.
func SetReply(m, r *dns.Msg) *dns.Msg {
	m.ID = r.ID
	m.Response = true
	m.Opcode = r.Opcode
	if m.Opcode == dns.OpcodeQuery {
		m.RecursionDesired = r.RecursionDesired
		m.CheckingDisabled = r.CheckingDisabled
		m.Security = r.Security
	}
	m.Flags = 0 // RFC 6891, section 6.1.4: a sender zeroes these.
	m.Rcode = dns.RcodeSuccess
	m.Question = r.Question
	m.Reset()
	return m
}
