package dnsname

import (
	"net/netip"
	"testing"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
	"codeberg.org/miekg/dns/rdata"
)

func testRequest() *dns.Msg {
	r := dnsutil.SetQuestion(new(dns.Msg), "example.com.", dns.TypeA)
	r.ID = 0x1234
	r.RecursionDesired = true
	r.CheckingDisabled = true
	r.Security = true
	return r
}

func TestSetReplyCopiesRequestFields(t *testing.T) {
	t.Parallel()
	r := testRequest()
	m := SetReply(new(dns.Msg), r)

	if m.ID != r.ID {
		t.Errorf("ID = %#x, want %#x", m.ID, r.ID)
	}
	if !m.Response {
		t.Error("Response bit not set")
	}
	if m.Opcode != dns.OpcodeQuery || m.Rcode != dns.RcodeSuccess {
		t.Errorf("opcode/rcode = %d/%d, want query/success", m.Opcode, m.Rcode)
	}
	if !m.RecursionDesired || !m.CheckingDisabled || !m.Security {
		t.Errorf("RD/CD/DO not copied: %v/%v/%v", m.RecursionDesired, m.CheckingDisabled, m.Security)
	}
	if len(m.Question) != 1 || m.Question[0].Header().Name != "example.com." {
		t.Errorf("question not copied: %v", m.Question)
	}
	if len(m.Answer) != 0 || len(m.Ns) != 0 || len(m.Extra) != 0 {
		t.Error("answer/authority/additional sections must be empty")
	}
}

// The request must come out untouched: handlers keep reading it (logging,
// retries, the ID for the wire reply) after building a reply from it.
func TestSetReplyDoesNotMutateRequest(t *testing.T) {
	t.Parallel()
	r := testRequest()
	r.Rcode = dns.RcodeRefused // would be reset if r itself were turned into the reply
	SetReply(new(dns.Msg), r)

	if r.Response {
		t.Error("request was turned into a response")
	}
	if r.Rcode != dns.RcodeRefused {
		t.Errorf("request rcode changed to %d", r.Rcode)
	}
	if !r.RecursionDesired || !r.CheckingDisabled || !r.Security || r.ID != 0x1234 {
		t.Error("request header bits were modified")
	}
}

func TestSetReplyResetsReusedMessage(t *testing.T) {
	t.Parallel()
	m := new(dns.Msg)
	m.Answer = append(m.Answer, &dns.A{
		Hdr: dns.Header{Name: "old.example.", Class: dns.ClassINET, TTL: 30},
		A:   rdata.A{Addr: netip.MustParseAddr("192.0.2.1")},
	})
	m.Rcode = dns.RcodeServerFailure
	m.Authoritative = true

	SetReply(m, testRequest())
	if len(m.Answer) != 0 {
		t.Errorf("stale answer survived: %v", m.Answer)
	}
	if m.Rcode != dns.RcodeSuccess {
		t.Errorf("rcode = %d, want success", m.Rcode)
	}
}

func TestSetReplyNonQueryOpcodeSkipsQueryBits(t *testing.T) {
	t.Parallel()
	r := testRequest()
	r.Opcode = dns.OpcodeNotify
	m := SetReply(new(dns.Msg), r)
	if m.Opcode != dns.OpcodeNotify {
		t.Errorf("opcode = %d, want notify", m.Opcode)
	}
	if m.RecursionDesired || m.CheckingDisabled || m.Security {
		t.Error("RD/CD/DO must only be copied for a query")
	}
}
