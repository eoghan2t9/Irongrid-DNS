package dnsserver

import (
	"crypto"
	"net"
	"testing"
	"time"

	"github.com/eoghan2t9/Irongrid-DNS/internal/dnssec"
	"github.com/eoghan2t9/Irongrid-DNS/internal/filter"
	"github.com/eoghan2t9/Irongrid-DNS/internal/upstream"
	"github.com/miekg/dns"
)

// This file exercises Handler.serve's DNSSEC local-validation wiring
// end-to-end (real listener -> real handler -> real Validator), not just
// the dnssec package in isolation. It builds a minimal two-level signed
// chain: root "." -> "example." (a TLD signed directly under the root, to
// keep the fixture small — the recursive chain-walk logic itself is
// already covered by internal/dnssec's own tests).

type dnssecIntegrationKey struct {
	zone string
	dnsk *dns.DNSKEY
	priv crypto.Signer
}

func genIntegrationKey(t *testing.T, zone string) dnssecIntegrationKey {
	t.Helper()
	k := &dns.DNSKEY{
		Hdr:       dns.RR_Header{Name: zone, Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 3600},
		Flags:     257,
		Protocol:  3,
		Algorithm: dns.ECDSAP256SHA256,
	}
	priv, err := k.Generate(256)
	if err != nil {
		t.Fatalf("generate key for %s: %v", zone, err)
	}
	signer, ok := priv.(crypto.Signer)
	if !ok {
		t.Fatalf("key for %s is not a crypto.Signer", zone)
	}
	return dnssecIntegrationKey{zone: zone, dnsk: k, priv: signer}
}

func signIntegration(t *testing.T, k dnssecIntegrationKey, rrset []dns.RR) *dns.RRSIG {
	t.Helper()
	hdr := rrset[0].Header()
	sig := &dns.RRSIG{
		Hdr:         dns.RR_Header{Name: hdr.Name, Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: hdr.Ttl},
		TypeCovered: hdr.Rrtype,
		Algorithm:   k.dnsk.Algorithm,
		Labels:      uint8(len(dns.SplitDomainName(hdr.Name))),
		OrigTtl:     hdr.Ttl,
		Expiration:  uint32(time.Now().Add(24 * time.Hour).Unix()),
		Inception:   uint32(time.Now().Add(-1 * time.Hour).Unix()),
		KeyTag:      k.dnsk.KeyTag(),
		SignerName:  k.zone,
	}
	if err := sig.Sign(k.priv, rrset); err != nil {
		t.Fatalf("sign %s/%s: %v", hdr.Name, dns.TypeToString[hdr.Rrtype], err)
	}
	return sig
}

// dnssecIntegrationFixture wires a root -> "example." chain and a UDP test
// server answering it, tamperA optionally corrupting the served A record's
// address after it was already signed (simulating a tampered/forged answer
// riding along with an otherwise-legitimate signature).
func dnssecIntegrationFixture(t *testing.T, tamperA bool) (addr string, anchor dnssec.TrustAnchor) {
	t.Helper()
	root := genIntegrationKey(t, ".")
	leaf := genIntegrationKey(t, "example.")

	rootDS := root.dnsk.ToDS(dns.SHA256)
	anchor = dnssec.TrustAnchor{Zone: ".", KeyTag: rootDS.KeyTag, Algorithm: rootDS.Algorithm, DigestType: rootDS.DigestType, Digest: rootDS.Digest}

	a := &dns.A{
		Hdr: dns.RR_Header{Name: "example.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
		A:   net.ParseIP("192.0.2.1"),
	}
	aRRset := []dns.RR{a}
	aSig := signIntegration(t, leaf, aRRset)

	mux := dns.NewServeMux()
	mux.HandleFunc(".", func(w dns.ResponseWriter, r *dns.Msg) {
		q := r.Question[0]
		m := new(dns.Msg)
		m.SetReply(r)
		switch {
		case q.Name == "." && q.Qtype == dns.TypeDNSKEY:
			rrset := []dns.RR{root.dnsk}
			m.Answer = append(m.Answer, root.dnsk, signIntegration(t, root, rrset))
		case q.Name == "example." && q.Qtype == dns.TypeDNSKEY:
			rrset := []dns.RR{leaf.dnsk}
			m.Answer = append(m.Answer, leaf.dnsk, signIntegration(t, leaf, rrset))
		case q.Name == "example." && q.Qtype == dns.TypeDS:
			ds := leaf.dnsk.ToDS(dns.SHA256)
			ds.Hdr = dns.RR_Header{Name: "example.", Rrtype: dns.TypeDS, Class: dns.ClassINET, Ttl: 3600}
			rrset := []dns.RR{ds}
			m.Answer = append(m.Answer, ds, signIntegration(t, root, rrset))
		case q.Name == "example." && q.Qtype == dns.TypeA:
			served := a
			if tamperA {
				served = &dns.A{Hdr: a.Hdr, A: net.ParseIP("198.51.100.66")}
			}
			m.Answer = append(m.Answer, served, aSig)
			m.AuthenticatedData = true // a lying/compromised upstream claiming AD=1 regardless
		}
		_ = w.WriteMsg(m)
	})
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := &dns.Server{PacketConn: pc, Handler: mux}
	go func() { _ = srv.ActivateAndServe() }()
	t.Cleanup(func() { _ = srv.Shutdown() })
	return pc.LocalAddr().String(), anchor
}

func TestHandlerLocalDNSSECValidationAcceptsGenuineChain(t *testing.T) {
	addr, anchor := dnssecIntegrationFixture(t, false)
	h := NewHandler(filter.NewEngine(), nil, []*upstream.Upstream{{Transport: upstream.UDP, Addr: addr}}, nil, "nxdomain", 600, 5*time.Second)
	h.DNSSECValidator = dnssec.NewValidator(dnssec.NewAnchorManagerForTest(anchor))
	h.SetDNSSEC(true, false)
	h.SetDNSSECValidateLocally(true)

	m := new(dns.Msg)
	m.SetQuestion("example.", dns.TypeA)
	fw := &fakeWriter{}
	h.ServeDNS(fw, m)

	if fw.msg == nil {
		t.Fatal("expected a response")
	}
	if fw.msg.Rcode != dns.RcodeSuccess || len(fw.msg.Answer) == 0 {
		t.Fatalf("expected a successful validated answer, got rcode=%d answer=%v", fw.msg.Rcode, fw.msg.Answer)
	}
}

func TestHandlerLocalDNSSECValidationRejectsTamperedAnswerDespiteADBit(t *testing.T) {
	addr, anchor := dnssecIntegrationFixture(t, true) // tampered A record
	h := NewHandler(filter.NewEngine(), nil, []*upstream.Upstream{{Transport: upstream.UDP, Addr: addr}}, nil, "nxdomain", 600, 5*time.Second)
	h.DNSSECValidator = dnssec.NewValidator(dnssec.NewAnchorManagerForTest(anchor))
	h.SetDNSSEC(true, false)
	h.SetDNSSECValidateLocally(true)

	m := new(dns.Msg)
	m.SetQuestion("example.", dns.TypeA)
	fw := &fakeWriter{}
	h.ServeDNS(fw, m)

	if fw.msg == nil {
		t.Fatal("expected a response")
	}
	// The fixture's upstream sets AuthenticatedData=true regardless — this
	// is exactly the "compromised/lying upstream" scenario the AD-bit-only
	// check (require_ad, without local validation) can never catch. Local
	// validation must reject it anyway.
	if fw.msg.Rcode != dns.RcodeServerFailure {
		t.Fatalf("expected SERVFAIL for a tampered answer despite AD=1, got rcode=%d", fw.msg.Rcode)
	}
}

// TestHandlerLocalDNSSECValidationFailsOpenOnInfrastructureError verifies
// the other half of the fail-open/fail-closed contract: when the extra
// DNSKEY/DS lookups a chain walk needs simply can't be completed (the
// upstream doesn't answer them at all here), that's "couldn't check", not
// "checked and it's bogus" — the query must still resolve via the
// pre-existing AD-bit-trust behavior rather than SERVFAILing every signed
// domain whenever a chain-walk lookup has a transient hiccup.
func TestHandlerLocalDNSSECValidationFailsOpenOnInfrastructureError(t *testing.T) {
	root := genIntegrationKey(t, ".")
	leaf := genIntegrationKey(t, "example.")
	rootDS := root.dnsk.ToDS(dns.SHA256)
	anchor := dnssec.TrustAnchor{Zone: ".", KeyTag: rootDS.KeyTag, Algorithm: rootDS.Algorithm, DigestType: rootDS.DigestType, Digest: rootDS.Digest}

	a := &dns.A{
		Hdr: dns.RR_Header{Name: "example.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
		A:   net.ParseIP("192.0.2.1"),
	}
	aSig := signIntegration(t, leaf, []dns.RR{a})

	// This upstream answers the original A query (with AD=1, as any
	// upstream the require_ad model already trusts would) but returns
	// NXDOMAIN for every DNSKEY/DS lookup the chain walk needs — modeling
	// an upstream that's degraded or doesn't support those record types
	// right now, without actually being compromised.
	mux := dns.NewServeMux()
	mux.HandleFunc(".", func(w dns.ResponseWriter, r *dns.Msg) {
		q := r.Question[0]
		m := new(dns.Msg)
		m.SetReply(r)
		if q.Name == "example." && q.Qtype == dns.TypeA {
			m.Answer = append(m.Answer, a, aSig)
			m.AuthenticatedData = true
		} else {
			m.Rcode = dns.RcodeServerFailure // DNSKEY/DS lookups all fail
		}
		_ = w.WriteMsg(m)
	})
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := &dns.Server{PacketConn: pc, Handler: mux}
	go func() { _ = srv.ActivateAndServe() }()
	t.Cleanup(func() { _ = srv.Shutdown() })

	h := NewHandler(filter.NewEngine(), nil, []*upstream.Upstream{{Transport: upstream.UDP, Addr: pc.LocalAddr().String()}}, nil, "nxdomain", 600, 5*time.Second)
	h.DNSSECValidator = dnssec.NewValidator(dnssec.NewAnchorManagerForTest(anchor))
	h.SetDNSSEC(true, false)
	h.SetDNSSECValidateLocally(true)

	m := new(dns.Msg)
	m.SetQuestion("example.", dns.TypeA)
	fw := &fakeWriter{}
	h.ServeDNS(fw, m)

	if fw.msg == nil || fw.msg.Rcode != dns.RcodeSuccess || len(fw.msg.Answer) == 0 {
		t.Fatalf("a chain-walk infrastructure failure must fail open to AD-bit trust, not SERVFAIL a legitimate answer; got %v", fw.msg)
	}
}

func TestHandlerDNSSECValidateLocallyOffPreservesADBitTrust(t *testing.T) {
	// With dnssec.validate_locally left off (the default), a tampered
	// answer that the upstream marks AD=1 must still pass through
	// unmodified — this is the pre-existing, unchanged behavior.
	addr, anchor := dnssecIntegrationFixture(t, true)
	h := NewHandler(filter.NewEngine(), nil, []*upstream.Upstream{{Transport: upstream.UDP, Addr: addr}}, nil, "nxdomain", 600, 5*time.Second)
	h.DNSSECValidator = dnssec.NewValidator(dnssec.NewAnchorManagerForTest(anchor))
	h.SetDNSSEC(true, false) // require_ad off, local validation left off (default)

	m := new(dns.Msg)
	m.SetQuestion("example.", dns.TypeA)
	fw := &fakeWriter{}
	h.ServeDNS(fw, m)

	if fw.msg == nil || fw.msg.Rcode != dns.RcodeSuccess {
		t.Fatalf("with local validation off, expected the pre-existing AD-bit-trust behavior to pass the answer through, got %v", fw.msg)
	}
}
