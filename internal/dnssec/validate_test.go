package dnssec

import (
	"context"
	"crypto"
	"net"
	"testing"
	"time"

	"github.com/eoghan2t9/Irongrid-DNS/internal/upstream"
	"github.com/miekg/dns"
)

// zoneKey is one test zone's signing key (a single combined KSK/ZSK, flags
// 257, for simplicity — a valid real-world configuration, just not the most
// common one).
type zoneKey struct {
	zone string
	dnsk *dns.DNSKEY
	priv crypto.Signer
}

func generateZoneKey(t *testing.T, zone string) zoneKey {
	t.Helper()
	k := &dns.DNSKEY{
		Hdr:       dns.RR_Header{Name: zone, Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 3600},
		Flags:     257, // ZONE (256) + SEP (1): usable as both KSK and ZSK
		Protocol:  3,
		Algorithm: dns.ECDSAP256SHA256,
	}
	priv, err := k.Generate(256)
	if err != nil {
		t.Fatalf("generate key for %s: %v", zone, err)
	}
	signer, ok := priv.(crypto.Signer)
	if !ok {
		t.Fatalf("generated private key for %s is not a crypto.Signer", zone)
	}
	return zoneKey{zone: zone, dnsk: k, priv: signer}
}

// sign produces an RRSIG for rrset (all records must share name/type),
// signed by k as SignerName k.zone.
func sign(t *testing.T, k zoneKey, rrset []dns.RR) *dns.RRSIG {
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

// dnssecTestZones builds a 3-level signed chain: root "." -> "test." ->
// "example.test.", each with its own key, the two delegations backed by
// real DS records signed by the parent, and a final signed A record at
// example.test. Returns the three keys and a root TrustAnchor matching the
// root key, ready to hand to a Validator.
type dnssecTestZones struct {
	root, tld, leaf zoneKey
	anchor          TrustAnchor
	aRRset          []dns.RR
	aSig            *dns.RRSIG
}

func buildDNSSECTestZones(t *testing.T) dnssecTestZones {
	t.Helper()
	root := generateZoneKey(t, ".")
	tld := generateZoneKey(t, "test.")
	leaf := generateZoneKey(t, "example.test.")

	rootDS := root.dnsk.ToDS(dns.SHA256)
	anchor := TrustAnchor{Zone: ".", KeyTag: rootDS.KeyTag, Algorithm: rootDS.Algorithm, DigestType: rootDS.DigestType, Digest: rootDS.Digest}

	a := &dns.A{
		Hdr: dns.RR_Header{Name: "example.test.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
		A:   net.ParseIP("192.0.2.1"),
	}
	aRRset := []dns.RR{a}
	aSig := sign(t, leaf, aRRset)

	return dnssecTestZones{root: root, tld: tld, leaf: leaf, anchor: anchor, aRRset: aRRset, aSig: aSig}
}

// startDNSSECTestUpstream runs a UDP server answering exactly the DNSKEY,
// DS and final-A queries a chain walk from example.test. up to the root
// needs, all signed with z's keys.
func startDNSSECTestUpstream(t *testing.T, z dnssecTestZones) *upstream.Upstream {
	t.Helper()
	mux := dns.NewServeMux()
	mux.HandleFunc(".", func(w dns.ResponseWriter, r *dns.Msg) {
		q := r.Question[0]
		m := new(dns.Msg)
		m.SetReply(r)
		switch {
		case q.Name == "." && q.Qtype == dns.TypeDNSKEY:
			rrset := []dns.RR{z.root.dnsk}
			m.Answer = append(m.Answer, z.root.dnsk, sign(t, z.root, rrset))
		case q.Name == "test." && q.Qtype == dns.TypeDNSKEY:
			rrset := []dns.RR{z.tld.dnsk}
			m.Answer = append(m.Answer, z.tld.dnsk, sign(t, z.tld, rrset))
		case q.Name == "test." && q.Qtype == dns.TypeDS:
			ds := z.tld.dnsk.ToDS(dns.SHA256)
			ds.Hdr = dns.RR_Header{Name: "test.", Rrtype: dns.TypeDS, Class: dns.ClassINET, Ttl: 3600}
			rrset := []dns.RR{ds}
			m.Answer = append(m.Answer, ds, sign(t, z.root, rrset))
		case q.Name == "example.test." && q.Qtype == dns.TypeDNSKEY:
			rrset := []dns.RR{z.leaf.dnsk}
			m.Answer = append(m.Answer, z.leaf.dnsk, sign(t, z.leaf, rrset))
		case q.Name == "example.test." && q.Qtype == dns.TypeDS:
			ds := z.leaf.dnsk.ToDS(dns.SHA256)
			ds.Hdr = dns.RR_Header{Name: "example.test.", Rrtype: dns.TypeDS, Class: dns.ClassINET, Ttl: 3600}
			rrset := []dns.RR{ds}
			m.Answer = append(m.Answer, ds, sign(t, z.tld, rrset))
		case q.Name == "example.test." && q.Qtype == dns.TypeA:
			m.Answer = append(m.Answer, z.aRRset...)
			m.Answer = append(m.Answer, z.aSig)
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
	return &upstream.Upstream{Transport: upstream.UDP, Addr: pc.LocalAddr().String()}
}

func testAnchorManager(anchor TrustAnchor) *AnchorManager {
	m := NewAnchorManager("http://127.0.0.1:0/unused", "", time.Hour)
	m.anchors = []TrustAnchor{anchor}
	return m
}

func TestValidatorValidatesFullChain(t *testing.T) {
	z := buildDNSSECTestZones(t)
	up := startDNSSECTestUpstream(t, z)
	v := NewValidator(testAnchorManager(z.anchor))

	resp := new(dns.Msg)
	resp.Answer = append(resp.Answer, z.aRRset...)
	resp.Answer = append(resp.Answer, z.aSig)

	secure, signed, err := v.Validate(context.Background(), up, resp)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if !signed {
		t.Fatal("expected signed=true for a response carrying an RRSIG")
	}
	if !secure {
		t.Fatal("expected secure=true for a genuinely valid chain")
	}
}

func TestValidatorRejectsTamperedAnswer(t *testing.T) {
	z := buildDNSSECTestZones(t)
	up := startDNSSECTestUpstream(t, z)
	v := NewValidator(testAnchorManager(z.anchor))

	// A response claiming a different A record than what was actually
	// signed — simulating a tampered/forged answer riding along with a
	// legitimate signature.
	tampered := &dns.A{
		Hdr: dns.RR_Header{Name: "example.test.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
		A:   net.ParseIP("198.51.100.66"), // different from the signed 192.0.2.1
	}
	resp := new(dns.Msg)
	resp.Answer = append(resp.Answer, tampered, z.aSig)

	secure, signed, err := v.Validate(context.Background(), up, resp)
	if !signed {
		t.Fatal("expected signed=true — an RRSIG is present")
	}
	if secure {
		t.Fatal("a tampered answer must never validate as secure")
	}
	// A cryptographic mismatch is a completed, valid "no" — not an
	// infrastructure failure — so err must be nil: the caller (the
	// handler) needs to tell "checked and it's bogus" (secure=false,
	// err=nil: fail closed) apart from "couldn't check" (err!=nil: fail
	// open), and conflating the two here would make a real forged answer
	// silently pass through on the handler's fail-open path instead of
	// being rejected — see the handler-level regression test in
	// internal/dnsserver that caught exactly this.
	if err != nil {
		t.Fatalf("a cryptographic verification failure must report err=nil, got: %v", err)
	}
}

func TestValidatorRejectsUntrustedAnchor(t *testing.T) {
	z := buildDNSSECTestZones(t)
	up := startDNSSECTestUpstream(t, z)
	// A validator configured with a DIFFERENT root anchor than the one the
	// test root actually used — simulating a validator that hasn't been
	// told to trust this (attacker-controlled, in the real world) root.
	wrongAnchor := TrustAnchor{Zone: ".", KeyTag: z.anchor.KeyTag + 1, Algorithm: z.anchor.Algorithm, DigestType: z.anchor.DigestType, Digest: z.anchor.Digest}
	v := NewValidator(testAnchorManager(wrongAnchor))

	resp := new(dns.Msg)
	resp.Answer = append(resp.Answer, z.aRRset...)
	resp.Answer = append(resp.Answer, z.aSig)

	secure, signed, err := v.Validate(context.Background(), up, resp)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if !signed {
		t.Fatal("expected signed=true")
	}
	if secure {
		t.Fatal("a chain rooted at an untrusted anchor must not validate as secure")
	}
}

func TestValidatorUnsignedResponseIsNotSecureNorAnError(t *testing.T) {
	v := NewValidator(testAnchorManager(DefaultRootAnchors[0]))
	resp := new(dns.Msg)
	resp.Answer = append(resp.Answer, &dns.A{
		Hdr: dns.RR_Header{Name: "plain.example.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
		A:   net.ParseIP("192.0.2.9"),
	})

	secure, signed, err := v.Validate(context.Background(), nil, resp)
	if err != nil {
		t.Fatalf("Validate on an unsigned response should never error, got: %v", err)
	}
	if signed {
		t.Fatal("expected signed=false: no RRSIG present")
	}
	if secure {
		t.Fatal("expected secure=false for an unsigned response")
	}
}

func TestZoneCacheAvoidsRepeatedQueries(t *testing.T) {
	z := buildDNSSECTestZones(t)
	up := startDNSSECTestUpstream(t, z)
	v := NewValidator(testAnchorManager(z.anchor))
	ctx := context.Background()

	if _, _, err := v.zoneKeys(ctx, up, "example.test.", 0); err != nil {
		t.Fatalf("first zoneKeys call: %v", err)
	}
	// A cache hit must not touch the network at all — verified indirectly:
	// the validator's own cache should now report the zone as fresh.
	if _, ok := v.cached("example.test."); !ok {
		t.Fatal("expected example.test. to be cached after a successful validation")
	}
	if _, ok := v.cached("test."); !ok {
		t.Fatal("expected the intermediate zone test. to be cached too")
	}
	if _, ok := v.cached("."); !ok {
		t.Fatal("expected the root to be cached too")
	}
}

func TestParentZone(t *testing.T) {
	tests := []struct{ in, want string }{
		{".", "."},
		{"com.", "."},
		{"example.com.", "com."},
		{"www.example.com.", "example.com."},
	}
	for _, tt := range tests {
		if got := parentZone(tt.in); got != tt.want {
			t.Errorf("parentZone(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}
