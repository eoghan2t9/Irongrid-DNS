package dnssec

import (
	"context"
	"crypto"
	"net"
	"strings"
	"sync"
	"sync/atomic"
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

// startDNSSECTestUpstreamCounting is startDNSSECTestUpstream plus a counter
// of DNSKEY queries received, for asserting singleflight coalescing.
func startDNSSECTestUpstreamCounting(t *testing.T, z dnssecTestZones, dnskeyQueries *atomic.Int64) *upstream.Upstream {
	t.Helper()
	mux := dns.NewServeMux()
	mux.HandleFunc(".", func(w dns.ResponseWriter, r *dns.Msg) {
		q := r.Question[0]
		m := new(dns.Msg)
		m.SetReply(r)
		switch {
		case q.Name == "." && q.Qtype == dns.TypeDNSKEY:
			dnskeyQueries.Add(1)
			rrset := []dns.RR{z.root.dnsk}
			m.Answer = append(m.Answer, z.root.dnsk, sign(t, z.root, rrset))
		case q.Name == "test." && q.Qtype == dns.TypeDNSKEY:
			dnskeyQueries.Add(1)
			rrset := []dns.RR{z.tld.dnsk}
			m.Answer = append(m.Answer, z.tld.dnsk, sign(t, z.tld, rrset))
		case q.Name == "test." && q.Qtype == dns.TypeDS:
			ds := z.tld.dnsk.ToDS(dns.SHA256)
			ds.Hdr = dns.RR_Header{Name: "test.", Rrtype: dns.TypeDS, Class: dns.ClassINET, Ttl: 3600}
			rrset := []dns.RR{ds}
			m.Answer = append(m.Answer, ds, sign(t, z.root, rrset))
		case q.Name == "example.test." && q.Qtype == dns.TypeDNSKEY:
			dnskeyQueries.Add(1)
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

func TestZoneKeysCoalescesConcurrentCallsForSameZone(t *testing.T) {
	z := buildDNSSECTestZones(t)
	var dnskeyQueries atomic.Int64
	up := startDNSSECTestUpstreamCounting(t, z, &dnskeyQueries)
	v := NewValidator(testAnchorManager(z.anchor))

	const n = 20
	var wg sync.WaitGroup
	wg.Add(n)
	for range n {
		go func() {
			defer wg.Done()
			_, secure, err := v.zoneKeys(context.Background(), up, "example.test.", 0)
			if err != nil || !secure {
				t.Errorf("zoneKeys: secure=%v err=%v", secure, err)
			}
		}()
	}
	wg.Wait()

	// 3 zones (example.test., test., .) x 1 DNSKEY query each — concurrent
	// callers for the same zone must share one fetch, not issue n each.
	if got := dnskeyQueries.Load(); got != 3 {
		t.Fatalf("DNSKEY queries issued = %d, want exactly 3 (one per zone, coalesced across %d concurrent callers)", got, n)
	}
}

// --- NSEC/NSEC3 denial-of-existence tests -------------------------------
//
// The record shapes below mirror live captures taken from real signed
// zones during development (not invented from the RFC text alone):
//   - Classic two-NSEC NXDOMAIN proof: isc.org (algorithm 13).
//   - Classic NSEC3 NXDOMAIN proof: verisign.com and iana.org (algorithms
//     8 and 13 respectively).
//   - Single-record "compact denial of existence" NSEC synthesis (owner ==
//     qname, Next Domain Name one label longer): cloudflare.com and
//     ietf.org — both increasingly common in production, which is why
//     nsecCovers treats the owner side as inclusive.
// Kept self-signed with a fresh key (via the existing buildDNSSECTestZones
// harness) rather than replayed verbatim, since real RRSIGs expire within
// days and a committed test must keep passing indefinitely.

func nsecRR(t *testing.T, k zoneKey, owner, next string, types ...uint16) (*dns.NSEC, *dns.RRSIG) {
	t.Helper()
	n := &dns.NSEC{
		Hdr:        dns.RR_Header{Name: owner, Rrtype: dns.TypeNSEC, Class: dns.ClassINET, Ttl: 300},
		NextDomain: next,
		TypeBitMap: types,
	}
	return n, sign(t, k, []dns.RR{n})
}

func TestValidateDenialNSECProvesNXDOMAIN(t *testing.T) {
	z := buildDNSSECTestZones(t)
	up := startDNSSECTestUpstream(t, z)
	v := NewValidator(testAnchorManager(z.anchor))

	// Classic two-record proof (mirrors the real isc.org capture): one
	// NSEC covers the queried name itself, a second covers the wildcard at
	// the zone apex (the closest encloser, since nothing more specific
	// exists) — proving neither an exact match nor a wildcard could answer.
	coverQname, coverQnameSig := nsecRR(t, z.leaf, "a.example.test.", "z.example.test.", dns.TypeA)
	coverWildcard, coverWildcardSig := nsecRR(t, z.leaf, "example.test.", "0.example.test.", dns.TypeSOA, dns.TypeNS, dns.TypeNSEC)

	resp := new(dns.Msg)
	resp.Rcode = dns.RcodeNameError
	resp.Question = []dns.Question{{Name: "missing.example.test.", Qtype: dns.TypeA, Qclass: dns.ClassINET}}
	resp.Ns = []dns.RR{coverQname, coverQnameSig, coverWildcard, coverWildcardSig}

	secure, signed, err := v.Validate(context.Background(), up, resp)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if !signed {
		t.Fatal("expected signed=true — NSEC records with RRSIG are present")
	}
	if !secure {
		t.Fatal("expected secure=true — a genuine two-NSEC NXDOMAIN proof")
	}
}

func TestValidateDenialNSECCompactDenialSynthesis(t *testing.T) {
	z := buildDNSSECTestZones(t)
	up := startDNSSECTestUpstream(t, z)
	v := NewValidator(testAnchorManager(z.anchor))

	qname := "missing.example.test."
	// Mirrors the live cloudflare.com/ietf.org capture's shape: owner ==
	// qname, Next Domain Name is qname with one extra leftmost label (the
	// real capture uses a NUL-byte label so nothing can sort between them;
	// canonicalLess's tail case only cares about the label *count*
	// difference, not that label's content, so any extra label exercises
	// the same inclusive-owner-side logic without the escaping ambiguity
	// of representing a literal NUL byte in a Go source string).
	n, sig := nsecRR(t, z.leaf, qname, "min."+qname, dns.TypeRRSIG, dns.TypeNSEC)

	resp := new(dns.Msg)
	resp.Rcode = dns.RcodeNameError
	resp.Question = []dns.Question{{Name: qname, Qtype: dns.TypeA, Qclass: dns.ClassINET}}
	resp.Ns = []dns.RR{n, sig}

	secure, signed, err := v.Validate(context.Background(), up, resp)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if !signed {
		t.Fatal("expected signed=true")
	}
	if !secure {
		t.Fatal("expected secure=true — compact-denial NSEC synthesis must validate, not just classic two-record proofs")
	}
}

func TestValidateDenialNSECProvesNODATA(t *testing.T) {
	z := buildDNSSECTestZones(t)
	up := startDNSSECTestUpstream(t, z)
	v := NewValidator(testAnchorManager(z.anchor))

	// example.test. exists (has an A record per the shared test zone) but
	// this NSEC proves it has no AAAA.
	n, sig := nsecRR(t, z.leaf, "example.test.", "z.example.test.", dns.TypeA, dns.TypeRRSIG, dns.TypeNSEC)

	resp := new(dns.Msg)
	resp.Rcode = dns.RcodeSuccess
	resp.Question = []dns.Question{{Name: "example.test.", Qtype: dns.TypeAAAA, Qclass: dns.ClassINET}}
	resp.Ns = []dns.RR{n, sig}

	secure, signed, err := v.Validate(context.Background(), up, resp)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if !signed || !secure {
		t.Fatalf("expected signed=true, secure=true for a genuine NODATA proof, got signed=%v secure=%v", signed, secure)
	}
}

func TestValidateDenialNSECRejectsNonCoveringProof(t *testing.T) {
	z := buildDNSSECTestZones(t)
	up := startDNSSECTestUpstream(t, z)
	v := NewValidator(testAnchorManager(z.anchor))

	// Both NSEC records are validly signed, but neither actually covers
	// the queried name — a forged/mismatched proof that must not validate
	// just because the signatures happen to be real.
	n1, sig1 := nsecRR(t, z.leaf, "a.example.test.", "b.example.test.", dns.TypeA)
	n2, sig2 := nsecRR(t, z.leaf, "c.example.test.", "d.example.test.", dns.TypeA)

	resp := new(dns.Msg)
	resp.Rcode = dns.RcodeNameError
	resp.Question = []dns.Question{{Name: "nowhere-near.example.test.", Qtype: dns.TypeA, Qclass: dns.ClassINET}}
	resp.Ns = []dns.RR{n1, sig1, n2, sig2}

	secure, signed, err := v.Validate(context.Background(), up, resp)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if !signed {
		t.Fatal("expected signed=true — the RRSIGs are real")
	}
	if secure {
		t.Fatal("a non-covering NSEC set must never validate as secure, no matter how validly it's signed")
	}
}

// nsec3Hash is dns.HashName with this test's fixed algorithm/iterations/no
// salt, used both to build owner names and to derive covering brackets.
func nsec3Hash(name string) string {
	return dns.HashName(name, dns.SHA1, 0, "")
}

// base32hexAlphabet mirrors RFC 4648 §7 (no padding), as used by NSEC3 owner
// and Next Hashed Owner Name text encoding.
const base32hexAlphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUV"

// bumpBase32Hex returns s with its last character shifted by delta
// positions in the base32hex alphabet — a test-only way to construct an
// NSEC3 owner/next hash that's deterministically just below or above a
// known hash value, bracketing it without needing a real multi-name zone.
func bumpBase32Hex(t *testing.T, s string, delta int) string {
	t.Helper()
	if delta != 1 && delta != -1 {
		t.Fatalf("bumpBase32Hex: delta must be +1 or -1, got %d", delta)
	}
	b := []byte(s)
	for i := len(b) - 1; i >= 0; i-- {
		idx := strings.IndexByte(base32hexAlphabet, b[i])
		if idx < 0 {
			t.Fatalf("bumpBase32Hex: %q not in base32hex alphabet", string(b[i]))
		}
		idx += delta
		if idx >= 0 && idx < len(base32hexAlphabet) {
			b[i] = base32hexAlphabet[idx]
			return string(b)
		}
		// This position wrapped — same as manual base-32 increment/decrement,
		// carry into the next position left.
		if delta > 0 {
			b[i] = base32hexAlphabet[0]
		} else {
			b[i] = base32hexAlphabet[len(base32hexAlphabet)-1]
		}
	}
	t.Fatalf("bumpBase32Hex: overflowed entire string %q", s)
	return ""
}

func nsec3RR(t *testing.T, k zoneKey, zone, ownerHash, nextHash string, types ...uint16) (*dns.NSEC3, *dns.RRSIG) {
	t.Helper()
	n := &dns.NSEC3{
		Hdr:        dns.RR_Header{Name: ownerHash + "." + zone, Rrtype: dns.TypeNSEC3, Class: dns.ClassINET, Ttl: 300},
		Hash:       dns.SHA1,
		Flags:      0,
		Iterations: 0,
		SaltLength: 0,
		Salt:       "",
		HashLength: uint8(len(nextHash)),
		NextDomain: nextHash,
		TypeBitMap: types,
	}
	return n, sign(t, k, []dns.RR{n})
}

func TestValidateDenialNSEC3ProvesNXDOMAIN(t *testing.T) {
	z := buildDNSSECTestZones(t)
	up := startDNSSECTestUpstream(t, z)
	v := NewValidator(testAnchorManager(z.anchor))

	qname := "missing.example.test."
	hQname := nsec3Hash(qname)
	// One NSEC3 covering qname's hash (no exact match)...
	coverQname, coverQnameSig := nsec3RR(t, z.leaf, "example.test.",
		bumpBase32Hex(t, hQname, -1), bumpBase32Hex(t, hQname, 1), dns.TypeA)

	// ...and one whose owner hash exactly matches the zone apex (the
	// closest encloser) and whose next-hash covers the wildcard's hash —
	// proving no wildcard could answer either. Owner must be hApex exactly
	// (so Match succeeds); NSEC3.Cover's own wrap-around handling covers
	// hWildcard correctly whether it sorts above or below hApex, so no
	// manual branching on their relative order is needed.
	hApex := nsec3Hash("example.test.")
	hWildcard := nsec3Hash("*.example.test.")
	ceRR, ceSig := nsec3RR(t, z.leaf, "example.test.", hApex, bumpBase32Hex(t, hWildcard, 1), dns.TypeSOA, dns.TypeNS)

	resp := new(dns.Msg)
	resp.Rcode = dns.RcodeNameError
	resp.Question = []dns.Question{{Name: qname, Qtype: dns.TypeA, Qclass: dns.ClassINET}}
	resp.Ns = []dns.RR{coverQname, coverQnameSig, ceRR, ceSig}

	secure, signed, err := v.Validate(context.Background(), up, resp)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if !signed {
		t.Fatal("expected signed=true")
	}
	if !secure {
		t.Fatalf("expected secure=true — a genuine NSEC3 NXDOMAIN proof (hQname=%s hApex=%s hWildcard=%s)", hQname, hApex, hWildcard)
	}
}

func TestValidateDenialNSEC3ProvesNODATA(t *testing.T) {
	z := buildDNSSECTestZones(t)
	up := startDNSSECTestUpstream(t, z)
	v := NewValidator(testAnchorManager(z.anchor))

	hOwner := nsec3Hash("example.test.")
	n, sig := nsec3RR(t, z.leaf, "example.test.", hOwner, bumpBase32Hex(t, hOwner, 1), dns.TypeA, dns.TypeRRSIG, dns.TypeNSEC3)

	resp := new(dns.Msg)
	resp.Rcode = dns.RcodeSuccess
	resp.Question = []dns.Question{{Name: "example.test.", Qtype: dns.TypeAAAA, Qclass: dns.ClassINET}}
	resp.Ns = []dns.RR{n, sig}

	secure, signed, err := v.Validate(context.Background(), up, resp)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if !signed || !secure {
		t.Fatalf("expected signed=true, secure=true for a genuine NSEC3 NODATA proof, got signed=%v secure=%v", signed, secure)
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
