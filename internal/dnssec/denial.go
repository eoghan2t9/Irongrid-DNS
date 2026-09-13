package dnssec

import (
	"context"
	"strings"

	"github.com/eoghan2t9/Irongrid-DNS/internal/upstream"
	"github.com/miekg/dns"
)

// validateDenial checks whether resp's Authority section (NSEC or NSEC3
// records) cryptographically proves the negative result it's returning:
// NXDOMAIN (the name doesn't exist) or NODATA (the name exists but not with
// the queried type) — the two legitimate negative-answer shapes RFC 2308
// defines. Only reached from Validate when the Answer section carries no
// RRSIG at all, which for a genuine negative answer is expected (there's
// nothing to sign there); the proof, if any, lives in Authority instead.
//
// Conservative by design, matching Validate's existing philosophy: any
// shape that doesn't cleanly fit RFC 4035 §5.4 (NSEC) or RFC 5155 §8
// (NSEC3) returns secure=false rather than guessing. Under-proving falls
// back to the caller's existing AD-bit trust path (safe); over-proving
// would be a real security bug, so ambiguity always loses.
func (v *Validator) validateDenial(ctx context.Context, up *upstream.Upstream, resp *dns.Msg) (secure, signed bool, err error) {
	if len(resp.Question) == 0 {
		return false, false, nil
	}
	q := resp.Question[0]
	qname := strings.ToLower(dns.Fqdn(q.Name))

	var nsecs []*dns.NSEC
	var nsec3s []*dns.NSEC3
	var nsecSigs, nsec3Sigs []*dns.RRSIG
	for _, rr := range resp.Ns {
		switch t := rr.(type) {
		case *dns.NSEC:
			nsecs = append(nsecs, t)
		case *dns.NSEC3:
			nsec3s = append(nsec3s, t)
		case *dns.RRSIG:
			switch t.TypeCovered {
			case dns.TypeNSEC:
				nsecSigs = append(nsecSigs, t)
			case dns.TypeNSEC3:
				nsec3Sigs = append(nsec3Sigs, t)
			}
		}
	}
	if len(nsecs) == 0 && len(nsec3s) == 0 {
		// Nothing to validate — a negative answer with no NSEC/NSEC3 at
		// all is indistinguishable from a plain unsigned zone here.
		return false, false, nil
	}

	// Every NSEC/NSEC3 record must itself carry a verified signature
	// before its content is trusted for a proof — verified individually
	// (rather than batched) since each record is its own single-RR RRset
	// (a name has at most one NSEC/NSEC3), so batching different owners
	// together would just fail RRSIG.Verify's owner-name check.
	for _, n := range nsecs {
		if !v.verifyDenialRR(ctx, up, n, nsecSigs) {
			return false, true, nil
		}
	}
	for _, n := range nsec3s {
		if !v.verifyDenialRR(ctx, up, n, nsec3Sigs) {
			return false, true, nil
		}
	}

	if len(nsec3s) > 0 {
		return proveNSEC3(resp.Rcode, qname, q.Qtype, nsec3s), true, nil
	}
	return proveNSEC(resp.Rcode, qname, q.Qtype, nsecs), true, nil
}

// verifyDenialRR reports whether rr has a verified signature among sigs,
// resolving the signer's zone keys on demand (cached/coalesced the same way
// every other zone-key lookup in this package is).
func (v *Validator) verifyDenialRR(ctx context.Context, up *upstream.Upstream, rr dns.RR, sigs []*dns.RRSIG) bool {
	owner := strings.ToLower(rr.Header().Name)
	for _, sig := range sigs {
		if !strings.EqualFold(strings.ToLower(sig.Header().Name), owner) {
			continue
		}
		keys, secure, err := v.zoneKeys(ctx, up, sig.SignerName, 0)
		if err != nil || !secure {
			continue
		}
		if verifySigned(sig, []dns.RR{rr}, keys) {
			return true
		}
	}
	return false
}

// bitmapHasType reports whether t is present in an NSEC/NSEC3 type bitmap
// (miekg/dns decodes the wire bitmap into a plain list of present types).
func bitmapHasType(bitmap []uint16, t uint16) bool {
	for _, bt := range bitmap {
		if bt == t {
			return true
		}
	}
	return false
}

// proveNSEC applies RFC 4035 §5.4's NSEC denial-of-existence proof.
func proveNSEC(rcode int, qname string, qtype uint16, nsecs []*dns.NSEC) bool {
	if rcode == dns.RcodeSuccess {
		// NODATA: an NSEC record owned exactly by qname, with qtype's (and
		// CNAME's — a CNAME would mean this is actually a redirect, not a
		// true NODATA) bit absent from its type bitmap, proves the name
		// exists but this type doesn't.
		for _, n := range nsecs {
			if strings.EqualFold(strings.ToLower(dns.Fqdn(n.Header().Name)), qname) {
				return !bitmapHasType(n.TypeBitMap, qtype) && !bitmapHasType(n.TypeBitMap, dns.TypeCNAME)
			}
		}
		return false
	}
	if rcode != dns.RcodeNameError {
		return false
	}

	// NXDOMAIN needs two things proven: (1) no exact match for qname, and
	// (2) no wildcard could have synthesized an answer either.
	if !nsecCoversAny(nsecs, qname) {
		return false
	}
	// Compact denial of existence: a single NSEC record whose owner is
	// exactly qname (the same synthesis nsecCoversAny's doc comment
	// describes) already proves the whole NXDOMAIN case by itself — an
	// online-signing resolver generating this minimally-covering record
	// would have returned the wildcard's real data instead had a wildcard
	// applied, so no separate wildcard-non-existence proof is expected.
	if nsecOwnerExists(nsecs, qname) {
		return true
	}
	// Closest encloser: walk qname's ancestors from most to least specific
	// until one is proven to exist (some NSEC's owner name matches it
	// exactly) — that's the closest encloser, since it's the longest
	// ancestor known to be present. Then a wildcard beneath it must be
	// covered (proven absent) too.
	labels := dns.SplitDomainName(qname)
	for i := 1; i < len(labels); i++ {
		ancestor := dns.Fqdn(strings.Join(labels[i:], "."))
		if !nsecOwnerExists(nsecs, ancestor) {
			continue
		}
		return nsecCoversAny(nsecs, "*."+ancestor)
	}
	return false
}

// nsecCoversAny reports whether any NSEC in nsecs covers name (RFC 4035
// §5.4: name falls strictly between the NSEC's owner and its Next Domain
// Name in canonical DNS order, wrapping at the end of the zone) — with one
// deliberate relaxation: the owner side is inclusive (owner <= name), not
// strictly less. This is required to recognize "compact denial of
// existence" / minimally-covering NSEC synthesis (deployed by Cloudflare
// and others, verified against a live cloudflare.com NXDOMAIN response):
// the synthesized NSEC's owner name is set to the queried name itself, with
// Next Domain Name one label longer, proving nothing between qname
// (inclusive) and just-past-qname exists. A classic, non-synthesized NSEC
// chain never has owner == a genuinely nonexistent name in the first place
// (an NSEC's owner always names something that really exists), so this
// relaxation never weakens the classic case — it only additionally accepts
// the synthesized one.
func nsecCoversAny(nsecs []*dns.NSEC, name string) bool {
	for _, n := range nsecs {
		owner := strings.ToLower(dns.Fqdn(n.Header().Name))
		next := strings.ToLower(dns.Fqdn(n.NextDomain))
		if nsecCovers(owner, next, name) {
			return true
		}
	}
	return false
}

func nsecCovers(owner, next, name string) bool {
	if !canonicalLess(owner, next) {
		// Wrap-around: this NSEC is the last in the chain, covering
		// owner..end-of-zone plus start-of-zone..next.
		return !canonicalLess(name, owner) || canonicalLess(name, next)
	}
	return !canonicalLess(name, owner) && canonicalLess(name, next)
}

// nsecOwnerExists reports whether some NSEC's owner name exactly equals
// name — used for the closest-encloser step, where the apex's own NSEC
// (which always exists in any signed zone) guarantees the walk terminates.
func nsecOwnerExists(nsecs []*dns.NSEC, name string) bool {
	for _, n := range nsecs {
		if strings.EqualFold(strings.ToLower(dns.Fqdn(n.Header().Name)), name) {
			return true
		}
	}
	return false
}

// canonicalLess reports whether a sorts strictly before b in RFC 4034 §6.1
// canonical DNS name order: compared label-by-label from the rightmost
// (most significant) label inward, each label byte-compared after
// ASCII-lowercasing; a name that's a strict prefix of another (from the
// right) sorts first. Scoped to ASCII labels — real-world domain names are
// effectively always ASCII/punycode, and this package never needs to order
// arbitrary binary label content.
func canonicalLess(a, b string) bool {
	la := dns.SplitDomainName(dns.Fqdn(a))
	lb := dns.SplitDomainName(dns.Fqdn(b))
	for i, j := len(la)-1, len(lb)-1; i >= 0 && j >= 0; i, j = i-1, j-1 {
		c := strings.Compare(strings.ToLower(la[i]), strings.ToLower(lb[j]))
		if c != 0 {
			return c < 0
		}
	}
	return len(la) < len(lb)
}

// proveNSEC3 applies RFC 5155 §8's NSEC3 denial-of-existence proof, using
// miekg/dns's own NSEC3.Cover/Match — which hash the candidate name with
// the record's own algorithm/iterations/salt internally — rather than
// reimplementing RFC 5155's iterated salted hashing by hand. Verified
// against live NXDOMAIN responses from verisign.com and iana.org.
//
// Opt-out (NSEC3 Flags bit 0) isn't special-cased: it means the covering
// record doesn't prove there's no *unsigned delegation* hiding in its
// range, a claim this function never makes for a plain name's own
// existence — Cover/Match's interval math is unaffected by the flag.
func proveNSEC3(rcode int, qname string, qtype uint16, nsec3s []*dns.NSEC3) bool {
	if rcode == dns.RcodeSuccess {
		for _, n := range nsec3s {
			if n.Match(qname) {
				return !bitmapHasType(n.TypeBitMap, qtype) && !bitmapHasType(n.TypeBitMap, dns.TypeCNAME)
			}
		}
		return false
	}
	if rcode != dns.RcodeNameError {
		return false
	}

	if !nsec3CoversAny(nsec3s, qname) {
		return false
	}
	labels := dns.SplitDomainName(qname)
	for i := 1; i < len(labels); i++ {
		ancestor := dns.Fqdn(strings.Join(labels[i:], "."))
		matched := false
		for _, n := range nsec3s {
			if n.Match(ancestor) {
				matched = true
				break
			}
		}
		if !matched {
			continue
		}
		return nsec3CoversAny(nsec3s, "*."+ancestor)
	}
	return false
}

func nsec3CoversAny(nsec3s []*dns.NSEC3, name string) bool {
	for _, n := range nsec3s {
		if n.Cover(name) {
			return true
		}
	}
	return false
}
