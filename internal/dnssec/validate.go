package dnssec

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/eoghan2t9/Irongrid-DNS/internal/upstream"
	"github.com/miekg/dns"
)

const (
	// minZoneKeyTTL/maxZoneKeyTTL bound how long a validated (or
	// known-insecure) zone's DNSKEY set is cached, regardless of what TTL
	// the zone itself published — a very short TTL would re-validate (and
	// re-query DNSKEY/DS) far too often, a very long one would delay
	// picking up a real key rollover.
	minZoneKeyTTL = 5 * time.Minute
	maxZoneKeyTTL = 24 * time.Hour

	// queryTimeout bounds each extra DNSKEY/DS lookup the chain walk
	// issues; independent of the caller's own query budget.
	queryTimeout = 5 * time.Second

	// maxChainDepth is a generous bound against a pathological or looping
	// zone name; a real domain never needs more than a handful of labels.
	maxChainDepth = 20
)

type zoneCacheEntry struct {
	keys    []*dns.DNSKEY
	secure  bool
	expires time.Time
}

// Validator performs opportunistic local DNSSEC chain-of-trust validation.
// It is safe for concurrent use and holds its own per-zone DNSKEY cache, so
// one Validator should be shared across every query rather than built per
// request.
type Validator struct {
	anchors *AnchorManager

	mu    sync.Mutex
	cache map[string]zoneCacheEntry
}

// NewValidator creates a Validator backed by anchors for its root of trust.
func NewValidator(anchors *AnchorManager) *Validator {
	return &Validator{anchors: anchors, cache: make(map[string]zoneCacheEntry)}
}

// Validate performs opportunistic DNSSEC validation on resp — the response
// as returned by an upstream that was asked for it (the DO bit set on the
// outbound query, so a signed zone answers with RRSIG records attached).
//
// signed reports whether resp carried any RRSIG at all. A response with
// none (the vast majority of the internet — most zones aren't signed)
// returns signed=false, secure=false, err=nil: that's "nothing to
// validate", not a failure. Callers decide what policy applies to an
// unsigned answer; this package only judges what it can actually check.
//
// When signed is true, secure reports whether every covered RRset's
// signature verified all the way to a trust anchor. err is returned
// separately from a plain "didn't validate" (secure=false, err=nil) for a
// reason that matters operationally: err means the chain walk itself
// failed for an infrastructure reason (a DNSKEY/DS query timed out or the
// upstream errored) — "couldn't check", which a caller should usually fail
// open on rather than blocking real resolution over a transient hiccup.
// secure=false with err=nil covers both "the parent publishes no DS for
// this zone" (would need an NSEC/NSEC3 proof to call this provably
// insecure rather than just unchecked — this package doesn't implement
// that) and "a signature or DS hash flatly didn't match" (an actual
// integrity failure) — both are folded into the same conservative
// "couldn't confirm this is secure", which the caller should generally
// treat as fail-closed for an answer that DID present RRSIG but a hard
// cryptographic mismatch was found (see the distinct error wrapping for
// "did not verify" cases below, which callers may want to key off of if
// they need to tell the two apart).
func (v *Validator) Validate(ctx context.Context, up *upstream.Upstream, resp *dns.Msg) (secure, signed bool, err error) {
	if resp == nil {
		return false, false, nil
	}
	byType := make(map[uint16][]dns.RR)
	var sigs []*dns.RRSIG
	for _, rr := range resp.Answer {
		if sig, ok := rr.(*dns.RRSIG); ok {
			sigs = append(sigs, sig)
			continue
		}
		byType[rr.Header().Rrtype] = append(byType[rr.Header().Rrtype], rr)
	}
	if len(sigs) == 0 {
		return false, false, nil
	}

	for _, sig := range sigs {
		rrset := byType[sig.TypeCovered]
		if len(rrset) == 0 {
			// An RRSIG with nothing in the answer for it to cover — not
			// itself a validation failure (e.g. a signature that arrived
			// for a type this handler stripped), just nothing to check.
			continue
		}
		keys, zoneSecure, kerr := v.zoneKeys(ctx, up, sig.SignerName, 0)
		if kerr != nil {
			return false, true, kerr
		}
		if !zoneSecure {
			return false, true, nil
		}
		if !verifySigned(sig, rrset, keys) {
			// A cryptographic mismatch — the whole point of this check —
			// is a completed, valid "no" answer, not an infrastructure
			// failure: err stays nil so the caller fails closed on
			// secure=false rather than treating this the same as a
			// DNSKEY/DS query that simply couldn't be completed.
			return false, true, nil
		}
	}
	return true, true, nil
}

// zoneKeys returns zone's validated DNSKEY set, walking the chain of trust
// up through parent zones (cached at every level) to the configured trust
// anchor. secure=false with err=nil means the walk completed but couldn't
// establish trust (no DS at the parent, or DS doesn't match any published
// key) — treated as "insecure", never silently as "trusted".
func (v *Validator) zoneKeys(ctx context.Context, up *upstream.Upstream, zone string, depth int) (keys []*dns.DNSKEY, secure bool, err error) {
	zone = dns.Fqdn(zone)
	if depth > maxChainDepth {
		return nil, false, fmt.Errorf("dnssec: chain depth exceeded validating %s", zone)
	}

	if cached, ok := v.cached(zone); ok {
		return cached.keys, cached.secure, nil
	}

	dnskeyMsg, err := queryZone(ctx, up, zone, dns.TypeDNSKEY)
	if err != nil {
		return nil, false, fmt.Errorf("dnssec: DNSKEY query for %s: %w", zone, err)
	}
	if dnskeyMsg.Rcode != dns.RcodeSuccess {
		// The query itself failed (SERVFAIL/REFUSED/...) — an
		// infrastructure problem, not confirmation the zone has no
		// DNSKEY. Only a clean NOERROR response with an empty answer
		// (handled below) means that.
		return nil, false, fmt.Errorf("dnssec: DNSKEY query for %s returned %s", zone, dns.RcodeToString[dnskeyMsg.Rcode])
	}
	dnskeys, dnskeyRRset, dnskeySigs := splitAnswer[*dns.DNSKEY](dnskeyMsg.Answer, dns.TypeDNSKEY)
	ttl := zoneKeyTTL(dnskeyMsg.Answer)

	if len(dnskeys) == 0 {
		v.storeZone(zone, nil, false, ttl)
		return nil, false, nil
	}

	if zone == "." {
		secure := verifyAgainstAnchors(dnskeys, dnskeySigs, dnskeyRRset, v.anchors.Anchors())
		v.storeZone(zone, dnskeys, secure, ttl)
		return dnskeys, secure, nil
	}

	parent := parentZone(zone)
	parentKeys, parentSecure, err := v.zoneKeys(ctx, up, parent, depth+1)
	if err != nil {
		return nil, false, err
	}
	if !parentSecure {
		v.storeZone(zone, dnskeys, false, ttl)
		return dnskeys, false, nil
	}

	dsMsg, err := queryZone(ctx, up, zone, dns.TypeDS)
	if err != nil {
		return nil, false, fmt.Errorf("dnssec: DS query for %s: %w", zone, err)
	}
	if dsMsg.Rcode != dns.RcodeSuccess {
		// Same reasoning as the DNSKEY query above: a failed query is not
		// confirmation of an insecure delegation.
		return nil, false, fmt.Errorf("dnssec: DS query for %s returned %s", zone, dns.RcodeToString[dsMsg.Rcode])
	}
	dsRecords, dsRRset, dsSigs := splitAnswer[*dns.DS](dsMsg.Answer, dns.TypeDS)
	if len(dsRecords) == 0 {
		// No DS published at the parent for this zone: a full validator
		// would demand an NSEC/NSEC3 proof of that absence before calling
		// it a provably-insecure delegation; this package doesn't
		// implement that, so it conservatively lands on "insecure",
		// exactly like any other unsigned zone.
		v.storeZone(zone, dnskeys, false, ttl)
		return dnskeys, false, nil
	}
	if !verifySignedAny(dsSigs, dsRRset, parentKeys) {
		// Cryptographic mismatch, not an infra failure — see the identical
		// reasoning in Validate for the leaf-answer case. Cached as
		// insecure so a repeated query for the same bad zone doesn't
		// re-walk the chain every time.
		v.storeZone(zone, dnskeys, false, ttl)
		return dnskeys, false, nil
	}

	matched := matchDS(dnskeys, dsRecords)
	if matched == nil {
		v.storeZone(zone, dnskeys, false, ttl)
		return dnskeys, false, nil
	}
	if !verifySignedAny(dnskeySigs, dnskeyRRset, []*dns.DNSKEY{matched}) {
		v.storeZone(zone, dnskeys, false, ttl)
		return dnskeys, false, nil
	}

	v.storeZone(zone, dnskeys, true, ttl)
	return dnskeys, true, nil
}

func (v *Validator) cached(zone string) (zoneCacheEntry, bool) {
	v.mu.Lock()
	defer v.mu.Unlock()
	e, ok := v.cache[zone]
	if !ok || time.Now().After(e.expires) {
		return zoneCacheEntry{}, false
	}
	return e, true
}

func (v *Validator) storeZone(zone string, keys []*dns.DNSKEY, secure bool, ttl time.Duration) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.cache[zone] = zoneCacheEntry{keys: keys, secure: secure, expires: time.Now().Add(ttl)}
}

// queryZone issues one DO-bit query for name/qtype through up — the same
// upstream that answered the original client query, so the extra DNSKEY/DS
// lookups get the same trust properties (encrypted transport, etc.) as the
// query being validated.
func queryZone(ctx context.Context, up *upstream.Upstream, name string, qtype uint16) (*dns.Msg, error) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), qtype)
	m.SetEdns0(4096, true)
	qctx, cancel := context.WithTimeout(ctx, queryTimeout)
	defer cancel()
	return up.Query(qctx, m)
}

// splitAnswer pulls every T-typed record plus the RRSIGs covering
// typeCovered out of an Answer section, returning the typed records (for
// matching/inspection), the same records as a plain []dns.RR (as
// RRSIG.Verify wants), and their covering signatures.
func splitAnswer[T dns.RR](answer []dns.RR, typeCovered uint16) (typed []T, rrset []dns.RR, sigs []*dns.RRSIG) {
	for _, rr := range answer {
		switch t := rr.(type) {
		case T:
			typed = append(typed, t)
			rrset = append(rrset, rr)
		case *dns.RRSIG:
			if t.TypeCovered == typeCovered {
				sigs = append(sigs, t)
			}
		}
	}
	return typed, rrset, sigs
}

// verifySigned reports whether sig — within its validity window — verifies
// rrset against some key in keys matching its tag and algorithm.
func verifySigned(sig *dns.RRSIG, rrset []dns.RR, keys []*dns.DNSKEY) bool {
	if !sig.ValidityPeriod(time.Now()) {
		return false
	}
	for _, k := range keys {
		if k.Algorithm != sig.Algorithm || k.KeyTag() != sig.KeyTag {
			continue
		}
		if err := sig.Verify(k, rrset); err == nil {
			return true
		}
	}
	return false
}

// verifySignedAny reports whether any signature in sigs verifies rrset
// against keys — an RRset legitimately carries multiple RRSIGs during a
// key rollover, so any one matching is sufficient.
func verifySignedAny(sigs []*dns.RRSIG, rrset []dns.RR, keys []*dns.DNSKEY) bool {
	for _, sig := range sigs {
		if verifySigned(sig, rrset, keys) {
			return true
		}
	}
	return false
}

// matchDS returns the DNSKEY among keys whose computed digest matches one
// of dsRecords, or nil if none does.
func matchDS(keys []*dns.DNSKEY, dsRecords []*dns.DS) *dns.DNSKEY {
	for _, ds := range dsRecords {
		for _, k := range keys {
			cand := k.ToDS(ds.DigestType)
			if cand == nil {
				continue
			}
			if cand.KeyTag == ds.KeyTag && cand.Algorithm == ds.Algorithm && strings.EqualFold(cand.Digest, ds.Digest) {
				return k
			}
		}
	}
	return nil
}

// verifyAgainstAnchors is matchDS + verifySignedAny for the root: the
// configured trust anchors take the place of a parent's DS records.
func verifyAgainstAnchors(keys []*dns.DNSKEY, sigs []*dns.RRSIG, rrset []dns.RR, anchors []TrustAnchor) bool {
	var matched *dns.DNSKEY
	for _, a := range anchors {
		for _, k := range keys {
			cand := k.ToDS(a.DigestType)
			if cand == nil {
				continue
			}
			if cand.KeyTag == a.KeyTag && cand.Algorithm == a.Algorithm && strings.EqualFold(cand.Digest, a.Digest) {
				matched = k
				break
			}
		}
		if matched != nil {
			break
		}
	}
	if matched == nil {
		return false
	}
	return verifySignedAny(sigs, rrset, []*dns.DNSKEY{matched})
}

// parentZone strips the leftmost label from zone ("example.com." ->
// "com."); the root's own parent is itself, since the chain walk's
// zone == "." branch handles the root specially and never calls this on it.
func parentZone(zone string) string {
	zone = dns.Fqdn(zone)
	if zone == "." {
		return "."
	}
	labels := dns.SplitDomainName(zone)
	if len(labels) <= 1 {
		return "."
	}
	return dns.Fqdn(strings.Join(labels[1:], "."))
}

// zoneKeyTTL derives a cache lifetime from a DNSKEY RRset's own TTL,
// bounded to [minZoneKeyTTL, maxZoneKeyTTL].
func zoneKeyTTL(rrs []dns.RR) time.Duration {
	var min uint32
	for _, rr := range rrs {
		if _, ok := rr.(*dns.DNSKEY); !ok {
			continue
		}
		ttl := rr.Header().Ttl
		if min == 0 || ttl < min {
			min = ttl
		}
	}
	d := time.Duration(min) * time.Second
	if d < minZoneKeyTTL {
		return minZoneKeyTTL
	}
	if d > maxZoneKeyTTL {
		return maxZoneKeyTTL
	}
	return d
}
