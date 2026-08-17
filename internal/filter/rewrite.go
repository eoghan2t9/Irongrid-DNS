package filter

import (
	"net"
	"strings"
	"sync"

	"github.com/miekg/dns"
)

// RewriteSpec mirrors config.RewriteSpec (see ListSpec for why this package
// keeps its own copy instead of importing the config package).
type RewriteSpec struct {
	Domain string
	Type   string // "A", "AAAA" or "CNAME"
	Value  string
	TTL    uint32
}

// RewriteRule is a single compiled local DNS record: qname is answered
// directly with rrtype/value instead of being forwarded upstream.
type RewriteRule struct {
	Type  uint16 // dns.TypeA, dns.TypeAAAA or dns.TypeCNAME
	Value string
	TTL   uint32
}

// Rewriter answers queries for locally-configured domains (e.g.
// "nas.home" -> 192.168.1.10) without touching the cache or upstreams.
// Safe for concurrent use; Set fully replaces the rule set so config reloads
// are atomic from a reader's perspective.
type Rewriter struct {
	mu sync.RWMutex
	// exact holds non-wildcard rules keyed by domain; wildcard holds "*."
	// rules keyed by the suffix (without the "*.").
	exact    map[string][]RewriteRule
	wildcard map[string][]RewriteRule
}

// NewRewriter returns an empty rewriter (Lookup always misses).
func NewRewriter() *Rewriter {
	return &Rewriter{exact: map[string][]RewriteRule{}, wildcard: map[string][]RewriteRule{}}
}

// Set replaces the whole rule set. Malformed specs (bad type, empty domain
// or value) are skipped rather than failing the whole set — config-level
// validation should already reject these before they reach here.
func (rw *Rewriter) Set(specs []RewriteSpec) {
	exact := map[string][]RewriteRule{}
	wildcard := map[string][]RewriteRule{}
	for _, s := range specs {
		domain := normalizeDomain(s.Domain)
		if domain == "" || s.Value == "" {
			continue
		}
		var qtype uint16
		switch strings.ToUpper(s.Type) {
		case "A":
			qtype = dns.TypeA
		case "AAAA":
			qtype = dns.TypeAAAA
		case "CNAME":
			qtype = dns.TypeCNAME
		default:
			continue
		}
		ttl := s.TTL
		if ttl == 0 {
			ttl = 300
		}
		rule := RewriteRule{Type: qtype, Value: s.Value, TTL: ttl}
		if after, ok := strings.CutPrefix(domain, "*."); ok {
			suffix := after
			wildcard[suffix] = append(wildcard[suffix], rule)
		} else {
			exact[domain] = append(exact[domain], rule)
		}
	}
	rw.mu.Lock()
	rw.exact = exact
	rw.wildcard = wildcard
	rw.mu.Unlock()
}

// Lookup returns the rules for qname if a local record matches, or ok=false
// to fall through to cache/upstream. Exact matches win over wildcard subtree
// matches.
func (rw *Rewriter) Lookup(qname string) (rules []RewriteRule, ok bool) {
	qname = normalizeDomain(qname)
	if qname == "" {
		return nil, false
	}
	rw.mu.RLock()
	defer rw.mu.RUnlock()
	if len(rw.exact) == 0 && len(rw.wildcard) == 0 {
		return nil, false
	}
	if rules, found := rw.exact[qname]; found {
		return rules, true
	}
	labels := strings.Split(qname, ".")
	for i := 1; i < len(labels); i++ {
		suffix := strings.Join(labels[i:], ".")
		if rules, found := rw.wildcard[suffix]; found {
			return rules, true
		}
	}
	return nil, false
}

// BuildAnswer turns matched rules into a response for the original query, or
// nil when no rule matches qtype (and none is a CNAME) — NODATA territory,
// left to the caller to render as an empty NOERROR. A CNAME rule answers any
// query type, matching normal DNS semantics.
func BuildAnswer(r *dns.Msg, rules []RewriteRule, qname string, qtype uint16) *dns.Msg {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative = true
	hdr := func(ttl uint32, rrtype uint16) dns.RR_Header {
		return dns.RR_Header{Name: dns.Fqdn(qname), Rrtype: rrtype, Class: dns.ClassINET, Ttl: ttl}
	}
	matched := false
	for _, ru := range rules {
		switch {
		case ru.Type == dns.TypeCNAME:
			m.Answer = append(m.Answer, &dns.CNAME{Hdr: hdr(ru.TTL, dns.TypeCNAME), Target: dns.Fqdn(ru.Value)})
			matched = true
		case ru.Type == dns.TypeA && qtype == dns.TypeA:
			if ip := net.ParseIP(ru.Value).To4(); ip != nil {
				m.Answer = append(m.Answer, &dns.A{Hdr: hdr(ru.TTL, dns.TypeA), A: ip})
				matched = true
			}
		case ru.Type == dns.TypeAAAA && qtype == dns.TypeAAAA:
			if ip := net.ParseIP(ru.Value); ip != nil {
				m.Answer = append(m.Answer, &dns.AAAA{Hdr: hdr(ru.TTL, dns.TypeAAAA), AAAA: ip})
				matched = true
			}
		}
	}
	if !matched {
		return nil
	}
	return m
}
