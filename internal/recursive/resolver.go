package recursive

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

const (
	// maxHops bounds a single Resolve call's referral walk (root -> TLD ->
	// authoritative is normally 2-3 hops; this only matters as a backstop
	// against a misbehaving or hostile server).
	maxHops = 30
	// maxCNAMEChain bounds how many CNAME targets one query will chase.
	maxCNAMEChain = 10
	// maxNSResolveDepth bounds how deep a chain of glueless (out-of-bailiwick)
	// nameserver lookups is allowed to nest — resolving ns1.dnsimple.com's own
	// address is a completely independent walk, so without a cap a pathological
	// or hostile chain of glueless delegations could recurse indefinitely.
	maxNSResolveDepth = 3

	perServerTimeout = 3 * time.Second
	minDelegationTTL = 60 * time.Second
	maxDelegationTTL = 24 * time.Hour
)

// Resolver performs iterative resolution starting from the DNS root,
// following referrals itself instead of forwarding to a recursive resolver.
// It caches NS delegations (which servers are authoritative for which zone)
// so only the first query under a given TLD or domain pays the full walk;
// later queries under the same zone jump straight to the deepest known
// delegation. Safe for concurrent use.
type Resolver struct {
	rootHints []string
	// nsPort is the port assumed for every address derived from glue
	// records — real DNS glue (A/AAAA) never carries a port, so production
	// always resolves to 53; overridable only for tests running a fake
	// server hierarchy on non-standard ports.
	nsPort string

	mu          sync.RWMutex
	delegations map[string]delegation
}

type delegation struct {
	servers []string // "ip:port" / "[ipv6]:port", dial-ready
	expiry  time.Time
}

// New returns a Resolver seeded with rootHints ("ip:port" strings). A
// nil/empty slice falls back to DefaultRootHints.
func New(rootHints []string) *Resolver {
	if len(rootHints) == 0 {
		rootHints = DefaultRootHints
	}
	return &Resolver{
		rootHints:   rootHints,
		nsPort:      "53",
		delegations: map[string]delegation{},
	}
}

// Resolve performs iterative resolution for m's question and returns a
// response with m's Id rebased in, matching the contract of
// upstream.Upstream.Query so the two are interchangeable to callers.
func (r *Resolver) Resolve(ctx context.Context, m *dns.Msg) (*dns.Msg, error) {
	if len(m.Question) == 0 {
		return nil, fmt.Errorf("recursive: query has no question")
	}
	resp, err := r.resolve(ctx, m.Question[0], 0, 0)
	if err != nil {
		return nil, err
	}
	resp.Id = m.Id
	resp.RecursionAvailable = true
	return resp, nil
}

func (r *Resolver) resolve(ctx context.Context, q dns.Question, cnameDepth, nsDepth int) (*dns.Msg, error) {
	if cnameDepth > maxCNAMEChain {
		return nil, fmt.Errorf("recursive: CNAME chain too long resolving %s", q.Name)
	}

	zone, servers := r.bestDelegation(q.Name)
	visited := map[string]bool{zone: true}

	for hop := 0; hop < maxHops; hop++ {
		resp, err := r.queryServers(ctx, servers, q)
		if err != nil {
			return nil, err
		}

		if isFinal(resp) {
			return r.chaseCNAME(ctx, q, resp, cnameDepth, nsDepth)
		}

		nextZone, nsRecords, ttl, hasNS := parseReferral(resp)
		if !hasNS {
			// No NS records at all in Authority and not otherwise final
			// (isFinal already covers the AA/answer/NXDOMAIN cases) —
			// there's nothing more this walk can do with it.
			return resp, nil
		}
		nextServers := r.resolveNameservers(ctx, nsRecords, nsDepth)
		if len(nextServers) == 0 {
			return nil, fmt.Errorf("recursive: zone %s delegated with no resolvable nameservers", nextZone)
		}
		if visited[nextZone] {
			// Referral loop (a misbehaving server re-delegating to a zone
			// already visited this walk) — return the best-effort answer
			// rather than spinning.
			return resp, nil
		}
		visited[nextZone] = true
		r.cacheDelegation(nextZone, nextServers, ttl)
		zone, servers = nextZone, nextServers
	}
	return nil, fmt.Errorf("recursive: exceeded %d referral hops resolving %s", maxHops, q.Name)
}

// isFinal reports whether resp answers the query (positively or as an
// authoritative NXDOMAIN/NODATA) rather than being a referral. A referral
// carries NS records in the Authority section without the AA bit; an
// authoritative NODATA/NXDOMAIN carries a SOA in Authority with AA set.
func isFinal(resp *dns.Msg) bool {
	if resp.Rcode == dns.RcodeNameError {
		return true
	}
	if len(resp.Answer) > 0 {
		return true
	}
	return resp.Authoritative
}

// chaseCNAME follows a CNAME in resp's answer to its target when the client
// asked for a different type and the target's own records weren't already
// included, merging the target's answer onto the CNAME hop.
func (r *Resolver) chaseCNAME(ctx context.Context, q dns.Question, resp *dns.Msg, cnameDepth, nsDepth int) (*dns.Msg, error) {
	if q.Qtype == dns.TypeCNAME {
		return resp, nil
	}
	var target string
	for _, rr := range resp.Answer {
		if rr.Header().Rrtype == q.Qtype {
			return resp, nil // already has the actual answer alongside the CNAME
		}
		if cn, ok := rr.(*dns.CNAME); ok && strings.EqualFold(cn.Header().Name, q.Name) {
			target = cn.Target
		}
	}
	if target == "" {
		return resp, nil
	}
	follow, err := r.resolve(ctx, dns.Question{Name: target, Qtype: q.Qtype, Qclass: q.Qclass}, cnameDepth+1, nsDepth)
	if err != nil {
		// Return the CNAME hop we do have rather than failing the whole
		// query over a downstream failure resolving its target.
		return resp, nil
	}
	merged := resp.Copy()
	merged.Answer = append(merged.Answer, follow.Answer...)
	merged.Rcode = follow.Rcode
	if follow.Authoritative {
		merged.Ns = follow.Ns
	}
	return merged, nil
}

// queryServers tries each candidate server in order (each a plain address a
// dns.Client can dial), falling back to TCP on a truncated UDP reply, and
// returns the first successful response.
func (r *Resolver) queryServers(ctx context.Context, servers []string, q dns.Question) (*dns.Msg, error) {
	m := new(dns.Msg)
	m.SetQuestion(q.Name, q.Qtype)
	m.Question[0].Qclass = q.Qclass
	m.RecursionDesired = false
	m.SetEdns0(4096, false)

	var lastErr error
	for _, addr := range servers {
		resp, err := exchange(ctx, addr, m, "udp")
		if err != nil {
			lastErr = err
			continue
		}
		if resp.Truncated {
			resp, err = exchange(ctx, addr, m, "tcp")
			if err != nil {
				lastErr = err
				continue
			}
		}
		return resp, nil
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no servers to query")
	}
	return nil, fmt.Errorf("recursive: resolving %s: %w", q.Name, lastErr)
}

func exchange(ctx context.Context, addr string, m *dns.Msg, network string) (*dns.Msg, error) {
	cctx, cancel := context.WithTimeout(ctx, perServerTimeout)
	defer cancel()
	c := &dns.Client{Net: network, Timeout: perServerTimeout}
	resp, _, err := c.ExchangeContext(cctx, m, addr)
	return resp, err
}

// nsInfo is one delegated nameserver: its hostname, plus any glue addresses
// (raw IPs, no port) the referral itself supplied for it.
type nsInfo struct {
	name    string
	glueIPs []string
}

// parseReferral extracts the next zone's nameservers and any glue from a
// referral response. hasNS is false only when resp carries no NS records at
// all (i.e. it isn't a referral). A nameserver with no glue is included with
// an empty glueIPs — the common case for an out-of-bailiwick nameserver
// (e.g. a domain hosted on Cloudflare/Route53/DNSimple-style DNS, whose
// hostname lives outside the zone being delegated), which the parent has no
// glue obligation for.
func parseReferral(resp *dns.Msg) (zone string, ns []nsInfo, ttl time.Duration, hasNS bool) {
	var nsNames []string
	var minTTL uint32
	for _, rr := range resp.Ns {
		nsRR, ok := rr.(*dns.NS)
		if !ok {
			continue
		}
		zone = strings.ToLower(nsRR.Header().Name)
		nsNames = append(nsNames, strings.ToLower(nsRR.Ns))
		if minTTL == 0 || nsRR.Header().Ttl < minTTL {
			minTTL = nsRR.Header().Ttl
		}
	}
	if len(nsNames) == 0 {
		return "", nil, 0, false
	}

	glue := map[string][]string{}
	for _, rr := range resp.Extra {
		switch v := rr.(type) {
		case *dns.A:
			name := strings.ToLower(v.Header().Name)
			glue[name] = append(glue[name], v.A.String())
		case *dns.AAAA:
			name := strings.ToLower(v.Header().Name)
			glue[name] = append(glue[name], v.AAAA.String())
		}
	}
	for _, name := range nsNames {
		ns = append(ns, nsInfo{name: name, glueIPs: glue[name]})
	}

	ttl = time.Duration(minTTL) * time.Second
	if ttl < minDelegationTTL {
		ttl = minDelegationTTL
	}
	if ttl > maxDelegationTTL {
		ttl = maxDelegationTTL
	}
	return zone, ns, ttl, true
}

// resolveNameservers turns a referral's nameservers into dial-ready
// addresses: glue is used directly when the referral supplied it, and an
// out-of-bailiwick nameserver (no glue) is resolved with its own
// independent lookup, bounded by nsDepth against a runaway chain of
// glueless delegations.
func (r *Resolver) resolveNameservers(ctx context.Context, ns []nsInfo, nsDepth int) []string {
	var servers []string
	for _, n := range ns {
		if len(n.glueIPs) > 0 {
			for _, ip := range n.glueIPs {
				servers = append(servers, net.JoinHostPort(ip, r.nsPort))
			}
			continue
		}
		if nsDepth >= maxNSResolveDepth {
			continue
		}
		if addr, ok := r.resolveNSAddr(ctx, n.name, nsDepth+1); ok {
			servers = append(servers, addr)
		}
	}
	return servers
}

// resolveNSAddr independently resolves a nameserver hostname's own address
// (A, falling back to AAAA) via a nested walk that goes through the exact
// same referral/glue handling as any other query, one nsDepth deeper.
func (r *Resolver) resolveNSAddr(ctx context.Context, host string, nsDepth int) (string, bool) {
	for _, qtype := range [...]uint16{dns.TypeA, dns.TypeAAAA} {
		resp, err := r.resolve(ctx, dns.Question{Name: host, Qtype: qtype, Qclass: dns.ClassINET}, 0, nsDepth)
		if err != nil {
			continue
		}
		for _, rr := range resp.Answer {
			switch v := rr.(type) {
			case *dns.A:
				return net.JoinHostPort(v.A.String(), r.nsPort), true
			case *dns.AAAA:
				return net.JoinHostPort(v.AAAA.String(), r.nsPort), true
			}
		}
	}
	return "", false
}

// bestDelegation returns the deepest cached, unexpired delegation covering
// qname, walking ancestors the same zero-allocation way filter.Engine does.
// Falls back to the root hints when nothing is cached.
func (r *Resolver) bestDelegation(qname string) (zone string, servers []string) {
	qname = strings.ToLower(qname)
	r.mu.RLock()
	defer r.mu.RUnlock()
	now := time.Now()
	name := qname
	for {
		if d, ok := r.delegations[name]; ok && now.Before(d.expiry) {
			return name, d.servers
		}
		i := strings.IndexByte(name, '.')
		if i < 0 || i+1 >= len(name) {
			break
		}
		name = name[i+1:]
	}
	return ".", r.rootHints
}

func (r *Resolver) cacheDelegation(zone string, servers []string, ttl time.Duration) {
	r.mu.Lock()
	r.delegations[zone] = delegation{servers: servers, expiry: time.Now().Add(ttl)}
	r.mu.Unlock()
}
