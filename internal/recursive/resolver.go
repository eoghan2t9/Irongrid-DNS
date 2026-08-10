package recursive

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
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

	// perServerTimeout is the default budget for one exchange with one
	// nameserver during a referral walk; SetDefaultServerTimeout can
	// override it for every resolver (see serverTimeout).
	perServerTimeout = 3 * time.Second
	minDelegationTTL = 60 * time.Second
	maxDelegationTTL = 24 * time.Hour
)

// defaultServerTimeout is the package-wide per-server exchange timeout used
// by resolvers that haven't been individually configured — overridable via
// SetDefaultServerTimeout so the config layer can tune recursive://
// upstreams without plumbing the value through every construction site
// (boot, config reload, per-client-group upstreams). Mirrors
// SetDefaultRootHints. Read at query time, so a live reload takes effect
// for resolvers that already exist.
var defaultServerTimeout atomic.Int64 // nanoseconds; 0 = perServerTimeout

// SetDefaultServerTimeout overrides the per-server exchange timeout for
// every Resolver (0 restores the built-in perServerTimeout default).
func SetDefaultServerTimeout(d time.Duration) {
	defaultServerTimeout.Store(int64(d))
}

// serverTimeout returns the effective budget for one exchange with one
// nameserver during a referral walk: the package-wide default when set,
// otherwise perServerTimeout.
func serverTimeout() time.Duration {
	if d := time.Duration(defaultServerTimeout.Load()); d > 0 {
		return d
	}
	return perServerTimeout
}

// Resolver performs iterative resolution starting from the DNS root,
// following referrals itself instead of forwarding to a recursive resolver.
// It caches NS delegations (which servers are authoritative for which zone)
// so only the first query under a given TLD or domain pays the full walk;
// later queries under the same zone jump straight to the deepest known
// delegation. It also caches the addresses of out-of-bailiwick nameservers
// themselves, so a second domain hosted by the same DNS provider skips the
// nested lookup of that provider's nameservers. Safe for concurrent use.
type Resolver struct {
	rootHints []string
	// nsPort is the port assumed for every address derived from glue
	// records — real DNS glue (A/AAAA) never carries a port, so production
	// always resolves to 53; overridable only for tests running a fake
	// server hierarchy on non-standard ports.
	nsPort string

	mu          sync.RWMutex
	delegations map[string]delegation
	nsAddrs     map[string]nsAddr
}

type delegation struct {
	servers []string // "ip:port" / "[ipv6]:port", dial-ready
	expiry  time.Time
}

// nsAddr caches an out-of-bailiwick nameserver's own address lookup so it
// happens once per TTL instead of once per newly-encountered domain.
type nsAddr struct {
	addr   string // "ip:port" / "[ipv6]:port", dial-ready
	expiry time.Time
}

// New returns a Resolver seeded with rootHints ("ip:port" strings). A
// nil/empty slice falls back to the process's current default root hints —
// the bundled DefaultRootHints, unless SetDefaultRootHints has replaced
// them with a fetched copy of the authoritative named.root file.
func New(rootHints []string) *Resolver {
	if len(rootHints) == 0 {
		rootHints = defaultHints()
	}
	return &Resolver{
		rootHints:   rootHints,
		nsPort:      "53",
		delegations: map[string]delegation{},
		nsAddrs:     map[string]nsAddr{},
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
		// zone is only read via the visited map above; only servers feeds the
		// next hop (staticcheck ineffassign).
		servers = nextServers
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

// queryServers asks every candidate server (each a plain address a
// dns.Client can dial) concurrently and returns the first usable response,
// falling back to TCP on a truncated UDP reply for the same server. Racing
// mirrors the handler's raceUpstreams: a single dead or slow server in a
// zone used to cost a full per-server timeout (attempts ran sequentially, so
// a second unresponsive server could blow the whole per-query budget before
// a healthy one was ever tried) — now the fastest healthy server answers in
// roughly one round trip. Each goroutine performs exactly one send into a
// channel buffered for every server, so nothing leaks; the losers' exchanges
// run on a deadline (perServerTimeout) rather than being interrupted the
// instant the winner returns, exactly like raceUpstreams.
func (r *Resolver) queryServers(ctx context.Context, servers []string, q dns.Question) (*dns.Msg, error) {
	m := new(dns.Msg)
	m.SetQuestion(q.Name, q.Qtype)
	m.Question[0].Qclass = q.Qclass
	m.RecursionDesired = false
	m.SetEdns0(4096, false)

	qctx, qcancel := context.WithCancel(ctx)
	defer qcancel()
	timeout := serverTimeout()
	type result struct {
		resp *dns.Msg
		err  error
	}
	ch := make(chan result, len(servers))
	for _, addr := range servers {
		go func(addr string) {
			// Copy the query per server: miekg/dns's transport overwrites
			// msg.Id while sending, so the same message cannot be handed to
			// several servers concurrently (the rule raceUpstreams follows).
			qm := m.Copy()
			resp, err := exchange(qctx, addr, qm, "udp", timeout)
			if err == nil && resp.Truncated {
				// A truncated UDP reply falls back to TCP on the same
				// server, like a client would; the TCP attempt's error (if
				// any) supersedes the UDP one.
				if tcpResp, tcpErr := exchange(qctx, addr, qm, "tcp", timeout); tcpErr == nil {
					resp = tcpResp
				} else {
					err = tcpErr
				}
			}
			ch <- result{resp: resp, err: err}
		}(addr)
	}
	var lastErr error
	for range len(servers) {
		res := <-ch
		if res.err == nil && res.resp != nil {
			return res.resp, nil
		}
		if res.err != nil {
			lastErr = res.err
		}
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no servers to query")
	}
	return nil, fmt.Errorf("recursive: resolving %s: %w", q.Name, lastErr)
}

// exchange sends one query to one nameserver over network ("udp" or "tcp")
// bounded by timeout — the resolver's effective per-server budget, itself
// capped by the caller's overall context.
func exchange(ctx context.Context, addr string, m *dns.Msg, network string, timeout time.Duration) (*dns.Msg, error) {
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	c := &dns.Client{Net: network, Timeout: timeout}
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

	return zone, ns, clampDelegationTTL(time.Duration(minTTL) * time.Second), true
}

// resolveNameservers turns a referral's nameservers into dial-ready
// addresses: glue is used directly when the referral supplied it, and an
// out-of-bailiwick nameserver (no glue) is resolved with its own
// independent lookup, bounded by nsDepth against a runaway chain of
// glueless delegations. Glueless nameservers are the common case (the DNS
// hosting used by Cloudflare/Route53/DNSimple-style setups lives outside
// the delegated zone), and each address lookup is an independent walk, so
// they run concurrently and every address that resolves is collected — the
// referral loop races them anyway, and only one working address is needed.
func (r *Resolver) resolveNameservers(ctx context.Context, ns []nsInfo, nsDepth int) []string {
	var servers []string
	var glueless []string
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
		glueless = append(glueless, n.name)
	}
	if len(glueless) == 0 {
		return servers
	}
	addrs := make([]string, len(glueless))
	var wg sync.WaitGroup
	for i, host := range glueless {
		wg.Add(1)
		go func(i int, host string) {
			defer wg.Done()
			if addr, ok := r.resolveNSAddr(ctx, host, nsDepth+1); ok {
				addrs[i] = addr
			}
		}(i, host)
	}
	wg.Wait()
	for _, a := range addrs {
		if a != "" {
			servers = append(servers, a)
		}
	}
	return servers
}

// resolveNSAddr independently resolves a nameserver hostname's own address
// (A, falling back to AAAA) via a nested walk that goes through the exact
// same referral/glue handling as any other query, one nsDepth deeper.
// Successful lookups are cached per hostname (with the same TTL clamping
// as delegations) so a second domain hosted by the same DNS provider skips
// the walk entirely.
func (r *Resolver) resolveNSAddr(ctx context.Context, host string, nsDepth int) (string, bool) {
	if addr, ok := r.cachedNSAddr(host); ok {
		return addr, true
	}
	for _, qtype := range [...]uint16{dns.TypeA, dns.TypeAAAA} {
		resp, err := r.resolve(ctx, dns.Question{Name: host, Qtype: qtype, Qclass: dns.ClassINET}, 0, nsDepth)
		if err != nil {
			continue
		}
		for _, rr := range resp.Answer {
			switch v := rr.(type) {
			case *dns.A:
				addr := net.JoinHostPort(v.A.String(), r.nsPort)
				r.cacheNSAddr(host, addr, nsAnswerTTL(resp))
				return addr, true
			case *dns.AAAA:
				addr := net.JoinHostPort(v.AAAA.String(), r.nsPort)
				r.cacheNSAddr(host, addr, nsAnswerTTL(resp))
				return addr, true
			}
		}
	}
	return "", false
}

// nsAnswerTTL is the caching lifetime for a nameserver-address answer: the
// minimum A/AAAA record TTL, clamped to the same window delegations use.
func nsAnswerTTL(resp *dns.Msg) time.Duration {
	var min uint32
	for _, rr := range resp.Answer {
		if rr.Header().Rrtype != dns.TypeA && rr.Header().Rrtype != dns.TypeAAAA {
			continue
		}
		if min == 0 || rr.Header().Ttl < min {
			min = rr.Header().Ttl
		}
	}
	if min == 0 {
		return minDelegationTTL
	}
	return clampDelegationTTL(time.Duration(min) * time.Second)
}

// cachedNSAddr returns the cached dial-ready address for a nameserver
// hostname while it's still fresh.
func (r *Resolver) cachedNSAddr(host string) (string, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if e, ok := r.nsAddrs[host]; ok && time.Now().Before(e.expiry) {
		return e.addr, true
	}
	return "", false
}

// cacheNSAddr records a nameserver hostname's resolved address for ttl.
func (r *Resolver) cacheNSAddr(host, addr string, ttl time.Duration) {
	r.mu.Lock()
	r.nsAddrs[host] = nsAddr{addr: addr, expiry: time.Now().Add(ttl)}
	r.mu.Unlock()
}

// clampDelegationTTL bounds a delegation or nameserver-address TTL to the
// configured window so a wild TTL (0 or absurdly large) from a misbehaving
// server can't pin a referral for seconds or years.
func clampDelegationTTL(ttl time.Duration) time.Duration {
	if ttl < minDelegationTTL {
		return minDelegationTTL
	}
	if ttl > maxDelegationTTL {
		return maxDelegationTTL
	}
	return ttl
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
