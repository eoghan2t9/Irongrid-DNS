package recursive

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/sync/singleflight"

	"github.com/eoghan2t9/Irongrid-DNS/internal/tuning"
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
	// minCNAMEFollowBudget is the minimum time chaseCNAME guarantees the
	// nested resolve of a CNAME target, even when the parent query's
	// context deadline is nearly exhausted by the walk that produced the
	// CNAME itself — otherwise a slow multi-hop referral walk for the
	// alias leaves the target's own (independent, from-scratch) walk too
	// little budget to ever succeed, and its error gets swallowed below,
	// silently returning a CNAME with no address records.
	minCNAMEFollowBudget = 2 * time.Second
	minDelegationTTL     = 60 * time.Second
	maxDelegationTTL     = 24 * time.Hour
	// ednsUDPSize is the UDP payload size advertised on queries to
	// nameservers (see dnsserver.ednsUDPSize for the reasoning).
	ednsUDPSize = 1232

	// nsPoolMaxIdle mirrors upstream.poolMaxIdle: a connection idle in the
	// pool longer than this is presumed stale (the server closed it) and
	// evicted instead of reused, so reuse never wastes a query on a
	// guaranteed EOF.
	nsPoolMaxIdle = 20 * time.Second
)

// nsConnPoolSize bounds warm connections kept per (network, address) pair —
// a cache of ready-to-reuse connections, not a concurrency limit: a query
// that finds the pool empty just dials fresh, same as before pooling
// existed. Mirrors upstream.upstreamPoolSize, proportionally smaller since
// recursive mode fans out across many distinct nameservers rather than one
// upstream, so per-key reuse benefit is lower.
var nsConnPoolSize = tuning.ScaleByCores(2, 2, 64)

// nsConnPoolMaxKeys bounds how many distinct (network, address) pairs get
// pooled at all. Unlike upstream.Upstream's fixed forwarder set, a resolver
// may talk to thousands of distinct authoritative servers over its
// lifetime, most queried exactly once (a random domain's own nameservers) —
// pooling every one of them would grow unbounded pool state for a
// long-running process. Root and TLD servers are hit on nearly every cold
// cache-miss walk and are the first ones pooled, so the cap naturally
// concentrates the reuse benefit on the addresses that are actually hot. An
// address that shows up once the cap is full just dials fresh, exactly like
// the no-pooling case. Derived from the tuned memory ceiling
// (tuning.ScaleByMemory) so a big box doing recursive resolution at scale —
// more concurrent domains in flight, more distinct hot nameservers — can
// hold a bigger key set before the cap starts forcing fresh dials.
var nsConnPoolMaxKeys = tuning.ScaleByMemory(0.0002, 128, 512, 8192, 512)

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

	// nsFlight coalesces concurrent address lookups for the same glueless
	// nameserver hostname into one referral walk (see resolveNSAddr).
	nsFlight singleflight.Group

	// connPools holds warm connections to nameservers, keyed by "network|addr"
	// (e.g. "udp|198.41.0.4:53"), bounded to nsConnPoolMaxKeys distinct keys
	// by poolKeyCount. See exchange/getConn/putConn.
	connPools    sync.Map
	poolKeyCount atomic.Int64
}

// nsPooledConn is a warm connection tagged with the moment it was returned
// to the pool, so getConn can evict connections that sat idle too long.
// Mirrors upstream.pooledConn.
type nsPooledConn struct {
	conn     *dns.Conn
	pooledAt time.Time
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
	// full disables QNAME minimization for the rest of this walk once a
	// minimized query gets an untrustworthy response (see the fallback
	// case below) — RFC 9156 requires this: some authoritative servers
	// mishandle a synthetic NS query for a label with no real delegation,
	// and a minimized query's NXDOMAIN/SERVFAIL must never be trusted as
	// an answer about the real qname.
	full := false

	for range maxHops {
		// QNAME minimization (RFC 7816, relaxed by RFC 9156): reveal only
		// the labels needed to find the next delegation, not the full
		// qname, to every server that doesn't need to know more — ask for
		// NS of one label deeper than the current zone, escalating to the
		// real question only on the final hop (next == q.Name) or once
		// minimization has been abandoned for this walk.
		askQ := q
		minimized := false
		if !full {
			if next, ok := nextMinimizedLabel(zone, q.Name); ok && !strings.EqualFold(next, q.Name) {
				askQ = dns.Question{Name: next, Qtype: dns.TypeNS, Qclass: q.Qclass}
				minimized = true
			}
		}

		resp, err := r.queryServers(ctx, servers, askQ)
		if err != nil {
			return nil, err
		}

		nextZone, nsRecords, ttl, hasNS := parseReferral(resp)
		if hasNS {
			nextServers := r.resolveNameservers(ctx, nsRecords, nsDepth)
			if len(nextServers) == 0 {
				return nil, fmt.Errorf("recursive: zone %s delegated with no resolvable nameservers", nextZone)
			}
			if visited[nextZone] {
				// Referral loop (a misbehaving server re-delegating to a
				// zone already visited this walk) — return the
				// best-effort answer rather than spinning.
				return resp, nil
			}
			visited[nextZone] = true
			r.cacheDelegation(nextZone, nextServers, ttl)
			zone, servers = nextZone, nextServers
			continue
		}

		// No delegation in this response.
		if !minimized {
			// The real question (minimization reached its final hop
			// naturally, or is disabled/abandoned for this walk) —
			// resolve exactly as before minimization existed.
			if isFinal(resp) {
				return r.chaseCNAME(ctx, q, resp, cnameDepth, nsDepth)
			}
			return resp, nil
		}
		if resp.Rcode == dns.RcodeSuccess {
			// The synthetic NS query got a plain NOERROR/NODATA: this
			// zone is authoritative this deep too, just with no
			// delegation at this exact label (common — most labels on
			// the path to a name aren't themselves delegation points).
			// Record it and step to the next label at the same servers.
			zone = askQ.Name
			continue
		}
		// RFC 9156: anything else (NXDOMAIN, SERVFAIL, ...) answering a
		// minimized query is not trustworthy as an answer about the real
		// qname. Fall back to the full name at the current servers
		// instead of failing the walk or misinterpreting a spurious
		// NXDOMAIN as "this domain doesn't exist".
		full = true
	}
	return nil, fmt.Errorf("recursive: exceeded %d referral hops resolving %s", maxHops, q.Name)
}

// nextMinimizedLabel returns qname truncated to exactly one label deeper
// than zone (e.g. zone="com.", qname="www.example.com." -> "example.com."),
// the next query QNAME minimization (RFC 7816/9156) should ask for. ok is
// false when zone already equals qname (nothing left to minimize) or zone
// isn't an ancestor of qname with fewer labels (defensive: bestDelegation's
// own walk always returns a true ancestor, so this should never happen in
// practice — falling back to the unminimized qname is always safe).
func nextMinimizedLabel(zone, qname string) (next string, ok bool) {
	zone = strings.ToLower(dns.Fqdn(zone))
	qname = strings.ToLower(dns.Fqdn(qname))
	if zone == qname {
		return "", false
	}
	qLabels := dns.SplitDomainName(qname)
	zLabels := dns.SplitDomainName(zone)
	if len(zLabels) >= len(qLabels) {
		return "", false
	}
	keep := qLabels[len(qLabels)-len(zLabels)-1:]
	return dns.Fqdn(strings.Join(keep, ".")), true
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
	// The alias's own referral walk may already have spent most of ctx's
	// deadline; the target's walk is an entirely independent, from-scratch
	// resolution (possibly through a different set of root/TLD/authoritative
	// servers) and deserves its own minimum budget rather than whatever
	// scraps are left — otherwise it starves and its error below gets
	// swallowed, silently handing the client a CNAME with no address
	// records instead of the answer.
	followCtx := ctx
	if dl, ok := ctx.Deadline(); ok {
		if remaining := time.Until(dl); remaining < minCNAMEFollowBudget {
			var cancel context.CancelFunc
			followCtx, cancel = context.WithTimeout(context.WithoutCancel(ctx), minCNAMEFollowBudget)
			defer cancel()
		}
	}
	follow, err := r.resolve(followCtx, dns.Question{Name: target, Qtype: q.Qtype, Qclass: q.Qclass}, cnameDepth+1, nsDepth)
	if err != nil {
		// Return the CNAME hop we do have rather than failing the whole
		// query over a downstream failure resolving its target — but log
		// it, since a client silently getting an alias with no address is
		// otherwise indistinguishable from an addressless CNAME being the
		// correct answer.
		slog.Warn("recursive: CNAME target resolution failed, returning alias only", "name", q.Name, "target", target, "error", err)
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
	// Advertise the DNS Flag Day 2020 recommended 1232-byte UDP payload
	// (see dnsserver.ednsUDPSize): large enough for realistic answers
	// without risking IP fragmentation, with anything bigger flowing over
	// the TCP fallback on truncation.
	m.SetEdns0(ednsUDPSize, false)

	qctx, qcancel := context.WithCancel(ctx)
	defer qcancel()
	timeout := serverTimeout()
	type result struct {
		resp *dns.Msg
		err  error
	}
	ch := make(chan result, len(servers))
	for _, addr := range servers {
		go func() {
			// Copy the query per server: miekg/dns's transport overwrites
			// msg.Id while sending, so the same message cannot be handed to
			// several servers concurrently (the rule raceUpstreams follows).
			qm := m.Copy()
			resp, err := r.exchange(qctx, addr, qm, "udp", timeout)
			if err == nil && resp.Truncated {
				// A truncated UDP reply falls back to TCP on the same
				// server, like a client would; the TCP attempt's error (if
				// any) supersedes the UDP one.
				if tcpResp, tcpErr := r.exchange(qctx, addr, qm, "tcp", timeout); tcpErr == nil {
					resp = tcpResp
				} else {
					err = tcpErr
				}
			}
			ch <- result{resp: resp, err: err}
		}()
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
// capped by the caller's overall context. Reuses a warm connection from the
// resolver's pool when one is available (for TCP this skips a full
// connection setup — there's no TLS handshake to save on plain nameserver
// TCP, but the three-way handshake itself is real latency on every hop of a
// cold walk) and dials fresh otherwise, exactly like upstream.pooledExchange
// does for the fixed forwarder set.
func (r *Resolver) exchange(ctx context.Context, addr string, m *dns.Msg, network string, timeout time.Duration) (*dns.Msg, error) {
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	c := &dns.Client{Net: network, Timeout: timeout}
	if conn := r.getConn(network, addr); conn != nil {
		resp, _, err := c.ExchangeWithConnContext(cctx, m, conn)
		if err == nil {
			r.putConn(network, addr, conn)
			return resp, nil
		}
		conn.Close()
		// The pooled connection may have gone stale while idle (the
		// nameserver closed it, a NAT dropped it) — fall through to a fresh
		// dial rather than failing the query over a warm-connection hiccup.
	}
	conn, err := c.DialContext(cctx, addr)
	if err != nil {
		return nil, err
	}
	resp, _, err := c.ExchangeWithConnContext(cctx, m, conn)
	if err != nil {
		conn.Close()
		return nil, err
	}
	r.putConn(network, addr, conn)
	return resp, nil
}

// getConn pops a warm connection from the pool for (network, addr), or nil
// if none are available (including when nothing has ever been pooled for
// that key). A connection that sat idle longer than nsPoolMaxIdle is
// presumed stale and closed instead of returned, so reuse never wastes a
// query on a guaranteed EOF.
func (r *Resolver) getConn(network, addr string) *dns.Conn {
	v, ok := r.connPools.Load(network + "|" + addr)
	if !ok {
		return nil
	}
	pool := v.(chan *nsPooledConn)
	for {
		select {
		case pc := <-pool:
			if time.Since(pc.pooledAt) > nsPoolMaxIdle {
				pc.conn.Close()
				continue
			}
			return pc.conn
		default:
			return nil
		}
	}
}

// putConn returns a connection to the pool for (network, addr), closing it
// instead if the per-key pool is full or the key cap (nsConnPoolMaxKeys) has
// already been reached for a brand-new key.
func (r *Resolver) putConn(network, addr string, c *dns.Conn) {
	key := network + "|" + addr
	v, ok := r.connPools.Load(key)
	if !ok {
		if r.poolKeyCount.Load() >= int64(nsConnPoolMaxKeys) {
			c.Close()
			return
		}
		newPool := make(chan *nsPooledConn, nsConnPoolSize)
		actual, loaded := r.connPools.LoadOrStore(key, newPool)
		if !loaded {
			r.poolKeyCount.Add(1)
		}
		v = actual
	}
	pool := v.(chan *nsPooledConn)
	select {
	case pool <- &nsPooledConn{conn: c, pooledAt: time.Now()}:
	default:
		c.Close()
	}
}

// Close releases every pooled connection. Called when a config reload
// replaces the recursive upstream (and with it, this Resolver) so warm
// connections from the outgoing instance don't leak.
func (r *Resolver) Close() {
	r.connPools.Range(func(key, v any) bool {
		pool := v.(chan *nsPooledConn)
	drain:
		for {
			select {
			case pc := <-pool:
				pc.conn.Close()
			default:
				break drain
			}
		}
		r.connPools.Delete(key)
		return true
	})
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
		wg.Go(func() {
			if addr, ok := r.resolveNSAddr(ctx, host, nsDepth+1); ok {
				addrs[i] = addr
			}
		})
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
//
// Concurrent lookups for the same hostname are coalesced into one walk: two
// domains hosted by the same DNS provider resolved at once would otherwise
// each chase the provider's nameservers from the root. The winner's walk
// feeds every waiter. The flight key includes nsDepth so a walk's own nested
// lookup of the same host (a pathological delegation loop) gets a different
// key and can never wait on its own goroutine — singleflight would deadlock
// on same-key re-entry.
func (r *Resolver) resolveNSAddr(ctx context.Context, host string, nsDepth int) (string, bool) {
	if addr, ok := r.cachedNSAddr(host); ok {
		return addr, true
	}
	ch := r.nsFlight.DoChan(host+"|"+strconv.Itoa(nsDepth), func() (any, error) {
		if addr, ok := r.cachedNSAddr(host); ok {
			return nsAddrResult{addr: addr, ok: true}, nil
		}
		addr, ok := r.resolveNSAddrWalk(ctx, host, nsDepth)
		return nsAddrResult{addr: addr, ok: ok}, nil
	})
	select {
	case res := <-ch:
		fr, _ := res.Val.(nsAddrResult)
		return fr.addr, fr.ok
	case <-ctx.Done():
		// Our deadline expired while waiting on the leader's walk: the
		// leader may still have just finished and cached — take that, else
		// report the lookup as failed under our own budget.
		if addr, ok := r.cachedNSAddr(host); ok {
			return addr, true
		}
		return "", false
	}
}

// nsAddrResult is the outcome of one coalesced nameserver-address lookup.
type nsAddrResult struct {
	addr string
	ok   bool
}

// resolveNSAddrWalk runs the actual nested walk for a nameserver hostname's
// address (see resolveNSAddr for the coalescing wrapper).
func (r *Resolver) resolveNSAddrWalk(ctx context.Context, host string, nsDepth int) (string, bool) {
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
