// Package dnsserver implements every DNS listener (UDP, TCP, DoT, DoH, DoQ)
// plus the shared query handler that applies filtering, caching, forwarding
// and logging.
package dnsserver

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"log/slog"
	"math/bits"
	"net"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/sync/singleflight"

	"github.com/eoghan2t9/Irongrid-DNS/internal/cache"
	"github.com/eoghan2t9/Irongrid-DNS/internal/dnsname"
	"github.com/eoghan2t9/Irongrid-DNS/internal/filter"
	"github.com/eoghan2t9/Irongrid-DNS/internal/geoip"
	"github.com/eoghan2t9/Irongrid-DNS/internal/querylog"
	"github.com/eoghan2t9/Irongrid-DNS/internal/upstream"
)

// Upstream resolution strategies for multiple upstreams (config
// upstream_mode). Race (default) queries every available upstream
// concurrently and uses the fastest successful answer; sequential tries them
// in list order, failing over to the next only when the previous errors or
// answers SERVFAIL.
const (
	UpstreamModeRace       = "race"
	UpstreamModeSequential = "sequential"
)

// Stats aggregates runtime counters exposed via the API.
type Stats struct {
	Total   atomic.Int64
	Blocked atomic.Int64
	Allowed atomic.Int64
	Cached  atomic.Int64
	Errors  atomic.Int64
	// Honeypot counts refused trap-domain hits (attack traffic). It is not
	// part of the query log — honeypot hits are never logged — so this is
	// the only place an active flood remains observable.
	Honeypot   atomic.Int64
	ByProtocol map[string]*atomic.Int64
	// Flights is how many upstream resolutions actually ran through the
	// in-flight request pool — one per unique question sent upstream.
	// Merged is how many queries were served by a flight that multiple
	// callers shared (singleflight marks every caller of a shared flight,
	// leader included, so this is the pool's total absorbed traffic, not
	// just the waiters). Only *successful* shared flights count — a query
	// that shared a failed flight is invisible here. Saved round trips are
	// merged - flights; the two are equal whenever every flight was shared.
	Flights atomic.Int64
	Merged  atomic.Int64
	// ASNHeader counts DoH requests whose response carried the
	// X-Irongrid-Client-ASN header (server.doh_asn_header on AND the
	// client's ISP resolved in a configured ASN list) — the dashboard's
	// "ASN headers" row.
	ASNHeader atomic.Int64
	// UDP listener counters distinguish packets that reached userspace from
	// packets rejected before the shared handler. They make worker-pool
	// saturation and malformed traffic visible without platform-specific
	// socket APIs.
	UDPReceived   atomic.Int64
	UDPInvalid    atomic.Int64
	UDPQueueDrops atomic.Int64
	UDPCompleted  atomic.Int64
	WriteErrors   atomic.Int64
}

func newStats() *Stats {
	s := &Stats{ByProtocol: map[string]*atomic.Int64{
		"udp": {}, "tcp": {}, "dot": {}, "doh": {}, "doh3": {}, "doq": {},
	}}
	return s
}

// DHCPHostResolver is implemented by the DHCP server so locally-assigned
// client hostnames and addresses resolve through the DNS handler (Pi-hole
// style: "printer" and "printer.lan" both answer, and PTR queries for a
// leased address answer with the client's registered hostname). LookupHost
// returns the client's address(es); ok=false for unknown names.
type DHCPHostResolver interface {
	LookupHost(name string) ([]net.IP, bool)
	// LookupPTR resolves a leased address back to its registered hostname
	// (with the configured domain suffix); ok=false for unknown addresses.
	LookupPTR(ip string) (hostname string, ok bool)
}

// Handler is the shared request pipeline for all listeners.
type Handler struct {
	Engine *filter.Engine
	Log    *querylog.Log
	// DHCPHosts resolves locally-assigned client hostnames (set at boot;
	// never swapped — the DHCP server lives for the process).
	DHCPHosts DHCPHostResolver

	// settings is the immutable snapshot of every hot-swappable knob the
	// request path reads (see handlerSettings). serve() loads it with one
	// atomic pointer load per query instead of an RLock copying 17 fields;
	// the Set* methods swap in a fresh copy (serialized by setMu, which the
	// read path never takes), so a loaded snapshot is never mutated and
	// concurrent readers always see a consistent view.
	settings atomic.Pointer[handlerSettings]
	// setMu serializes settings swaps (config reloads are rare; the hot
	// path never takes it).
	setMu sync.Mutex
	// Padding pads responses on the encrypted transports (DoT/DoH/DoH3/DoQ)
	// to fixed 128-byte blocks (RFC 7830) so message lengths don't leak
	// which domain was queried. Set via SetPadding. Atomic because write()
	// reads it on every response — an RLock per reply is measurable on the
	// flat-out path, one load is not.
	Padding atomic.Bool
	// Cookies enables server DNS cookies (RFC 7873). Set via SetCookies.
	Cookies atomic.Bool
	// cookieSecret is the HMAC key for server cookies, generated once at
	// construction and never mutated — a reader never races a writer.
	cookieSecret []byte
	// latency is the in-process response-time histogram backing the
	// dashboard's Performance card percentiles (see latencyHist).
	latency latencyHist
	// asnCache memoizes ClientASN per client IP: attribution is stable while
	// the installed ASN tables are unchanged, and the record path resolves
	// it on every logged query. swapSettings clears it on any settings swap
	// (the only way the tables change), so it can never serve stale data.
	// Bounded like the client router's policy cache — full = reset, cheap to
	// rebuild. Zero entries are cached too (stored as 0 = "no ASN"), so a
	// client with no attribution pays the parse+search exactly once.
	asnCache     sync.Map
	asnCacheSize atomic.Int64
	// cacheWriteSlots bounds concurrent background cache-write goroutines
	// (Set/SetNegative): under a sustained miss flood each query spawns one,
	// and a bounded pool turns that goroutine churn into a fixed ceiling.
	// When the slots are exhausted the write is skipped — the cache only
	// helps future queries, so dropping under saturation is the right trade
	// (the same philosophy as the query log's bounded queue).
	cacheWriteSlots chan struct{}

	Stats *Stats

	// flight coalesces concurrent identical questions (same name/type/class)
	// into a single upstream resolution: a burst of clients resolving the
	// same domain — OS connectivity checks, a shared CDN hostname, an app
	// launched across the LAN at once — pays one round trip, and every
	// waiter gets the answer the moment the leader's query returns instead
	// of each paying its own upstream RTT. See resolveUpstreams.
	flight singleflight.Group
}

// handlerSettings is one immutable snapshot of the handler's hot-swappable
// configuration, published via Handler.settings. Fields are only ever
// replaced whole, never mutated in place, so a query that loaded the
// snapshot can read it without any lock.
type handlerSettings struct {
	Upstreams    []*upstream.Upstream
	UpstreamMode string // "race" or "sequential" (see UpstreamModeRace/Sequential)
	// UpstreamRoutes is conditional (split-horizon) routing: per-domain
	// upstream sets that win over the global forwarders and client-group
	// upstream overrides (the most specific intent wins). Set via
	// SetUpstreamRoutes.
	UpstreamRoutes []UpstreamRoute
	BlockResponse  string
	BlockTTL       uint32
	Timeout        time.Duration
	// FailureTTL is how long a resolution failure (upstream never answered,
	// no serve-stale entry) is negatively cached as SERVFAIL; <= 0 uses the
	// cache's configured negative TTL.
	FailureTTL   time.Duration
	Cache        *cache.Cache
	Rewriter     *filter.Rewriter // local DNS records; never nil, may be empty
	ClientRouter *ClientRouter    // per-client policy; never nil, may be empty
	RateLimiter  *RateLimiter     // nil disables rate limiting
	NXGuard      *NXGuard         // nil disables the NXDOMAIN flood guard
	Geo          *geoip.Blocker   // nil disables geo-blocking
	IPBanner     *geoip.Banner    // nil disables IP/honeypot blocking
	// TrustUDP opt-in: when true, a honeypot hit over plain UDP auto-blocks
	// its source address too. Off by default — a UDP source can be spoofed,
	// so enabling this lets a spoofing attacker permanently block an
	// innocent victim; only meaningful on a trusted network where clients
	// are real (the flag does nothing unless an IP banner is installed).
	TrustUDP bool
	// HoneypotUDPBlock, when > 0, is the bounded middle ground for UDP
	// honeypot hits: the source is auto-blocked via the rate limiter for
	// this window (dropped at the DNS layer, expiring automatically,
	// visible and unblockable on the dashboard) instead of earning the
	// permanent banner/firewall block that trust_udp grants. A spoofed
	// packet can then only block a victim for the window, never forever.
	// Does nothing unless a rate limiter is installed.
	HoneypotUDPBlock time.Duration
	DNSSECEnabled    bool
	DNSSECRequireAD  bool
	// CNAMECloakingProtection checks every CNAME hop in an upstream answer
	// against the filter engine, not just the originally queried name. Set
	// via SetCNAMECloakingProtection.
	CNAMECloakingProtection bool
}

// NewHandler builds a handler with default stats.
func NewHandler(engine *filter.Engine, c *cache.Cache, ups []*upstream.Upstream, ql *querylog.Log, blockResp string, blockTTL uint32, timeout time.Duration) *Handler {
	h := &Handler{
		Engine:          engine,
		Log:             ql,
		Stats:           newStats(),
		cacheWriteSlots: make(chan struct{}, maxCacheWriters),
	}
	h.settings.Store(&handlerSettings{
		Upstreams:     ups,
		UpstreamMode:  UpstreamModeRace,
		Cache:         c,
		BlockResponse: blockResp,
		BlockTTL:      blockTTL,
		Timeout:       timeout,
		Rewriter:      filter.NewRewriter(),
		ClientRouter:  NewClientRouter(),
	})
	// Server-cookie HMAC key. crypto/rand failure is effectively impossible
	// (kernel entropy); the time-seeded fallback keeps DNS cookies working
	// on a pathological system rather than silently disabling them.
	h.cookieSecret = make([]byte, 32)
	if _, err := rand.Read(h.cookieSecret); err != nil {
		slog.Warn("crypto/rand failed; DNS cookie key falls back to time-derived", "error", err)
		sum := sha256.Sum256([]byte(time.Now().UTC().String()))
		h.cookieSecret = sum[:]
	}
	return h
}

// ServeDNS implements dns.Handler. clientIP may be empty (callers that know
// it better — like the DoH server — supply it through the context).
func (h *Handler) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	client := clientIPOf(w.RemoteAddr())
	h.serve(w, r, client, "udp")
}

// ServeDNSWithProto is used by TCP/DoT/DoQ servers to tag the protocol.
func (h *Handler) ServeDNSWithProto(w dns.ResponseWriter, r *dns.Msg, proto string) {
	h.serve(w, r, clientIPOf(w.RemoteAddr()), proto)
}

// ServeDNSFromContext serves a message where the client IP was captured
// separately (DoH).
func (h *Handler) ServeDNSFromContext(w dns.ResponseWriter, r *dns.Msg, clientIP, proto string) {
	h.serve(w, r, clientIP, proto)
}

// UpstreamRoute sends queries for one domain subtree to a dedicated
// upstream set (split-horizon / conditional forwarding). Domain matches
// exactly and every subdomain under it; the longest matching domain wins
// when routes overlap.
type UpstreamRoute struct {
	Domain    string
	Upstreams []*upstream.Upstream
}

// RouteSpec is the config form of an UpstreamRoute: the raw upstream
// strings before parsing.
type RouteSpec struct {
	Domain    string
	Upstreams []string
}

// ParseRoutes compiles RouteSpecs into UpstreamRoutes (parsing every
// upstream spec). It is the validation half of SetUpstreamRoutes: callers
// parse up front — before any live reference is swapped on a reload — so a
// bad spec fails the reload with nothing touched, then hand the compiled
// routes to SetUpstreamRoutes, which can no longer fail.
func ParseRoutes(specs []RouteSpec) ([]UpstreamRoute, error) {
	compiled := make([]UpstreamRoute, 0, len(specs))
	for _, s := range specs {
		ups := make([]*upstream.Upstream, 0, len(s.Upstreams))
		for _, spec := range s.Upstreams {
			up, err := upstream.Parse(spec)
			if err != nil {
				return nil, fmt.Errorf("upstream route %q: %w", s.Domain, err)
			}
			ups = append(ups, up)
		}
		compiled = append(compiled, UpstreamRoute{
			Domain:    dnsname.CanonicalDomain(s.Domain),
			Upstreams: ups,
		})
	}
	return compiled, nil
}

// swapSettings replaces the published settings snapshot with ns (a copy the
// caller has already modified). The swap and the post-swap cleanup of the
// old snapshot (closing replaced upstreams, …) run under setMu so two
// concurrent reloads can't interleave; readers never take the lock.
func (h *Handler) swapSettings(ns *handlerSettings, cleanup func(old *handlerSettings)) {
	h.setMu.Lock()
	defer h.setMu.Unlock()
	old := h.settings.Load()
	h.settings.Store(ns)
	if cleanup != nil {
		cleanup(old)
	}
	// ASN attribution depends on the installed ASN tables, which any swap
	// may have replaced (SetGeo, SetClientRouter) — the memo must not serve
	// attribution computed against the previous tables.
	h.asnCache.Clear()
	h.asnCacheSize.Store(0)
}

// SetUpstreamRoutes hot-swaps the conditional per-domain upstream routing.
// Routes must come from ParseRoutes (which does the upstream parsing); the
// previous routes' upstreams are closed after the swap (they hold pooled
// TCP/DoT connections and persistent QUIC sessions, like SetUpstreams).
func (h *Handler) SetUpstreamRoutes(routes []UpstreamRoute) {
	ns := *h.settings.Load()
	ns.UpstreamRoutes = routes
	h.swapSettings(&ns, func(old *handlerSettings) {
		for _, rt := range old.UpstreamRoutes {
			for _, u := range rt.Upstreams {
				u.Close()
			}
		}
	})
}

// routeMatch returns the most specific route whose domain matches name
// (lowercased, no trailing dot) — exactly or as any ancestor — or nil.
func routeMatch(routes []UpstreamRoute, name string) *UpstreamRoute {
	var best *UpstreamRoute
	bestLen := -1
	for i := range routes {
		dom := routes[i].Domain
		if name == dom || strings.HasSuffix(name, "."+dom) {
			if len(dom) > bestLen {
				best = &routes[i]
				bestLen = len(dom)
			}
		}
	}
	return best
}

// SetUpstreams hot-swaps the upstream forwarders (config live-apply).
func (h *Handler) SetUpstreams(ups []*upstream.Upstream) {
	ns := *h.settings.Load()
	ns.Upstreams = ups
	h.swapSettings(&ns, func(old *handlerSettings) {
		// TCP/DoT keep a pooled connection and DoQ keeps a persistent QUIC
		// connection; without closing the replaced upstreams, every config
		// reload that touches the upstream list would leak sockets for the
		// life of the process.
		for _, u := range old.Upstreams {
			u.Close()
		}
	})
}

// SetCache hot-swaps the response cache (config reload).
func (h *Handler) SetCache(c *cache.Cache) {
	ns := *h.settings.Load()
	ns.Cache = c
	h.swapSettings(&ns, nil)
}

// SetBlockPolicy hot-swaps the block response mode and TTL.
func (h *Handler) SetBlockPolicy(resp string, ttl uint32) {
	ns := *h.settings.Load()
	ns.BlockResponse = resp
	ns.BlockTTL = ttl
	h.swapSettings(&ns, nil)
}

// SetTimeout hot-swaps the per-query upstream timeout.
func (h *Handler) SetTimeout(d time.Duration) {
	ns := *h.settings.Load()
	ns.Timeout = d
	h.swapSettings(&ns, nil)
}

// SetUpstreamMode hot-swaps the multi-upstream resolution strategy
// (UpstreamModeRace queries every upstream at once and uses the fastest
// answer; UpstreamModeSequential tries them in list order, failing over).
func (h *Handler) SetUpstreamMode(mode string) {
	ns := *h.settings.Load()
	ns.UpstreamMode = mode
	h.swapSettings(&ns, nil)
}

// SetFailureTTL hot-swaps how long a resolution failure is negatively
// cached as SERVFAIL; <= 0 restores the cache's configured negative TTL.
func (h *Handler) SetFailureTTL(d time.Duration) {
	ns := *h.settings.Load()
	ns.FailureTTL = d
	h.swapSettings(&ns, nil)
}

// SetRewriter hot-swaps the local DNS records (config live-apply).
func (h *Handler) SetRewriter(rw *filter.Rewriter) {
	ns := *h.settings.Load()
	ns.Rewriter = rw
	h.swapSettings(&ns, nil)
}

// SetClientRouter hot-swaps the per-client policy routing table.
func (h *Handler) SetClientRouter(cr *ClientRouter) {
	ns := *h.settings.Load()
	ns.ClientRouter = cr
	h.swapSettings(&ns, nil)
}

// ClientASN returns the ASN the server attributes to clientIP for the DoH
// X-Irongrid-Client-ASN response header and the query log: the client
// router's table (a group matched by ASN) first, then the geo blocker's
// allow/block ASN tables. ok is false when the server holds no ASN data
// covering the client — no ASN rules are configured, or the client's ISP is
// in none of the configured lists — and the header is then omitted.
//
// The result is memoized per client IP (Handler.asnCache): the record path
// resolves it on every logged query, and without the memo a config with ASN
// data would pay a ParseIP plus two table searches per entry. Attribution
// is stable while the installed tables are unchanged, and swapSettings
// clears the memo on any settings swap, so it never goes stale.
func (h *Handler) ClientASN(clientIP string) (uint32, bool) {
	if clientIP == "" {
		return 0, false
	}
	if v, ok := h.asnCache.Load(clientIP); ok {
		a := v.(uint32)
		return a, a != 0 // 0 is cached as "no ASN" (ASN 0 is not assignable)
	}
	// Parse once and share the net.IP between the router and geo lookups
	// instead of each re-parsing the string.
	ip := net.ParseIP(clientIP)
	var asn uint32
	var found bool
	if ip != nil {
		ns := h.settings.Load()
		if cr := ns.ClientRouter; cr != nil {
			if a, ok := cr.ASNOfIP(ip); ok {
				asn, found = a, true
			}
		}
		if !found {
			if g := ns.Geo; g != nil {
				if a, ok := g.ASNOf(ip); ok {
					asn, found = a, true
				}
			}
		}
	}
	if h.asnCacheSize.Add(1) > maxASNCache {
		h.asnCache.Clear()
		h.asnCacheSize.Store(0)
	}
	h.asnCache.Store(clientIP, asn)
	return asn, found
}

// SetRateLimiter hot-swaps the rate limiter; nil disables rate limiting.
func (h *Handler) SetRateLimiter(rl *RateLimiter) {
	ns := *h.settings.Load()
	ns.RateLimiter = rl
	h.swapSettings(&ns, nil)
}

// SetNXGuard hot-swaps the NXDOMAIN flood guard; nil disables it.
func (h *Handler) SetNXGuard(g *NXGuard) {
	ns := *h.settings.Load()
	ns.NXGuard = g
	h.swapSettings(&ns, nil)
}

// SetGeo hot-swaps the geo blocker; nil disables geo-blocking.
func (h *Handler) SetGeo(g *geoip.Blocker) {
	ns := *h.settings.Load()
	ns.Geo = g
	h.swapSettings(&ns, nil)
}

// SetIPBanner hot-swaps the client-IP banner (explicit block list + honeypot
// auto-blocks); nil disables it.
func (h *Handler) SetIPBanner(b *geoip.Banner) {
	ns := *h.settings.Load()
	ns.IPBanner = b
	h.swapSettings(&ns, nil)
}

// SetTrustUDP hot-swaps the opt-in that lets plain-UDP honeypot hits
// auto-block their source (see TrustUDP's doc comment on the struct).
func (h *Handler) SetTrustUDP(on bool) {
	ns := *h.settings.Load()
	ns.TrustUDP = on
	h.swapSettings(&ns, nil)
}

// SetHoneypotUDPBlock hot-swaps the bounded UDP-honeypot block window (see
// HoneypotUDPBlock's doc comment on the struct); <= 0 disables it.
func (h *Handler) SetHoneypotUDPBlock(d time.Duration) {
	ns := *h.settings.Load()
	ns.HoneypotUDPBlock = d
	h.swapSettings(&ns, nil)
}

// CurrentIPBanner returns the active banner (nil when disabled), for the
// API's blocked-list/unblock endpoints.
func (h *Handler) CurrentIPBanner() *geoip.Banner {
	return h.settings.Load().IPBanner
}

// BlockedClients returns the clients currently under an auto-block (from the
// rate limiter), for the dashboard.
func (h *Handler) BlockedClients() []BlockedClient {
	rl := h.settings.Load().RateLimiter
	if rl == nil {
		return nil
	}
	return rl.BlockedList()
}

// UnblockClient lifts an auto-blocked client's cooldown early.
func (h *Handler) UnblockClient(ip string) {
	if rl := h.settings.Load().RateLimiter; rl != nil {
		rl.Unblock(ip)
	}
}

// SetDNSSEC hot-swaps DNSSEC enforcement (see DNSSECConfig's doc comment for
// what "enabled" actually means: trusting an encrypted, validating upstream,
// not local chain-of-trust validation).
func (h *Handler) SetDNSSEC(enabled, requireAD bool) {
	ns := *h.settings.Load()
	ns.DNSSECEnabled = enabled
	ns.DNSSECRequireAD = requireAD
	h.swapSettings(&ns, nil)
}

// SetCNAMECloakingProtection hot-swaps CNAME cloaking protection.
func (h *Handler) SetCNAMECloakingProtection(enabled bool) {
	ns := *h.settings.Load()
	ns.CNAMECloakingProtection = enabled
	h.swapSettings(&ns, nil)
}

// SetPadding hot-swaps RFC 7830 response padding on the encrypted transports.
func (h *Handler) SetPadding(on bool) {
	h.Padding.Store(on)
}

// SetCookies hot-swaps RFC 7873 server DNS cookies.
func (h *Handler) SetCookies(on bool) {
	h.Cookies.Store(on)
}

func (h *Handler) serve(w dns.ResponseWriter, r *dns.Msg, client, proto string) {
	w = &statsResponseWriter{ResponseWriter: w, writeErrors: &h.Stats.WriteErrors}
	// Every listener (UDP/TCP/DoT/DoH/DoH3/DoQ) funnels into this one
	// function in this one process — an unrecovered panic anywhere in the
	// pipeline below (filter engine, cache, upstream, DHCP host lookups, …)
	// would otherwise crash the whole server and take down every protocol
	// at once, not just the query that triggered it. Recovering here turns
	// that into a single failed query.
	defer func() {
		if rec := recover(); rec != nil {
			//nolint:gosec // G706: client is a socket-derived IP, no control chars
			slog.Error("recovered panic serving query", "client", client, "proto", proto, "panic", rec, "stack", string(debug.Stack()))
			h.Stats.Errors.Add(1)
			if r != nil && len(r.Question) > 0 {
				m := new(dns.Msg)
				m.SetRcode(r, dns.RcodeServerFailure)
				_ = w.WriteMsg(m)
			}
		}
	}()
	start := time.Now()
	h.Stats.Total.Add(1)
	if p, ok := h.Stats.ByProtocol[proto]; ok {
		p.Add(1)
	}

	// One atomic load per query instead of an RLock snapshot: the settings
	// pointer is swapped whole by the Set* methods, never mutated in place.
	s := h.settings.Load()
	upstreams := s.Upstreams
	upstreamMode := s.UpstreamMode
	routes := s.UpstreamRoutes
	blockResp := s.BlockResponse
	blockTTL := s.BlockTTL
	timeout := s.Timeout
	failureTTL := s.FailureTTL
	cch := s.Cache
	rewriter := s.Rewriter
	clientRouter := s.ClientRouter
	rateLimiter := s.RateLimiter
	nxGuard := s.NXGuard
	geo := s.Geo
	ipbanner := s.IPBanner
	trustUDP := s.TrustUDP
	honeypotUDPBlock := s.HoneypotUDPBlock
	dnssecEnabled := s.DNSSECEnabled
	dnssecRequireAD := s.DNSSECRequireAD
	cnameCloakingEnabled := s.CNAMECloakingProtection
	cookiesOn := h.Cookies.Load()

	if r == nil || len(r.Question) == 0 {
		m := getMsg()
		m.Response = true
		m.Rcode = dns.RcodeFormatError
		_ = h.write(w, m, r, proto)
		putMsg(m)
		return
	}

	// 0.2 EDNS version check (RFC 6891 §6.1.3): a query advertising an EDNS
	//     version we don't implement is answered BADVERS instead of being
	//     processed — options under an unknown version may not mean what
	//     we'd assume, so nothing past the OPT record is safe to interpret
	//     until the client falls back to a version we support. Only version
	//     0 is defined today, so this only ever fires against a client
	//     probing for/expecting a future EDNS version.
	if opt := r.IsEdns0(); opt != nil && opt.Version() != 0 {
		m := newReply(r)
		m.Rcode = dns.RcodeBadVers
		m.SetEdns0(ednsUDPSize, false)
		_ = h.write(w, m, r, proto)
		putMsg(m)
		return
	}

	// 0.25 DNS cookies (RFC 7873): a client that sends a COOKIE option gets
	//    its client cookie echoed with our HMAC server cookie on every
	//    response (attached in write), and a query carrying a stale or
	//    forged server cookie is answered BADCOOKIE here instead of being
	//    processed — an off-path attacker cannot spoof a query with a valid
	//    server cookie, and cannot push forged answers past a validating
	//    client. The check runs before the rate limiter so a spoofed flood
	//    of bad-cookie queries is answered cheaply instead of burning the
	//    victim's token bucket.
	if cookiesOn && client != "" {
		if reqCookie := requestCookieValue(r); len(reqCookie) >= clientCookieHexLen {
			cc := reqCookie[:clientCookieHexLen]
			expected := cc + h.serverCookie(client, cc)
			// Compare only the expected prefix: some clients append extra
			// bytes to the echoed server cookie. Cookie comparison is not
			// timing-sensitive — the value travels in cleartext inside the
			// cookie itself — so EqualFold (hex is case-insensitive) is fine.
			if len(reqCookie) > clientCookieHexLen &&
				!strings.EqualFold(reqCookie[:2*clientCookieHexLen], expected) {
				m := newReply(r)
				m.Rcode = dns.RcodeBadCookie
				// attachCookie returns a fresh Copy(), so m itself is unused
				// the moment it returns — safe to putMsg right after.
				out := attachCookie(m, expected)
				putMsg(m)
				_ = h.write(w, out, r, proto)
				return
			}
		}
	}

	// 0. Rate limit: the cheapest possible check, before any real work. A
	//    UDP response is simply dropped rather than answered REFUSED —
	//    answering at all hands a spoofed source IP amplification, however
	//    small. Connection-oriented protocols (TCP/DoT/DoH/DoQ) already
	//    required a real handshake, so REFUSED is safe there.
	if rateLimiter != nil && !rateLimiter.Allow(client) {
		h.Stats.Errors.Add(1)
		if proto == "udp" {
			return
		}
		refused := getMsg()
		refused.SetReply(r)
		refused.Rcode = dns.RcodeRefused
		_ = h.write(w, refused, r, proto)
		putMsg(refused)
		return
	}
	// 0.1 NXDOMAIN flood guard: a prefix currently serving a random-subdomain
	//    flood is refused the same way as a rate-limited client — silent UDP
	//    drop, REFUSED on the stream transports. The check runs before any
	//    real work so a blocked prefix can't burn cache/upstream resources.
	if nxGuard != nil && !nxGuard.Allow(clientPrefix(client)) {
		h.Stats.Errors.Add(1)
		if proto == "udp" {
			return
		}
		refused := getMsg()
		refused.SetReply(r)
		refused.Rcode = dns.RcodeRefused
		_ = h.write(w, refused, r, proto)
		putMsg(refused)
		return
	}

	q := r.Question[0]
	qname := dnsname.CanonicalDomain(q.Name)

	// 0.5 Client blocking: a geo-blocked country (source-IP country in the
	//    blocked set), a block-listed ASN's client, or a banner-blocked
	//    client (explicit IPs/CIDRs plus IPs auto-added by honeypot hits) is
	//    REFUSED on every transport — an explicit answer, not a silent drop
	//    (the user's chosen trade-off). The geo/ASN allowlists are checked
	//    inside the blockers, so whitelisted IPs and unblocked ISPs always
	//    pass. The blocking source is surfaced in the query log so an
	//    ASN-blocked client reads as "asn-blocked" rather than a country or
	//    IP block.
	if client != "" {
		geoBlocked, geoSource := false, ""
		if geo != nil {
			geoBlocked, geoSource = geo.BlockedAs(client)
		}
		bannerBlocked, bannerSource := false, ""
		if ipbanner != nil {
			bannerBlocked, bannerSource = ipbanner.BlockedAs(client)
		}
		if geoBlocked || bannerBlocked {
			h.Stats.Blocked.Add(1)
			action, reason := "geo-blocked", "country-blocked"
			blockSource := geoSource
			if bannerBlocked {
				action, reason = "ip-blocked", "blocked-client"
				blockSource = bannerSource
			}
			if blockSource == "asn" {
				reason = "asn-blocked"
			}
			refused := getMsg()
			refused.SetReply(r)
			refused.Rcode = dns.RcodeRefused
			h.record(client, qname, q, action, reason, "", start, refused)
			out := refused
			if r.IsEdns0() != nil {
				// Prohibited: the block is about who's asking, not what's
				// being asked — distinct from a domain-blocklist hit below.
				out = attachEDE(refused, dns.ExtendedErrorCodeProhibited, reason)
			}
			_ = h.write(w, out, r, proto)
			putMsg(refused)
			return
		}
	}
	// 0.6 Honeypot: a configured trap domain (and everything under it) is
	// never answered. The client that asked for it is auto-blocked —
	// persisted across restarts and pushed into the host firewall so its
	// subsequent connections are dropped at the packet level, not just
	// refused at the DNS layer. Honeypot traffic is attack traffic, so it
	// is not written to the query log either — the dashboard's blocked-
	// clients card still surfaces every auto-blocked client via
	// /api/geo/blocked, and the blocked counter below stays live.
	// Fail closed on trust: a honeypot hit may only auto-block its
	// querying client when it arrived over a known connection-oriented
	// transport (TCP/DoT/DoH/DoQ), which required a real handshake, so
	// the source address is genuine. A plain-UDP source can be trivially
	// spoofed — trusting it would let anyone permanently block an
	// innocent victim with a single spoofed packet — so UDP honeypot hits
	// are never answered at all (replying to a spoofed packet is pure
	// amplification, the same rationale behind the rate limiter's UDP
	// silent drop) and never earn a permanent block. The operator has two
	// opt-ins that give a UDP source teeth: trust_udp (permanent block,
	// trusted networks only) and honeypot_udp_block (a bounded window via
	// the rate limiter, so a spoofed packet can only block a victim until
	// the window elapses).
	if ipbanner != nil && ipbanner.LookupHoneypot(qname) {
		trusted := proto == "tcp" || proto == "dot" || proto == "doh" || proto == "doq"
		if client != "" {
			switch {
			case trusted || trustUDP:
				// Permanent block (persisted + firewall drop): a real
				// handshake proves the source, and trust_udp is the
				// operator's explicit opt-in for trusted networks.
				if err := ipbanner.Block(client); err != nil {
					//nolint:gosec // G706: client is a socket-derived IP, no control chars
					slog.Error("honeypot blocking client failed", "client", client, "error", err)
				}
			case honeypotUDPBlock > 0 && rateLimiter != nil:
				// Bounded block: the source is dropped at the DNS layer
				// for the window, then freed — surfaced on the dashboard's
				// blocked-clients list and liftable early via Unblock.
				rateLimiter.ForceBlock(client, honeypotUDPBlock)
			}
		}
		h.Stats.Blocked.Add(1)
		h.Stats.Honeypot.Add(1)
		if proto == "udp" {
			// Silent drop: answering a spoofed UDP honeypot packet would
			// amplify it, and a flooder deserves no feedback.
			return
		}
		refused := getMsg()
		refused.SetReply(r)
		refused.Rcode = dns.RcodeRefused
		_ = h.write(w, refused, r, proto)
		putMsg(refused)
		return
	}

	// 0.7 ANY minimization (RFC 8482): QTYPE=ANY has no well-defined
	//    "everything you've got" semantics for a caching resolver, and
	//    answering it in full is a well-known reflection-amplification
	//    vector — a small spoofed UDP query can pull back a large
	//    multi-RRset response. Like every other major resolver (BIND,
	//    Unbound, PowerDNS, …), ANY gets a minimal synthetic response
	//    instead of real processing: a single HINFO record, RFC 8482's
	//    suggested stand-in, with nothing forwarded from cache or upstream.
	if q.Qtype == dns.TypeANY {
		m := newReply(r)
		m.Answer = append(m.Answer, &dns.HINFO{
			Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeHINFO, Class: dns.ClassINET, Ttl: anyMinimalTTL},
			Cpu: "RFC8482",
			Os:  "",
		})
		h.Stats.Allowed.Add(1)
		h.record(client, qname, q, "minimal", "rfc8482-any", "", start, m)
		_ = h.write(w, m, r, proto)
		putMsg(m)
		return
	}

	// 1. Local DNS records win over everything else — an explicit config
	//    entry is a stronger signal of intent than any blocklist or cache,
	//    and it's global (not per-client-group) so it's checked up front.
	if rewriter != nil {
		if rules, ok := rewriter.Lookup(q.Name); ok {
			if ans := filter.BuildAnswer(r, rules, q.Name, q.Qtype); ans != nil {
				h.Stats.Allowed.Add(1)
				h.record(client, qname, q, "rewrite", "local-dns", "", start, ans)
				_ = h.write(w, ans, r, proto)
				return
			}
			// The name matched but not this record type: NODATA is the
			// correct answer for an authoritatively-local name, not a
			// blocklist/cache/upstream lookup.
			h.Stats.Allowed.Add(1)
			m := newReply(r)
			h.record(client, qname, q, "rewrite", "local-dns-nodata", "", start, m)
			_ = h.write(w, m, r, proto)
			putMsg(m)
			return
		}
	}

	// 1.5 DHCP-assigned hostnames: a client the DHCP server registered (its
	//     hostname from DHCPREQUEST, optionally under the configured domain)
	//     resolves locally — the address is authoritative while the lease is
	//     live, so the answer never goes upstream. Both <hostname>.<domain>
	//     and the bare <hostname> match; the other address family of a known
	//     host is answered with authoritative NODATA (it exists, just not as
	//     an AAAA). Short TTL so a hostname change propagates within minutes.
	if h.DHCPHosts != nil {
		if ips, ok := h.DHCPHosts.LookupHost(q.Name); ok && len(ips) > 0 {
			m := getMsg()
			m.SetReply(r)
			m.Authoritative = true
			for _, ip := range ips {
				switch {
				case q.Qtype == dns.TypeA && ip.To4() != nil:
					m.Answer = append(m.Answer, &dns.A{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: dhcpHostTTL}, A: ip.To4()})
				case q.Qtype == dns.TypeAAAA && ip.To4() == nil && ip.To16() != nil:
					m.Answer = append(m.Answer, &dns.AAAA{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: dhcpHostTTL}, AAAA: ip.To16()})
				}
			}
			h.Stats.Allowed.Add(1)
			if len(m.Answer) > 0 {
				h.record(client, qname, q, "rewrite", "dhcp-host", "", start, m)
			} else {
				h.record(client, qname, q, "rewrite", "dhcp-host-nodata", "", start, m)
			}
			_ = h.write(w, m, r, proto)
			putMsg(m)
			return
		}
		// 1.6 DHCP reverse lookups: a PTR query for a leased address answers
		//     with the client's registered hostname, so logs and tools that
		//     reverse-resolve client IPs (e.g. /api/log/hostnames) see names
		//     instead of numbers. Only addresses the DHCP server actually
		//     assigned are intercepted — every other reverse name falls
		//     through to the upstreams unchanged.
		if q.Qtype == dns.TypePTR {
			if ip := reverseNameIP(q.Name); ip != nil {
				if host, ok := h.DHCPHosts.LookupPTR(ip.String()); ok {
					m := getMsg()
					m.SetReply(r)
					m.Authoritative = true
					m.Answer = append(m.Answer, &dns.PTR{
						Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypePTR, Class: dns.ClassINET, Ttl: dhcpHostTTL},
						Ptr: host + ".",
					})
					h.Stats.Allowed.Add(1)
					h.record(client, qname, q, "rewrite", "dhcp-host-ptr", "", start, m)
					_ = h.write(w, m, r, proto)
					putMsg(m)
					return
				}
			}
		}
	}

	// 2. Per-client policy: a client whose IP falls in a configured group
	//    uses that group's blocklists/whitelist (and upstreams, if
	//    overridden) instead of the global ones.
	engine := h.Engine
	if clientRouter != nil {
		if policy := clientRouter.Resolve(client); policy != nil {
			engine = policy.Engine
			if len(policy.Upstreams) > 0 {
				upstreams = policy.Upstreams
			}
		}
	}
	// 2.5 Conditional routing (split horizon): a per-domain route is the
	//     most specific intent there is — "*.lan queries go to the LAN
	//     resolver" — so it wins over both the global forwarders and a
	//     client group's upstream override. Routes partition the name space
	//     (a question matches at most one route), so the shared response
	//     cache and in-flight coalescing stay sound.
	if rt := routeMatch(routes, qname); rt != nil && len(rt.Upstreams) > 0 {
		upstreams = rt.Upstreams
	}

	// 3. Filtering: whitelist overrides everything; blocklists stop the query.
	decision := engine.DecideDomain(q.Name)
	if decision.Action == filter.Block {
		blocked := filter.BuildBlockResponse(r, blockResp, blockTTL)
		h.Stats.Blocked.Add(1)
		h.record(client, qname, q, "blocked", decision.Reason, "", start, blocked)
		if r.IsEdns0() != nil {
			blocked = attachEDE(blocked, dns.ExtendedErrorCodeBlocked, decision.Reason)
		}
		_ = h.write(w, blocked, r, proto)
		return
	}
	// A domain-whitelist hit must also exempt the answer from IP-based
	// blocking below (step 7) — otherwise a whitelisted domain that happens
	// to resolve to a blocklisted IP (a shared CDN address, for instance)
	// gets blocked anyway, contradicting "whitelist overrides everything"
	// above.
	domainWhitelisted := strings.HasPrefix(decision.Reason, "whitelist")
	// 4. Cache lookup (only for standard record types). Cached messages carry
	//    the ID of the original query, so rebase to this request's ID.
	// Lookup hashes the question once and checks positive then negative
	// entries, instead of two independent Get/GetNegative calls that each
	// re-derived the same key. The budget is deliberately short: if
	// Dragonfly is slow or down, the query must reach the upstream rather
	// than stall. A hit may also be stale (RFC 8767): an entry past its TTL
	// but still within its serve-stale window, which we only answer from if
	// re-resolution below fails.
	var stale cache.LookupResult
	if cch != nil && !isMetaQuery(q) {
		// Lookup is context-free: the L1 hit path allocates nothing, and the
		// L2 read is bounded by the cache's own lookup budget (see
		// cache.defaultLookupTimeout), so a slow or down cache tier can't
		// stall the query. A fresh hit is served straight from the stored
		// packed bytes — writeRaw patches the query ID and rebases the
		// answer TTLs in a private copy, so no Unpack and no re-pack ever
		// happens on the hit path.
		hit := cch.Lookup(q)
		if len(hit.Raw) > 0 && !hit.Stale {
			h.Stats.Cached.Add(1)
			reason := "cache"
			if hit.Negative {
				reason = "cache-negative"
				// A cached NXDOMAIN is a genuine missing name (blocked
				// responses are never cached), so it counts toward the
				// NXDOMAIN flood guard just like an upstream NXDOMAIN.
				if nxGuard != nil && packedRcode(hit.Raw) == dns.RcodeNameError {
					nxGuard.NoteNX(clientPrefix(client))
				}
			}
			// record needs the rcode and answer count; both are header
			// fields, read off the packed bytes without decoding.
			h.recordRaw(client, qname, q, "cached", reason, "", start, hit.Raw)
			_ = h.writeRaw(w, hit, r, proto)
			return
		}
		if len(hit.Raw) > 0 {
			stale = hit
		}
	}

	// 5. Forward to upstreams according to the configured strategy: race
	// (default) queries every available upstream concurrently and uses the
	// fastest healthy answer; sequential tries them in list order and fails
	// over. A single upstream is queried directly to avoid goroutine
	// overhead. The outgoing query always advertises EDNS0 with the DNS
	// Flag Day 2020 recommended 1232-byte UDP payload (the DO bit only when
	// DNSSEC is enabled): without EDNS the upstream caps its UDP answer at
	// 512 bytes, and a larger buffer risks IP fragmentation (which many
	// paths drop silently) — 1232 fits every common path MTU while keeping
	// large records on the TCP fallback. The query is copied so the
	// client's message is never mutated. Upstreams whose circuit is open
	// (consecutive failures inside the cooldown window) are skipped so a
	// dead server can't burn its full timeout on every query; a single
	// upstream in cooldown fails fast into serve-stale/SERVFAIL below.
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	upstreamQuery := r.Copy()
	// Replace the client's EDNS OPT rather than layering a second one on:
	// miekg/dns's SetEdns0 appends, and a query carrying two OPT records is
	// malformed (RFC 6891 §6.1.1: "it MUST be the only OPT RR in that
	// message"). Strict resolvers (Quad9 in particular) reject it with
	// FORMERR, which the client sees as a resolution failure. The client's
	// own advertisement is superseded by the EDNS one below anyway, so
	// drop every OPT (always last in practice, but filtered regardless) and
	// preserve any other additional records (e.g. TSIG).
	extra := upstreamQuery.Extra[:0]
	for _, rr := range upstreamQuery.Extra {
		if rr.Header().Rrtype != dns.TypeOPT {
			extra = append(extra, rr)
		}
	}
	upstreamQuery.Extra = extra
	upstreamQuery.SetEdns0(ednsUDPSize, dnssecEnabled)
	var (
		resp   *dns.Msg
		usedUp string
		err    error
	)
	resp, usedUp, err = h.resolveUpstreams(ctx, r, q, upstreams, upstreamMode, upstreamQuery)
	// NXDOMAIN flood guard: an upstream NXDOMAIN is the flood's signature
	// (random subdomains under a victim domain), so it's counted here — the
	// guard's Allow check at the top of serve() then refuses the prefix once
	// the burst trips the threshold. Blocked responses never reach this
	// point (they're answered before forwarding), so legit blocklist
	// NXDOMAINs aren't counted as flood traffic.
	if nxGuard != nil && err == nil && resp != nil && resp.Rcode == dns.RcodeNameError {
		nxGuard.NoteNX(clientPrefix(client))
	}
	// RFC 8767: an upstream that *answers* SERVFAIL is also a resolution
	// failure — serve stale rather than propagating the failure.
	if err == nil && resp != nil && resp.Rcode == dns.RcodeServerFailure && len(stale.Raw) > 0 {
		if m := stale.Msg(); m != nil {
			m.Id = r.Id
			capTTL(m, staleServeTTL)
			h.Stats.Cached.Add(1)
			h.record(client, qname, q, "cached", "stale", usedUp, start, m)
			out := m
			if r.IsEdns0() != nil {
				out = attachEDE(m, dns.ExtendedErrorCodeStaleAnswer, "")
			}
			_ = h.write(w, out, r, proto)
			putMsg(m) // fresh per-read decode, safe once written
			return
		}
	}
	if err != nil || resp == nil {
		// Serve-stale: re-resolution failed but a previously cached answer
		// is still within its stale window. Answering from it beats
		// SERVFAIL; its TTLs are capped so no client caches the stale data
		// long (RFC 8767 recommends a short TTL on stale answers). Note
		// that this bypasses the DNSSEC requireAD check below — a stale
		// answer was validated when first cached if requireAD was on then;
		// serving it during an outage is the deliberate availability
		// trade-off of serve-stale.
		if len(stale.Raw) > 0 {
			if m := stale.Msg(); m != nil {
				m.Id = r.Id
				capTTL(m, staleServeTTL)
				h.Stats.Cached.Add(1)
				h.record(client, qname, q, "cached", "stale", usedUp, start, m)
				out := m
				if r.IsEdns0() != nil {
					out = attachEDE(m, dns.ExtendedErrorCodeStaleAnswer, "")
				}
				_ = h.write(w, out, r, proto)
				putMsg(m) // fresh per-read decode, safe once written
				return
			}
		}
		h.Stats.Errors.Add(1)
		// Not putMsg'd: when cache != nil this is handed unmodified into a
		// background cache.SetNegative goroutine below, and serve() returns
		// without waiting for it — recycling m here would race that
		// goroutine. See msgpool.go's doc comment.
		m := newReply(r)
		m.Rcode = dns.RcodeServerFailure
		errStr := "no upstream available"
		if err != nil {
			errStr = err.Error()
		}
		h.record(client, qname, q, "error", errStr, usedUp, start, m)
		out := m
		if r.IsEdns0() != nil {
			// A fresh copy for the client only — m itself may be handed to
			// the background SetNegative write below unmodified.
			out = attachEDE(m, dns.ExtendedErrorCodeNetworkError, errStr)
		}
		_ = h.write(w, out, r, proto)
		// Cache the failure briefly (negative_ttl) so a dead upstream or
		// zone doesn't burn the full timeout on every retry — a failing
		// domain's retries used to re-pay the whole per-query timeout each
		// time. SERVFAIL is cacheable (RFC 2308 section 5.2) and the short
		// negative TTL bounds how long a transient failure can shadow a
		// recovery. Only when nothing is stale: if a previous answer is in
		// its serve-stale window, retries must keep probing upstream so the
		// stale data wins on success — a cached SERVFAIL must never shadow
		// it. (An upstream that *answers* SERVFAIL is already negatively
		// cached by the success path below; this fills the gap where the
		// upstream never answered at all.) The write runs after WriteMsg
		// deliberately: the SERVFAIL has then been packed and sent, so m is
		// exclusively this goroutine's and the cache writer can take it
		// directly — no copy (SetNegative mutates the message: SetReply,
		// Compress, Pack).
		if cch != nil && len(stale.Raw) == 0 && !isMetaQuery(q) {
			// Bounded by cacheWriteSlots: a flood of misses can't spawn
			// unbounded goroutines — a saturated pool skips the write (the
			// cache only helps future queries, so dropping is the right
			// trade under pressure).
			select {
			case h.cacheWriteSlots <- struct{}{}:
				go func() {
					defer recoverPanic("background cache write (failure)")
					defer func() { <-h.cacheWriteSlots }()
					cctx, ccancel := context.WithTimeout(context.Background(), 3*time.Second)
					defer ccancel()
					// failureTTL <= 0 falls back to the cache's configured
					// negative TTL (cache.failure_ttl knob).
					cch.SetNegative(cctx, q, m, failureTTL)
				}()
			default:
				// Saturated — skip this write.
			}
		}
		return
	}

	// 6. DNSSEC enforcement: reject an answer the upstream didn't mark
	//    authenticated instead of passing it through unvalidated. Only
	//    meaningful over an encrypted upstream transport (DoT/DoH/DoQ),
	//    where the AD bit can't be stripped or forged in flight.
	if dnssecEnabled && dnssecRequireAD && !resp.AuthenticatedData {
		h.Stats.Errors.Add(1)
		m := newReply(r)
		m.Rcode = dns.RcodeServerFailure
		h.record(client, qname, q, "error", "dnssec: upstream did not authenticate the answer", usedUp, start, m)
		_ = h.write(w, m, r, proto)
		putMsg(m)
		return
	}

	// 7. IP-based blocking: if the blocklists contain IP rules, check the
	//    answers (A/AAAA) returned by the upstream. The gate is an atomic
	//    read so the common domain-only list setup skips the answer walk
	//    entirely — answerIPs allocates a slice and ip.String() per address
	//    on every upstream response otherwise.
	if engine.HasIPRules() && !domainWhitelisted {
		if blockedByIP, reason := engine.CheckIPs(answerIPs(resp)); blockedByIP {
			blocked := filter.BuildBlockResponse(r, blockResp, blockTTL)
			h.Stats.Blocked.Add(1)
			h.record(client, qname, q, "blocked", reason, usedUp, start, blocked)
			if r.IsEdns0() != nil {
				blocked = attachEDE(blocked, dns.ExtendedErrorCodeBlocked, reason)
			}
			_ = h.write(w, blocked, r, proto)
			return
		}
	}

	// 7.5 CNAME cloaking protection: a tracker can disguise itself behind a
	//    first-party-looking subdomain that CNAMEs to a blocklisted domain.
	//    Walk every CNAME hop in the answer (a classic upstream's raw chain,
	//    or the recursive resolver's own already-merged chaseCNAME result)
	//    and block if any target matches the blocklist/whitelist rules, not
	//    just the originally queried name.
	if cnameCloakingEnabled {
		if owner, target, decision := cnameCloakCheck(engine, resp); decision.Action == filter.Block {
			blocked := filter.BuildBlockResponse(r, blockResp, blockTTL)
			h.Stats.Blocked.Add(1)
			reason := "cname-cloaking:" + owner + "->" + target + ":" + decision.Reason
			h.record(client, qname, q, "blocked", reason, usedUp, start, blocked)
			if r.IsEdns0() != nil {
				blocked = attachEDE(blocked, dns.ExtendedErrorCodeBlocked, reason)
			}
			_ = h.write(w, blocked, r, proto)
			return
		}
	}

	// resp is deliberately never put into msgPool: when caching is on it's
	// handed unmodified into the background goroutine below, which keeps
	// reading/mutating/Pack()-ing it after serve() has already returned —
	// recycling it here would race that goroutine. See msgpool.go.
	h.Stats.Allowed.Add(1)
	h.record(client, qname, q, "allowed", "", usedUp, start, resp)
	_ = h.write(w, resp, r, proto)

	// 8. Cache the result (positive or negative) in the background. Caching
	//    only ever helps *future* queries, so there's no reason to make this
	//    client wait on a cache round trip before getting the answer it
	//    already has. The write runs after WriteMsg deliberately: the
	//    response has then been packed and sent, so resp is exclusively this
	//    goroutine's and can be handed to the cache writer directly.
	//    Cache.Set/SetNegative mutate the message they're given (SetReply,
	//    Compress, Pack) while writing it — the old code copied resp here
	//    because the background write raced w.WriteMsg's concurrent pack;
	//    ordering eliminates the race and the per-query copy with it. The
	//    trade-off: on a stream transport the cache write now waits for the
	//    client write to finish, but DNS responses are small and that write
	//    virtually never blocks. Zero TTLs fall back to the configured
	//    Dragonfly cache lifetimes.
	if cch != nil && !isMetaQuery(q) {
		// Bounded by cacheWriteSlots like the failure path above — same
		// rationale: a miss flood must not spawn unbounded goroutines.
		select {
		case h.cacheWriteSlots <- struct{}{}:
			go func() {
				defer recoverPanic("background cache write")
				defer func() { <-h.cacheWriteSlots }()
				cctx, ccancel := context.WithTimeout(context.Background(), 3*time.Second)
				defer ccancel()
				if len(resp.Answer) > 0 {
					cch.Set(cctx, q, resp, 0)
				} else {
					cch.SetNegative(cctx, q, resp, 0)
				}
			}()
		default:
			// Saturated — skip this write.
		}
	}
}

// statsResponseWriter records transport write failures in one place. Handler
// call sites deliberately remain free to ignore write errors because a DNS
// response cannot be retried safely after a partial stream write, but the
// failures must still be observable.
type statsResponseWriter struct {
	dns.ResponseWriter
	writeErrors *atomic.Int64
}

func (w *statsResponseWriter) WriteMsg(m *dns.Msg) error {
	err := w.ResponseWriter.WriteMsg(m)
	if err != nil {
		w.writeErrors.Add(1)
	}
	return err
}

func (w *statsResponseWriter) Write(b []byte) (int, error) {
	n, err := w.ResponseWriter.Write(b)
	if err != nil {
		w.writeErrors.Add(1)
	}
	return n, err
}

func (h *Handler) record(client, qname string, q dns.Question, action, reason, upstreamName string, start time.Time, m *dns.Msg) {
	rcode, answers := dns.RcodeServerFailure, 0
	if m != nil {
		rcode = m.Rcode
		answers = len(m.Answer)
	}
	h.recordEntry(client, qname, q, action, reason, upstreamName, start, rcode, answers)
}

// recordRaw is record for a cache hit served from packed bytes: the rcode
// and answer count are header fields, read off the wire form without
// decoding the message into a dns.Msg.
func (h *Handler) recordRaw(client, qname string, q dns.Question, action, reason, upstreamName string, start time.Time, raw []byte) {
	h.recordEntry(client, qname, q, action, reason, upstreamName, start, packedRcode(raw), packedAnCount(raw))
}

// packedRcode returns the header rcode (lower 4 bits of byte 3) of a packed
// DNS message, or SERVFAIL for a too-short one. All cached negatives are
// NOERROR/NXDOMAIN/SERVFAIL — well under the 16 rcode values the header
// byte can express — so extended-rcode bits never matter here.
func packedRcode(raw []byte) int {
	if len(raw) < 4 {
		return dns.RcodeServerFailure
	}
	return int(raw[3] & 0x0F)
}

// packedAnCount returns the Answer-section record count from a packed DNS
// message's header (bytes 6-7), or 0 for a too-short one.
func packedAnCount(raw []byte) int {
	if len(raw) < 12 {
		return 0
	}
	return int(binary.BigEndian.Uint16(raw[6:8]))
}

func (h *Handler) recordEntry(client, qname string, q dns.Question, action, reason, upstreamName string, start time.Time, rcode, answers int) {
	h.latency.record(time.Since(start))
	if h.Log == nil {
		return
	}
	// The client's ASN, attributed from the same pruned ip2asn tables the
	// X-Irongrid-Client-ASN DoH header uses. 0 when the ISP is in none of
	// the configured lists — the dashboard then falls back to its external
	// RIPEstat lookup. Resolved per logged query; a config without ASN data
	// resolves instantly (nil tables), one with it pays a binary search.
	asn, _ := h.ClientASN(client)
	h.Log.Record(querylog.Entry{
		Time:           start,
		Client:         client,
		Domain:         qname,
		Type:           dns.TypeToString[q.Qtype],
		Action:         action,
		Reason:         reason,
		Upstream:       upstreamName,
		ResponseTimeMS: time.Since(start).Milliseconds(),
		Rcode:          rcode,
		Answers:        answers,
		ASN:            asn,
	})
}

// clientUDPSize returns the largest UDP payload this client will accept:
// its advertised EDNS0 buffer (RFC 6891), or the 512-byte RFC 1035 limit
// for legacy clients that send no OPT record. A nil request (the FORMERR
// path, where the query was unparseable) is treated as a legacy client.
func clientUDPSize(r *dns.Msg) int {
	if r != nil {
		if opt := r.IsEdns0(); opt != nil {
			if s := int(opt.UDPSize()); s >= dns.MinMsgSize {
				return s
			}
		}
	}
	return dns.MinMsgSize
}

// clientCookieHexLen is the hex length of an RFC 7873 client cookie (8 bytes
// = 16 hex chars). The server cookie is generated at the same length, so a
// full cookie round-trips as 32 hex chars.
const clientCookieHexLen = 16

// requestCookieValue returns the request's COOKIE option value (a hex
// string), or "" when the message carries none — RFC 7873 clients may omit
// the option entirely, and a server must not force cookies on them.
func requestCookieValue(r *dns.Msg) string {
	if r == nil {
		return ""
	}
	opt := r.IsEdns0()
	if opt == nil {
		return ""
	}
	for _, o := range opt.Option {
		if c, ok := o.(*dns.EDNS0_COOKIE); ok {
			return c.Cookie
		}
	}
	return ""
}

// requestClientCookie returns the request's client cookie — the first
// clientCookieHexLen hex chars of its COOKIE option. An option shorter than
// 8 bytes is malformed and ignored (RFC 7873 §5.2.3).
func requestClientCookie(r *dns.Msg) string {
	if c := requestCookieValue(r); len(c) >= clientCookieHexLen {
		return c[:clientCookieHexLen]
	}
	return ""
}

// serverCookie is the RFC 7873 server cookie for a client: the first 8 bytes
// of HMAC-SHA256(secret, clientIP || clientCookie), hex-encoded. It is
// deterministic — the same client IP and client cookie always produce the
// same value, so an echoed cookie validates on every later query — and
// binding it to the client IP means a cookie minted for one client is
// useless from another source, which is exactly what makes an off-path
// attacker's spoofed queries fail the BADCOOKIE check.
func (h *Handler) serverCookie(clientIP, clientCookie string) string {
	mac := hmac.New(sha256.New, h.cookieSecret)
	mac.Write([]byte(clientIP))
	mac.Write([]byte(clientCookie))
	return hex.EncodeToString(mac.Sum(nil))[:clientCookieHexLen]
}

// attachCookie returns a copy of m carrying the given COOKIE option (the
// client cookie echoed with the server cookie appended), replacing any
// existing COOKIE option. It copies so the caller's message — a cache hit,
// or resp about to be handed to the background cache writer — is never
// mutated.
func attachCookie(m *dns.Msg, cookie string) *dns.Msg {
	c := m.Copy()
	opt := c.IsEdns0()
	if opt == nil {
		opt = &dns.OPT{Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeOPT}}
		opt.SetUDPSize(udpMaxPacketSize)
		c.Extra = append(c.Extra, opt)
	}
	keep := opt.Option[:0]
	for _, o := range opt.Option {
		if o.Option() != dns.EDNS0COOKIE {
			keep = append(keep, o)
		}
	}
	opt.Option = keep
	opt.Option = append(opt.Option, &dns.EDNS0_COOKIE{Code: dns.EDNS0COOKIE, Cookie: cookie})
	return c
}

// attachEDE returns a copy of m carrying an Extended DNS Error option (RFC
// 8914) with the given info code and human-readable extra text, replacing
// any existing EDE option. Only meaningful for a client that sent its own
// OPT record — callers gate on r.IsEdns0() != nil before calling this, the
// same convention attachCookie's caller uses for the COOKIE option.
func attachEDE(m *dns.Msg, code uint16, extra string) *dns.Msg {
	c := m.Copy()
	opt := c.IsEdns0()
	if opt == nil {
		opt = &dns.OPT{Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeOPT}}
		opt.SetUDPSize(udpMaxPacketSize)
		c.Extra = append(c.Extra, opt)
	}
	keep := opt.Option[:0]
	for _, o := range opt.Option {
		if o.Option() != dns.EDNS0EDE {
			keep = append(keep, o)
		}
	}
	opt.Option = keep
	opt.Option = append(opt.Option, &dns.EDNS0_EDE{InfoCode: code, ExtraText: extra})
	return c
}

// padMessage returns a copy of m padded so its packed length is a multiple
// of block bytes (RFC 7830). Any padding option the message already carries
// (e.g. one forwarded from an upstream) is replaced by a single option that
// lands the total exactly on the boundary. The copy is mandatory: the
// caller's message is often resp about to be cached, and a padded answer
// must not be stored for every other client.
func padMessage(m *dns.Msg, block int) *dns.Msg {
	c := m.Copy()
	c.Compress = true
	opt := c.IsEdns0()
	if opt == nil {
		opt = &dns.OPT{Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeOPT}}
		opt.SetUDPSize(udpMaxPacketSize)
		c.Extra = append(c.Extra, opt)
	}
	keep := opt.Option[:0]
	for _, o := range opt.Option {
		if o.Option() != dns.EDNS0PADDING {
			keep = append(keep, o)
		}
	}
	opt.Option = keep
	// The padding option costs 4 bytes of framing (code + length fields)
	// once added; size its data so the total lands on the boundary.
	base := c.Len() + 4
	if need := block - (base % block); need != block {
		opt.Option = append(opt.Option, &dns.EDNS0_PADDING{Padding: make([]byte, need)})
	}
	return c
}

// write packs m for the client and sends it. DNS message compression
// (RFC 1035 §4.1.4) replaces repeated owner names with pointers to earlier
// occurrences in the message, typically cutting the wire form 20-40% — real
// bandwidth savings on the stream transports (TCP/DoT/DoH/DoQ) and smaller
// UDP datagrams that stay comfortably under the fragmentation threshold.
// Every reply path (rewritten, blocked, cached, upstream, error) funnels
// through here so no response goes out uncompressed.
//
// On UDP the response is also sized to the client's advertised buffer
// (clientUDPSize): an oversized datagram is silently dropped or ignored by
// many stacks, so a legacy 512-byte client must receive a truncated answer
// with the TC bit set (RFC 1035 §4.2.1, RFC 6891) to fall back over TCP —
// the previous code sent the full answer regardless of the client's limit,
// surfacing as silent resolution failures for exactly the clients most
// likely to be older devices. Stream transports have no size limit to
// respect. The truncation runs on a copy, never the caller's message: the
// success path hands resp to the background cache writer right after this,
// and a truncated answer must not poison the shared cache for every other
// client (a small-buffer client would otherwise evict everyone's full
// answer).
//
// With RFC 7830 padding enabled, responses on the encrypted transports
// (DoT/DoH/DoH3/DoQ) are padded to a 128-byte block boundary so message
// lengths don't reveal the query; plain UDP/TCP are never padded. With RFC
// 7873 cookies enabled, a request that carried a COOKIE option gets the
// cookie echoed with our server cookie attached. Padding and cookie
// attachment both run on a copy — the caller's message (resp, a cache hit)
// must never be mutated, for the same reason truncation copies: the success
// path caches resp right after the write, and a padded or cookie-laden
// answer must not be stored for every other client.
func (h *Handler) write(w dns.ResponseWriter, m *dns.Msg, r *dns.Msg, proto string) error {
	m.Compress = true
	// Fast path: pack the response once into a pooled buffer and hand the
	// bytes straight to the transport. This is the every-query path — the
	// old code packed once for the m.Len() size check and again inside
	// WriteMsg (and a third time for a UDP truncation). Only the rare
	// per-client transformations below (an oversized datagram for a
	// small-buffer client, RFC 7830 padding, RFC 7873 cookie attachment)
	// fall back to the decoded-message path, which copies the message so
	// the caller's — resp about to be handed to the background cache
	// writer — is never mutated.
	pad := h.Padding.Load() && (proto == "dot" || proto == "doh" || proto == "doh3" || proto == "doq")
	cookie := h.Cookies.Load() && requestClientCookie(r) != ""
	if !pad && !cookie {
		buf := getPackBuf()
		packed, err := m.PackBuffer(buf)
		if err != nil {
			putPackBuf(buf)
			return err
		}
		if proto != "udp" || len(packed) <= clientUDPSize(r) {
			_, werr := w.Write(packed)
			putPackBuf(packed)
			return werr
		}
		putPackBuf(buf)
	}
	// Slow path: a per-client transformation is needed. Padding only helps
	// where the stream is encrypted anyway — on plain UDP the padded
	// datagram length leaks just as much as the unpadded one, and padding
	// must not inflate a datagram toward the client's buffer limit.
	out := m
	if proto == "udp" {
		if limit := clientUDPSize(r); m.Len() > limit {
			c := m.Copy()
			c.Truncate(limit)
			out = c
		}
	}
	if pad {
		out = padMessage(out, 128)
	}
	if cookie {
		cc := requestClientCookie(r)
		out = attachCookie(out, cc+h.serverCookie(clientIPOf(w.RemoteAddr()), cc))
	}
	return w.WriteMsg(out)
}

// writeRaw serves a cache hit straight from its stored packed bytes,
// skipping the Unpack→re-Pack round trip entirely: the query ID is patched
// (bytes 0-1) and positive-entry answer TTLs are rebased to their remaining
// lifetime at the precomputed byte offsets, all in a private pooled copy
// that is written out and recycled. The stored bytes are never mutated.
//
// The few responses that need a real message fall back to the decoded path
// (write): RFC 7830 padding, RFC 7873 cookie attachment, and a UDP datagram
// that exceeds the client's advertised buffer (truncation needs the RR
// structure). An L2-sourced hit without TTL offsets also decodes — its
// re-warm into L1 records them, so every later hit is raw.
func (h *Handler) writeRaw(w dns.ResponseWriter, res cache.LookupResult, r *dns.Msg, proto string) error {
	raw := res.Raw
	pad := h.Padding.Load() && (proto == "dot" || proto == "doh" || proto == "doh3" || proto == "doq")
	cookie := h.Cookies.Load() && requestClientCookie(r) != ""
	rebaseOK := res.Negative || len(res.TTLOffsets) > 0
	if !rebaseOK || pad || cookie || (proto == "udp" && len(raw) > clientUDPSize(r)) {
		m := res.Msg()
		if m == nil {
			return nil // corrupt entry: answer nothing rather than garbage
		}
		m.Id = r.Id
		return h.write(w, m, r, proto)
	}
	buf := getPackBuf()
	if len(raw) > len(buf) {
		buf = make([]byte, len(raw))
	}
	n := copy(buf, raw)
	// Rebase the query ID to this request's (the stored bytes carry the
	// original query's ID).
	buf[0], buf[1] = byte(r.Id>>8), byte(r.Id)
	if !res.Negative {
		// Rebase every answer TTL to its remaining lifetime, floor 1 so a
		// client never caches a zero-TTL answer as immortal — the same
		// arithmetic unpackEntry performs on the decoded path.
		elapsed := time.Now().Unix() - res.StoredAt
		for _, off := range res.TTLOffsets {
			if int(off)+4 > n {
				break
			}
			ttl := binary.BigEndian.Uint32(buf[off : off+4])
			if elapsed > 0 && ttl > uint32(elapsed) {
				ttl -= uint32(elapsed)
			} else {
				ttl = 1
			}
			binary.BigEndian.PutUint32(buf[off:off+4], ttl)
		}
	}
	_, err := w.Write(buf[:n])
	putPackBuf(buf)
	return err
}

// newReply allocates the empty response skeleton used by the error, NODATA
// and DNSSEC-failure paths: the client's ID, RD/CD flags and first question
// copied, Response and RA set. It is allocated lazily — the fast paths (cache
// hit, blocklist, rewrite answer, successful upstream resolution) never pay
// for it, and most queries are served from one of those.
//
// It draws its *dns.Msg from msgPool, which is safe for every caller — Get
// never has a safety concern, only Put does. Whether a given caller may also
// putMsg it back afterward depends on that call site's own lifetime; see the
// safety comment at each one.
func newReply(r *dns.Msg) *dns.Msg {
	m := getMsg()
	m.SetReply(r)
	m.RecursionAvailable = true
	return m
}

func answerIPs(m *dns.Msg) []net.IP {
	if m == nil {
		return nil
	}
	var ips []net.IP
	for _, rr := range m.Answer {
		switch v := rr.(type) {
		case *dns.A:
			ips = append(ips, v.A)
		case *dns.AAAA:
			ips = append(ips, v.AAAA)
		}
	}
	return ips
}

// cnameCloakCheck evaluates every CNAME hop in an answer against the filter
// engine and returns the first one whose target is blocked (owner name,
// target name, decision). If no hop is blocked, decision.Action is
// filter.Allow.
func cnameCloakCheck(engine *filter.Engine, m *dns.Msg) (owner, target string, decision filter.Decision) {
	if m == nil {
		return "", "", filter.Decision{Action: filter.Allow}
	}
	for _, rr := range m.Answer {
		cname, ok := rr.(*dns.CNAME)
		if !ok {
			continue
		}
		if d := engine.DecideDomain(cname.Target); d.Action == filter.Block {
			return cname.Hdr.Name, cname.Target, d
		}
	}
	return "", "", filter.Decision{Action: filter.Allow}
}

// flightResult is the shared outcome of one coalesced upstream resolution.
// The response is deliberately not exposed to waiters directly: serve() packs
// the message while writing it, and concurrently packing one *dns.Msg from
// several goroutines would race. resolveUpstreams hands every caller its own
// copy instead.
type flightResult struct {
	resp *dns.Msg
	up   string
}

// resolveUpstreams forwards r to the upstream set exactly like
// queryUpstreams, but coalesces concurrent identical questions into a single
// in-flight resolution. When several clients ask the same question at once,
// the first one becomes the leader (running the full queryUpstreams path with
// its context and timeout) and the rest wait on its result — one upstream
// round trip serves the whole burst, cutting both upstream load and the
// waiters' latency. Each caller (leader included) receives its own copy of
// the response with its own message ID, so nothing is shared on the wire.
//
// Queries that can't safely share a resolution bypass the pool entirely (see
// coalesceEligible). Client-group upstream routing is not a merge blocker:
// the answer for a question is the same regardless of which upstream group
// won, and the response cache already serves every client group from the same
// entries.
func (h *Handler) resolveUpstreams(ctx context.Context, r *dns.Msg, q dns.Question, upstreams []*upstream.Upstream, mode string, query *dns.Msg) (*dns.Msg, string, error) {
	if !coalesceEligible(r) {
		return queryUpstreams(ctx, upstreams, mode, query)
	}
	// DoChan (not Do) so a caller whose own deadline expires while waiting
	// on the leader can bail and resolve under its own budget: the leader
	// may be a prefetch or warmer resolution running on a longer context
	// (up to 15s), and a live query must not overrun its own 5s timeout
	// just because it joined a slower leader's flight.
	ch := h.flight.DoChan(flightKey(q), func() (any, error) {
		// One flight per question actually sent upstream: this is the
		// pool's upstream load (the number of real round trips it issued).
		h.Stats.Flights.Add(1)
		resp, up, qerr := queryUpstreams(ctx, upstreams, mode, query)
		return flightResult{resp: resp, up: up}, qerr
	})
	select {
	case res := <-ch:
		fr, ok := res.Val.(flightResult)
		if !ok || res.Err != nil || fr.resp == nil {
			return nil, fr.up, res.Err
		}
		// Shared means this query was served by a flight that multiple
		// callers shared (singleflight marks the leader of a shared flight
		// too) — the pool absorbed this query without its own round trip
		// beyond the one flight.
		if res.Shared {
			h.Stats.Merged.Add(1)
			// Copy per caller: WriteMsg packs the message, and the shared
			// result is one *dns.Msg that several callers would pack
			// concurrently — a race. The shared result's ID also belongs to
			// the leader, so rebase it to this request's ID so a UDP client
			// doesn't silently drop a mismatched-ID response.
			out := fr.resp.Copy()
			out.Id = r.Id
			return out, fr.up, nil
		}
		// No other caller shared this flight: the result is exclusively
		// ours, so take ownership directly — rebase the ID to this request
		// and return it without a copy, skipping the allocation the shared
		// path must pay.
		fr.resp.Id = r.Id
		return fr.resp, fr.up, nil
	case <-ctx.Done():
		// Deadline expired while waiting on the leader: return the timeout
		// without re-querying. A dead-context query would fail instantly and
		// blame the upstream for a caller-side deadline — counting a
		// circuit-breaker failure per bailed waiter — even though the
		// upstream may be perfectly healthy (just slower than our budget).
		return nil, "", ctx.Err()
	}
}

// coalesceEligible reports whether r's question may be merged with an
// identical question from another client. Plain recursive lookups are
// interchangeable; anything whose answer could legitimately differ between
// senders — RD=0 probes, CD-set queries (DNSSEC client semantics travel in
// the flags), meta queries (AXFR/ANY...) and messages carrying TSIG or other
// non-OPT additional records — resolves on its own.
func coalesceEligible(r *dns.Msg) bool {
	if !r.RecursionDesired || r.CheckingDisabled {
		return false
	}
	// Exactly one question: a degenerate multi-question message shares only
	// its first question with an identical-looking query from another client
	// and must never merge (its additional questions would be lost).
	if len(r.Question) != 1 || isMetaQuery(r.Question[0]) {
		return false
	}
	for _, rr := range r.Extra {
		if rr.Header().Rrtype != dns.TypeOPT {
			return false
		}
	}
	return true
}

// flightKey is the coalescing key: the canonical lowercased question. DNS
// names are case-insensitive, so the key must be canonicalised or two
// clients spelling the same name differently would resolve twice.
func flightKey(q dns.Question) string {
	var b strings.Builder
	b.Grow(len(q.Name) + 8)
	for _, c := range q.Name {
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		b.WriteRune(c)
	}
	b.WriteByte('|')
	b.WriteString(strconv.Itoa(int(q.Qtype)))
	b.WriteByte('|')
	b.WriteString(strconv.Itoa(int(q.Qclass)))
	return b.String()
}

// cooldownLogInterval throttles the "in failure cooldown" log lines below to
// at most once per interval — the only place a total-cooldown outage
// becomes visible outside the dashboard's per-query log (queryUpstreams's
// early returns bypass raceUpstreams/sequentialUpstreams's own "all
// upstreams failed" log entirely, since no upstream is even attempted), so
// it must not stay silent — but it also must not flood the log once per
// query at real query volume during a sustained outage.
const cooldownLogInterval = 5 * time.Second

// lastCooldownLog is the last time logCooldownOnce actually emitted a line.
var lastCooldownLog atomic.Int64

// logCooldownOnce logs msg at most once per cooldownLogInterval.
func logCooldownOnce(msg string, args ...any) {
	now := time.Now().UnixNano()
	last := lastCooldownLog.Load()
	if now-last < int64(cooldownLogInterval) {
		return
	}
	if lastCooldownLog.CompareAndSwap(last, now) {
		slog.Error(msg, args...)
	}
}

// queryUpstreams forwards r to the upstream set according to the resolution
// strategy (mode). A single upstream is queried directly to avoid goroutine
// overhead. With several, UpstreamModeRace races them all concurrently (first
// success wins) and UpstreamModeSequential tries them in list order, failing
// over to the next on error or SERVFAIL. Upstreams whose circuit breaker is
// open (consecutive failures inside the cooldown window) are skipped in the
// multi-upstream modes so a dead server can't burn its full timeout on every
// query; a single upstream in cooldown fails fast into serve-stale/SERVFAIL
// below.
func queryUpstreams(ctx context.Context, upstreams []*upstream.Upstream, mode string, r *dns.Msg) (*dns.Msg, string, error) {
	if mode == "" {
		mode = UpstreamModeRace
	}
	if len(upstreams) == 1 {
		u := upstreams[0]
		if !u.Available() {
			logCooldownOnce("upstream in failure cooldown, query refused", "upstream", u.Name())
			return nil, u.Name(), fmt.Errorf("upstream %s in failure cooldown", u.Name())
		}
		resp, err := u.Query(ctx, r)
		if err != nil {
			slog.Error("upstream failed", "upstream", u.Name(), "error", err)
			return nil, "", err
		}
		return resp, u.Name(), nil
	}
	avail := make([]*upstream.Upstream, 0, len(upstreams))
	for _, u := range upstreams {
		if u.Available() {
			avail = append(avail, u)
		}
	}
	if len(avail) == 0 {
		logCooldownOnce("all upstreams in failure cooldown, query refused", "upstreams", len(upstreams))
		return nil, "", fmt.Errorf("all upstreams in failure cooldown")
	}
	if mode == UpstreamModeSequential {
		return sequentialUpstreams(ctx, avail, r)
	}
	return raceUpstreams(ctx, avail, r)
}

// sequentialUpstreams tries each upstream in list order and returns the first
// real answer — classic failover. A SERVFAIL answer counts as a failure and
// moves on to the next upstream (that's the point: a primary that is
// SERVFAILing must not mask a working backup); if every upstream fails or
// SERVFAILs, the last SERVFAIL response is returned so the caller can serve
// stale / cache the failure exactly as it would for a single upstream that
// answered SERVFAIL.
//
// ctx's remaining deadline is split evenly across the upstreams still to be
// tried, via a fresh sub-context per attempt. Without this, one upstream
// that fails slowly (e.g. a TCP/TLS dial that hangs until the timeout
// instead of refusing instantly) can consume the entire per-query budget:
// by the time the loop reached the next upstream, ctx.Err() was already
// non-nil and the "if ctx.Err() != nil { break }" check below silently
// stopped the failover after just one attempt — "sequential" mode
// degrading to "only the first upstream" whenever that upstream failed
// slowly rather than instantly. Splitting the budget guarantees every
// remaining upstream gets a fair share of the time left to answer.
func sequentialUpstreams(ctx context.Context, ups []*upstream.Upstream, r *dns.Msg) (*dns.Msg, string, error) {
	var (
		lastErr    error
		lastFail   *dns.Msg
		lastFailUp string
	)
	for i, up := range ups {
		if ctx.Err() != nil {
			break
		}
		// One query message is reused across attempts: miekg/dns's
		// ExchangeContext writes it as-is and matches the reply by the
		// unchanged ID — it never rewrites msg.Id — and Pack is safe to call
		// repeatedly on a single message. The per-attempt Copy() the
		// previous code made only mattered for race mode's concurrent
		// sends; here the message belongs to this loop for its whole run.
		attemptCtx := ctx
		cancel := func() {}
		if deadline, ok := ctx.Deadline(); ok {
			if remaining := len(ups) - i; remaining > 1 {
				if share := time.Until(deadline) / time.Duration(remaining); share > 0 {
					attemptCtx, cancel = context.WithTimeout(ctx, share)
				}
			}
		}
		resp, err := up.Query(attemptCtx, r)
		cancel()
		if err != nil {
			lastErr = err
			continue
		}
		if resp == nil {
			lastErr = fmt.Errorf("upstream %s returned no response", up.Name())
			continue
		}
		if resp.Rcode == dns.RcodeServerFailure {
			lastFail, lastFailUp = resp, up.Name()
			lastErr = fmt.Errorf("upstream %s answered SERVFAIL", up.Name())
			continue
		}
		return resp, up.Name(), nil
	}
	if lastFail != nil {
		return lastFail, lastFailUp, nil
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no upstream returned a response")
	}
	slog.Error("all upstreams failed", "error", lastErr)
	return nil, "", lastErr
}

// raceUpstreams queries every upstream concurrently and returns the first
// successful response, hiding slow or down upstreams behind the fastest one.
// On success the shared context is cancelled so the losing queries abort
// instead of burning the full timeout. Each goroutine performs exactly one
// send into a channel buffered for every upstream, so nothing leaks.
func raceUpstreams(ctx context.Context, ups []*upstream.Upstream, r *dns.Msg) (*dns.Msg, string, error) {
	qctx, qcancel := context.WithCancel(ctx)
	defer qcancel()
	type result struct {
		resp *dns.Msg
		up   string
		err  error
	}
	ch := make(chan result, len(ups))
	for _, up := range ups {
		go func() {
			// The collector loop below always waits for exactly len(ups)
			// sends, so a panicked goroutine must still send a result (a
			// synthetic error) or the loop blocks forever — recovering
			// without this would trade a process crash for a goroutine and
			// query hang instead.
			defer func() {
				if rec := recover(); rec != nil {
					slog.Error("recovered panic querying upstream", "upstream", up.Name(), "panic", rec, "stack", string(debug.Stack()))
					ch <- result{err: fmt.Errorf("panic querying upstream %s: %v", up.Name(), rec)}
				}
			}()
			// Copy the query per upstream: each concurrent send must own the
			// message it hands the transport — sending can mutate the message
			// (TSIG signing does, and a library bump could change what the
			// transport rewrites), so a shared *dns.Msg would race, and each
			// reply must match the query its own conn sent. Sequential mode
			// reuses one message instead (see sequentialUpstreams).
			resp, err := up.Query(qctx, r.Copy())
			ch <- result{resp: resp, up: up.Name(), err: err}
		}()
	}
	var lastErr error
	for range len(ups) {
		res := <-ch
		if res.err == nil && res.resp != nil {
			return res.resp, res.up, nil
		}
		if res.err != nil {
			lastErr = res.err
		}
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no upstream returned a response")
	}
	// Log only when the whole query failed. In a healthy race the losing
	// upstreams routinely report transport hiccups (a stale pooled
	// connection, a momentary timeout) while another wins — logging each of
	// those per query turns a single degraded upstream into log spam. Each
	// upstream's health stays visible through the circuit breaker on the
	// dashboard's Upstreams card.
	slog.Error("all upstreams failed", "error", lastErr)
	return nil, "", lastErr
}

// resolveAndCache re-resolves q through the current upstreams and re-caches
// the result (positive or negative). It is shared by the cache's prefetch
// callback (Refresh) and the proactive cache warmer, so both mechanisms
// resolve through the exact same path — snapshotting the hot-swappable
// upstreams and cache at call time.
func (h *Handler) resolveAndCache(ctx context.Context, q dns.Question) error {
	s := h.settings.Load()
	ups := s.Upstreams
	routes := s.UpstreamRoutes
	cache := s.Cache
	mode := s.UpstreamMode
	// Conditional routes apply to background resolutions too: a prefetched
	// or warmed question under a routed subtree must resolve through the
	// same upstreams a live query would use, or the cached entry could
	// disagree with the route's split-horizon answer.
	if rt := routeMatch(routes, dnsname.CanonicalDomain(q.Name)); rt != nil && len(rt.Upstreams) > 0 {
		ups = rt.Upstreams
	}
	if len(ups) == 0 {
		return fmt.Errorf("no upstreams configured")
	}
	if cache == nil {
		return fmt.Errorf("no cache configured")
	}
	m := new(dns.Msg)
	m.SetQuestion(q.Name, q.Qtype)
	m.RecursionDesired = true
	// The same strategy the query path uses (race by default) applies to
	// prefetch and warmer resolutions, so a sequential-mode deployment
	// always talks to the primary first, never fanning out. These also run
	// through the same in-flight request pool as live queries, so a
	// background refresh that overlaps a client's query (or another
	// background refresh) shares one upstream round trip instead of
	// doubling it.
	resp, _, err := h.resolveUpstreams(ctx, m, q, ups, mode, m)
	if err != nil {
		return err
	}
	if resp == nil {
		return fmt.Errorf("upstream returned no response")
	}
	// The cache write is bounded like the handler's hot path (3s): the
	// caller's context may be the warmer's whole pass, and a stuck
	// Dragonfly must not be able to block a worker (or a prefetch) behind
	// it — the entry is disposable either way.
	wctx, wcancel := context.WithTimeout(ctx, 3*time.Second)
	defer wcancel()
	if len(resp.Answer) > 0 {
		cache.Set(wctx, q, resp, 0)
	} else {
		cache.SetNegative(wctx, q, resp, 0)
	}
	return nil
}

// Refresh re-resolves q via the current upstreams and re-caches the result.
// It is the cache's prefetch callback: invoked in the background for hot
// entries near the end of their lifetime so the next query finds a fresh
// answer instead of paying an upstream round trip. Best-effort — failures
// are dropped (the entry is expiring anyway and the normal resolution path
// handles the next query).
func (h *Handler) Refresh(ctx context.Context, q dns.Question) {
	_ = h.resolveAndCache(ctx, q)
}

// staleServeTTL caps the TTLs of a serve-stale answer (RFC 8767 section 5:
// stale answers should carry a small TTL so clients re-resolve quickly).
const staleServeTTL = 30

// dhcpHostTTL is the TTL on DHCP-registered hostname answers: short so a
// client that re-negotiates a different address is re-resolved quickly, long
// enough that LAN lookups are cheap.
const dhcpHostTTL = 120

// reverseNameIP parses an in-addr.arpa or ip6.arpa name back into the IP
// address it encodes, or nil when the name isn't a well-formed reverse
// zone (only full 4-octet IPv4 and full 32-nibble IPv6 names are accepted,
// so a query for a /24 reverse zone or a random name falls through).
func reverseNameIP(name string) net.IP {
	n := dnsname.CanonicalDomain(name)
	if before, ok := strings.CutSuffix(n, ".in-addr.arpa"); ok {
		octets := strings.Split(before, ".")
		if len(octets) != 4 {
			return nil
		}
		var b [4]byte
		for i := range 4 {
			v, err := strconv.Atoi(octets[3-i]) // labels are least-significant first
			if err != nil || v < 0 || v > 255 {
				return nil
			}
			b[i] = byte(v)
		}
		return net.IPv4(b[0], b[1], b[2], b[3])
	}
	if before, ok := strings.CutSuffix(n, ".ip6.arpa"); ok {
		nibbles := strings.Split(before, ".")
		if len(nibbles) != 32 {
			return nil
		}
		var b [16]byte
		for i := range 32 {
			v, err := strconv.ParseUint(nibbles[31-i], 16, 4) // nibbles are least-significant first
			if err != nil {
				return nil
			}
			if i%2 == 0 {
				b[i/2] = byte(v) << 4
			} else {
				b[i/2] |= byte(v)
			}
		}
		return net.IP(b[:])
	}
	return nil
}

// ednsUDPSize is the UDP payload size advertised on outgoing upstream
// queries: the DNS Flag Day 2020 recommended 1232 bytes, the largest value
// that fits every common path MTU without IP fragmentation (1280-byte IPv6
// minimum minus 48 bytes of IP/UDP/DNS headers). Bigger answers flow over
// the TCP fallback instead of being dropped as fragments.
// maxCacheWriters caps how many background cache-write goroutines (Set /
// SetNegative on the success and failure paths) may be in flight at once;
// further writes are skipped until a slot frees. Sized well above the
// sustained miss rates a busy resolver sees, so it only ever bounds a flood.
const maxCacheWriters = 64

// maxASNCache bounds the per-client ASN memo (see Handler.asnCache). When
// full it resets — attribution is cheap to recompute for a few clients.
const maxASNCache = 4096

const ednsUDPSize = 1232

// anyMinimalTTL is the TTL on the synthetic HINFO record returned for
// QTYPE=ANY (RFC 8482). Short-lived: it's not real data, just a marker, so
// there's no reason for a resolver downstream of us to hold onto it.
const anyMinimalTTL = 60

// capTTL floors every record's TTL at max across Answer, Ns and Extra — a
// stale negative answer's SOA in the Authority section would otherwise let a
// client cache the negative for its original (long) TTL. The OPT pseudo-
// record in the additional section is skipped: its TTL field carries
// extended-rcode / version / DO flags, not a lifetime, and rewriting it
// would corrupt those flags.
func capTTL(m *dns.Msg, max uint32) {
	for _, rr := range m.Answer {
		if rr.Header().Ttl > max {
			rr.Header().Ttl = max
		}
	}
	for _, rr := range m.Ns {
		if rr.Header().Ttl > max {
			rr.Header().Ttl = max
		}
	}
	for _, rr := range m.Extra {
		if _, ok := rr.(*dns.OPT); ok {
			continue
		}
		if rr.Header().Ttl > max {
			rr.Header().Ttl = max
		}
	}
}

// latencyHist estimates response-time percentiles from a fixed set of
// millisecond buckets (powers of two, plus an overflow bucket), so the
// dashboard's Performance card gets p50/p95/p99 without scanning the query
// log or holding locks on the hot path — recording a query is one atomic add.
type latencyHist struct {
	// bucket i (i>=1) covers (2^(i-1), 2^i] ms; bucket 0 covers exactly 0ms
	// (a sub-millisecond response); the last bucket absorbs everything above
	// it.
	buckets [12]atomic.Int64
	total   atomic.Int64
}

func (h *latencyHist) record(d time.Duration) {
	i := bits.Len64(uint64(d.Milliseconds())) // 0 for 0ms; upper bound of bucket i is 2^i ms
	if i >= len(h.buckets) {
		i = len(h.buckets) - 1
	}
	h.buckets[i].Add(1)
	h.total.Add(1)
}

// pct returns the estimated response time (ms) at percentile p (0..100),
// or 0 when nothing has been recorded. Values are bucket upper bounds — an
// estimate, not an exact quantile.
func (h *latencyHist) pct(p float64) float64 {
	total := h.total.Load()
	if total == 0 {
		return 0
	}
	target := int64(float64(total) * p / 100)
	var seen int64
	last := -1 // highest bucket observed so far
	for i := range len(h.buckets) {
		n := h.buckets[i].Load()
		seen += n
		if n > 0 {
			last = i
		}
		if seen > target {
			if i == 0 {
				return 1
			}
			if i == len(h.buckets)-1 {
				return float64(int(1) << (i + 1)) // overflow: at least 2^(i+1) ms
			}
			return float64(int(1) << i)
		}
	}
	// Nothing crossed the target: either p == 100 (target == total, so the
	// top populated bucket is the answer) or the atomic snapshot caught
	// total just ahead of a concurrent record's bucket add. Estimate from
	// the highest populated bucket rather than a hardcoded overflow
	// constant, so a benign snapshot race can't paint a phantom 4s tail on
	// an otherwise fast server.
	if last <= 0 {
		return 1
	}
	if last == len(h.buckets)-1 {
		return float64(int(1) << (last + 1))
	}
	return float64(int(1) << last)
}

// LatencySummary is the dashboard Performance card's data: response-time
// percentiles (ms, estimated from the in-process histogram) since the
// process started.
type LatencySummary struct {
	Count int64   `json:"count"`
	P50   float64 `json:"p50"`
	P95   float64 `json:"p95"`
	P99   float64 `json:"p99"`
}

// LatencySummary returns the recorded percentiles since process start.
func (h *Handler) LatencySummary() LatencySummary {
	return LatencySummary{
		Count: h.latency.total.Load(),
		P50:   h.latency.pct(50),
		P95:   h.latency.pct(95),
		P99:   h.latency.pct(99),
	}
}

// UpstreamHealth is one upstream's circuit-breaker state for the dashboard's
// Upstreams card.
type UpstreamHealth struct {
	Name      string `json:"name"`
	Transport string `json:"transport"`
	// Fails is the consecutive-failure count driving the circuit breaker.
	Fails int64 `json:"fails"`
	// Available is false only while the circuit is open (circuitOpenFails+
	// consecutive failures inside the cooldown window).
	Available bool `json:"available"`
	// CooldownUntil is when an open circuit re-arms; nil when closed.
	CooldownUntil *time.Time `json:"cooldown_until,omitempty"`
	// Recursive reports whether this upstream resolves iteratively from the
	// root servers rather than forwarding.
	Recursive bool `json:"recursive"`
}

// UpstreamHealth snapshots the current upstream set's circuit state.
func (h *Handler) UpstreamHealth() []UpstreamHealth {
	ups := h.settings.Load().Upstreams
	out := make([]UpstreamHealth, 0, len(ups))
	for _, u := range ups {
		out = append(out, UpstreamHealth{
			Name:          u.Name(),
			Transport:     string(u.Transport),
			Fails:         u.Fails(),
			Available:     u.Available(),
			CooldownUntil: u.CooldownUntil(),
			Recursive:     u.Transport == upstream.Recursive,
		})
	}
	return out
}

func isMetaQuery(q dns.Question) bool {
	switch q.Qtype {
	case dns.TypeAXFR, dns.TypeIXFR, dns.TypeOPT, dns.TypeTSIG, dns.TypeANY:
		return true
	}
	return false
}

func clientIPOf(addr net.Addr) string {
	if addr == nil {
		return ""
	}
	// Fast path: every socket transport hands us a *net.UDPAddr (the custom
	// UDP worker) or *net.TCPAddr (TCP/DoT), and formatting the IP directly
	// skips the String() + SplitHostPort round trip — addr.String() builds
	// the full "ip:port" (allocating net.IPv4 + IP.String + JoinHostPort)
	// only to have SplitHostPort slice the port back off. Measured ~250ns/3
	// allocs vs ~80ns/1 alloc per query, and this runs on every query from
	// every socket transport.
	switch a := addr.(type) {
	case *net.UDPAddr:
		return a.IP.String()
	case *net.TCPAddr:
		return a.IP.String()
	}
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return addr.String()
	}
	return host
}
