// Package dnsserver implements every DNS listener (UDP, TCP, DoT, DoH, DoQ)
// plus the shared query handler that applies filtering, caching, forwarding
// and logging.
package dnsserver

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"log/slog"
	"net"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"

	"github.com/eoghan2t9/Irongrid-DNS/internal/vpn"
	"golang.org/x/sync/singleflight"

	"github.com/eoghan2t9/Irongrid-DNS/internal/cache"
	"github.com/eoghan2t9/Irongrid-DNS/internal/dnsname"
	"github.com/eoghan2t9/Irongrid-DNS/internal/dnssec"
	"github.com/eoghan2t9/Irongrid-DNS/internal/filter"
	"github.com/eoghan2t9/Irongrid-DNS/internal/geoip"
	"github.com/eoghan2t9/Irongrid-DNS/internal/querylog"
	"github.com/eoghan2t9/Irongrid-DNS/internal/tuning"
	"github.com/eoghan2t9/Irongrid-DNS/internal/upstream"
)

// Upstream resolution strategies for multiple upstreams (config
// upstream_mode). Race (default) queries every available upstream
// concurrently and uses the fastest successful answer; sequential tries them
// in list order, failing over to the next only when the previous errors or
// answers SERVFAIL; round-robin load-balances, sending each query to the next
// upstream in turn (and failing over to the following ones if it errors or
// answers SERVFAIL).
const (
	UpstreamModeRace       = "race"
	UpstreamModeSequential = "sequential"
	UpstreamModeRoundRobin = "roundrobin"
)

// rrCounter drives round-robin rotation: every query advances it by one, so
// consecutive queries start on consecutive upstreams. It is process-wide
// rather than per-handler, which keeps the spread even across client groups
// that share the same upstream list.
var rrCounter atomic.Uint64

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
	// DNSSECValidator performs opportunistic local DNSSEC chain-of-trust
	// validation (set at boot; never swapped — it owns its own long-lived
	// per-zone key cache). Whether it's actually consulted per query is
	// the hot-swappable dnssec.validate_locally setting; see
	// SetDNSSECValidateLocally and handlerSettings.DNSSECValidateLocally.
	DNSSECValidator *dnssec.Validator

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
	// ddr is the Discovery of Designated Resolvers (RFC 9462) configuration
	// answered for _dns.resolver.arpa. Set via SetDDR; nil advertises nothing.
	ddr atomic.Pointer[DDRConfig]
	// vpnRouter is the optional domain-based VPN split-tunnel manager; nil
	// (the default) disables the hook entirely. Set via SetVPNRouter. Its
	// Observe method is called directly from write() on every response, so
	// it must never block — see internal/vpn's Manager doc comment.
	vpnRouter atomic.Pointer[vpn.Manager]
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
	UpstreamMode string // "race", "sequential" or "roundrobin" (see UpstreamMode*)
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
	RepeatGuard  *RepeatGuard     // nil disables the repeat-query flood guard
	Geo          *geoip.Blocker   // nil disables geo-blocking
	IPBanner     *geoip.Banner    // nil disables IP/honeypot blocking
	// ACL is the server.allow_from query allow-list; nil permits every
	// client (the default, backward-compatible behavior).
	ACL *ACL
	// UpstreamHealthCheck gates proactive upstream health probing
	// (upstream_health.enabled); see StartUpstreamHealthCheck.
	UpstreamHealthCheck bool
	// DNSSECValidateLocally gates whether Handler.DNSSECValidator is
	// actually consulted per query (dnssec.validate_locally).
	DNSSECValidateLocally bool
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
	// RepeatQueryBlockFor is how long a client that trips the repeat-query
	// flood guard (RepeatGuard) is blocked when its source is trusted — a
	// real handshake (TCP/DoT/DoH/DoQ) or the TrustUDP opt-in. Does nothing
	// unless RepeatGuard is installed.
	RepeatQueryBlockFor time.Duration
	// RepeatQueryUDPBlockFor is the bounded middle ground for a plain-UDP
	// source that trips the repeat-query flood guard: blocked for this
	// window instead of RepeatQueryBlockFor, mirroring HoneypotUDPBlock's
	// rationale (a spoofed source must only ever earn a bounded block).
	// Zero means an untrusted UDP source is never blocked by this guard.
	RepeatQueryUDPBlockFor time.Duration
	DNSSECEnabled          bool
	DNSSECRequireAD        bool
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

func (h *Handler) serve(w dns.ResponseWriter, r *dns.Msg, client, proto string) {
	sw := getStatsWriter(w, &h.Stats.WriteErrors)
	w = sw
	// retained is set when a goroutine outlives serve() still holding w; the
	// wrapper must then not be recycled. Registered before the recover defer
	// below so it runs after it (which still writes through w).
	retained := false
	defer func() {
		if !retained {
			putStatsWriter(sw)
		}
	}()
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
	cch := s.Cache
	rewriter := s.Rewriter
	clientRouter := s.ClientRouter
	rateLimiter := s.RateLimiter
	nxGuard := s.NXGuard
	repeatGuard := s.RepeatGuard
	repeatQueryBlockFor := s.RepeatQueryBlockFor
	repeatQueryUDPBlockFor := s.RepeatQueryUDPBlockFor
	geo := s.Geo
	ipbanner := s.IPBanner
	acl := s.ACL
	trustUDP := s.TrustUDP
	honeypotUDPBlock := s.HoneypotUDPBlock
	dnssecEnabled := s.DNSSECEnabled
	cookiesOn := h.Cookies.Load()

	if r == nil || len(r.Question) == 0 {
		m := getMsg()
		m.Response = true
		m.Rcode = dns.RcodeFormatError
		_ = h.write(w, m, r, proto)
		putMsg(m)
		return
	}

	// 0.05 Query ACL (server.allow_from): an unlisted client is REFUSED
	//    before any other work — including the rate limiter and NXGuard —
	//    so an unauthorized client can never consume those budgets either.
	//    A nil ACL (the default, nothing configured) allows every client,
	//    unchanged from prior behavior.
	if acl != nil && client != "" && !acl.Allowed(client) {
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
	// 0.15 Repeat-query flood guard: a client currently blocked for
	//    hammering one domain is refused the same way as a rate-limited or
	//    NXDOMAIN-flooding client.
	if repeatGuard != nil && !repeatGuard.Allow(client) {
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

	// 0.52 Repeat-query flood detection: a client resolving the *same*
	//    domain over and over at a rapid pace looks like it's using this
	//    resolver to flood/DDoS that domain rather than browsing normally —
	//    ordinary browsing moves between many names, so only a same-domain
	//    streak trips this. The triggering query itself is answered
	//    normally; only *subsequent* queries are refused, via the Allow
	//    check above. A query's source is spoofable over plain UDP, so a
	//    verified transport (or the trust_udp opt-in) earns the configured
	//    RepeatQueryBlockFor while a plain-UDP source only ever earns the
	//    bounded RepeatQueryUDPBlockFor (0 disables blocking it at all) —
	//    the same trust tiering the honeypot path uses. Also mirrored into
	//    the rate limiter (when installed) purely so the block shows up on
	//    the dashboard's existing blocked-clients list.
	if repeatGuard != nil && client != "" && repeatGuard.NoteQuery(client, qname) {
		trusted := proto == "tcp" || proto == "dot" || proto == "doh" || proto == "doq"
		var blockDur time.Duration
		switch {
		case trusted || trustUDP:
			blockDur = repeatQueryBlockFor
		case repeatQueryUDPBlockFor > 0:
			blockDur = repeatQueryUDPBlockFor
		}
		if blockDur > 0 {
			repeatGuard.ForceBlock(client, blockDur)
			if rateLimiter != nil {
				rateLimiter.ForceBlock(client, blockDur)
			}
		}
	}

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

	// 0.9 Discovery of Designated Resolvers (RFC 9462): _dns.resolver.arpa is
	//    answered locally and never forwarded or filtered — an upstream's own
	//    designation would point clients past this server, and the name must
	//    not be subject to blocklists. It sits behind the ACL, rate limit and
	//    client-blocking checks above, so an unauthorized client gets nothing.
	if isDDRQuery(qname) {
		h.Stats.Allowed.Add(1)
		m := ddrAnswer(r, q, h.ddr.Load(), ddrLocalIP(w.LocalAddr(), client))
		h.record(client, qname, q, "rewrite", "ddr", "", start, m)
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

	// 1.4 Domain-based VPN "Smart DNS" proxy routes: a Proxy-enabled
	//     vpn.routes domain whose profile is currently connected answers
	//     with this server's own IP instead of the real one, so the
	//     client's connection lands on the SNI/Host relay (internal/vpn's
	//     Relay) instead — see config.VPNProxyConfig. Checked before DHCP
	//     hostnames since it's an explicit routing decision, same rank as
	//     the local-DNS-records check just above.
	if ans := h.tryProxyAnswer(r, q); ans != nil {
		h.Stats.Allowed.Add(1)
		h.record(client, qname, q, "rewrite", "vpn-proxy", "", start, ans)
		_ = h.write(w, ans, r, proto)
		putMsg(ans)
		return
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
		// A stale entry is kept as the serve-stale fallback only when it
		// holds real data. A stale cached SERVFAIL (a dead domain's
		// negatively-cached failure) protects nothing: keeping it made every
		// retry re-resolve upstream and then answer from the stale SERVFAIL
		// without ever refreshing it, for the whole stale window. Dropping it
		// lets the retry resolve once and cache the fresh result, so the
		// retries after it are plain cache hits. (A stale NXDOMAIN/NODATA is
		// real data and is still kept.)
		if len(hit.Raw) > 0 && !(hit.Negative && packedRcode(hit.Raw) == dns.RcodeServerFailure) {
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
	// Fresh transaction ID per upstream hop (crypto/rand-backed, dns.Id()):
	// forwarding the client's own ID unchanged means an off-path attacker
	// who already knows/guesses the client's ID (weak stub resolvers exist)
	// gets it for free against the upstream hop too. Meaningful mainly for
	// a plain UDP/TCP upstream — DoT/DoH/DoQ already can't be blindly
	// spoofed. The response's ID is remapped back to the client's own
	// before it's ever written out (see the resp.Id reset below), so this
	// is invisible to the client.
	upstreamQuery.Id = dns.Id()

	// No stale entry to race against (the overwhelmingly common case): there
	// is nothing to select on, so resolve inline instead of paying for a
	// goroutine, a channel and a result struct on every cache miss. Running
	// on serve()'s own goroutine also puts resolveUpstreams under serve()'s
	// panic recovery. resolveUpstreams is unchanged, still governed by
	// ctx's deadline.
	if len(stale.Raw) == 0 {
		defer cancel()
		resp, usedUp, err := h.resolveUpstreams(ctx, r, q, upstreams, upstreamMode, upstreamQuery)
		h.finishResolve(w, r, q, client, qname, proto, start, resp, usedUp, err, stale, s, engine, domainWhitelisted, false)
		return
	}

	// Serve-stale race (RFC 8767): a client shouldn't wait nearly as long for
	// a resolution attempt as it would with no cache at all when a
	// perfectly-serviceable (if expired) answer already sits in cache —
	// that defeats the resiliency RFC 8767 exists for. Resolve on its own
	// goroutine so it can race staleGrace below instead of always waiting
	// the full timeout out. If the upstream hasn't answered in time, serve
	// the stale answer now and let the resolution keep running:
	// finishResolve still applies to whatever it eventually returns
	// (DNSSEC/blocking/caching), just without writing to the client a second
	// time (skipWrite) — so the cache still benefits from a fresh answer, or
	// a genuine failure still gets logged, even though the client already
	// has its response.
	type resolveOutcome struct {
		resp   *dns.Msg
		usedUp string
		err    error
	}
	resCh := make(chan resolveOutcome, 1)
	go func() {
		resp, usedUp, err := h.resolveUpstreams(ctx, r, q, upstreams, upstreamMode, upstreamQuery)
		resCh <- resolveOutcome{resp, usedUp, err}
	}()
	timer := time.NewTimer(staleGrace(timeout))
	select {
	case out := <-resCh:
		timer.Stop()
		cancel()
		h.finishResolve(w, r, q, client, qname, proto, start, out.resp, out.usedUp, out.err, stale, s, engine, domainWhitelisted, false)
	case <-timer.C:
		if m := stale.Msg(); m != nil {
			m.Id = r.Id
			capTTL(m, staleServeTTL)
			h.Stats.Cached.Add(1)
			h.record(client, qname, q, "cached", "stale", "", start, m)
			out := m
			if r.IsEdns0() != nil {
				out = attachEDE(m, dns.ExtendedErrorCodeStaleAnswer, "")
			}
			_ = h.write(w, out, r, proto)
			putMsg(m) // fresh per-read decode, safe once written
		}
		retained = true // this goroutine keeps using w after serve() returns
		go func() {
			defer recoverPanic("background stale-race resolve")
			defer cancel()
			out := <-resCh
			h.finishResolve(w, r, q, client, qname, proto, start, out.resp, out.usedUp, out.err, stale, s, engine, domainWhitelisted, true)
		}()
	}
}

// staleGrace bounds how long serve() waits for a fresh upstream answer
// before falling back to an available stale cache entry: half the
// configured upstream timeout, capped at 2s, so a slow-or-down upstream
// can't make a client wait nearly as long as if no stale answer existed at
// all. Config validation enforces timeout >= 1s, so this is never below
// 500ms.
func staleGrace(timeout time.Duration) time.Duration {
	return min(timeout/2, 2*time.Second)
}

// finishResolve is serve()'s continuation once an upstream resolution
// outcome (resp/usedUp/err) is available: NXDOMAIN flood counting,
// serve-stale on failure, DNSSEC enforcement, IP/CNAME-cloaking blocking,
// the client write, and the background cache write. Runs synchronously
// from serve() in the common case. When the serve-stale race above already
// wrote a fast stale answer to the client, it instead runs from its own
// goroutine (own panic recovery — serve()'s top-level recover only covers
// serve()'s own goroutine) with skipWrite set: every write below becomes a
// no-op, but Stats/query-log and the cache write still run, so the cache
// benefits from whatever the resolution found and the log reflects it —
// meaning one client query can produce two log entries/stats increments in
// the raced case (a deliberate trade-off, not a bug: the alternative is a
// log that doesn't show a background refresh happened at all).
func (h *Handler) finishResolve(
	w dns.ResponseWriter, r *dns.Msg, q dns.Question, client, qname, proto string, start time.Time,
	resp *dns.Msg, usedUp string, err error, stale cache.LookupResult,
	s *handlerSettings, engine *filter.Engine, domainWhitelisted, skipWrite bool,
) {
	upstreams := s.Upstreams
	blockResp := s.BlockResponse
	blockTTL := s.BlockTTL
	failureTTL := s.FailureTTL
	cch := s.Cache
	nxGuard := s.NXGuard
	dnssecEnabled := s.DNSSECEnabled
	dnssecRequireAD := s.DNSSECRequireAD
	dnssecValidateLocally := s.DNSSECValidateLocally
	cnameCloakingEnabled := s.CNAMECloakingProtection

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
			if !skipWrite {
				_ = h.write(w, out, r, proto)
			}
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
				if !skipWrite {
					_ = h.write(w, out, r, proto)
				}
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
		if !skipWrite {
			_ = h.write(w, out, r, proto)
		}
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

	// 6. DNSSEC enforcement.
	if dnssecEnabled {
		// 6a. Local chain-of-trust validation (dnssec.validate_locally):
		//    real cryptographic verification up to a trust anchor, not
		//    just trusting the upstream's AD bit — catches a compromised
		//    or lying upstream that sets AD=1 on a tampered answer, which
		//    the plain AD-bit check below can never detect. Only acts on
		//    a signed answer (the upstream returned RRSIG because the DO
		//    bit was set); an unsigned zone — the vast majority of the
		//    internet — falls straight through to 6b unchanged.
		if dnssecValidateLocally && h.DNSSECValidator != nil {
			if up := upstreamByName(upstreams, usedUp); up != nil {
				vctx, vcancel := context.WithTimeout(context.Background(), dnssecValidateTimeout)
				secure, signed, verr := h.DNSSECValidator.Validate(vctx, up, resp)
				vcancel()
				switch {
				case verr != nil:
					// Couldn't complete the check (a DNSKEY/DS lookup
					// failed or timed out) — an infrastructure hiccup,
					// not evidence the answer is bad. Fail open to 6b.
					slog.Debug("dnssec: local validation incomplete, falling back to AD-bit trust", "qname", qname, "error", verr)
				case signed && !secure:
					// A real cryptographic mismatch, or a chain that
					// doesn't reach a trust anchor — reject outright,
					// regardless of what the upstream's own AD bit says.
					h.Stats.Errors.Add(1)
					m := newReply(r)
					m.Rcode = dns.RcodeServerFailure
					h.record(client, qname, q, "error", "dnssec: local chain-of-trust validation failed", usedUp, start, m)
					if !skipWrite {
						_ = h.write(w, m, r, proto)
					}
					putMsg(m)
					return
				case signed && secure:
					// Locally verified: this is a stronger guarantee than
					// the upstream's AD bit, so trust it even if the
					// upstream (oddly) didn't set AD itself.
					resp.AuthenticatedData = true
				}
			}
		}
		// 6b. AD-bit trust: reject an answer the upstream didn't mark
		//    authenticated instead of passing it through unvalidated. Only
		//    meaningful over an encrypted upstream transport (DoT/DoH/DoQ),
		//    where the AD bit can't be stripped or forged in flight. Also
		//    the fallback path when 6a validated nothing (unsigned zone)
		//    or couldn't complete (infrastructure error).
		if dnssecRequireAD && !resp.AuthenticatedData {
			h.Stats.Errors.Add(1)
			m := newReply(r)
			m.Rcode = dns.RcodeServerFailure
			h.record(client, qname, q, "error", "dnssec: upstream did not authenticate the answer", usedUp, start, m)
			if !skipWrite {
				_ = h.write(w, m, r, proto)
			}
			putMsg(m)
			return
		}
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
			if !skipWrite {
				_ = h.write(w, blocked, r, proto)
			}
			return
		}
	}

	// 7.5 CNAME cloaking protection: a tracker can disguise itself behind a
	//    first-party-looking subdomain that CNAMEs to a blocklisted domain.
	//    Walk every CNAME hop in the answer (a classic upstream's raw chain,
	//    or the recursive resolver's own already-merged chaseCNAME result)
	//    and block if any target matches the blocklist/whitelist rules, not
	//    just the originally queried name. Gated on !domainWhitelisted like
	//    the IP-based block above: an operator who explicitly whitelisted
	//    the queried name has already made the call that it's trusted, so a
	//    CDN it happens to route through (which may independently appear on
	//    a blocklist for unrelated third-party traffic) must not override
	//    that decision.
	if cnameCloakingEnabled && !domainWhitelisted {
		if owner, target, decision := cnameCloakCheck(engine, resp); decision.Action == filter.Block {
			blocked := filter.BuildBlockResponse(r, blockResp, blockTTL)
			h.Stats.Blocked.Add(1)
			reason := "cname-cloaking:" + owner + "->" + target + ":" + decision.Reason
			h.record(client, qname, q, "blocked", reason, usedUp, start, blocked)
			if r.IsEdns0() != nil {
				blocked = attachEDE(blocked, dns.ExtendedErrorCodeBlocked, reason)
			}
			if !skipWrite {
				_ = h.write(w, blocked, r, proto)
			}
			return
		}
	}

	// resp carries the fresh per-hop ID set on upstreamQuery above (not the
	// client's own r.Id) — restore it before this ever reaches the client
	// or the query log; caching doesn't care (writeRaw patches the ID on
	// every cache-hit read regardless of what was cached).
	resp.Id = r.Id
	// resp is deliberately never put into msgPool: when caching is on it's
	// handed unmodified into the background goroutine below, which keeps
	// reading/mutating/Pack()-ing it after serve() has already returned —
	// recycling it here would race that goroutine. See msgpool.go.
	h.Stats.Allowed.Add(1)
	h.record(client, qname, q, "allowed", "", usedUp, start, resp)
	if !skipWrite {
		_ = h.write(w, resp, r, proto)
	}

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
// further writes are skipped until a slot frees. Derived from the tuned core
// count (tuning.ScaleByCores) so a busier box — which also means more
// concurrent cache-miss writes — gets proportionally more headroom before
// this ever bounds anything but a genuine flood.
var maxCacheWriters = tuning.ScaleByCores(16, 64, 4096)

// maxASNCache bounds the per-client ASN memo (see Handler.asnCache). When
// full it resets — attribution is cheap to recompute for a few clients.
// Derived from the tuned memory ceiling (tuning.ScaleByMemory) so a busy
// LAN/CGNAT edge with many concurrent unique clients on a big box can hold a
// bigger memo before paying a full-map reset, while a Raspberry Pi keeps
// today's default.
var maxASNCache = tuning.ScaleByMemory(0.001, 64, 4096, 262144, 4096)

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
