package dnsserver

import (
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/eoghan2t9/Irongrid-DNS/internal/cache"
	"github.com/eoghan2t9/Irongrid-DNS/internal/dnsname"
	"github.com/eoghan2t9/Irongrid-DNS/internal/filter"
	"github.com/eoghan2t9/Irongrid-DNS/internal/geoip"
	"github.com/eoghan2t9/Irongrid-DNS/internal/upstream"
)

// Handler settings: route parsing, hot-swappable settings and every Set* accessor.

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
	if h.asnCacheSize.Add(1) > int64(maxASNCache) {
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

// SetRepeatGuard hot-swaps the repeat-query flood guard; nil disables it.
func (h *Handler) SetRepeatGuard(g *RepeatGuard) {
	ns := *h.settings.Load()
	ns.RepeatGuard = g
	h.swapSettings(&ns, nil)
}

// SetRepeatQueryBlockFor hot-swaps how long a trusted-source repeat-query
// flood trip is blocked (see RepeatQueryBlockFor's doc comment).
func (h *Handler) SetRepeatQueryBlockFor(d time.Duration) {
	ns := *h.settings.Load()
	ns.RepeatQueryBlockFor = d
	h.swapSettings(&ns, nil)
}

// SetRepeatQueryUDPBlockFor hot-swaps the bounded UDP repeat-query-flood
// block window (see RepeatQueryUDPBlockFor's doc comment); <= 0 disables it.
func (h *Handler) SetRepeatQueryUDPBlockFor(d time.Duration) {
	ns := *h.settings.Load()
	ns.RepeatQueryUDPBlockFor = d
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

// SetACL hot-swaps the query allow-list (server.allow_from); nil permits
// every client.
func (h *Handler) SetACL(a *ACL) {
	ns := *h.settings.Load()
	ns.ACL = a
	h.swapSettings(&ns, nil)
}

// SetDNSSECValidateLocally hot-swaps whether Handler.DNSSECValidator is
// actually consulted per query (dnssec.validate_locally). A no-op when
// DNSSECValidator is nil (not constructed at boot), regardless of the flag.
func (h *Handler) SetDNSSECValidateLocally(enabled bool) {
	ns := *h.settings.Load()
	ns.DNSSECValidateLocally = enabled
	h.swapSettings(&ns, nil)
}

// SetUpstreamHealthCheck hot-swaps whether proactive upstream health
// probing (upstream_health.enabled) actually does anything; the probe
// ticker itself runs for the life of the process (see
// StartUpstreamHealthCheck) and just no-ops on every tick while disabled.
func (h *Handler) SetUpstreamHealthCheck(enabled bool) {
	ns := *h.settings.Load()
	ns.UpstreamHealthCheck = enabled
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
