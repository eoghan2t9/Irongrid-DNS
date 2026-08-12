// Package dnsserver implements every DNS listener (UDP, TCP, DoT, DoH, DoQ)
// plus the shared query handler that applies filtering, caching, forwarding
// and logging.
package dnsserver

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"math/bits"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/sync/singleflight"

	"github.com/eoghan2t9/Irongrid-DNS/internal/cache"
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
}

func newStats() *Stats {
	s := &Stats{ByProtocol: map[string]*atomic.Int64{
		"udp": {}, "tcp": {}, "dot": {}, "doh": {}, "doh3": {}, "doq": {},
	}}
	return s
}

// Handler is the shared request pipeline for all listeners.
type Handler struct {
	Engine *filter.Engine
	Cache  *cache.Cache
	Log    *querylog.Log

	// mu guards the hot-swappable settings below so the API can live-apply
	// config changes without a restart.
	mu            sync.RWMutex
	Upstreams     []*upstream.Upstream
	UpstreamMode  string // "race" or "sequential" (see UpstreamModeRace/Sequential)
	BlockResponse string
	BlockTTL      uint32
	Timeout       time.Duration
	// FailureTTL is how long a resolution failure (upstream never answered,
	// no serve-stale entry) is negatively cached as SERVFAIL; <= 0 uses the
	// cache's configured negative TTL. Set via SetFailureTTL; snapshot on
	// the hot path like the other tunables.
	FailureTTL   time.Duration
	Rewriter     *filter.Rewriter // local DNS records; never nil, may be empty
	ClientRouter *ClientRouter    // per-client policy; never nil, may be empty
	RateLimiter  *RateLimiter     // nil disables rate limiting
	Geo          *geoip.Blocker   // nil disables geo-blocking
	IPBanner     *geoip.Banner    // nil disables IP/honeypot blocking
	// TrustUDP opt-in: when true, a honeypot hit over plain UDP auto-blocks
	// its source address too. Off by default — a UDP source can be spoofed,
	// so enabling this lets a spoofing attacker permanently block an
	// innocent victim; only meaningful on a trusted network where clients
	// are real (the flag does nothing unless an IP banner is installed).
	TrustUDP        bool
	DNSSECEnabled   bool
	DNSSECRequireAD bool
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

	Stats *Stats

	// flight coalesces concurrent identical questions (same name/type/class)
	// into a single upstream resolution: a burst of clients resolving the
	// same domain — OS connectivity checks, a shared CDN hostname, an app
	// launched across the LAN at once — pays one round trip, and every
	// waiter gets the answer the moment the leader's query returns instead
	// of each paying its own upstream RTT. See resolveUpstreams.
	flight singleflight.Group
}

// NewHandler builds a handler with default stats.
func NewHandler(engine *filter.Engine, c *cache.Cache, ups []*upstream.Upstream, ql *querylog.Log, blockResp string, blockTTL uint32, timeout time.Duration) *Handler {
	h := &Handler{
		Engine:        engine,
		Cache:         c,
		Upstreams:     ups,
		UpstreamMode:  UpstreamModeRace,
		Log:           ql,
		BlockResponse: blockResp,
		BlockTTL:      blockTTL,
		Timeout:       timeout,
		Rewriter:      filter.NewRewriter(),
		ClientRouter:  NewClientRouter(),
		Stats:         newStats(),
	}
	// Server-cookie HMAC key. crypto/rand failure is effectively impossible
	// (kernel entropy); the time-seeded fallback keeps DNS cookies working
	// on a pathological system rather than silently disabling them.
	h.cookieSecret = make([]byte, 32)
	if _, err := rand.Read(h.cookieSecret); err != nil {
		log.Printf("[dns] warning: crypto/rand failed (%v); DNS cookie key falls back to time-derived", err)
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

// SetUpstreams hot-swaps the upstream forwarders (config live-apply).
func (h *Handler) SetUpstreams(ups []*upstream.Upstream) {
	h.mu.Lock()
	old := h.Upstreams
	h.Upstreams = ups
	h.mu.Unlock()
	// TCP/DoT keep a pooled connection and DoQ keeps a persistent QUIC
	// connection; without closing the replaced upstreams, every config
	// reload that touches the upstream list would leak sockets for the
	// life of the process.
	for _, u := range old {
		u.Close()
	}
}

// SetCache hot-swaps the response cache (config reload).
func (h *Handler) SetCache(c *cache.Cache) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.Cache = c
}

// SetBlockPolicy hot-swaps the block response mode and TTL.
func (h *Handler) SetBlockPolicy(resp string, ttl uint32) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.BlockResponse = resp
	h.BlockTTL = ttl
}

// SetTimeout hot-swaps the per-query upstream timeout.
func (h *Handler) SetTimeout(d time.Duration) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.Timeout = d
}

// SetUpstreamMode hot-swaps the multi-upstream resolution strategy
// (UpstreamModeRace queries every upstream at once and uses the fastest
// answer; UpstreamModeSequential tries them in list order, failing over).
func (h *Handler) SetUpstreamMode(mode string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.UpstreamMode = mode
}

// SetFailureTTL hot-swaps how long a resolution failure is negatively
// cached as SERVFAIL; <= 0 restores the cache's configured negative TTL.
func (h *Handler) SetFailureTTL(d time.Duration) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.FailureTTL = d
}

// SetRewriter hot-swaps the local DNS records (config live-apply).
func (h *Handler) SetRewriter(rw *filter.Rewriter) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.Rewriter = rw
}

// SetClientRouter hot-swaps the per-client policy routing table.
func (h *Handler) SetClientRouter(cr *ClientRouter) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.ClientRouter = cr
}

// SetRateLimiter hot-swaps the rate limiter; nil disables rate limiting.
func (h *Handler) SetRateLimiter(rl *RateLimiter) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.RateLimiter = rl
}

// SetGeo hot-swaps the geo blocker; nil disables geo-blocking.
func (h *Handler) SetGeo(g *geoip.Blocker) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.Geo = g
}

// SetIPBanner hot-swaps the client-IP banner (explicit block list + honeypot
// auto-blocks); nil disables it.
func (h *Handler) SetIPBanner(b *geoip.Banner) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.IPBanner = b
}

// SetTrustUDP hot-swaps the opt-in that lets plain-UDP honeypot hits
// auto-block their source (see TrustUDP's doc comment on the struct).
func (h *Handler) SetTrustUDP(on bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.TrustUDP = on
}

// CurrentIPBanner returns the active banner (nil when disabled), for the
// API's blocked-list/unblock endpoints.
func (h *Handler) CurrentIPBanner() *geoip.Banner {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.IPBanner
}

// BlockedClients returns the clients currently under an auto-block (from the
// rate limiter), for the dashboard.
func (h *Handler) BlockedClients() []BlockedClient {
	h.mu.RLock()
	rl := h.RateLimiter
	h.mu.RUnlock()
	if rl == nil {
		return nil
	}
	return rl.BlockedList()
}

// UnblockClient lifts an auto-blocked client's cooldown early.
func (h *Handler) UnblockClient(ip string) {
	h.mu.RLock()
	rl := h.RateLimiter
	h.mu.RUnlock()
	if rl != nil {
		rl.Unblock(ip)
	}
}

// SetDNSSEC hot-swaps DNSSEC enforcement (see DNSSECConfig's doc comment for
// what "enabled" actually means: trusting an encrypted, validating upstream,
// not local chain-of-trust validation).
func (h *Handler) SetDNSSEC(enabled, requireAD bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.DNSSECEnabled = enabled
	h.DNSSECRequireAD = requireAD
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
	start := time.Now()
	h.Stats.Total.Add(1)
	if p, ok := h.Stats.ByProtocol[proto]; ok {
		p.Add(1)
	}

	// Snapshot hot-swappable settings once so the pipeline below is race-free.
	h.mu.RLock()
	upstreams := h.Upstreams
	upstreamMode := h.UpstreamMode
	blockResp := h.BlockResponse
	blockTTL := h.BlockTTL
	timeout := h.Timeout
	failureTTL := h.FailureTTL
	cache := h.Cache
	rewriter := h.Rewriter
	clientRouter := h.ClientRouter
	rateLimiter := h.RateLimiter
	geo := h.Geo
	ipbanner := h.IPBanner
	trustUDP := h.TrustUDP
	dnssecEnabled := h.DNSSECEnabled
	dnssecRequireAD := h.DNSSECRequireAD
	cookiesOn := h.Cookies.Load()
	h.mu.RUnlock()

	if r == nil || len(r.Question) == 0 {
		m := new(dns.Msg)
		m.Response = true
		m.Rcode = dns.RcodeFormatError
		_ = h.write(w, m, r, proto)
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
				// Attach the correct cookie so the client can retry with it.
				_ = h.write(w, attachCookie(m, expected), r, proto)
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
		refused := new(dns.Msg)
		refused.SetReply(r)
		refused.Rcode = dns.RcodeRefused
		_ = h.write(w, refused, r, proto)
		return
	}

	q := r.Question[0]
	qname := strings.ToLower(strings.TrimSuffix(q.Name, "."))

	// 0.5 Client blocking: a geo-blocked country (source-IP country in the
	//    blocked set) or a banner-blocked client (explicit IPs/CIDRs plus
	//    IPs auto-added by honeypot hits) is REFUSED on every transport — an
	//    explicit answer, not a silent drop (the user's chosen trade-off).
	//    The geo allowlist is checked inside the blocker, so whitelisted IPs
	//    always pass.
	if client != "" {
		geoBlocked := geo != nil && geo.Blocked(client)
		bannerBlocked := ipbanner != nil && ipbanner.Blocked(client)
		if geoBlocked || bannerBlocked {
			h.Stats.Blocked.Add(1)
			action, reason := "geo-blocked", "country-blocked"
			if bannerBlocked {
				action, reason = "ip-blocked", "blocked-client"
			}
			refused := new(dns.Msg)
			refused.SetReply(r)
			refused.Rcode = dns.RcodeRefused
			h.record(client, qname, q, action, reason, "", start, refused)
			_ = h.write(w, refused, r, proto)
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
	// innocent victim with a single spoofed packet — and an unrecognised
	// transport is treated the same way. Anything else is refused but
	// never auto-blocked, unless the operator explicitly opted into
	// trusting UDP sources (geo_block.trust_udp) on a network where
	// clients are real: the same trust model the rate limiter uses for
	// its silent-drop/REFUSED split.
	if ipbanner != nil && ipbanner.LookupHoneypot(qname) {
		// Connection-oriented transports (a real handshake) always auto-block;
		// plain UDP only when the operator opted in via trust_udp.
		trusted := proto == "tcp" || proto == "dot" || proto == "doh" || proto == "doq"
		if client != "" && (trusted || trustUDP) {
			if err := ipbanner.Block(client); err != nil {
				//nolint:gosec // G706: client is a socket-derived IP, no control chars
				log.Printf("[geo] honeypot: blocking client %s: %v", client, err)
			}
		}
		h.Stats.Blocked.Add(1)
		h.Stats.Honeypot.Add(1)
		refused := new(dns.Msg)
		refused.SetReply(r)
		refused.Rcode = dns.RcodeRefused
		_ = h.write(w, refused, r, proto)
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
			return
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

	// 3. Filtering: whitelist overrides everything; blocklists stop the query.
	decision := engine.DecideDomain(q.Name)
	if decision.Action == filter.Block {
		blocked := filter.BuildBlockResponse(r, blockResp, blockTTL)
		h.Stats.Blocked.Add(1)
		h.record(client, qname, q, "blocked", decision.Reason, "", start, blocked)
		_ = h.write(w, blocked, r, proto)
		return
	} // 4. Cache lookup (only for standard record types). Cached messages carry
	//    the ID of the original query, so rebase to this request's ID.
	// Lookup hashes the question once and checks positive then negative
	// entries, instead of two independent Get/GetNegative calls that each
	// re-derived the same key. The budget is deliberately short: if
	// Dragonfly is slow or down, the query must reach the upstream rather
	// than stall. A hit may also be stale (RFC 8767): an entry past its TTL
	// but still within its serve-stale window, which we only answer from if
	// re-resolution below fails.
	var stale *dns.Msg
	if cache != nil && !isMetaQuery(q) {
		// Lookup is context-free: the L1 hit path allocates nothing, and the
		// L2 read is bounded by the cache's own lookup budget (see
		// cache.defaultLookupTimeout), so a slow or down cache tier can't
		// stall the query.
		hit := cache.Lookup(q)
		if hit.Msg != nil && !hit.Stale {
			hit.Msg.Id = r.Id
			h.Stats.Cached.Add(1)
			reason := "cache"
			if hit.Negative {
				reason = "cache-negative"
			}
			h.record(client, qname, q, "cached", reason, "", start, hit.Msg)
			_ = h.write(w, hit.Msg, r, proto)
			return
		}
		if hit.Msg != nil {
			stale = hit.Msg
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
	// RFC 8767: an upstream that *answers* SERVFAIL is also a resolution
	// failure — serve stale rather than propagating the failure.
	if err == nil && resp != nil && resp.Rcode == dns.RcodeServerFailure && stale != nil {
		stale.Id = r.Id
		capTTL(stale, staleServeTTL)
		h.Stats.Cached.Add(1)
		h.record(client, qname, q, "cached", "stale", usedUp, start, stale)
		_ = h.write(w, stale, r, proto)
		return
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
		if stale != nil {
			stale.Id = r.Id
			capTTL(stale, staleServeTTL)
			h.Stats.Cached.Add(1)
			h.record(client, qname, q, "cached", "stale", usedUp, start, stale)
			_ = h.write(w, stale, r, proto)
			return
		}
		h.Stats.Errors.Add(1)
		m := newReply(r)
		m.Rcode = dns.RcodeServerFailure
		errStr := "no upstream available"
		if err != nil {
			errStr = err.Error()
		}
		h.record(client, qname, q, "error", errStr, usedUp, start, m)
		_ = h.write(w, m, r, proto)
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
		if cache != nil && stale == nil && !isMetaQuery(q) {
			go func() {
				cctx, ccancel := context.WithTimeout(context.Background(), 3*time.Second)
				defer ccancel()
				// failureTTL <= 0 falls back to the cache's configured
				// negative TTL (cache.failure_ttl knob).
				cache.SetNegative(cctx, q, m, failureTTL)
			}()
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
		return
	}

	// 7. IP-based blocking: if the blocklists contain IP rules, check the
	//    answers (A/AAAA) returned by the upstream.
	if blockedByIP, reason := engine.CheckIPs(answerIPs(resp)); blockedByIP {
		blocked := filter.BuildBlockResponse(r, blockResp, blockTTL)
		h.Stats.Blocked.Add(1)
		h.record(client, qname, q, "blocked", reason, usedUp, start, blocked)
		_ = h.write(w, blocked, r, proto)
		return
	}

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
	if cache != nil && !isMetaQuery(q) {
		go func() {
			cctx, ccancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer ccancel()
			if len(resp.Answer) > 0 {
				cache.Set(cctx, q, resp, 0)
			} else {
				cache.SetNegative(cctx, q, resp, 0)
			}
		}()
	}
}

func (h *Handler) record(client, qname string, q dns.Question, action, reason, upstreamName string, start time.Time, m *dns.Msg) {
	h.latency.record(time.Since(start))
	if h.Log == nil {
		return
	}
	answers := 0
	rcode := dns.RcodeServerFailure
	if m != nil {
		rcode = m.Rcode
		answers = len(m.Answer)
	}
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
	out := m
	if proto == "udp" {
		if limit := clientUDPSize(r); m.Len() > limit {
			c := m.Copy()
			c.Truncate(limit)
			out = c
		}
	}
	// Padding only helps where the stream is encrypted anyway — on plain UDP
	// the padded datagram length leaks just as much as the unpadded one, and
	// padding must not inflate a datagram toward the client's buffer limit.
	if h.Padding.Load() && (proto == "dot" || proto == "doh" || proto == "doh3" || proto == "doq") {
		out = padMessage(out, 128)
	}
	if h.Cookies.Load() {
		if cc := requestClientCookie(r); cc != "" {
			cookie := cc + h.serverCookie(clientIPOf(w.RemoteAddr()), cc)
			out = attachCookie(out, cookie)
		}
	}
	return w.WriteMsg(out)
}

// newReply allocates the empty response skeleton used by the error, NODATA
// and DNSSEC-failure paths: the client's ID, RD/CD flags and first question
// copied, Response and RA set. It is allocated lazily — the fast paths (cache
// hit, blocklist, rewrite answer, successful upstream resolution) never pay
// for it, and most queries are served from one of those.
func newReply(r *dns.Msg) *dns.Msg {
	m := new(dns.Msg)
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
	return strings.ToLower(q.Name) + "|" + strconv.Itoa(int(q.Qtype)) + "|" + strconv.Itoa(int(q.Qclass))
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
			return nil, u.Name(), fmt.Errorf("upstream %s in failure cooldown", u.Name())
		}
		resp, err := u.Query(ctx, r)
		if err != nil {
			log.Printf("[dns] upstream %s failed: %v", u.Name(), err)
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
func sequentialUpstreams(ctx context.Context, ups []*upstream.Upstream, r *dns.Msg) (*dns.Msg, string, error) {
	var (
		lastErr    error
		lastFail   *dns.Msg
		lastFailUp string
	)
	for _, up := range ups {
		if ctx.Err() != nil {
			break
		}
		// One query message is reused across attempts: miekg/dns's
		// ExchangeContext writes it as-is and matches the reply by the
		// unchanged ID — it never rewrites msg.Id — and Pack is safe to call
		// repeatedly on a single message. The per-attempt Copy() the
		// previous code made only mattered for race mode's concurrent
		// sends; here the message belongs to this loop for its whole run.
		resp, err := up.Query(ctx, r)
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
	log.Printf("[dns] all upstreams failed: %v", lastErr)
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
		go func(u *upstream.Upstream) {
			// Copy the query per upstream: each concurrent send must own the
			// message it hands the transport — sending can mutate the message
			// (TSIG signing does, and a library bump could change what the
			// transport rewrites), so a shared *dns.Msg would race, and each
			// reply must match the query its own conn sent. Sequential mode
			// reuses one message instead (see sequentialUpstreams).
			resp, err := u.Query(qctx, r.Copy())
			ch <- result{resp: resp, up: u.Name(), err: err}
		}(up)
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
	log.Printf("[dns] all upstreams failed: %v", lastErr)
	return nil, "", lastErr
}

// resolveAndCache re-resolves q through the current upstreams and re-caches
// the result (positive or negative). It is shared by the cache's prefetch
// callback (Refresh) and the proactive cache warmer, so both mechanisms
// resolve through the exact same path — snapshotting the hot-swappable
// upstreams and cache at call time.
func (h *Handler) resolveAndCache(ctx context.Context, q dns.Question) error {
	h.mu.RLock()
	ups := h.Upstreams
	cache := h.Cache
	mode := h.UpstreamMode
	h.mu.RUnlock()
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

// ednsUDPSize is the UDP payload size advertised on outgoing upstream
// queries: the DNS Flag Day 2020 recommended 1232 bytes, the largest value
// that fits every common path MTU without IP fragmentation (1280-byte IPv6
// minimum minus 48 bytes of IP/UDP/DNS headers). Bigger answers flow over
// the TCP fallback instead of being dropped as fragments.
const ednsUDPSize = 1232

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
	for i := 0; i < len(h.buckets); i++ {
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
	h.mu.RLock()
	ups := h.Upstreams
	h.mu.RUnlock()
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
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return addr.String()
	}
	return host
}
