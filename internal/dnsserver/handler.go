// Package dnsserver implements every DNS listener (UDP, TCP, DoT, DoH, DoQ)
// plus the shared query handler that applies filtering, caching, forwarding
// and logging.
package dnsserver

import (
	"context"
	"fmt"
	"log"
	"math/bits"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"

	"github.com/eoghan2t9/Irongrid-DNS/internal/cache"
	"github.com/eoghan2t9/Irongrid-DNS/internal/filter"
	"github.com/eoghan2t9/Irongrid-DNS/internal/geoip"
	"github.com/eoghan2t9/Irongrid-DNS/internal/querylog"
	"github.com/eoghan2t9/Irongrid-DNS/internal/upstream"
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
}

func newStats() *Stats {
	s := &Stats{ByProtocol: map[string]*atomic.Int64{
		"udp": {}, "tcp": {}, "dot": {}, "doh": {}, "doq": {},
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
	BlockResponse string
	BlockTTL      uint32
	Timeout       time.Duration
	// FailureTTL is how long a resolution failure (upstream never answered,
	// no serve-stale entry) is negatively cached as SERVFAIL; <= 0 uses the
	// cache's configured negative TTL. Set via SetFailureTTL; snapshot on
	// the hot path like the other tunables.
	FailureTTL time.Duration
	Rewriter   *filter.Rewriter // local DNS records; never nil, may be empty
	ClientRouter  *ClientRouter    // per-client policy; never nil, may be empty
	RateLimiter   *RateLimiter     // nil disables rate limiting
	Geo           *geoip.Blocker   // nil disables geo-blocking
	IPBanner      *geoip.Banner    // nil disables IP/honeypot blocking
	// TrustUDP opt-in: when true, a honeypot hit over plain UDP auto-blocks
	// its source address too. Off by default — a UDP source can be spoofed,
	// so enabling this lets a spoofing attacker permanently block an
	// innocent victim; only meaningful on a trusted network where clients
	// are real (the flag does nothing unless an IP banner is installed).
	TrustUDP        bool
	DNSSECEnabled   bool
	DNSSECRequireAD bool
	// latency is the in-process response-time histogram backing the
	// dashboard's Performance card percentiles (see latencyHist).
	latency latencyHist

	Stats *Stats
}

// NewHandler builds a handler with default stats.
func NewHandler(engine *filter.Engine, c *cache.Cache, ups []*upstream.Upstream, ql *querylog.Log, blockResp string, blockTTL uint32, timeout time.Duration) *Handler {
	return &Handler{
		Engine:        engine,
		Cache:         c,
		Upstreams:     ups,
		Log:           ql,
		BlockResponse: blockResp,
		BlockTTL:      blockTTL,
		Timeout:       timeout,
		Rewriter:      filter.NewRewriter(),
		ClientRouter:  NewClientRouter(),
		Stats:         newStats(),
	}
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

func (h *Handler) serve(w dns.ResponseWriter, r *dns.Msg, client, proto string) {
	start := time.Now()
	h.Stats.Total.Add(1)
	if p, ok := h.Stats.ByProtocol[proto]; ok {
		p.Add(1)
	}

	// Snapshot hot-swappable settings once so the pipeline below is race-free.
	h.mu.RLock()
	upstreams := h.Upstreams
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
	h.mu.RUnlock()

	if r == nil || len(r.Question) == 0 {
		m := new(dns.Msg)
		m.Response = true
		m.Rcode = dns.RcodeFormatError
		_ = w.WriteMsg(m)
		return
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
		_ = w.WriteMsg(refused)
		return
	}

	m := new(dns.Msg)
	m.SetReply(r)
	m.RecursionAvailable = true
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
			_ = w.WriteMsg(refused)
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
		_ = w.WriteMsg(refused)
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
				_ = w.WriteMsg(ans)
				return
			}
			// The name matched but not this record type: NODATA is the
			// correct answer for an authoritatively-local name, not a
			// blocklist/cache/upstream lookup.
			h.Stats.Allowed.Add(1)
			h.record(client, qname, q, "rewrite", "local-dns-nodata", "", start, m)
			_ = w.WriteMsg(m)
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
		_ = w.WriteMsg(blocked)
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
			_ = w.WriteMsg(hit.Msg)
			return
		}
		if hit.Msg != nil {
			stale = hit.Msg
		}
	}

	// 5. Forward to upstreams. Multiple upstreams are raced concurrently so
	// the fastest healthy one answers; a single upstream is queried
	// directly to avoid goroutine overhead. The outgoing query always
	// advertises EDNS0 (4096 bytes; the DO bit only when DNSSEC is
	// enabled) — without it the upstream caps its UDP answer at 512 bytes
	// and large records fall back to a TCP round trip. The query is copied
	// so the client's message is never mutated. Upstreams whose circuit is
	// open (consecutive failures inside the cooldown window) are skipped so
	// a dead server can't burn its full timeout on every query; a single
	// upstream in cooldown fails fast into serve-stale/SERVFAIL below.
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	upstreamQuery := r.Copy()
	// Replace the client's EDNS OPT rather than layering a second one on:
	// miekg/dns's SetEdns0 appends, and a query carrying two OPT records is
	// malformed (RFC 6891 §6.1.1: "it MUST be the only OPT RR in that
	// message"). Strict resolvers (Quad9 in particular) reject it with
	// FORMERR, which the client sees as a resolution failure. The client's
	// own advertisement is superseded by the 4096-byte one below anyway, so
	// drop every OPT (always last in practice, but filtered regardless) and
	// preserve any other additional records (e.g. TSIG).
	extra := upstreamQuery.Extra[:0]
	for _, rr := range upstreamQuery.Extra {
		if rr.Header().Rrtype != dns.TypeOPT {
			extra = append(extra, rr)
		}
	}
	upstreamQuery.Extra = extra
	upstreamQuery.SetEdns0(4096, dnssecEnabled)
	var (
		resp   *dns.Msg
		usedUp string
		err    error
	)
	if len(upstreams) == 1 {
		if upstreams[0].Available() {
			resp, err = upstreams[0].Query(ctx, upstreamQuery)
			if err == nil && resp != nil {
				usedUp = upstreams[0].Name()
			} else if err != nil {
				log.Printf("[dns] upstream %s failed: %v", upstreams[0].Name(), err)
			}
		} else {
			usedUp = upstreams[0].Name()
			err = fmt.Errorf("upstream %s in failure cooldown", upstreams[0].Name())
		}
	} else {
		avail := make([]*upstream.Upstream, 0, len(upstreams))
		for _, u := range upstreams {
			if u.Available() {
				avail = append(avail, u)
			}
		}
		if len(avail) == 0 {
			err = fmt.Errorf("all upstreams in failure cooldown")
		} else {
			resp, usedUp, err = raceUpstreams(ctx, avail, upstreamQuery)
		}
	}
	// RFC 8767: an upstream that *answers* SERVFAIL is also a resolution
	// failure — serve stale rather than propagating the failure.
	if err == nil && resp != nil && resp.Rcode == dns.RcodeServerFailure && stale != nil {
		stale.Id = r.Id
		capTTL(stale, staleServeTTL)
		h.Stats.Cached.Add(1)
		h.record(client, qname, q, "cached", "stale", usedUp, start, stale)
		_ = w.WriteMsg(stale)
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
			_ = w.WriteMsg(stale)
			return
		}
		h.Stats.Errors.Add(1)
		m.Rcode = dns.RcodeServerFailure
		errStr := "no upstream available"
		if err != nil {
			errStr = err.Error()
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
		// upstream never answered at all.)
		if cache != nil && stale == nil && !isMetaQuery(q) {
			cacheResp := m.Copy()
			go func() {
				cctx, ccancel := context.WithTimeout(context.Background(), 3*time.Second)
				defer ccancel()
				// failureTTL <= 0 falls back to the cache's configured
				// negative TTL (cache.failure_ttl knob).
				cache.SetNegative(cctx, q, cacheResp, failureTTL)
			}()
		}
		h.record(client, qname, q, "error", errStr, usedUp, start, m)
		_ = w.WriteMsg(m)
		return
	}

	// 6. DNSSEC enforcement: reject an answer the upstream didn't mark
	//    authenticated instead of passing it through unvalidated. Only
	//    meaningful over an encrypted upstream transport (DoT/DoH/DoQ),
	//    where the AD bit can't be stripped or forged in flight.
	if dnssecEnabled && dnssecRequireAD && !resp.AuthenticatedData {
		h.Stats.Errors.Add(1)
		m.Rcode = dns.RcodeServerFailure
		h.record(client, qname, q, "error", "dnssec: upstream did not authenticate the answer", usedUp, start, m)
		_ = w.WriteMsg(m)
		return
	}

	// 7. IP-based blocking: if the blocklists contain IP rules, check the
	//    answers (A/AAAA) returned by the upstream.
	if blockedByIP, reason := engine.CheckIPs(answerIPs(resp)); blockedByIP {
		blocked := filter.BuildBlockResponse(r, blockResp, blockTTL)
		h.Stats.Blocked.Add(1)
		h.record(client, qname, q, "blocked", reason, usedUp, start, blocked)
		_ = w.WriteMsg(blocked)
		return
	}

	// 8. Cache the result (positive or negative) in the background. Caching
	//    only ever helps *future* queries, so there's no reason to make this
	//    client wait on a Redis round trip before getting the answer it
	//    already has. Cache.Set/SetNegative mutate the message they're given
	//    (SetReply, Compress, Pack) while writing it, so a copy is handed to
	//    the goroutine — resp itself is about to be packed concurrently by
	//    w.WriteMsg below, and sharing the same *dns.Msg between the two
	//    would race. Zero TTLs fall back to the configured Dragonfly cache
	//    lifetimes.
	if cache != nil && !isMetaQuery(q) {
		cacheResp := resp.Copy()
		go func() {
			cctx, ccancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer ccancel()
			if len(cacheResp.Answer) > 0 {
				cache.Set(cctx, q, cacheResp, 0)
			} else {
				cache.SetNegative(cctx, q, cacheResp, 0)
			}
		}()
	}

	h.Stats.Allowed.Add(1)
	h.record(client, qname, q, "allowed", "", usedUp, start, resp)
	_ = w.WriteMsg(resp)
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
			// Copy the query: miekg/dns's transport layer overwrites msg.Id
			// while sending, so the same message cannot be handed to several
			// upstreams concurrently.
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
			log.Printf("[dns] upstream %s failed: %v", res.up, res.err)
		}
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no upstream returned a response")
	}
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
	var (
		resp *dns.Msg
		err  error
	)
	if len(ups) == 1 {
		resp, err = ups[0].Query(ctx, m)
	} else {
		resp, _, err = raceUpstreams(ctx, ups, m)
	}
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
