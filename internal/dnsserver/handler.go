// Package dnsserver implements every DNS listener (UDP, TCP, DoT, DoH, DoQ)
// plus the shared query handler that applies filtering, caching, forwarding
// and logging.
package dnsserver

import (
	"context"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"

	"github.com/eoghan2t9/Irongrid-DNS/internal/cache"
	"github.com/eoghan2t9/Irongrid-DNS/internal/filter"
	"github.com/eoghan2t9/Irongrid-DNS/internal/querylog"
	"github.com/eoghan2t9/Irongrid-DNS/internal/upstream"
)

// Stats aggregates runtime counters exposed via the API.
type Stats struct {
	Total      atomic.Int64
	Blocked    atomic.Int64
	Allowed    atomic.Int64
	Cached     atomic.Int64
	Errors     atomic.Int64
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
	mu              sync.RWMutex
	Upstreams       []*upstream.Upstream
	BlockResponse   string
	BlockTTL        uint32
	Timeout         time.Duration
	Rewriter        *filter.Rewriter // local DNS records; never nil, may be empty
	ClientRouter    *ClientRouter    // per-client policy; never nil, may be empty
	RateLimiter     *RateLimiter     // nil disables rate limiting
	DNSSECEnabled   bool
	DNSSECRequireAD bool

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
	defer h.mu.Unlock()
	h.Upstreams = ups
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
	cache := h.Cache
	rewriter := h.Rewriter
	clientRouter := h.ClientRouter
	rateLimiter := h.RateLimiter
	dnssecEnabled := h.DNSSECEnabled
	dnssecRequireAD := h.DNSSECRequireAD
	h.mu.RUnlock()

	if r == nil || len(r.Question) == 0 {
		m := new(dns.Msg)
		m.Response = true
		m.Rcode = dns.RcodeFormatError
		w.WriteMsg(m)
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
		w.WriteMsg(refused)
		return
	}

	m := new(dns.Msg)
	m.SetReply(r)
	m.RecursionAvailable = true
	q := r.Question[0]
	qname := strings.ToLower(strings.TrimSuffix(q.Name, "."))

	// 1. Local DNS records win over everything else — an explicit config
	//    entry is a stronger signal of intent than any blocklist or cache,
	//    and it's global (not per-client-group) so it's checked up front.
	if rewriter != nil {
		if rules, ok := rewriter.Lookup(q.Name); ok {
			if ans := filter.BuildAnswer(r, rules, q.Name, q.Qtype); ans != nil {
				h.Stats.Allowed.Add(1)
				h.record(client, qname, q, "rewrite", "local-dns", "", start, ans)
				w.WriteMsg(ans)
				return
			}
			// The name matched but not this record type: NODATA is the
			// correct answer for an authoritatively-local name, not a
			// blocklist/cache/upstream lookup.
			h.Stats.Allowed.Add(1)
			h.record(client, qname, q, "rewrite", "local-dns-nodata", "", start, m)
			w.WriteMsg(m)
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
		w.WriteMsg(blocked)
		return
	}

	// 4. Cache lookup (only for standard record types). Cached messages carry
	//    the ID of the original query, so rebase to this request's ID.
	// Lookup hashes the question once and checks positive then negative
	// entries, instead of two independent Get/GetNegative calls that each
	// re-derived the same key.
	if cache != nil && !isMetaQuery(q) {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		cached, negative := cache.Lookup(ctx, q)
		cancel()
		if cached != nil {
			cached.Id = r.Id
			h.Stats.Cached.Add(1)
			reason := "cache"
			if negative {
				reason = "cache-negative"
			}
			h.record(client, qname, q, "cached", reason, "", start, cached)
			w.WriteMsg(cached)
			return
		}
	}

	// 5. Forward to upstreams. Multiple upstreams are raced concurrently so
	//    the fastest healthy one answers; a single upstream is queried
	//    directly to avoid goroutine overhead. When DNSSEC is enabled the
	//    outgoing query carries the DO (DNSSEC OK) bit, asking a validating
	//    upstream to do the work — see DNSSECConfig's doc comment for why
	//    this resolver trusts the upstream rather than validating locally.
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	upstreamQuery := r
	if dnssecEnabled {
		upstreamQuery = r.Copy()
		upstreamQuery.SetEdns0(4096, true)
	}
	var (
		resp   *dns.Msg
		usedUp string
		err    error
	)
	if len(upstreams) == 1 {
		resp, err = upstreams[0].Query(ctx, upstreamQuery)
		if err == nil && resp != nil {
			usedUp = upstreams[0].Name()
		} else if err != nil {
			log.Printf("[dns] upstream %s failed: %v", upstreams[0].Name(), err)
		}
	} else {
		resp, usedUp, err = raceUpstreams(ctx, upstreams, upstreamQuery)
	}
	if err != nil || resp == nil {
		h.Stats.Errors.Add(1)
		m.Rcode = dns.RcodeServerFailure
		errStr := "no upstream available"
		if err != nil {
			errStr = err.Error()
		}
		h.record(client, qname, q, "error", errStr, usedUp, start, m)
		w.WriteMsg(m)
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
		w.WriteMsg(m)
		return
	}

	// 7. IP-based blocking: if the blocklists contain IP rules, check the
	//    answers (A/AAAA) returned by the upstream.
	if blockedByIP, reason := engine.CheckIPs(answerIPs(resp)); blockedByIP {
		blocked := filter.BuildBlockResponse(r, blockResp, blockTTL)
		h.Stats.Blocked.Add(1)
		h.record(client, qname, q, "blocked", reason, usedUp, start, blocked)
		w.WriteMsg(blocked)
		return
	}

	// 8. Cache the result (positive or negative) and return. Zero TTLs fall
	//    back to the configured Dragonfly cache lifetimes.
	if cache != nil && !isMetaQuery(q) {
		cctx, ccancel := context.WithTimeout(context.Background(), 3*time.Second)
		if len(resp.Answer) > 0 {
			cache.Set(cctx, q, resp, 0)
		} else {
			cache.SetNegative(cctx, q, resp, 0)
		}
		ccancel()
	}

	h.Stats.Allowed.Add(1)
	h.record(client, qname, q, "allowed", "", usedUp, start, resp)
	w.WriteMsg(resp)
}

func (h *Handler) record(client, qname string, q dns.Question, action, reason, upstreamName string, start time.Time, m *dns.Msg) {
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
