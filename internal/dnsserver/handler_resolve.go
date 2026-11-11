package dnsserver

import (
	"context"
	"fmt"
	"log/slog"
	"runtime/debug"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/eoghan2t9/Irongrid-DNS/internal/dnsname"
	"github.com/eoghan2t9/Irongrid-DNS/internal/upstream"
	"github.com/miekg/dns"
)

// Upstream resolution: singleflight coalescing, upstream query modes, resolve-and-cache and refresh.

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
	switch mode {
	case UpstreamModeSequential:
		return sequentialUpstreams(ctx, avail, r)
	case UpstreamModeRoundRobin:
		// Rotate so this query's first choice is the next upstream in turn;
		// the rest of the rotated list is its failover order. avail is a
		// fresh per-call slice, so rotating it in place is safe. The counter
		// advances over the *available* upstreams, so a server in cooldown
		// simply drops out of the rotation instead of leaving a gap.
		start := int((rrCounter.Add(1) - 1) % uint64(len(avail)))
		slices.Reverse(avail[:start]) // rotate left by start, in place
		slices.Reverse(avail[start:])
		slices.Reverse(avail)
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
