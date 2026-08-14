// Proactive cache warmer: a background loop that pre-caches the answers for
// the domains your network actually uses. The existing prefetch mechanism
// only refreshes entries a client happens to query near expiry; it can't
// help right after a restart or a cache flush, when every first query still
// pays a full upstream round trip. The warmer instead scans the query log
// for the domains seen within the configured lookback window and re-resolves
// them (A + AAAA) through the current upstreams into the cache, so the first
// real query for any of them finds a warm entry.
package dnsserver

import (
	"context"
	"fmt"
	"log"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"

	"github.com/eoghan2t9/Irongrid-DNS/internal/cache"
	"github.com/eoghan2t9/Irongrid-DNS/internal/config"
	"github.com/eoghan2t9/Irongrid-DNS/internal/filter"
	"github.com/eoghan2t9/Irongrid-DNS/internal/querylog"
)

const (
	// defaultWarmInterval / defaultWarmLookback / defaultWarmMaxDomains /
	// defaultWarmConcurrency mirror config.WarmerConfig's defaults (see
	// config.Default) — they apply when the config value is left at 0 (e.g.
	// empty duration strings from the web UI). Keep both in sync.
	defaultWarmInterval    = 15 * time.Minute
	defaultWarmLookback    = 24 * time.Hour
	defaultWarmMaxDomains  = 5000
	defaultWarmConcurrency = 8
	// idleWarmRecheck is how often a disabled warmer re-checks its config so
	// a dashboard toggle is picked up promptly (same pattern as the geo
	// auto-refresh goroutine) instead of on the previous — possibly never —
	// cadence.
	idleWarmRecheck = time.Hour
	// warmPassTimeout bounds a single pass so a slow upstream or a stuck
	// Dragonfly can't tie up the loop (and defer every later pass) for hours.
	// Whatever wasn't warmed is picked up on the next pass.
	warmPassTimeout = 15 * time.Minute
)

// Warmer is a background cache warmer. It is safe for concurrent use: config
// and stats are guarded by mu, and at most one warming pass runs at a time
// (the Start goroutine is the only caller of run).
type Warmer struct {
	h   *Handler
	log *querylog.Log

	mu        sync.Mutex // guards everything below
	enabled   bool
	interval  time.Duration
	lookback  time.Duration
	maxDoms   int
	workers   int
	lastRun   time.Time
	lastError string
	// Cumulative counters across passes (since process start).
	runs    int64
	domains int64 // distinct domains considered
	warmed  int64 // answers written to the cache
	skipped int64 // domains/questions skipped (blocked, rewritten, fresh)
	failed  int64 // resolutions that errored

	// trigger kicks the loop into an immediate pass (SetConfig on a
	// disabled->enabled transition, or a manual /api/cache/warm). Buffered
	// so the sender never blocks; stale kicks are harmless.
	trigger chan struct{}
}

// NewWarmer builds a warmer over a handler (for its upstreams, cache, filter
// engine and rewriter) and a query log (the source of active domains). It
// starts disabled; call SetConfig before Start.
func NewWarmer(h *Handler, log *querylog.Log) *Warmer {
	return &Warmer{h: h, log: log, trigger: make(chan struct{}, 1)}
}

// SetConfig hot-swaps the warmer's settings (config live-apply). Transitioning
// from disabled to enabled kicks an immediate pass so a dashboard toggle takes
// effect without waiting for the interval.
func (w *Warmer) SetConfig(c config.WarmerConfig) {
	w.mu.Lock()
	wasEnabled := w.enabled
	w.enabled = c.Enabled
	w.interval = c.Interval
	w.lookback = c.Lookback
	w.maxDoms = c.MaxDomains
	w.workers = c.Concurrency
	w.mu.Unlock()
	if c.Enabled && !wasEnabled {
		select {
		case w.trigger <- struct{}{}:
		default:
		}
	}
}

// WarmNow requests an immediate warming pass on the background loop (the API's
// "warm now" action, e.g. after flushing the cache). No-op while disabled or
// while a pass is already in flight (a kick is coalesced).
func (w *Warmer) WarmNow() {
	select {
	case w.trigger <- struct{}{}:
	default:
	}
}

// Enabled reports whether the warmer is currently switched on (the API uses
// it to refuse a "warm now" while the feature is disabled instead of
// answering success for a no-op).
func (w *Warmer) Enabled() bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.enabled
}

// Start runs the warming loop until ctx is cancelled. An enabled warmer runs
// a pass immediately at boot (the cold-cache case a warmer exists for) and
// then every interval; a disabled one idles and re-checks hourly so a config
// change is picked up without a restart.
func (w *Warmer) Start(ctx context.Context) {
	go func() {
		w.mu.Lock()
		enabled := w.enabled
		w.mu.Unlock()
		if enabled {
			w.run(ctx)
		}
		for {
			w.mu.Lock()
			enabled = w.enabled
			interval := w.interval
			w.mu.Unlock()
			wait := idleWarmRecheck
			if enabled && interval > 0 {
				wait = interval
			} else if enabled {
				wait = defaultWarmInterval
			}
			select {
			case <-ctx.Done():
				return
			case <-w.trigger:
				// An enable-toggle or manual warm: fall through, re-read the
				// config and run a pass when enabled.
			case <-time.After(wait):
			}
			w.mu.Lock()
			enabled = w.enabled
			w.mu.Unlock()
			if enabled {
				w.run(ctx)
			}
		}
	}()
}

// WarmerStats is the dashboard card's snapshot of the warmer's state.
type WarmerStats struct {
	Enabled   bool      `json:"enabled"`
	Runs      int64     `json:"runs"`
	LastRun   time.Time `json:"last_run,omitempty"`
	Domains   int64     `json:"domains"` // distinct domains considered, cumulative
	Warmed    int64     `json:"warmed"`  // answers written to the cache, cumulative
	Skipped   int64     `json:"skipped"` // blocked/rewritten/already-fresh, cumulative
	Failed    int64     `json:"failed"`  // failed resolutions, cumulative
	LastError string    `json:"last_error,omitempty"`
}

// Snapshot returns the warmer's current state for the API/dashboard.
func (w *Warmer) Snapshot() WarmerStats {
	w.mu.Lock()
	defer w.mu.Unlock()
	return WarmerStats{
		Enabled:   w.enabled,
		Runs:      w.runs,
		LastRun:   w.lastRun,
		Domains:   w.domains,
		Warmed:    w.warmed,
		Skipped:   w.skipped,
		Failed:    w.failed,
		LastError: w.lastError,
	}
}

// run performs one warming pass: read the active domains from the query log,
// skip the ones the pipeline would never look up in the cache (blocked or
// rewritten), and refresh the rest through the handler's upstreams with
// bounded concurrency.
func (w *Warmer) run(ctx context.Context) {
	w.mu.Lock()
	lookback := w.lookback
	if lookback <= 0 {
		lookback = defaultWarmLookback
	}
	maxDoms := w.maxDoms
	workers := w.workers
	if workers <= 0 {
		workers = defaultWarmConcurrency
	}
	w.mu.Unlock()

	if w.log == nil {
		return
	}
	// Bound the whole pass: with slow upstreams a pass could otherwise run
	// for hours, deferring every later interval and manual kick.
	passCtx, cancel := context.WithTimeout(ctx, warmPassTimeout)
	defer cancel()
	domains, err := w.log.ActiveDomains(passCtx, time.Now().Add(-lookback), maxDoms)
	if err != nil {
		w.setLastError(fmt.Sprintf("active domains: %v", err))
		return
	}

	// Snapshot the handler's hot-swappable internals once per pass: the
	// warmer warms through the *global* engine/upstreams — it has no client
	// IP, so per-client-group policies don't apply (their answers share the
	// same cache and can overwrite a warmed entry, exactly as two clients
	// in different groups already do today). The settings snapshot is one
	// atomic load; the engine is fixed for the process.
	s := w.h.settings.Load()
	cache := s.Cache
	engine := w.h.Engine
	rewriter := s.Rewriter
	if cache == nil {
		return
	}

	var warmed, skipped, failed atomic.Int64
	sem := make(chan struct{}, workers)
	var wg sync.WaitGroup
	for _, td := range domains {
		name := dns.Fqdn(td.Domain)
		// Blocked domains are answered from the filter engine without ever
		// reaching the cache or an upstream — warming one would waste
		// upstream traffic (and leak the query). Rewrites are answered
		// locally the same way, so they're skipped too.
		if engine != nil && engine.DecideDomain(name).Action == filter.Block {
			skipped.Add(1)
			continue
		}
		if rewriter != nil {
			if _, ok := rewriter.Lookup(name); ok {
				skipped.Add(1)
				continue
			}
		}
		wg.Add(1)
		go func(name string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			wn, sn, err := w.warmDomain(passCtx, cache, name)
			if err != nil {
				failed.Add(1)
				return
			}
			warmed.Add(wn)
			skipped.Add(sn)
		}(name)
	}
	wg.Wait()

	w.mu.Lock()
	w.runs++
	w.domains += int64(len(domains))
	w.warmed += warmed.Load()
	w.skipped += skipped.Load()
	w.failed += failed.Load()
	w.lastRun = time.Now()
	if f := failed.Load(); f > 0 {
		w.lastError = fmt.Sprintf("%d resolution(s) failed last pass", f)
	} else {
		w.lastError = ""
	}
	w.mu.Unlock()
	log.Printf("[warmer] pass done: %d domain(s), %d warmed, %d skipped, %d failed",
		len(domains), warmed.Load(), skipped.Load(), failed.Load())
}

// warmDomain refreshes A and AAAA for name, skipping any question the cache
// already answers fresh (the quiet Fresh probe — no counter or prefetch
// side effects, so warming never skews the dashboard's cache cards or
// double-resolves with the cache's own near-expiry prefetch).
func (w *Warmer) warmDomain(ctx context.Context, c *cache.Cache, name string) (warmed, skipped int64, err error) {
	for _, qt := range []uint16{dns.TypeA, dns.TypeAAAA} {
		q := dns.Question{Name: name, Qtype: qt, Qclass: dns.ClassINET}
		// Fresh already: skip without counting the probe in the cache's
		// hit/miss counters (Fresh is a quiet probe, unlike Lookup) so
		// warming traffic doesn't skew the dashboard's cache cards.
		if c.Fresh(q) {
			skipped++
			continue
		}
		if err := w.h.resolveAndCache(ctx, q); err != nil {
			return warmed, skipped, err
		}
		warmed++
	}
	return warmed, skipped, nil
}

func (w *Warmer) setLastError(s string) {
	w.mu.Lock()
	w.lastError = s
	w.mu.Unlock()
	log.Printf("[warmer] pass failed: %s", s)
}
