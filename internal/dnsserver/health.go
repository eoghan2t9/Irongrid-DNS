package dnsserver

import (
	"context"
	"log/slog"
	"time"

	"github.com/miekg/dns"
)

// upstreamHealthCheckInterval is how often each configured upstream gets a
// canary query. The existing circuit breaker (see internal/upstream) only
// ever learns an upstream is degrading from real client queries failing —
// fine for a busy upstream, but a upstream that a client hasn't hit
// recently (or that loses every race) can silently rot until the next
// unlucky client hits it. This probe feeds the same circuit breaker so a
// bad upstream opens its circuit — and a recovered one closes it — without
// waiting on live traffic.
const upstreamHealthCheckInterval = 20 * time.Second

// upstreamHealthCheckTimeout bounds a single probe so a hung upstream can't
// pile up goroutines across ticks.
const upstreamHealthCheckTimeout = 5 * time.Second

// upstreamHealthCheckDomain is a stable, universally-resolvable domain used
// only for the probe query — never served to a client, never cached (the
// probe calls Upstream.Query directly, bypassing the response cache
// entirely).
const upstreamHealthCheckDomain = "example.com."

// StartUpstreamHealthCheck runs proactive upstream health probing
// (upstream_health.enabled) until ctx is done. A no-op — no goroutine
// started — when disabled; the enabled flag itself is still re-checked
// every tick from the live settings snapshot, so a config reload that
// toggles it takes effect without a restart.
func (h *Handler) StartUpstreamHealthCheck(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(upstreamHealthCheckInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				h.probeUpstreams(ctx)
			}
		}
	}()
}

// probeUpstreams sends one canary query to every currently configured
// upstream, in parallel, each bounded by upstreamHealthCheckTimeout. The
// result reaches the same Upstream.markResult path a real client query
// would, hot-swapped settings included, so this always probes whatever the
// live upstream list actually is at tick time.
func (h *Handler) probeUpstreams(ctx context.Context) {
	s := h.settings.Load()
	if !s.UpstreamHealthCheck {
		return
	}
	for _, up := range s.Upstreams {
		go func() {
			probeCtx, cancel := context.WithTimeout(ctx, upstreamHealthCheckTimeout)
			defer cancel()
			m := new(dns.Msg)
			m.SetQuestion(upstreamHealthCheckDomain, dns.TypeA)
			if _, err := up.Query(probeCtx, m); err != nil {
				slog.Debug("upstream health probe failed", "upstream", up.Name(), "error", err)
			}
		}()
	}
}
