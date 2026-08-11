// hostname resolution for the query-log and blocked-clients views: PTR
// lookups are run through the same upstreams the Tools page uses (configured
// upstreams first, public fallback), cached so a page polling every few
// seconds resolves each client IP once, and never touch the query log or the
// DNS hot path.
package api

import (
	"context"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

const (
	// hostPosTTL is how long a successful PTR result is remembered.
	hostPosTTL = time.Hour
	// hostNegTTL is how long a "no PTR record" answer is remembered, so a
	// log full of unroutable/PTR-less clients doesn't re-query the upstream
	// on every dashboard poll.
	hostNegTTL = 15 * time.Minute
	// hostCap bounds the cache: a spoofed-IP flood can add keys fast, so
	// beyond this the cache resets rather than growing without limit.
	hostCap = 10000
	// hostMaxBatch caps how many IPs one request resolves.
	hostMaxBatch = 50
	// hostWorkers bounds concurrent PTR lookups per request.
	hostWorkers = 8
	// hostTimeout bounds the whole batch so a slow upstream can't stall the
	// log page.
	hostTimeout = 6 * time.Second
)

// hostCache remembers PTR results per client IP (positive and negative).
type hostCache struct {
	mu  sync.Mutex
	pos map[string]hostEntry // ip -> resolved name
	neg map[string]time.Time // ip -> valid-until (no PTR record)
}

type hostEntry struct {
	name string
	at   time.Time
}

func newHostCache() *hostCache {
	return &hostCache{pos: map[string]hostEntry{}, neg: map[string]time.Time{}}
}

// get returns the cached name and true for a live entry — including a
// negative hit (name == ""). ok is false when nothing is cached.
func (c *hostCache) get(ip string, now time.Time) (string, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if e, ok := c.pos[ip]; ok && now.Sub(e.at) < hostPosTTL {
		return e.name, true
	}
	if until, ok := c.neg[ip]; ok && now.Before(until) {
		return "", true
	}
	return "", false
}

// put records a result; name == "" records a negative hit.
func (c *hostCache) put(ip, name string, now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.pos)+len(c.neg) >= hostCap {
		c.pos = map[string]hostEntry{}
		c.neg = map[string]time.Time{}
	}
	if name == "" {
		c.neg[ip] = now.Add(hostNegTTL)
	} else {
		c.pos[ip] = hostEntry{name: name, at: now}
	}
}

// hostCache returns the Handler's shared cache, creating it on first use.
func (h *Handler) hostCache() *hostCache {
	h.hostOnce.Do(func() { h.hosts = newHostCache() })
	return h.hosts
}

// logHostnames resolves reverse-DNS names for a comma-separated list of
// client IPs (?ips=1.2.3.4,5.6.7.8) so the query log and blocked-clients
// cards can label who is querying. Only IPs with a PTR record appear in the
// response; invalid entries are ignored.
func (h *Handler) logHostnames(w http.ResponseWriter, r *http.Request) {
	var ips []string
	for _, p := range strings.Split(r.URL.Query().Get("ips"), ",") {
		p = strings.TrimSpace(p)
		if net.ParseIP(p) != nil {
			ips = append(ips, p)
		}
		if len(ips) >= hostMaxBatch {
			break
		}
	}
	out := map[string]string{}
	if len(ips) == 0 {
		writeJSON(w, http.StatusOK, map[string]any{"hostnames": out})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), hostTimeout)
	defer cancel()

	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, hostWorkers)
	for _, ip := range ips {
		wg.Add(1)
		go func(ip string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			name := h.resolveHostname(ctx, ip)
			if name == "" {
				return
			}
			mu.Lock()
			out[ip] = name
			mu.Unlock()
		}(ip)
	}
	wg.Wait()
	writeJSON(w, http.StatusOK, map[string]any{"hostnames": out})
}

// resolveHostname returns the cached-or-fresh PTR name for ip, or "" when the
// address has no PTR record (or resolution failed). Concurrent lookups for
// the same IP (multiple dashboard views polling at once) are coalesced into
// one upstream PTR query.
func (h *Handler) resolveHostname(ctx context.Context, ip string) string {
	now := time.Now()
	if name, ok := h.hostCache().get(ip, now); ok {
		return name
	}
	ch := h.hostFlight.DoChan("host:"+ip, func() (any, error) {
		name := lookupPTR(ctx, h, ip)
		h.hostCache().put(ip, name, time.Now())
		return name, nil
	})
	select {
	case res := <-ch:
		name, _ := res.Val.(string)
		return name
	case <-ctx.Done():
		// Our batch deadline expired while waiting on the leader: take a
		// result the leader may have just cached, else report nothing.
		if name, ok := h.hostCache().get(ip, time.Now()); ok {
			return name
		}
		return ""
	}
}

// lookupPTR queries the reverse-zone name of ip through the configured
// upstreams (with resolveAny's public fallback) and returns the first PTR
// answer, minus its trailing dot.
func lookupPTR(ctx context.Context, h *Handler, ip string) string {
	rev, err := dns.ReverseAddr(ip)
	if err != nil {
		return ""
	}
	msg, err := h.resolveAny(ctx, rev, dns.TypePTR)
	if err != nil || msg == nil {
		return ""
	}
	for _, rr := range msg.Answer {
		if ptr, ok := rr.(*dns.PTR); ok {
			return strings.TrimSuffix(ptr.Ptr, ".")
		}
	}
	return ""
}
