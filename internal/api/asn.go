// Cached BGP/ISP owner lookups for the query-log and blocked-clients views.
// The lookups reuse lookupASN (the free RIPEstat API, no key required) and are
// remembered per IP so a page polling every few seconds asks RIPEstat once
// per address instead of on every poll.
package api

import (
	"context"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	// asnTTL is how long one IP's owner info is remembered. Routing
	// registrations change rarely, so 24h keeps the dashboard fresh enough
	// while making RIPEstat traffic negligible.
	asnTTL = 24 * time.Hour
	// asnCap bounds the cache: a spoofed-IP flood can add keys fast, so
	// beyond this the cache resets rather than growing without limit.
	asnCap = 10000
	// asnMaxBatch caps how many IPs one request resolves.
	asnMaxBatch = 50
	// asnWorkers bounds concurrent RIPEstat lookups per request (each lookup
	// is two sequential HTTP calls).
	asnWorkers = 4
	// asnTimeout bounds the whole batch so a slow RIPEstat can't stall the
	// log page.
	asnTimeout = 12 * time.Second
)

// asnCache remembers RIPEstat owner info per client IP (positive and the
// definitive "no routing information" outcome).
type asnCache struct {
	mu  sync.Mutex
	pos map[string]asnEntry
	neg map[string]time.Time
}

type asnEntry struct {
	info asnInfo
	at   time.Time
}

func newASNCache() *asnCache {
	return &asnCache{pos: map[string]asnEntry{}, neg: map[string]time.Time{}}
}

// get returns the cached info and true for a live entry — including a
// negative hit (zero asnInfo). ok is false when nothing is cached.
func (c *asnCache) get(ip string, now time.Time) (asnInfo, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if e, ok := c.pos[ip]; ok && now.Sub(e.at) < asnTTL {
		return e.info, true
	}
	if until, ok := c.neg[ip]; ok && now.Before(until) {
		return asnInfo{}, true
	}
	return asnInfo{}, false
}

// put records a result; a zero asnInfo records a negative hit.
func (c *asnCache) put(ip string, info asnInfo, now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.pos)+len(c.neg) >= asnCap {
		c.pos = map[string]asnEntry{}
		c.neg = map[string]time.Time{}
	}
	if info.ASN == "" {
		c.neg[ip] = now.Add(asnTTL)
	} else {
		c.pos[ip] = asnEntry{info: info, at: now}
	}
}

// asnCache returns the Handler's shared cache, creating it on first use.
func (h *Handler) asnCache() *asnCache {
	h.asnOnce.Do(func() { h.asns = newASNCache() })
	return h.asns
}

// logASN resolves BGP/ISP owner info for a comma-separated list of client IPs
// (?ips=1.2.3.4,5.6.7.8) so the query log and blocked-clients card can label
// who is querying. Only IPs with routing information appear in the response;
// invalid entries are ignored.
func (h *Handler) logASN(w http.ResponseWriter, r *http.Request) {
	var ips []string
	for _, p := range strings.Split(r.URL.Query().Get("ips"), ",") {
		p = strings.TrimSpace(p)
		if net.ParseIP(p) != nil {
			ips = append(ips, p)
		}
		if len(ips) >= asnMaxBatch {
			break
		}
	}
	out := map[string]asnInfo{}
	if len(ips) == 0 {
		writeJSON(w, http.StatusOK, map[string]any{"asn": out})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), asnTimeout)
	defer cancel()

	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, asnWorkers)
	for _, ip := range ips {
		wg.Add(1)
		go func(ip string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			info := h.resolveASN(ctx, ip)
			if info.ASN == "" {
				return
			}
			mu.Lock()
			out[ip] = info
			mu.Unlock()
		}(ip)
	}
	wg.Wait()
	writeJSON(w, http.StatusOK, map[string]any{"asn": out})
}

// resolveASN returns the cached-or-fresh owner info for ip. Only the
// definitive "no routing information" outcome is cached (negatively);
// transient RIPEstat failures are retried on the next poll instead of being
// remembered.
//
// Concurrent lookups for the same IP — two dashboard tabs, or the log page
// and blocked-clients card polling together — are coalesced into one
// RIPEstat round trip instead of each firing the two HTTP calls against the
// rate-limited API.
func (h *Handler) resolveASN(ctx context.Context, ip string) asnInfo {
	now := time.Now()
	if info, ok := h.asnCache().get(ip, now); ok {
		return info
	}
	ch := h.asnFlight.DoChan("asn:"+ip, func() (any, error) {
		info, err := lookupASN(ctx, ip)
		if err != nil {
			if strings.Contains(err.Error(), "no routing information") {
				h.asnCache().put(ip, asnInfo{}, time.Now())
			}
			return asnInfo{}, nil
		}
		h.asnCache().put(ip, info, time.Now())
		return info, nil
	})
	select {
	case res := <-ch:
		info, _ := res.Val.(asnInfo)
		return info
	case <-ctx.Done():
		// Our batch deadline expired while waiting on the leader: take a
		// result the leader may have just cached, else report nothing.
		if info, ok := h.asnCache().get(ip, time.Now()); ok {
			return info
		}
		return asnInfo{}
	}
}
