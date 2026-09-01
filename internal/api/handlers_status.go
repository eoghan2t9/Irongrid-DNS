package api

import (
	"context"
	"net/http"
	"runtime"
	"strconv"
	"time"

	"github.com/eoghan2t9/Irongrid-DNS/internal/tuning"
	"github.com/eoghan2t9/Irongrid-DNS/internal/version"
)

// ---- status & stats ----

func (h *Handler) getStatus(w http.ResponseWriter) {
	// System tuning state is independent of the config and involves a couple
	// of /proc/sys reads plus a getrlimit — cheap, but there's no reason to
	// hold the config lock while doing it.
	tuningStatus := tuning.Status()
	h.cfgMu.Lock()
	defer h.cfgMu.Unlock()
	listeners := map[string]bool{}
	for _, proto := range []string{"udp", "tcp", "dot", "doh", "doq"} {
		s := h.Cfg.Server
		listeners[proto] = (proto == "udp" && s.ListenUDP != "") ||
			(proto == "tcp" && s.ListenTCP != "") ||
			(proto == "dot" && s.ListenDoT != "") ||
			(proto == "doh" && s.ListenDoH != "") ||
			(proto == "doq" && s.ListenDoQ != "")
	}
	cacheOK := true
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if h.Cache != nil {
		if err := h.Cache.Ping(ctx); err != nil {
			cacheOK = false
		}
	}
	// Root-hints status (only present when a recursive:// upstream is
	// configured and the HintsManager exists).
	rootHints := map[string]any{"enabled": false}
	if h.Hints != nil {
		st := h.Hints.Status()
		rootHints = map[string]any{
			"enabled":          true,
			"source":           st.Source,
			"verified":         st.Verified,
			"last_fetch":       st.LastFetch,
			"last_error":       st.LastError,
			"addresses":        st.Addresses,
			"refresh_interval": st.RefreshInterval,
			"key_fingerprint":  st.KeyFingerprint,
		}
	}
	// SO_REUSEPORT socket counts actually bound (0 when the listener is
	// off): 1 on platforms without reuseport support, >1 when the kernel is
	// spreading datagrams across per-socket receive queues.
	udpSocks, doqSocks := 0, 0
	if h.DNSManager != nil {
		udpSocks, doqSocks = h.DNSManager.UDPListenerSockets()
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"version":     version.String(),
		"version_tag": version.Version,
		"uptime_sec":  int(time.Since(h.StartedAt).Seconds()),
		"listeners":   listeners,
		"udp_sockets": udpSocks,
		"doq_sockets": doqSocks,
		// num_cpu is the tuned GOMAXPROCS the UDP auto sizing runs off
		// (cgroup-aware via internal/tuning), so the dashboard's
		// "recommended values" can compute the exact same numbers.
		"num_cpu":    runtime.GOMAXPROCS(0),
		"cache_ok":   cacheOK,
		"tunnel":     h.Tunnel.Status(),
		"root_hints": rootHints,
		// System tuning state: file-descriptor limit, socket buffers, Linux
		// socket sysctls and the Go runtime settings (dashboard card).
		"tuning": tuningStatus,
	})
}

// todayStart returns local midnight — the "today" window for the dashboard's
// query-log card.
func todayStart() time.Time {
	now := time.Now()
	return time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())
}

func (h *Handler) getStats(ctx context.Context, w http.ResponseWriter) {
	// One stream walk (newest-first, cached for aggCacheTTL) serves all
	// three aggregate blocks — the 24h stats, the since-midnight "today"
	// stats and the 24-slot hourly series. They used to be three separate
	// paged walks of the same stream on every 10s poll; a failure now means
	// the stream is unreachable, so all three would have failed anyway.
	bundle, err := h.Log.StatsBundle(ctx, time.Now().Add(-24*time.Hour), todayStart())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	proto := map[string]int64{}
	for k, v := range h.DNS.Stats.ByProtocol {
		proto[k] = v.Load()
	}
	// Cache utilisation for the dashboard card: L1 is the in-process layer
	// (counters reset on restart), L2 is Dragonfly's cumulative INFO counters
	// (since the Dragonfly process started).
	cacheStats := map[string]any{"l1": nil, "l2": nil}
	if h.Cache != nil {
		l1h, l1m := h.Cache.L1Counters()
		cacheStats["l1"] = map[string]any{"hits": l1h, "misses": l1m}
		if s, err := h.Cache.L2Stats(ctx); err == nil {
			cacheStats["l2"] = map[string]any{
				"hits":        s.Hits,
				"misses":      s.Misses,
				"expired":     s.Expired,
				"evicted":     s.Evicted,
				"used_memory": s.UsedBytes,
				"max_memory":  s.MaxBytes,
				"keys":        s.Keys,
			}
		}
	}
	// In-flight request pool: flights are the upstream resolutions it
	// actually issued (one per unique question); merged are the queries
	// served by a shared flight (singleflight marks every caller of a
	// shared flight, leader included); saved is the conservative lower
	// bound on upstream round trips avoided (merged minus flights — exact
	// when every flight was shared).
	coalesceFlights := h.DNS.Stats.Flights.Load()
	coalesceMerged := h.DNS.Stats.Merged.Load()
	writeJSON(w, http.StatusOK, map[string]any{
		"query": bundle.Stats,
		"counters": map[string]int64{
			"total":           h.DNS.Stats.Total.Load(),
			"blocked":         h.DNS.Stats.Blocked.Load(),
			"allowed":         h.DNS.Stats.Allowed.Load(),
			"cached":          h.DNS.Stats.Cached.Load(),
			"errors":          h.DNS.Stats.Errors.Load(),
			"honeypot":        h.DNS.Stats.Honeypot.Load(),
			"asn_header":      h.DNS.Stats.ASNHeader.Load(),
			"udp_received":    h.DNS.Stats.UDPReceived.Load(),
			"udp_invalid":     h.DNS.Stats.UDPInvalid.Load(),
			"udp_queue_drops": h.DNS.Stats.UDPQueueDrops.Load(),
			"udp_completed":   h.DNS.Stats.UDPCompleted.Load(),
			"write_errors":    h.DNS.Stats.WriteErrors.Load(),
		},
		"protocol":     proto,
		"filter":       h.Engine.Stats(),
		"cache":        cacheStats,
		"latency":      h.DNS.LatencySummary(),
		"upstreams":    h.DNS.UpstreamHealth(),
		"query_today":  bundle.Today,
		"query_hourly": bundle.Hourly,
		"warmer":       warmerSnapshot(h.Warmer),
		"coalesce": map[string]int64{
			"flights": coalesceFlights,
			"merged":  coalesceMerged,
			"saved":   max(0, coalesceMerged-coalesceFlights),
		},
	})
}

// ---- query log ----

func (h *Handler) getLog(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	limit, _ := strconv.Atoi(q.Get("limit"))
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	offset, _ := strconv.Atoi(q.Get("offset"))
	entries, err := h.Log.Query(ctx, limit, offset, q.Get("action"), q.Get("domain"), q.Get("qtype"), q.Get("client"))
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"entries": entries})
}

func (h *Handler) clearLog(ctx context.Context, w http.ResponseWriter) {
	// Drop the whole stream: the query log now lives in Dragonfly.
	if err := h.Log.Clear(ctx); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"ok": "cleared"})
}
