package api

import (
	"context"
	"net/http"

	"github.com/eoghan2t9/Irongrid-DNS/internal/dnsserver"
)

// ---- cache ----

func (h *Handler) flushCache(ctx context.Context, w http.ResponseWriter) {
	if h.Cache == nil {
		// Mirrors warmCache's guard: every production wiring sets Cache (it
		// is a hard boot requirement), but a nil cache must return a clean
		// error rather than panic.
		writeJSON(w, http.StatusNotImplemented, map[string]string{"error": "cache not configured"})
		return
	}
	n, err := h.Cache.FlushAll(ctx)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": "flushed", "deleted": n})
}

// warmerSnapshot returns the warmer's stats (or an empty snapshot when no
// warmer is wired) so the dashboard's card always gets the same JSON shape.
func warmerSnapshot(w *dnsserver.Warmer) dnsserver.WarmerStats {
	if w == nil {
		return dnsserver.WarmerStats{}
	}
	return w.Snapshot()
}

// warmCache requests an immediate cache-warming pass (the dashboard's "Warm
// now" action, e.g. right after flushing the cache). It only kicks the
// background loop; the pass itself runs asynchronously.
func (h *Handler) warmCache(w http.ResponseWriter) {
	if h.Warmer == nil {
		writeJSON(w, http.StatusNotImplemented, map[string]string{"error": "cache warmer not configured"})
		return
	}
	if !h.Warmer.Enabled() {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "cache warmer is disabled — enable it under Settings → Cache warmer first"})
		return
	}
	h.Warmer.WarmNow()
	writeJSON(w, http.StatusOK, map[string]any{"ok": "warming"})
}
