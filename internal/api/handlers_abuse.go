package api

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"slices"
	"strings"
)

// ---- abuse protection: auto-blocked clients & geo blocking ----

// rateBlocked serves the currently auto-blocked clients for the dashboard.
func (h *Handler) rateBlocked(w http.ResponseWriter) {
	writeJSON(w, http.StatusOK, map[string]any{"blocked": h.DNS.BlockedClients()})
}

// rateUnblock lifts an auto-blocked client's cooldown early.
func (h *Handler) rateUnblock(w http.ResponseWriter, r *http.Request) {
	var p struct {
		IP string `json:"ip"`
	}
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil || p.IP == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "ip required"})
		return
	}
	h.DNS.UnblockClient(p.IP)
	writeJSON(w, http.StatusOK, map[string]string{"ok": "unblocked"})
}

// geoStatus serves the per-country geo data status, plus the auto-refresh
// cadence and when the next automatic refresh is due (zero/nil when disabled).
func (h *Handler) geoStatus(w http.ResponseWriter) {
	if h.Geo == nil {
		writeJSON(w, http.StatusOK, map[string]any{"enabled": false, "countries": []any{}})
		return
	}
	h.cfgMu.Lock()
	autoUpdate := h.Cfg.GeoBlock.AutoUpdate
	h.cfgMu.Unlock()
	last := h.Geo.LastRefresh()
	var next any
	if autoUpdate > 0 && !last.IsZero() {
		next = last.Add(autoUpdate)
	}
	// Firewall status: the packet-level mirror of geo blocking. Only shown
	// when main wired a firewall manager (always, in this build).
	fw := map[string]any{"available": false}
	if h.Firewall != nil {
		backend, active := h.Firewall.Status()
		fw = map[string]any{"available": true, "backend": backend, "active": active}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"enabled":      true,
		"countries":    h.Geo.Status(),
		"auto_update":  durationOrEmpty(autoUpdate),
		"last_refresh": last,
		"next_refresh": next,
		"firewall":     fw,
	})
}

// geoRefresh re-downloads the enabled countries' CIDR data and swaps the DNS
// handler's blocker when ready.
func (h *Handler) geoRefresh(w http.ResponseWriter) {
	if h.RebuildGeo == nil || h.Geo == nil {
		writeJSON(w, http.StatusNotImplemented, map[string]string{"error": "geo blocking not configured in this build"})
		return
	}
	h.cfgMu.Lock()
	geo := h.Cfg.GeoBlock
	h.cfgMu.Unlock()
	// Nothing to do when the feature is empty — say so instead of answering
	// "ok" for a no-op (the dashboard otherwise looks like it worked while
	// the blocker stays uninstalled). Note countries are optional: blocking
	// can run on explicit IPs / honeypots alone.
	if geo.Enabled && len(geo.Countries) == 0 && len(geo.IPs) == 0 && len(geo.Honeypots) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "geo blocking is enabled but nothing is configured — add countries, blocked IPs or honeypot domains in Settings, save, then refresh"})
		return
	}
	if err := h.RebuildGeo(geo); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "refreshing": true})
}

// geoBlocked serves the banner's honeypot-auto-blocked clients for the
// dashboard. Configured IPs are excluded — they're visible in the config
// editor and aren't unblockable.
func (h *Handler) geoBlocked(w http.ResponseWriter) {
	var ips []string
	if h.DNS != nil {
		if b := h.DNS.CurrentIPBanner(); b != nil {
			ips = b.AutoList()
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"blocked": ips})
}

// geoBlockIP adds a client IP (or the /prefix network containing it) to the
// always-blocked geo list (geo_block.ips), persists it and rebuilds the
// blocker/firewall. This is the dashboard's one-click "block this attacker"
// action — unlike the honeypot auto-block (which is per-IP and lives in the
// banner's runtime file), a quick-block lands in the config so it survives
// anything and feeds the host firewall's drop set at the packet level.
func (h *Handler) geoBlockIP(w http.ResponseWriter, r *http.Request) {
	var p struct {
		IP     string `json:"ip"`
		Prefix int    `json:"prefix"` // optional: block ip/prefix instead of the bare IP
	}
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil || strings.TrimSpace(p.IP) == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "ip required"})
		return
	}
	ip := net.ParseIP(strings.TrimSpace(p.IP))
	if ip == nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": fmt.Sprintf("%q is not an IP address", p.IP)})
		return
	}
	entry := ip.String()
	if p.Prefix > 0 {
		bits := 32
		if ip.To4() == nil {
			bits = 128
		}
		if p.Prefix > bits {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": fmt.Sprintf("prefix /%d is too large for this address family", p.Prefix)})
			return
		}
		n := &net.IPNet{IP: ip.Mask(net.CIDRMask(p.Prefix, bits)), Mask: net.CIDRMask(p.Prefix, bits)}
		entry = n.String()
	}

	h.cfgMu.Lock()
	defer h.cfgMu.Unlock()
	// A config-only add is a silent no-op while geo blocking is off (the
	// banner that enforces these entries doesn't exist), so refuse it — the
	// same guard geoRefresh uses for its inert case.
	if !h.Cfg.GeoBlock.Enabled {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "geo blocking is disabled — enable it in Settings before adding blocked IPs"})
		return
	}
	if slices.Contains(h.Cfg.GeoBlock.IPs, entry) {
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "already": true, "entry": entry})
		return
	}
	h.Cfg.GeoBlock.IPs = append(h.Cfg.GeoBlock.IPs, entry)
	// The client was almost certainly auto-blocked by a honeypot hit; drop
	// the runtime auto entry so the dashboard's honeypot list stays truthful
	// (the config entry now covers it permanently, and Unblock is a no-op for
	// entries that aren't runtime auto-blocks).
	if h.DNS != nil {
		if b := h.DNS.CurrentIPBanner(); b != nil {
			_ = b.Unblock(ip.String())
		}
	}
	if err := h.SaveConfig(); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	// Rebuild asynchronously, exactly like applyPayload: the geo rebuild can
	// fetch country data, which must never stall the API response.
	if h.RebuildGeo != nil {
		_ = h.RebuildGeo(h.Cfg.GeoBlock)
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "entry": entry})
}

// geoUnblock removes a honeypot-auto-blocked client from the banner and the
// host firewall's drop set.
func (h *Handler) geoUnblock(w http.ResponseWriter, r *http.Request) {
	var p struct {
		IP string `json:"ip"`
	}
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil || p.IP == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "ip required"})
		return
	}
	if h.DNS != nil {
		if b := h.DNS.CurrentIPBanner(); b != nil {
			if err := b.Unblock(p.IP); err != nil {
				writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
				return
			}
		}
	}
	if h.Firewall != nil {
		_ = h.Firewall.RemoveIP(p.IP)
	}
	writeJSON(w, http.StatusOK, map[string]string{"ok": "unblocked"})
}
