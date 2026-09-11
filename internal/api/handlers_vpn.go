package api

import "net/http"

// ---- vpn ----
//
// Profiles and routes themselves are edited through the generic
// config GET/PUT + reload endpoints (config.VPNConfig is just another part
// of the config document, like client_groups or upstream_routes) — this is
// the one bespoke endpoint, for live connection state the config file
// itself can't show.

func (h *Handler) vpnStatus(w http.ResponseWriter) {
	if h.VPN == nil {
		writeJSON(w, http.StatusOK, []any{})
		return
	}
	writeJSON(w, http.StatusOK, h.VPN.Status())
}
