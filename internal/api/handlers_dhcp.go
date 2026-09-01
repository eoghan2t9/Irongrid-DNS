package api

import (
	"net"
	"net/http"

	"github.com/eoghan2t9/Irongrid-DNS/internal/config"
	"github.com/eoghan2t9/Irongrid-DNS/internal/dhcp"
	"github.com/eoghan2t9/Irongrid-DNS/internal/dnsserver"
)

// ---- DHCP ----

// dhcpBindConfig is the subset of DHCP settings whose change requires a
// listener restart: the interface to bind and whether each protocol runs.
// Everything else (pool, options, statics) is read per packet by the
// handlers, so applyPayload live-applies it without a restart.
func dhcpBindConfig(c config.DHCPConfig) config.DHCPConfig {
	return config.DHCPConfig{
		Enabled:    c.Enabled,
		Interface:  c.Interface,
		Subnet:     c.Subnet,
		IPv6:       c.IPv6,
		IPv6Prefix: c.IPv6Prefix,
	}
}

// routeSpecs converts config-level conditional routes into the dnsserver
// package's RouteSpec form (raw upstream strings; parsing happens in
// SetUpstreamRoutes so a bad spec is rejected before anything swaps).
func routeSpecs(routes []config.UpstreamRoute) []dnsserver.RouteSpec {
	specs := make([]dnsserver.RouteSpec, 0, len(routes))
	for _, rt := range routes {
		specs = append(specs, dnsserver.RouteSpec{Domain: rt.Domain, Upstreams: rt.Upstreams})
	}
	return specs
}

// dhcpRuntimeConfig maps the config section into the dhcp package's runtime
// Config. It reuses dhcp.ConfigFrom (the same constructor main's boot path
// uses), so the API's live-apply and a process boot produce identical
// runtime configs. The host's own addresses are carried over from the
// currently running config (discovered at boot); they are only stale if the
// interface/subnet changed, in which case the user applies the restart and
// main re-discovers them.
func (h *Handler) dhcpRuntimeConfig(c config.DHCPConfig) dhcp.Config {
	var addrs dhcp.HostAddresses
	if h.DHCP != nil {
		s := h.DHCP.Config()
		addrs = dhcp.HostAddresses{IPv4: s.ServerIPv4, IPv6: s.ServerIPv6, MAC: s.ServerMAC}
	}
	statics := make([]dhcp.StaticLease, 0, len(c.StaticLeases))
	for _, sl := range c.StaticLeases {
		st := dhcp.StaticLease{MAC: sl.MAC, DUID: sl.DUID, Hostname: sl.Hostname}
		if ip := net.ParseIP(sl.IP); ip != nil {
			st.IP = ip
		}
		statics = append(statics, st)
	}
	return dhcp.ConfigFrom(c.Enabled, c.Interface, c.Subnet, c.RangeStart, c.RangeEnd,
		c.Gateway, c.DNS, c.LeaseTime, c.Domain, statics,
		c.IPv6, c.IPv6Prefix, c.IPv6RangeStart, c.IPv6RangeEnd, addrs)
}

// dhcpLeases serves the DHCP lease table for the dashboard's DHCP page.
func (h *Handler) dhcpLeases(w http.ResponseWriter) {
	if h.DHCP == nil {
		writeJSON(w, http.StatusOK, map[string]any{"enabled": false, "leases": []any{}})
		return
	}
	h.cfgMu.Lock()
	enabled := h.Cfg.DHCP.Enabled
	h.cfgMu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{
		"enabled": enabled,
		"leases":  h.DHCP.Leases(),
	})
}
