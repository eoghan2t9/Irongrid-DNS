package main

import (
	"log/slog"
	"net"

	"github.com/eoghan2t9/Irongrid-DNS/internal/config"
	"github.com/eoghan2t9/Irongrid-DNS/internal/vpn"
)

// VPN reconcile/public-IP/proxy helpers used by startup and reload.

// vpnReconcileArgs converts config.VPNConfig into the vpn package's own
// input types for Manager.Reconcile. A disabled vpn.enabled reconciles with
// no profiles/routes at all — Reconcile then tears down whatever was
// previously connected, same as flipping the feature off in the dashboard.
func vpnReconcileArgs(v config.VPNConfig) ([]vpn.ProfileSpec, []vpn.RouteSpec, vpn.Credentials) {
	if !v.Enabled {
		return nil, nil, vpn.Credentials{}
	}
	profiles := make([]vpn.ProfileSpec, 0, len(v.Profiles))
	for _, p := range v.Profiles {
		profiles = append(profiles, vpn.ProfileSpec{ID: p.ID, Provider: p.Provider, Region: p.Region})
	}
	routes := make([]vpn.RouteSpec, 0, len(v.Routes))
	for _, rt := range v.Routes {
		routes = append(routes, vpn.RouteSpec{Profile: rt.Profile, Domains: rt.Domains, Proxy: rt.Proxy})
	}
	creds := vpn.Credentials{
		NordVPNToken: v.Providers.NordVPN.Token,
		PIAUsername:  v.Providers.PIA.Username,
		PIAPassword:  v.Providers.PIA.Password,
	}
	return profiles, routes, creds
}

// detectPublicIP finds this host's outbound-facing address via the
// well-known "dial UDP, never send anything, read LocalAddr" trick — no
// packet is actually sent (UDP connect just picks a route/local address),
// so this costs nothing and needs no external service.
func detectPublicIP() net.IP {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return nil
	}
	defer conn.Close()
	addr, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok {
		return nil
	}
	return addr.IP
}

// applyVPNPublicIP resolves vpn.proxy.public_ip (explicit override, or
// auto-detected when empty) and installs it on mgr — the address
// ProxyAnswer hands out for Proxy-enabled routes. Safe to call at boot and
// again on every config reload.
func applyVPNPublicIP(mgr *vpn.Manager, pc config.VPNProxyConfig) {
	var ip net.IP
	if pc.PublicIP != "" {
		ip = net.ParseIP(pc.PublicIP)
		if ip == nil {
			slog.Error("vpn.proxy.public_ip is not a valid IP address", "value", pc.PublicIP)
		}
	}
	if ip == nil {
		ip = detectPublicIP()
	}
	mgr.SetPublicIP(ip)
	switch {
	case ip != nil:
		slog.Info("vpn: proxy relay public IP set", "ip", ip)
	case pc.Enabled:
		slog.Warn("vpn: could not determine a public IP for the proxy relay — Proxy-enabled routes will not resolve until vpn.proxy.public_ip is set explicitly")
	}
}

// applyVPNProxy (re)starts the SNI/Host relay listeners to match pc,
// stopping whatever was running first — safe to call at boot and again on
// every config reload; a no-op restart (identical config) still briefly
// bounces the listeners, which is an accepted tradeoff for keeping this
// simple (proxy reconfiguration is a rare, deliberate action, unlike the
// DNS listeners' hot-restart path).
func applyVPNProxy(mgr *vpn.Manager, pc config.VPNProxyConfig, webListen string) {
	vpnRelayMu.Lock()
	defer vpnRelayMu.Unlock()
	if vpnRelay != nil {
		vpnRelay.Stop()
		vpnRelay = nil
	}
	if !pc.Enabled {
		return
	}
	listen := pc.Listen
	if listen == "" {
		listen = ":443"
	}
	fallback := pc.Fallback
	if fallback == "" {
		fallback = webListen
	}
	if fallback == "" || fallback == listen {
		slog.Error("vpn.proxy: fallback must be set to a different address than listen (server.web_listen is empty or the same as vpn.proxy.listen) — the relay was not started", "listen", listen, "fallback", fallback)
		return
	}
	relay, err := vpn.NewRelay(mgr, fallback, "udp://1.1.1.1:53")
	if err != nil {
		slog.Error("vpn.proxy: relay init failed", "error", err)
		return
	}
	if err := relay.Start(listen, pc.ListenHTTP); err != nil {
		slog.Error("vpn.proxy: relay start failed", "error", err)
		return
	}
	vpnRelay = relay
	slog.Info("vpn: proxy relay started", "listen", listen, "listen_http", pc.ListenHTTP, "fallback", fallback)
}
