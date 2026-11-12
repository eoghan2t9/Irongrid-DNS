package main

import (
	"errors"
	"log/slog"
	"path/filepath"
	"time"

	"github.com/eoghan2t9/Irongrid-DNS/internal/config"
	"github.com/eoghan2t9/Irongrid-DNS/internal/dnsserver"
	"github.com/eoghan2t9/Irongrid-DNS/internal/firewall"
	"github.com/eoghan2t9/Irongrid-DNS/internal/geoip"
)

// refreshGroupASN loads the ip2asn dataset pruned to the union of every
// enabled client group's ASN list and publishes it for router rebuilds.
// nil when no group matches by ASN; a load failure keeps the previous
// table (like the country-data fallback) so a refresh hiccup doesn't
// silently drop ASN-matched groups.
func (a *app) refreshGroupASN(c *config.Config) *geoip.ASNTable {
	var asns []string
	for _, g := range c.ClientGroups {
		if g.Enabled {
			asns = append(asns, g.ASNs...)
		}
	}
	if len(asns) == 0 {
		return nil
	}
	tbl, _, err := a.geoMgr.RefreshASN(a.ctx, asns, nil)
	if err != nil {
		slog.Warn("client-group ASN data load failed — ASN-matched groups not applied", "error", err)
		if a.apiHandler != nil {
			return a.apiHandler.GroupASN.Load()
		}
		return nil
	}
	return tbl
}

// setupGeo wires geo blocking: the firewall manager, the async rebuild hooks and the
// auto-refresh loop.
func (a *app) setupGeo() {
	a.fwMgr = firewall.New()
	a.apiHandler.Geo = a.geoMgr
	a.apiHandler.Firewall = a.fwMgr
	// Async, same as RebuildGeo below: a 9-country geo_block config downloads
	// 18 URLs sequentially (~8-13s observed) and previously blocked the
	// dashboard/API listener (and everything sequenced after it) behind that
	// fetch. DNS itself already started above without waiting on this, so
	// there's no new gap here — just no longer holding up the dashboard too.
	go func() {
		if err := a.buildGeo(a.cfg.GeoBlock); err != nil {
			slog.Warn("initial geo load partially failed, using cached data", "error", err)
		}
	}()
	// The config-save and refresh-button paths must never stall on a
	// country-data download (multi-country fetches can take seconds), so
	// RebuildGeo runs the rebuild off the request path; the DNS handler
	// keeps serving with the previous blocker until the new one is ready.
	a.apiHandler.RebuildGeo = func(g config.GeoBlockConfig) error {
		go func() {
			if err := a.buildGeo(g); err != nil {
				slog.Error("geo background refresh failed", "error", err)
			}
		}()
		return nil
	}
	// Client-group ASN matching refreshes the same way on a config save:
	// the dataset download/parse runs off the request path, and the router
	// is rebuilt the moment the fresh table lands (until then the previous
	// table — or no ASN matching — stays in effect).
	a.apiHandler.RebuildClientGroups = func(c *config.Config) error {
		go func() {
			tbl := a.refreshGroupASN(c)
			a.apiHandler.GroupASN.Store(tbl)
			a.handler.SetClientRouter(dnsserver.BuildClientRouter(c, a.lists, tbl))
		}()
		return nil
	}
	// VPN split-tunnel profiles/routes: this is what actually applies a
	// dashboard save (PUT /api/config -> applyPayload), unlike the
	// reconcile call in Reload below, which only fires on a full listener
	// restart (POST /api/config/reload). Async for the same reason as
	// RebuildGeo above — (re)connecting a profile is a network round trip.
	a.apiHandler.RebuildVPN = func(c *config.Config) error {
		go func() {
			profiles, routes, creds := vpnReconcileArgs(c.VPN)
			if err := a.vpnMgr.Reconcile(a.ctx, profiles, routes, creds); err != nil {
				slog.Error("vpn: reconcile failed", "error", err)
			}
			applyVPNPublicIP(a.vpnMgr, c.VPN.Proxy)
			applyVPNProxy(a.vpnMgr, c.VPN.Proxy, c.Server.WebListen)
		}()
		return nil
	}

	// Auto-refresh keeps country data fresh without a manual refresh: the
	// ipverse/rir-ip aggregates change roughly weekly, so the default cadence
	// is weekly. The interval and enabled state are re-read from the live
	// config under the config mutex on every cycle, so dashboard changes
	// apply without a restart — when geo blocking is disabled (or auto-refresh
	// is off) the goroutine idles and re-checks hourly. Rebuilds run on this
	// goroutine and fall back to cached data on network failure, so a spell
	// of outages never clears the blocked set.
	cfgMu := a.apiHandler.ConfigMu()
	go func() {
		for {
			cfgMu.Lock()
			g := a.cfg.GeoBlock
			cfgMu.Unlock()
			// Idle cadence when nothing is scheduled: re-check hourly so a
			// dashboard toggle (enabling geo, or setting auto_update) is
			// picked up promptly instead of on the old — possibly never —
			// cadence.
			wait := time.Hour
			if g.Enabled && (len(g.Countries) > 0 || len(g.AllowASNs) > 0 || len(g.BlockASNs) > 0) && g.AutoUpdate > 0 {
				wait = g.AutoUpdate
			}
			timer := time.NewTimer(wait)
			select {
			case <-a.ctx.Done():
				if !timer.Stop() {
					select {
					case <-timer.C:
					default:
					}
				}
				return
			case <-timer.C:
			}
			// Re-read the config after the sleep: the user may have disabled
			// geo (or changed countries / the interval) while we waited, and
			// the rebuild must never act on a stale snapshot — otherwise a
			// long-interval refresh could re-enable blocking the dashboard
			// had just switched off.
			cfgMu.Lock()
			g = a.cfg.GeoBlock
			cfgMu.Unlock()
			if g.Enabled && (len(g.Countries) > 0 || len(g.AllowASNs) > 0 || len(g.BlockASNs) > 0) && g.AutoUpdate > 0 {
				if err := a.buildGeo(g); err != nil {
					slog.Error("geo auto-refresh failed", "error", err)
				}
			}
		}
	}()
}

// ---- geo blocking (country-based client blocking) ----
// Country CIDR data is fetched like blocklists (ipverse/rir-ip by
// default) and cached under the data dir. buildGeo loads it for the
// given config and hot-swaps the DNS handler's blocker: a network
// failure falls back to the last cached copy and only skips countries
// with neither, and an empty/disabled config uninstalls blocking.
//
// The same blocked-country CIDR lists drive a host-firewall DROP of all
// new inbound traffic (not just DNS): when geo blocking is on, buildGeo
// programs the native firewall — nftables when present, otherwise
// iptables + ipset — with the blocked countries' ranges. Disabling geo
// (or clearing the country list) clears those rules again. buildGeo can
// run from boot, a manual refresh and the auto-refresh goroutine at the
// same time, but the firewall Manager serialises its own Apply/Clear.
// geoMgr was created earlier (shared with client-group ASN matching);
// buildGeo below drives the country-data lifecycle.
func (a *app) buildGeo(g config.GeoBlockConfig) error {
	// A silent no-op here would be confusing: honeypots/IPs/ASN rules
	// are useless unless the feature is enabled, so say so loudly (boot
	// + every config save / refresh that hits this branch).
	if !g.Enabled && (len(g.IPs) > 0 || len(g.Honeypots) > 0 || len(g.AllowASNs) > 0 || len(g.BlockASNs) > 0) {
		slog.Warn("honeypot domains / blocked IPs / ASN rules are configured but geo_block.enabled is false — nothing is being enforced")
	}
	if !g.Enabled || (len(g.Countries) == 0 && len(g.IPs) == 0 && len(g.Honeypots) == 0 && len(g.AllowASNs) == 0 && len(g.BlockASNs) == 0) {
		a.handler.SetGeo(nil)
		a.handler.SetIPBanner(nil)
		if err := a.fwMgr.Clear(); err != nil {
			slog.Error("firewall clear failed", "error", err)
		}
		return nil
	}
	// ASN allow/block tables: the ip2asn dataset (iptoasn.com by
	// default), pruned to the configured ASNs and cached under the geo
	// dir. RefreshASN also persists asn-allowed.txt / asn-blocked.txt
	// so the firewall pass below exempts unblocked ISPs and drops
	// blocked ones at the packet level. A failure degrades: the ASN
	// rules are skipped (with a warning) while country/IP blocking
	// keeps working — same spirit as the country data fallback.
	allowASN, blockASN, asnErr := a.geoMgr.RefreshASN(a.ctx, g.AllowASNs, g.BlockASNs)
	if asnErr != nil {
		slog.Warn("ASN data load failed — ASN allow/block rules not enforced", "error", asnErr)
	}
	// Client-IP banner: configured block IPs/CIDRs plus honeypot
	// auto-blocks (loaded from a persisted file so they survive
	// restarts/reloads). A honeypot hit pushes the client straight into
	// the host firewall's drop set via OnBlock.
	banner := geoip.NewBanner(filepath.Join(a.geoDir, "blocked-ips.txt"), g.Allowlist, g.IPs, g.Honeypots)
	banner.SetASNs(allowASN, blockASN)
	a.handler.SetIPBanner(banner)
	// Opt-in: let plain-UDP honeypot hits auto-block their source too
	// (off by default — spoofed UDP must not be able to block victims).
	a.handler.SetTrustUDP(g.TrustUDP)
	// Bounded alternative to trust_udp: auto-block the source of a
	// plain-UDP honeypot hit for this window via the rate limiter
	// (expires on its own, never a permanent firewall drop).
	a.handler.SetHoneypotUDPBlock(g.HoneypotUDPBlock)
	banner.OnBlock = func(ip string) {
		if err := a.fwMgr.AddIP(ip); err != nil {
			slog.Error("firewall add blocked client failed", "ip", ip, "error", err)
		}
	}
	b, err := a.geoMgr.Refresh(a.ctx, g.Countries, g.Allowlist)
	b.SetASNs(allowASN, blockASN)
	a.handler.SetGeo(b)
	// Packet-level blocking: rebuild the firewall rules from the freshly
	// persisted CIDR lists plus the banner's full block set (configured
	// IPs and honeypot auto-blocks). A failure here (e.g. no cached data
	// yet, or no root) is logged and leaves the DNS-level REFUSED
	// blocking in effect — buildGeo's own error (data fetch) is what
	// the caller surfaces.
	if backend, ferr := a.fwMgr.Apply(g.Countries, g.Allowlist, banner.List(), a.geoDir); ferr != nil {
		slog.Error("firewall country rules not applied", "backend", backend, "error", ferr)
	} else {
		slog.Info("dropping inbound traffic from blocked countries", "backend", backend)
	}
	// Surface the ASN data failure alongside the country one so a
	// refresh that partially failed is reported as such.
	return errors.Join(err, asnErr)
}
