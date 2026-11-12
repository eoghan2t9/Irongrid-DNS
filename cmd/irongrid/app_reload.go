package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"path/filepath"
	"time"

	"github.com/eoghan2t9/Irongrid-DNS/internal/cache"
	"github.com/eoghan2t9/Irongrid-DNS/internal/cert"
	"github.com/eoghan2t9/Irongrid-DNS/internal/dnsserver"
	"github.com/eoghan2t9/Irongrid-DNS/internal/recursive"
	"github.com/eoghan2t9/Irongrid-DNS/internal/upstream"
)

// reload applies listener/cache/TLS/web changes in-process, failure-atomically:
// every new component is built before any live reference is swapped.
func (a *app) reload() error {
	// Failure-atomic ordering: build every new component first and restart
	// the listeners before swapping any live references, so a bad config
	// leaves the running server untouched.

	// Logging: cheap and side-effect-only, so applied immediately
	// regardless of how the rest of the reload turns out — a dashboard
	// change to logging.level/logging.json should not be held hostage
	// by an unrelated config problem elsewhere.
	slog.SetDefault(newLogger(a.cfg.Logging))

	// 1. Cache: connect to the new endpoint first; keep the old one on
	//    failure so a bad config never takes the server down.
	newCache, err := cache.New(a.cfg.Cache.Addr, a.cfg.Cache.Password, a.cfg.Cache.DB, a.cfg.Cache.TTL, a.cfg.Cache.NegativeTTL, a.cfg.Cache.ServeStale, resolveL1Entries(a.cfg.Cache.L1Entries))
	if err != nil {
		return fmt.Errorf("cache: %w", err)
	}
	if a.cfg.Cache.Prefetch {
		newCache.EnablePrefetch(a.handler.Refresh)
	}
	// 2. TLS: reload certificates before touching the listeners.
	newTLS, err := cert.LoadOrGenerate(a.cfg.TLS.CertFile, a.cfg.TLS.KeyFile, a.cfg.TLS.CertDir, a.cfg.TLS.SelfSignedHosts)
	if err != nil {
		_ = newCache.Close()
		return fmt.Errorf("tls: %w", err)
	}
	// 3. Upstreams: rebuild from the new specs.
	recursive.SetDefaultServerTimeout(a.cfg.Recursive.ServerTimeout)
	newUps := make([]*upstream.Upstream, 0, len(a.cfg.Upstreams))
	for _, spec := range a.cfg.Upstreams {
		up, err := upstream.Parse(spec)
		if err != nil {
			_ = newCache.Close()
			return fmt.Errorf("upstream %q: %w", spec, err)
		}
		newUps = append(newUps, up)
	}
	// Conditional route specs are parsed here too, before any live
	// reference is swapped: a bad route spec must fail the reload with
	// the running server untouched, not after SetCache/SetUpstreams have
	// already swapped (the parse is the only failing step left).
	newRoutes, err := dnsserver.ParseRoutes(routeSpecs(a.cfg.UpstreamRoutes))
	if err != nil {
		_ = newCache.Close()
		return fmt.Errorf("upstream routes: %w", err)
	}
	newACL, err := dnsserver.BuildACL(a.cfg.Server.AllowFrom)
	if err != nil {
		_ = newCache.Close()
		return fmt.Errorf("server.allow_from: %w", err)
	}
	// A reload can introduce recursive:// upstreams when none were
	// configured at boot (hintsMgr was never created). Start the manager
	// so they get the authoritative root hints too, not just the bundled
	// fallback. Once running it keeps refreshing weekly, covering any
	// later reloads as well.
	if a.hintsMgr == nil {
		hasRec := false
		for _, up := range newUps {
			if up.Transport == upstream.Recursive {
				hasRec = true
				break
			}
		}
		if hasRec {
			a.hintsMgr = recursive.NewHintsManager(recursive.RootHintsURL, filepath.Join(a.dataDir, "root-hints.txt"), recursive.DefaultRefreshInterval)
			a.hintsMgr.Refresh(a.ctx)
			a.hintsMgr.Start(a.ctx)
			a.apiHandler.Hints = a.hintsMgr
			st := a.hintsMgr.Status()
			slog.Info("root hints manager started on config reload", "source", st.Source, "addresses", st.Addresses, "pgp_verified", st.Verified)
		}
	}

	// 4. Restart the DNS listeners with the new addresses + TLS. This is
	//    the only step that can fail with hard bind errors, so it runs
	//    before anything is swapped. Note: UDP/TCP/DoT bind failures are
	//    reported asynchronously via the results channel, not as errors.
	a.dnsMgr.SetUDPSockets(a.cfg.Server.UDPSockets)
	a.dnsMgr.SetUDPWorkers(a.cfg.Server.UDPWorkers)
	a.dnsMgr.SetConnLimits(a.cfg.Server.MaxTCPConnsPerIP, a.cfg.Server.MaxHTTPConnsPerIP)
	// Proxy trust and the DoH ASN header are read per request, so they
	// are re-applied without a listener restart (the reload has already
	// validated them via the config check below, so a failure here is
	// unreachable — logged defensively only).
	if err := a.dnsMgr.SetProxyConfig(a.cfg.Server.TrustedProxies, a.cfg.Server.XFFHopLimit); err != nil {
		slog.Error("invalid server.trusted_proxies on reload", "error", err)
	}
	a.dnsMgr.SetDoHASNHeader(a.cfg.Server.DoHASNHeader)
	if err := a.dnsMgr.Restart(
		a.cfg.Server.ListenUDP, a.cfg.Server.ListenTCP,
		a.cfg.Server.ListenDoT, a.dohAddr(), a.cfg.Server.ListenDoH3, a.cfg.Server.ListenDoQ,
		a.cfg.Server.DoHPath, newTLS,
	); err != nil {
		_ = newCache.Close()
		return fmt.Errorf("dns listeners: %w", err)
	}

	// 5. Now swap the hot references — listeners are already serving with
	//    the new TLS config, so this only changes cache/upstreams/policy.
	a.handler.SetCache(newCache)
	a.handler.SetUpstreams(newUps)
	a.handler.SetUpstreamMode(a.cfg.UpstreamMode)
	a.handler.SetUpstreamRoutes(newRoutes)
	a.handler.SetBlockPolicy(a.cfg.Filter.BlockResponse, a.cfg.Filter.BlockTTL)
	a.handler.SetTimeout(time.Duration(a.cfg.Server.TimeoutSec) * time.Second)
	a.handler.SetFailureTTL(a.cfg.Cache.FailureTTL)
	newCache.SetLookupTimeout(a.cfg.Cache.LookupTimeout)
	a.handler.SetRewriter(dnsserver.BuildRewriter(a.cfg.Rewrites))
	// Reload picks up client-group ASN changes (and the data itself) from
	// the freshly re-read config, like every other hot knob below.
	a.groupASN = a.refreshGroupASN(a.cfg)
	a.apiHandler.GroupASN.Store(a.groupASN)
	a.handler.SetClientRouter(dnsserver.BuildClientRouter(a.cfg, a.lists, a.groupASN))
	a.handler.SetRateLimiter(dnsserver.BuildRateLimiter(a.cfg.RateLimit))
	a.handler.SetNXGuard(dnsserver.BuildNXGuard(a.cfg.RateLimit.NXGuard))
	a.handler.SetRepeatGuard(dnsserver.BuildRepeatGuard(a.cfg.RateLimit.RepeatQuery))
	a.handler.SetRepeatQueryBlockFor(a.cfg.RateLimit.RepeatQuery.BlockFor)
	a.handler.SetRepeatQueryUDPBlockFor(a.cfg.RateLimit.RepeatQuery.UDPBlockFor)
	a.handler.SetDNSSEC(a.cfg.DNSSEC.Enabled, a.cfg.DNSSEC.RequireAD)
	a.handler.SetCNAMECloakingProtection(a.cfg.Filter.CNAMECloakingProtection)
	if a.cfg.DNSSEC.ValidateLocally {
		a.startDNSSECAnchors()
	}
	a.handler.SetDNSSECValidateLocally(a.cfg.DNSSEC.ValidateLocally)
	a.handler.SetACL(newACL)
	a.handler.SetUpstreamHealthCheck(a.cfg.UpstreamHealth.Enabled)
	a.handler.SetPadding(a.cfg.Server.Padding)
	a.handler.SetCookies(a.cfg.Server.Cookies)
	a.handler.SetDDR(a.ddrConfig())
	// DHCP: pool/option/static changes apply immediately (handlers read
	// them per packet); a bind change (interface, enable state, subnet)
	// restarts the packet listeners without dropping leases. Capture the
	// old bind state before SetConfig swaps the runtime config.
	wasRunning := a.dhcpSrv.Enabled()
	wasIface := a.dhcpSrv.Interface()
	newDHCP := buildDHCPRuntime(a.cfg.DHCP)
	a.dhcpSrv.SetConfig(newDHCP)
	wantRunning := a.cfg.DHCP.Enabled && (a.cfg.DHCP.Subnet != "" || (a.cfg.DHCP.IPv6 && a.cfg.DHCP.IPv6Prefix != ""))
	// Restart when the enable state flipped, or when the NIC the
	// listeners bind changed (the server itself is always running in
	// this build, so wasRunning stays true across an interface edit).
	if wasRunning != wantRunning || (wantRunning && wasIface != a.cfg.DHCP.Interface) {
		if wantRunning {
			var err error
			if wasRunning {
				// Already bound: rebind to the new interface without
				// dropping the lease table.
				err = a.dhcpSrv.RestartListeners()
			} else {
				err = a.dhcpSrv.Start()
			}
			if err != nil {
				slog.Error("dhcp listener start failed", "error", err)
			}
		} else {
			a.dhcpSrv.Stop()
		}
	}
	// Geo blocking is hot-swapped asynchronously (see RebuildGeo).
	if a.apiHandler.RebuildGeo != nil {
		if err := a.apiHandler.RebuildGeo(a.cfg.GeoBlock); err != nil {
			slog.Warn("rebuild geo block on reload failed", "error", err)
		}
	}
	// VPN split-tunnel profiles/routes: reconciled asynchronously, like
	// geo blocking above — (re)connecting a profile can involve a slow
	// round trip to the vendor's API and must not hold up the rest of
	// this reload.
	go func() {
		profiles, routes, creds := vpnReconcileArgs(a.cfg.VPN)
		if err := a.vpnMgr.Reconcile(a.ctx, profiles, routes, creds); err != nil {
			slog.Error("vpn: reconcile failed", "error", err)
		}
	}()
	a.apiHandler.Cache = newCache
	a.apiHandler.Upstreams = newUps
	oldCache := a.dfly
	a.dfly = newCache
	_ = oldCache.Close()

	// 6. Rebind the web server if its address or TLS mode changed. Shutdown
	//    is run in a goroutine: calling Shutdown synchronously from inside
	//    a request served by the same server would wait on the in-flight
	//    handler and deadlock, and the delay lets the reload flush first.
	a.webMu.Lock()
	addrChanged := a.webSrv.Addr != a.cfg.Server.WebListen
	tlsChanged := a.webTLSServing != a.cfg.Server.WebTLS
	if addrChanged || tlsChanged {
		oldWeb := a.webSrv
		newWeb := &http.Server{
			Addr:         a.cfg.Server.WebListen,
			Handler:      a.webHandler(),
			ConnState:    a.dnsMgr.HTTPConnState(),
			ReadTimeout:  30 * time.Second,
			WriteTimeout: 30 * time.Second,
		}
		a.webSrv = newWeb
		a.webTLSServing = a.cfg.Server.WebTLS
		useTLS := a.webTLSServing
		a.webMu.Unlock()
		go func() {
			time.Sleep(200 * time.Millisecond) // let the reload response flush
			_ = oldWeb.Shutdown(context.Background())
			a.startWebServer(newWeb, useTLS)
		}()
	} else {
		a.webMu.Unlock()
	}
	// 7. Start/stop the ACME manager to match the new config: toggling
	//    tls.acme.enabled in the dashboard takes effect without a restart.
	if a.cfg.TLS.ACME.Enabled {
		// If the web_tls/web_redirect/port combination that decides
		// ExternalHTTP01 changed, recreate the manager so it doesn't keep
		// a stale challenge-listener arrangement (e.g. both listeners
		// fighting for port 80).
		httpPort := a.cfg.TLS.ACME.HTTP01Port
		if httpPort == 0 {
			httpPort = 80
		}
		redirectPort := a.cfg.Server.WebRedirectPort
		if redirectPort == 0 {
			redirectPort = 80
		}
		wantExternal := a.cfg.Server.WebTLS && a.cfg.Server.WebRedirect && redirectPort == httpPort
		if wantExternal != a.acmeExternalHTTP01 {
			a.stopACME()
			a.acmeExternalHTTP01 = wantExternal
		}
		a.startACME()
		if m := a.acmeMgr.Load(); m != nil && m.OnIssued == nil {
			m.OnIssued = func() {
				if err := a.apiHandler.ReloadTLS(); err != nil {
					slog.Error("acme reload after issuance failed", "error", err)
				}
			}
		}
	} else {
		a.stopACME()
	}
	// Re-evaluate the HTTP->HTTPS redirect listener on every reload: it
	// starts/stops/keeps itself based on the new web_tls/web_redirect config.
	a.startRedirect()
	slog.Info("config reload applied: listeners, cache, TLS, upstreams")
	return nil
}
