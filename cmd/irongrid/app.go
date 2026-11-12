package main

import (
	"context"
	"crypto/tls"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/eoghan2t9/Irongrid-DNS/internal/acme"
	"github.com/eoghan2t9/Irongrid-DNS/internal/api"
	"github.com/eoghan2t9/Irongrid-DNS/internal/cache"
	"github.com/eoghan2t9/Irongrid-DNS/internal/catalog"
	"github.com/eoghan2t9/Irongrid-DNS/internal/cert"
	"github.com/eoghan2t9/Irongrid-DNS/internal/cfupdate"
	"github.com/eoghan2t9/Irongrid-DNS/internal/config"
	"github.com/eoghan2t9/Irongrid-DNS/internal/dhcp"
	"github.com/eoghan2t9/Irongrid-DNS/internal/dnssec"
	"github.com/eoghan2t9/Irongrid-DNS/internal/dnsserver"
	"github.com/eoghan2t9/Irongrid-DNS/internal/filter"
	"github.com/eoghan2t9/Irongrid-DNS/internal/firewall"
	"github.com/eoghan2t9/Irongrid-DNS/internal/geoip"
	"github.com/eoghan2t9/Irongrid-DNS/internal/querylog"
	"github.com/eoghan2t9/Irongrid-DNS/internal/recursive"
	"github.com/eoghan2t9/Irongrid-DNS/internal/tuning"
	"github.com/eoghan2t9/Irongrid-DNS/internal/tunnel"
	"github.com/eoghan2t9/Irongrid-DNS/internal/upstream"
	"github.com/eoghan2t9/Irongrid-DNS/internal/version"
	"github.com/eoghan2t9/Irongrid-DNS/internal/vpn"
	"github.com/eoghan2t9/Irongrid-DNS/web"
)

// app holds the state shared between the startup phases and the config-reload
// hooks. It replaces the ~30 locals that one 1,200-line main() used to share
// through closures; behaviour is unchanged.
type app struct {
	cfg        *config.Config
	ctx        context.Context
	configPath string
	dataDir    string

	dfly      *cache.Cache
	hintsMgr  *recursive.HintsManager
	upstreams []*upstream.Upstream
	engine    *filter.Engine
	lists     *filter.ListManager
	ql        *querylog.Log
	tlsConf   *tls.Config
	handler   *dnsserver.Handler
	warmer    *dnsserver.Warmer

	geoMgr   *geoip.Manager
	geoDir   string
	groupASN *geoip.ASNTable
	fwMgr    *firewall.Manager

	apiHandler *api.Handler
	apiApp     *api.App

	dnssecAnchors        *dnssec.AnchorManager
	dnssecAnchorsStarted bool

	dhcpSrv   *dhcp.Server
	dnsMgr    *dnsserver.Manager
	tunnelMgr *tunnel.Manager
	vpnMgr    *vpn.Manager

	acmeMgr            atomic.Pointer[acme.Manager]
	acmeExternalHTTP01 bool

	// webMu serialises web-server rebinding between the ACME RunLoop goroutine
	// (OnIssued) and the config reload hook, which both swap webSrv.
	webMu         sync.Mutex
	webSrv        *http.Server
	webTLSServing bool
	redirectSrv   *http.Server
}

// setupCache connects to Dragonfly, the hard requirement for the DNS cache.
func (a *app) setupCache() {
	var err error
	// ---- Dragonfly cache (hard requirement) ----
	a.dfly, err = cache.New(a.cfg.Cache.Addr, a.cfg.Cache.Password, a.cfg.Cache.DB, a.cfg.Cache.TTL, a.cfg.Cache.NegativeTTL, a.cfg.Cache.ServeStale, resolveL1Entries(a.cfg.Cache.L1Entries))
	if err != nil {
		slog.Error("cache init failed — Dragonfly is a hard requirement, start it (see docker-compose.yml) and retry", "error", err)
		os.Exit(1)
	}
	// The client is closed by main() at process exit, not here: a defer in
	// this helper would run as soon as setupCache returns and leave every
	// later cache call failing with "redis: client is closed".
	slog.Info("Dragonfly caching enabled", "positive_ttl", a.cfg.Cache.TTL, "negative_ttl", a.cfg.Cache.NegativeTTL)

	// ---- validate Dragonfly config against system specs ----
	// Warns (never rewrites or restarts Dragonfly — see ValidateDragonfly's
	// doc comment) if its maxmemory/proactor_threads don't match what this
	// host's resources call for, e.g. after a resize. Async since it shells
	// out to python3 for a Redis INFO call; no reason boot should wait on it.
	go tuning.ValidateDragonfly(a.cfg.Cache.Addr)
}

// setupRootHints seeds recursive:// upstreams with the authoritative root hints.
func (a *app) setupRootHints() {
	// ---- authoritative root hints for recursive upstreams ----
	// recursive:// upstreams walk referrals from the root servers; seed them
	// from IANA's named.root file instead of the bundled snapshot so a
	// root-server address change is picked up without a release. The fetch
	// runs before upstreams are parsed (each resolver snapshots the default
	// hints at construction) and falls back to a last-known-good copy on
	// disk, then to the bundled hints, so boot never depends on network
	// access. SetDefaultRootHints also covers per-client-group upstreams and
	// any created by a later config reload.
	hasRecursive := slices.ContainsFunc(a.cfg.Upstreams, upstream.IsRecursiveSpec)
	if hasRecursive {
		// The manager fetches the authoritative named.root at boot, verifies
		// its detached PGP signature, persists a last-known-good copy on
		// disk and refreshes weekly while the server runs. The initial
		// Refresh runs synchronously before upstreams are parsed (each
		// resolver snapshots the default hints at construction); any
		// failure falls back to the disk cache and then the bundled hints,
		// so boot never depends on network access.
		a.hintsMgr = recursive.NewHintsManager(recursive.RootHintsURL, filepath.Join(a.dataDir, "root-hints.txt"), recursive.DefaultRefreshInterval)
		a.hintsMgr.Refresh(a.ctx)
		st := a.hintsMgr.Status()
		detail := ""
		if st.LastError != "" {
			detail = " — " + st.LastError
		}
		slog.Info("root hints loaded", "source", st.Source, "addresses", st.Addresses, "pgp_verified", st.Verified, "detail", detail)
		a.hintsMgr.Start(a.ctx)
	}
}

// setupUpstreams parses the configured upstream specs.
func (a *app) setupUpstreams() {
	// ---- upstreams ----
	// recursive.server_timeout tunes the per-server exchange timeout used by
	// recursive:// referral walks. Applied as a package-level default (read
	// at query time) so every resolver — boot, reload and per-client-group —
	// picks it up.
	recursive.SetDefaultServerTimeout(a.cfg.Recursive.ServerTimeout)
	for _, spec := range a.cfg.Upstreams {
		up, err := upstream.Parse(spec)
		if err != nil {
			slog.Error("invalid upstream", "spec", spec, "error", err)
			os.Exit(1)
		}
		a.upstreams = append(a.upstreams, up)
		slog.Info("upstream configured", "name", up.Name(), "address", up.Address())
	}
}

// setupFilter builds the filter engine and blocklist manager and starts refreshes.
func (a *app) setupFilter() {
	// ---- filter engine + blocklists ----
	a.engine = filter.NewEngine()
	a.engine.SetUserLists(a.cfg.Filter.Blacklist, a.cfg.Filter.Whitelist)

	listsDir := filepath.Join(a.dataDir, "lists")
	a.lists = filter.NewListManager(a.engine, listsDir)
	specs := make([]filter.ListSpec, 0, len(a.cfg.Filter.Blocklists))
	for _, s := range a.cfg.Filter.Blocklists {
		specs = append(specs, filter.ListSpec{ID: s.ID, Name: s.Name, URL: s.URL, Enabled: s.Enabled})
	}
	a.lists.SetSpecs(specs)
	a.lists.SetAutoUpdate(a.cfg.Filter.AutoUpdate)
	a.lists.LoadCached()
	a.lists.ReloadAll()
	a.lists.StartRefresh(a.ctx)

	// Async: the engine above is already compiled and serving from
	// LoadCached()+ReloadAll(), so this network refresh no longer needs to
	// hold up boot (same reasoning as the geo_block fetch above).
	go func() {
		// Retries the failed lists with backoff: the first attempt races the
		// DNS listener (we resolve list hosts through ourselves), and also
		// recompiles the engine when any list was refreshed.
		if err := a.lists.FetchAllWithRetry(a.ctx); err != nil {
			slog.Warn("blocklist fetch still failing after retries, using cached content", "error", err)
		}
	}()
}

// setupQueryLog opens the query log (a Dragonfly stream) and starts its pruner.
func (a *app) setupQueryLog() {
	var err error
	// ---- query log (Dragonfly stream, same tier as the DNS cache) ----
	a.ql, err = querylog.New(a.cfg.Cache.Addr, a.cfg.Cache.Password, a.cfg.Cache.DB, a.cfg.Log.RetentionDays, a.cfg.Log.BatchSize)
	if err != nil {
		slog.Error("query log init failed", "error", err)
		os.Exit(1)
	}
	a.ql.StartPruner(a.ctx)
}

// setupTLS loads (or generates) the certificate used by DoT/DoH/DoQ.
func (a *app) setupTLS() {
	var err error
	// ---- TLS for DoT / DoH / DoQ ----
	a.tlsConf, err = cert.LoadOrGenerate(
		a.cfg.TLS.CertFile, a.cfg.TLS.KeyFile,
		a.cfg.TLS.CertDir, a.cfg.TLS.SelfSignedHosts)
	if err != nil {
		slog.Error("tls init failed", "error", err)
		os.Exit(1)
	}
}

// setupHandler creates the DNS handler, prefetch and the cache warmer.
func (a *app) setupHandler() {
	// ---- DNS handler + listeners ----
	a.handler = dnsserver.NewHandler(
		a.engine, a.dfly, a.upstreams, a.ql,
		a.cfg.Filter.BlockResponse, a.cfg.Filter.BlockTTL,
		time.Duration(a.cfg.Server.TimeoutSec)*time.Second,
	)
	// Prefetch: the cache refreshes hot entries in the background shortly
	// before they expire, resolving through the handler's current upstreams
	// (which reload swaps atomically). Gated on cache.prefetch.
	if a.cfg.Cache.Prefetch {
		a.dfly.EnablePrefetch(a.handler.Refresh)
	}
	// Cache-read budget on the hot path (cache.lookup_timeout; 0 = default).
	a.dfly.SetLookupTimeout(a.cfg.Cache.LookupTimeout)
	// Failure-cache lifetime for unreachable upstreams (cache.failure_ttl;
	// 0 = use cache.negative_ttl; default 5s so a recovery is visible
	// quickly).
	a.handler.SetFailureTTL(a.cfg.Cache.FailureTTL)
	// Proactive cache warmer: scans the query log for the domains queried
	// within the lookback window and pre-resolves them (A + AAAA) through
	// the current upstreams into the cache, so a restart or cache flush
	// doesn't leave the first query for each domain cold. A pass runs
	// immediately at boot and then every interval. Gated on warmer.enabled
	// (off by default — warming uses upstreams even when nobody is asking).
	a.warmer = dnsserver.NewWarmer(a.handler, a.ql)
	a.warmer.SetConfig(a.cfg.Warmer)
	a.warmer.Start(a.ctx)
}

// setupPolicy applies filtering/rate-limit/DNSSEC/ACL policy to the handler and
// builds the IP-to-ASN manager used by geo blocking and client groups.
func (a *app) setupPolicy() {
	var err error
	// ---- IP→ASN data (shared by geo_block rules and client-group ASN
	// matching) ----
	// The manager downloads the free ip2asn dataset (iptoasn.com by default)
	// into the geo data dir; created here — before the client router below —
	// because client groups can match clients by ASN. apiHandler is declared
	// here too so the blocklist-change hook below (which fires after this
	// point) can read the published group table.
	a.geoDir = filepath.Join(a.dataDir, "geo")
	a.geoMgr = geoip.NewManager(a.geoDir, a.cfg.GeoBlock.BaseURL)
	a.geoMgr.SetASNBaseURL(a.cfg.GeoBlock.ASNBaseURL)
	a.groupASN = a.refreshGroupASN(a.cfg)
	a.handler.SetRewriter(dnsserver.BuildRewriter(a.cfg.Rewrites))
	a.handler.SetClientRouter(dnsserver.BuildClientRouter(a.cfg, a.lists, a.groupASN))
	a.handler.SetRateLimiter(dnsserver.BuildRateLimiter(a.cfg.RateLimit))
	a.handler.SetNXGuard(dnsserver.BuildNXGuard(a.cfg.RateLimit.NXGuard))
	a.handler.SetRepeatGuard(dnsserver.BuildRepeatGuard(a.cfg.RateLimit.RepeatQuery))
	a.handler.SetRepeatQueryBlockFor(a.cfg.RateLimit.RepeatQuery.BlockFor)
	a.handler.SetRepeatQueryUDPBlockFor(a.cfg.RateLimit.RepeatQuery.UDPBlockFor)
	a.handler.SetDNSSEC(a.cfg.DNSSEC.Enabled, a.cfg.DNSSEC.RequireAD)
	a.handler.SetCNAMECloakingProtection(a.cfg.Filter.CNAMECloakingProtection)
	// ---- DNSSEC local chain-of-trust validation (dnssec.validate_locally) ----
	// The AnchorManager is always constructed (cheap: pre-seeded with a
	// bundled default, no network call yet) so a later reload can turn
	// validation on without a restart; its live IANA fetch + periodic
	// refresh only start the first time the feature is actually enabled,
	// so a deployment that never opts in never makes this network call.
	a.dnssecAnchors = dnssec.NewAnchorManager("", filepath.Join(a.dataDir, "root-anchors.xml"), 0)
	a.handler.DNSSECValidator = dnssec.NewValidator(a.dnssecAnchors)
	a.dnssecAnchorsStarted = false
	if a.cfg.DNSSEC.ValidateLocally {
		a.startDNSSECAnchors()
	}
	a.handler.SetDNSSECValidateLocally(a.cfg.DNSSEC.ValidateLocally)
	// Query ACL (server.allow_from): parsed up front, like upstreams and
	// routes, so a bad CIDR/IP entry aborts boot instead of silently
	// leaving the server open.
	acl, err := dnsserver.BuildACL(a.cfg.Server.AllowFrom)
	if err != nil {
		slog.Error("invalid server.allow_from", "error", err)
		os.Exit(1)
	}
	a.handler.SetACL(acl)
	// Proactive upstream health probing (upstream_health.enabled): the
	// ticker runs for the life of the process and re-reads the enabled
	// flag from live settings every tick, so a later reload just toggles
	// it — no restart needed.
	a.handler.SetUpstreamHealthCheck(a.cfg.UpstreamHealth.Enabled)
	a.handler.StartUpstreamHealthCheck(a.ctx)
	// RFC 7830 response padding and RFC 7873 DNS cookies (server.padding /
	// server.cookies). Re-applied on every reload below so a dashboard
	// toggle applies without a restart.
	a.handler.SetPadding(a.cfg.Server.Padding)
	a.handler.SetCookies(a.cfg.Server.Cookies)
	a.handler.SetDDR(a.ddrConfig())
}

// ddrConfig builds the RFC 9462 Discovery of Designated Resolvers answer from
// the listener config. The advertised host is server.discovery_host, falling
// back to the first ACME domain (the name the certificate is issued for).
// Returns nil — advertise nothing — when neither is set.
func (a *app) ddrConfig() *dnsserver.DDRConfig {
	s := a.cfg.Server
	host := s.DiscoveryHost
	if host == "" && a.cfg.TLS.ACME.Enabled && len(a.cfg.TLS.ACME.Domains) > 0 {
		host = a.cfg.TLS.ACME.Domains[0]
	}
	return dnsserver.NewDDRConfig(host, s.ListenDoT, s.ListenDoH, s.ListenDoH3, s.ListenDoQ, s.DoHPath)
}

// startDNSSECAnchors starts the live IANA anchor fetch + refresh the first time local
// validation is enabled.
func (a *app) startDNSSECAnchors() {
	if a.dnssecAnchorsStarted {
		return
	}
	a.dnssecAnchorsStarted = true
	a.dnssecAnchors.Refresh(a.ctx)
	a.dnssecAnchors.Start(a.ctx)
}

// setupDHCP starts the built-in DHCP server when enabled.
func (a *app) setupDHCP() {
	// ---- built-in DHCP server (LAN feature, off by default) ----
	// Hands out IPv4 (RFC 2131) and optionally IPv6 (RFC 8415) addresses
	// from the config-driven pool, persists leases under the data dir, and
	// registers client hostnames so <hostname>.<domain> (and the bare
	// hostname) resolve locally through the DNS handler — Pi-hole style.
	// Only wired when the feature is enabled in the config; the DHCP server
	// lives for the process, so the DNS handler's DHCPHosts hook is set once
	// here and never swapped.
	a.dhcpSrv = dhcp.New(filepath.Join(a.dataDir, "dhcp"))
	a.dhcpSrv.SetConfig(buildDHCPRuntime(a.cfg.DHCP))
	if a.dhcpSrv.Enabled() {
		if err := a.dhcpSrv.Start(); err != nil {
			slog.Warn("dhcp failed to start, feature disabled", "error", err)
		} else {
			slog.Info("dhcp server enabled", "summary", dhcpSummary(a.cfg.DHCP))
		}
	}
	a.handler.DHCPHosts = a.dhcpSrv
}

// setupRouting applies the upstream mode and conditional routes, and wires list
// changes to per-client-group engines.
func (a *app) setupRouting() {
	var err error
	// Multi-upstream resolution strategy (config upstream_mode: race or
	// sequential). NewHandler defaults to race; apply the configured value.
	a.handler.SetUpstreamMode(a.cfg.UpstreamMode)
	// Conditional (split-horizon) routing: per-domain upstream sets that win
	// over the global forwarders and client-group overrides (e.g. "lan" ->
	// a local resolver so internal names never reach public resolvers).
	// Parsed up front (SetUpstreamRoutes itself cannot fail) so a bad route
	// spec aborts boot exactly like a bad upstream spec; re-applied on every
	// reload below, so a config change never needs a restart.
	routeUps, err := dnsserver.ParseRoutes(routeSpecs(a.cfg.UpstreamRoutes))
	if err != nil {
		slog.Error("invalid upstream routes", "error", err)
		os.Exit(1)
	}
	a.handler.SetUpstreamRoutes(routeUps)
	// Rebuild per-client-group engines whenever blocklist content changes
	// (auto-refresh ticker, manual "refresh all lists") — they're built from
	// the same cached content the global engine uses. The ASN table is
	// unchanged by a list refresh, so the published one is reused.
	a.lists.SetOnChange(func() {
		if a.apiHandler == nil {
			return
		}
		a.handler.SetClientRouter(dnsserver.BuildClientRouter(a.cfg, a.lists, a.apiHandler.GroupASN.Load()))
	})
}

// setupDNSListeners creates the listener manager and starts every DNS listener.
func (a *app) setupDNSListeners() {
	var err error
	a.dnsMgr = dnsserver.NewManager(a.handler, a.tlsConf)
	// SO_REUSEPORT socket count for the plain UDP and DoQ listeners
	// (server.udp_sockets: 0 = auto, 1 = exclusive single socket, N =
	// explicit). Re-applied before every listener restart below.
	a.dnsMgr.SetUDPSockets(a.cfg.Server.UDPSockets)
	// Handler-worker count per plain-UDP socket (server.udp_workers: 0 =
	// auto, N = exactly N per socket). Same lifecycle as udp_sockets.
	a.dnsMgr.SetUDPWorkers(a.cfg.Server.UDPWorkers)
	// Per-IP concurrent-connection caps (server.max_tcp_conns_per_ip /
	// server.max_http_conns_per_ip; 0 = unlimited). Same lifecycle.
	a.dnsMgr.SetConnLimits(a.cfg.Server.MaxTCPConnsPerIP, a.cfg.Server.MaxHTTPConnsPerIP)
	// DoH client identification (server.trusted_proxies / xff_hop_limit):
	// which reverse-proxy peers may stamp X-Forwarded-For beyond
	// loopback/private ones, and how many trusted hops the chain may
	// contain — the client IP those rules produce drives geo/ASN blocking,
	// rate limiting and per-client policy, so a public reverse proxy in
	// front of DoH must be listed here or only the proxy's own address is
	// ever seen. Plus the per-response ASN header (server.doh_asn_header).
	// Both are re-applied on every reload below; the DoH handler reads them
	// per request, so no listener restart is needed.
	if err := a.dnsMgr.SetProxyConfig(a.cfg.Server.TrustedProxies, a.cfg.Server.XFFHopLimit); err != nil {
		slog.Error("invalid server.trusted_proxies", "error", err)
		os.Exit(1)
	}
	a.dnsMgr.SetDoHASNHeader(a.cfg.Server.DoHASNHeader)
	if a.webSharesDoH() {
		slog.Info("dashboard and DoH sharing listener, serving /dns-query on the dashboard HTTPS listener", "addr", a.cfg.Server.WebListen)
	}
	results, err := a.dnsMgr.Start(
		a.cfg.Server.ListenUDP, a.cfg.Server.ListenTCP,
		a.cfg.Server.ListenDoT, a.dohAddr(), a.cfg.Server.ListenDoH3, a.cfg.Server.ListenDoQ,
		a.cfg.Server.DoHPath,
	)
	if err != nil {
		slog.Error("dns listeners failed to start", "error", err)
		os.Exit(1)
	}
	// Report listener bind errors (e.g. port 53 already in use).
	go func() {
		for res := range results {
			if res.Err != nil {
				slog.Error("dns listener failed", "proto", res.Proto, "addr", res.Addr, "error", res.Err)
			}
		}
	}()
}

// webSharesDoH reports whether the dashboard and DoH share one HTTPS port
// (server.web_listen == server.listen_doh with web_tls on). In that case
// the web server also serves /dns-query and no standalone DoH listener is
// started. Computed from cfg at call time so reloads pick up changes.
func (a *app) webSharesDoH() bool {
	return a.cfg.Server.WebTLS && a.cfg.Server.ListenDoH != "" && a.cfg.Server.WebListen != "" &&
		webTLSPort(a.cfg.Server.ListenDoH) == webTLSPort(a.cfg.Server.WebListen)
}

// dohAddr is the address the DNS manager should bind DoH on: empty when
// the web server serves /dns-query on the shared HTTPS port.
func (a *app) dohAddr() string {
	if a.webSharesDoH() {
		return ""
	}
	return a.cfg.Server.ListenDoH
}

// setupTunnelVPN creates the cloudflared tunnel manager and starts VPN routing.
func (a *app) setupTunnelVPN() {
	// ---- cloudflared tunnel (managed subprocess; binary auto-installed below) ----
	a.tunnelMgr = tunnel.NewManager(a.dataDir)

	// ---- VPN split-tunnel routing (domain-based, WireGuard via NordVPN/PIA) ----
	a.vpnMgr = vpn.NewManager()
	a.handler.SetVPNRouter(a.vpnMgr)
	// Bringing up tunnels means a network round trip to the vendor's
	// account API per profile (plus shelling out to ip/wg/nft) — reconcile
	// in the background so a slow or unreachable VPN provider never delays
	// the DNS server itself starting to serve queries.
	go func() {
		profiles, routes, creds := vpnReconcileArgs(a.cfg.VPN)
		if err := a.vpnMgr.Reconcile(a.ctx, profiles, routes, creds); err != nil {
			slog.Error("vpn: reconcile failed", "error", err)
		}
	}()
	// The Smart-DNS proxy relay (config.VPNProxyConfig): makes Proxy-enabled
	// routes work for clients that only use this server for DNS, not just
	// ones whose IP traffic already passes through this host. Public-IP
	// detection is cheap and local; the relay's listeners only bind when
	// vpn.proxy.enabled is true.
	applyVPNPublicIP(a.vpnMgr, a.cfg.VPN.Proxy)
	applyVPNProxy(a.vpnMgr, a.cfg.VPN.Proxy, a.cfg.Server.WebListen)
}

// setupAPI builds the REST API handler and web app.
func (a *app) setupAPI() {
	// ---- REST API + web UI ----
	var webFS fs.FS
	if web.HasFrontend() {
		webFS = web.FS()
	} else {
		slog.Warn("frontend not embedded — run `make web build` for the dashboard")
	}

	saveConfig := func() error { return a.cfg.Save(a.configPath) }
	a.apiApp = &api.App{
		Config:     a.cfg,
		ConfigPath: a.configPath,
		SaveConfig: saveConfig,
		WebFS:      webFS,
	}
	a.apiHandler = &api.Handler{
		Cfg:        a.cfg,
		ConfigPath: a.configPath,
		SaveConfig: saveConfig,
		Engine:     a.engine,
		Lists:      a.lists,
		Cache:      a.dfly,
		Log:        a.ql,
		DNS:        a.handler,
		DNSManager: a.dnsMgr,
		Tunnel:     a.tunnelMgr,
		VPN:        a.vpnMgr,
		Upstreams:  a.upstreams,
		Hints:      a.hintsMgr,
		Catalog:    catalog.Default(),
		StartedAt:  time.Now(),
		Version:    version.Version,
		Warmer:     a.warmer,
		DHCP:       a.dhcpSrv,
	}
	// Publish the boot-time client-group ASN table (the router was built
	// with it above; the API's config-apply path reads it from here).
	a.apiHandler.GroupASN.Store(a.groupASN)
	a.apiApp.Handler = a.apiHandler
	// authorize/validSession/issueSession snapshot the auth fields under the
	// same mutex applyPayload uses, so a session-secret rotation can never be
	// read as a torn mix.
	a.apiApp.Mu = a.apiHandler.ConfigMu()
}

// startCloudflared keeps the managed cloudflared binary up to date (best effort).
func (a *app) startCloudflared() {
	// ---- keep the managed cloudflared binary up to date ----
	// Runs once per process start (i.e. on every restart), always-on and
	// best-effort: a slow or failed GitHub check must never block the rest
	// of the server, so it runs synchronously but bounded, right before the
	// tunnel would auto-start — everything else in main has already bound
	// its listeners by this point.
	{
		cfCtx, cfCancel := context.WithTimeout(context.Background(), 30*time.Second)
		cfRes, cfErr := (&cfupdate.Client{}).Install(cfCtx, a.tunnelMgr.BinaryPath())
		cfCancel()
		binStatus := tunnel.BinaryStatus{LastChecked: time.Now()}
		switch {
		case cfErr != nil:
			slog.Warn("cloudflared update check failed", "error", cfErr)
			binStatus.Version = cfupdate.CurrentVersion(a.tunnelMgr.BinaryPath())
			binStatus.LastError = cfErr.Error()
		case cfRes.Installed:
			slog.Info("cloudflared updated", "from", cfRes.PreviousVersion, "to", cfRes.NewVersion)
			binStatus.Version = cfRes.NewVersion
			binStatus.LatestVersion = cfRes.NewVersion
		default:
			slog.Info("cloudflared up to date", "version", cfRes.NewVersion)
			binStatus.Version = cfRes.NewVersion
			binStatus.LatestVersion = cfRes.NewVersion
		}
		a.tunnelMgr.SetBinaryStatus(binStatus)
	}
}

// startTunnel auto-starts the tunnel when configured.
func (a *app) startTunnel() {
	// ---- auto-start tunnel if configured ----
	// The API is already serving by now and PUT /api/config mutates cfg under
	// this mutex, so snapshot the tunnel settings under it too.
	mu := a.apiHandler.ConfigMu()
	mu.Lock()
	t := a.cfg.Tunnel
	mu.Unlock()
	if t.Enabled {
		mode := tunnel.ModeConfig
		if t.Token != "" {
			mode = tunnel.ModeToken
		} else if t.QuickTunnel {
			mode = tunnel.ModeQuick
		}
		if err := a.tunnelMgr.Start(mode, t.Token, t.ConfigFile, t.QuickTunnelURL, t.Hostname); err != nil {
			slog.Error("tunnel failed to start", "error", err)
		} else {
			slog.Info("tunnel started", "mode", mode)
		}
	}
}
