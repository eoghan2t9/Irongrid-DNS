package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/net/http2"

	"github.com/eoghan2t9/Irongrid-DNS/internal/acme"
	"github.com/eoghan2t9/Irongrid-DNS/internal/api"
	"github.com/eoghan2t9/Irongrid-DNS/internal/cache"
	"github.com/eoghan2t9/Irongrid-DNS/internal/catalog"
	"github.com/eoghan2t9/Irongrid-DNS/internal/cert"
	"github.com/eoghan2t9/Irongrid-DNS/internal/cfupdate"
	"github.com/eoghan2t9/Irongrid-DNS/internal/config"
	"github.com/eoghan2t9/Irongrid-DNS/internal/dhcp"
	"github.com/eoghan2t9/Irongrid-DNS/internal/dnsserver"
	"github.com/eoghan2t9/Irongrid-DNS/internal/filter"
	"github.com/eoghan2t9/Irongrid-DNS/internal/firewall"
	"github.com/eoghan2t9/Irongrid-DNS/internal/geoip"
	"github.com/eoghan2t9/Irongrid-DNS/internal/installer"
	"github.com/eoghan2t9/Irongrid-DNS/internal/querylog"
	"github.com/eoghan2t9/Irongrid-DNS/internal/recursive"
	"github.com/eoghan2t9/Irongrid-DNS/internal/tuning"
	"github.com/eoghan2t9/Irongrid-DNS/internal/tunnel"
	"github.com/eoghan2t9/Irongrid-DNS/internal/upstream"
	"github.com/eoghan2t9/Irongrid-DNS/internal/version"
	"github.com/eoghan2t9/Irongrid-DNS/web"
)

func main() {
	// Use a private FlagSet: cloudflared's embedded packages register flags
	// on the global command line, which would panic on redefinition.
	flags := flag.NewFlagSet("irongrid", flag.ExitOnError)
	var (
		configPath = flags.String("config", "irongrid.yaml", "path to the YAML configuration file")
		dataDir    = flags.String("data", "data", "directory for runtime data (logs, lists, certs)")
		versionF   = flags.Bool("version", false, "print version and exit")
	)
	_ = flags.Parse(os.Args[1:])
	if *versionF {
		fmt.Println(version.String())
		return
	}

	// `irongrid install` launches the interactive TUI setup wizard.
	if len(os.Args) > 1 && os.Args[1] == "install" {
		installFlags := flag.NewFlagSet("irongrid install", flag.ExitOnError)
		instConfig := installFlags.String("config", "irongrid.yaml", "path to write the YAML configuration file")
		instData := installFlags.String("data", "data", "runtime data directory (querylog, lists, certs)")
		instDfly := installFlags.Bool("with-dragonfly", false, "detect and start Dragonfly if no cache answers at cache.addr")
		_ = installFlags.Parse(os.Args[2:])
		if err := installer.Run(installer.Options{
			ConfigPath:    *instConfig,
			DataDir:       *instData,
			WithDragonfly: *instDfly,
		}); err != nil {
			slog.Error("install failed", "error", err)
			os.Exit(1)
		}
		return
	}

	// UTC timestamps, matching the previous log.LUTC flag — the box running
	// this may be in any timezone, but log lines should compare cleanly
	// across a multi-instance deployment.
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
			if a.Key == slog.TimeKey {
				a.Value = slog.StringValue(a.Value.Time().UTC().Format(time.RFC3339))
			}
			return a
		},
	})))
	slog.Info(version.String())

	// ---- runtime auto-tuning: match GOMAXPROCS/GOGC/GOMEMLIMIT to whatever
	// hardware or container limits this process actually has, and keep
	// re-checking so a live resize is picked up without a restart.
	stopTuning := tuning.Start()
	defer stopTuning()

	// ---- system-level tuning: raise the file-descriptor soft limit (Unix)
	// and, as root on Linux, the kernel socket-buffer ceilings so the large
	// per-socket buffers the listeners request actually take effect.
	// Best-effort everywhere; must run before the DNS listeners are created.
	tuning.ApplySystem()

	// ---- config ----
	cfg, err := config.Load(*configPath)
	if err != nil {
		slog.Error("config load failed", "error", err)
		os.Exit(1)
	}
	if cfg.Web.Password == "" {
		cfg.Web.Password = "irongrid"
		slog.Warn("using default password — change it", "password", cfg.Web.Password, "config_path", *configPath)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// ---- Dragonfly cache (hard requirement) ----
	dfly, err := cache.New(cfg.Cache.Addr, cfg.Cache.Password, cfg.Cache.DB, cfg.Cache.TTL, cfg.Cache.NegativeTTL, cfg.Cache.ServeStale, resolveL1Entries(cfg.Cache.L1Entries))
	if err != nil {
		slog.Error("cache init failed — Dragonfly is a hard requirement, start it (see docker-compose.yml) and retry", "error", err)
		os.Exit(1)
	}
	// Note: closes the *current* cache, which reload may have swapped.
	defer func() { _ = dfly.Close() }()
	slog.Info("Dragonfly caching enabled", "positive_ttl", cfg.Cache.TTL, "negative_ttl", cfg.Cache.NegativeTTL)

	// ---- validate Dragonfly config against system specs ----
	// If Dragonfly was started with outdated flags (e.g. the old hardcoded
	// 512mb/2 threads), this restarts it with the correct auto-detected values.
	// Best-effort: failures are logged but never prevent irongrid from starting.
	tuning.ValidateDragonfly(cfg.Cache.Addr)

	// ---- authoritative root hints for recursive upstreams ----
	// recursive:// upstreams walk referrals from the root servers; seed them
	// from IANA's named.root file instead of the bundled snapshot so a
	// root-server address change is picked up without a release. The fetch
	// runs before upstreams are parsed (each resolver snapshots the default
	// hints at construction) and falls back to a last-known-good copy on
	// disk, then to the bundled hints, so boot never depends on network
	// access. SetDefaultRootHints also covers per-client-group upstreams and
	// any created by a later config reload.
	hasRecursive := slices.ContainsFunc(cfg.Upstreams, upstream.IsRecursiveSpec)
	var hintsMgr *recursive.HintsManager
	if hasRecursive {
		// The manager fetches the authoritative named.root at boot, verifies
		// its detached PGP signature, persists a last-known-good copy on
		// disk and refreshes weekly while the server runs. The initial
		// Refresh runs synchronously before upstreams are parsed (each
		// resolver snapshots the default hints at construction); any
		// failure falls back to the disk cache and then the bundled hints,
		// so boot never depends on network access.
		hintsMgr = recursive.NewHintsManager(recursive.RootHintsURL, filepath.Join(*dataDir, "root-hints.txt"), recursive.DefaultRefreshInterval)
		hintsMgr.Refresh(ctx)
		st := hintsMgr.Status()
		detail := ""
		if st.LastError != "" {
			detail = " — " + st.LastError
		}
		slog.Info("root hints loaded", "source", st.Source, "addresses", st.Addresses, "pgp_verified", st.Verified, "detail", detail)
		hintsMgr.Start(ctx)
	}

	// ---- upstreams ----
	// recursive.server_timeout tunes the per-server exchange timeout used by
	// recursive:// referral walks. Applied as a package-level default (read
	// at query time) so every resolver — boot, reload and per-client-group —
	// picks it up.
	recursive.SetDefaultServerTimeout(cfg.Recursive.ServerTimeout)
	var upstreams []*upstream.Upstream
	for _, spec := range cfg.Upstreams {
		up, err := upstream.Parse(spec)
		if err != nil {
			slog.Error("invalid upstream", "spec", spec, "error", err)
			os.Exit(1)
		}
		upstreams = append(upstreams, up)
		slog.Info("upstream configured", "name", up.Name(), "address", up.Address())
	}

	// ---- filter engine + blocklists ----
	engine := filter.NewEngine()
	engine.SetUserLists(cfg.Filter.Blacklist, cfg.Filter.Whitelist)

	listsDir := filepath.Join(*dataDir, "lists")
	lists := filter.NewListManager(engine, listsDir)
	specs := make([]filter.ListSpec, 0, len(cfg.Filter.Blocklists))
	for _, s := range cfg.Filter.Blocklists {
		specs = append(specs, filter.ListSpec{ID: s.ID, Name: s.Name, URL: s.URL, Enabled: s.Enabled})
	}
	lists.SetSpecs(specs)
	lists.SetAutoUpdate(cfg.Filter.AutoUpdate)
	lists.LoadCached()
	lists.ReloadAll()
	lists.StartRefresh(ctx)

	if err := lists.FetchAll(ctx); err != nil {
		slog.Warn("initial blocklist fetch partially failed, using cached content", "error", err)
	} else {
		lists.ReloadAll()
	}

	// ---- query log (Dragonfly stream, same tier as the DNS cache) ----
	ql, err := querylog.New(cfg.Cache.Addr, cfg.Cache.Password, cfg.Cache.DB, cfg.Log.RetentionDays, cfg.Log.BatchSize)
	if err != nil {
		slog.Error("query log init failed", "error", err)
		os.Exit(1)
	}
	defer ql.Close()
	ql.StartPruner(ctx)

	// ---- TLS for DoT / DoH / DoQ ----
	tlsConf, err := cert.LoadOrGenerate(
		cfg.TLS.CertFile, cfg.TLS.KeyFile,
		cfg.TLS.CertDir, cfg.TLS.SelfSignedHosts)
	if err != nil {
		slog.Error("tls init failed", "error", err)
		os.Exit(1)
	}

	// ---- DNS handler + listeners ----
	handler := dnsserver.NewHandler(
		engine, dfly, upstreams, ql,
		cfg.Filter.BlockResponse, cfg.Filter.BlockTTL,
		time.Duration(cfg.Server.TimeoutSec)*time.Second,
	)
	// Prefetch: the cache refreshes hot entries in the background shortly
	// before they expire, resolving through the handler's current upstreams
	// (which reload swaps atomically). Gated on cache.prefetch.
	if cfg.Cache.Prefetch {
		dfly.EnablePrefetch(handler.Refresh)
	}
	// Cache-read budget on the hot path (cache.lookup_timeout; 0 = default).
	dfly.SetLookupTimeout(cfg.Cache.LookupTimeout)
	// Failure-cache lifetime for unreachable upstreams (cache.failure_ttl;
	// 0 = use cache.negative_ttl; default 5s so a recovery is visible
	// quickly).
	handler.SetFailureTTL(cfg.Cache.FailureTTL)
	// Proactive cache warmer: scans the query log for the domains queried
	// within the lookback window and pre-resolves them (A + AAAA) through
	// the current upstreams into the cache, so a restart or cache flush
	// doesn't leave the first query for each domain cold. A pass runs
	// immediately at boot and then every interval. Gated on warmer.enabled
	// (off by default — warming uses upstreams even when nobody is asking).
	warmer := dnsserver.NewWarmer(handler, ql)
	warmer.SetConfig(cfg.Warmer)
	warmer.Start(ctx)
	// ---- IP→ASN data (shared by geo_block rules and client-group ASN
	// matching) ----
	// The manager downloads the free ip2asn dataset (iptoasn.com by default)
	// into the geo data dir; created here — before the client router below —
	// because client groups can match clients by ASN. apiHandler is declared
	// here too so the blocklist-change hook below (which fires after this
	// point) can read the published group table.
	var apiHandler *api.Handler
	geoDir := filepath.Join(*dataDir, "geo")
	geoMgr := geoip.NewManager(geoDir, cfg.GeoBlock.BaseURL)
	geoMgr.SetASNBaseURL(cfg.GeoBlock.ASNBaseURL)
	// refreshGroupASN loads the ip2asn dataset pruned to the union of every
	// enabled client group's ASN list and publishes it for router rebuilds.
	// nil when no group matches by ASN; a load failure keeps the previous
	// table (like the country-data fallback) so a refresh hiccup doesn't
	// silently drop ASN-matched groups.
	refreshGroupASN := func(c *config.Config) *geoip.ASNTable {
		var asns []string
		for _, g := range c.ClientGroups {
			if g.Enabled {
				asns = append(asns, g.ASNs...)
			}
		}
		if len(asns) == 0 {
			return nil
		}
		tbl, _, err := geoMgr.RefreshASN(ctx, asns, nil)
		if err != nil {
			slog.Warn("client-group ASN data load failed — ASN-matched groups not applied", "error", err)
			if apiHandler != nil {
				return apiHandler.GroupASN.Load()
			}
			return nil
		}
		return tbl
	}
	groupASN := refreshGroupASN(cfg)
	handler.SetRewriter(dnsserver.BuildRewriter(cfg.Rewrites))
	handler.SetClientRouter(dnsserver.BuildClientRouter(cfg, lists, groupASN))
	handler.SetRateLimiter(dnsserver.BuildRateLimiter(cfg.RateLimit))
	handler.SetNXGuard(dnsserver.BuildNXGuard(cfg.RateLimit.NXGuard))
	handler.SetDNSSEC(cfg.DNSSEC.Enabled, cfg.DNSSEC.RequireAD)
	handler.SetCNAMECloakingProtection(cfg.Filter.CNAMECloakingProtection)
	// RFC 7830 response padding and RFC 7873 DNS cookies (server.padding /
	// server.cookies). Re-applied on every reload below so a dashboard
	// toggle applies without a restart.
	handler.SetPadding(cfg.Server.Padding)
	handler.SetCookies(cfg.Server.Cookies)
	// ---- built-in DHCP server (LAN feature, off by default) ----
	// Hands out IPv4 (RFC 2131) and optionally IPv6 (RFC 8415) addresses
	// from the config-driven pool, persists leases under the data dir, and
	// registers client hostnames so <hostname>.<domain> (and the bare
	// hostname) resolve locally through the DNS handler — Pi-hole style.
	// Only wired when the feature is enabled in the config; the DHCP server
	// lives for the process, so the DNS handler's DHCPHosts hook is set once
	// here and never swapped.
	dhcpSrv := dhcp.New(filepath.Join(*dataDir, "dhcp"))
	dhcpSrv.SetConfig(buildDHCPRuntime(cfg.DHCP))
	if dhcpSrv.Enabled() {
		if err := dhcpSrv.Start(); err != nil {
			slog.Warn("dhcp failed to start, feature disabled", "error", err)
		} else {
			slog.Info("dhcp server enabled", "summary", dhcpSummary(cfg.DHCP))
		}
	}
	handler.DHCPHosts = dhcpSrv
	// Multi-upstream resolution strategy (config upstream_mode: race or
	// sequential). NewHandler defaults to race; apply the configured value.
	handler.SetUpstreamMode(cfg.UpstreamMode)
	// Conditional (split-horizon) routing: per-domain upstream sets that win
	// over the global forwarders and client-group overrides (e.g. "lan" ->
	// a local resolver so internal names never reach public resolvers).
	// Parsed up front (SetUpstreamRoutes itself cannot fail) so a bad route
	// spec aborts boot exactly like a bad upstream spec; re-applied on every
	// reload below, so a config change never needs a restart.
	routeUps, err := dnsserver.ParseRoutes(routeSpecs(cfg.UpstreamRoutes))
	if err != nil {
		slog.Error("invalid upstream routes", "error", err)
		os.Exit(1)
	}
	handler.SetUpstreamRoutes(routeUps)
	// Rebuild per-client-group engines whenever blocklist content changes
	// (auto-refresh ticker, manual "refresh all lists") — they're built from
	// the same cached content the global engine uses. The ASN table is
	// unchanged by a list refresh, so the published one is reused.
	lists.OnChange = func() {
		if apiHandler == nil {
			return
		}
		handler.SetClientRouter(dnsserver.BuildClientRouter(cfg, lists, apiHandler.GroupASN.Load()))
	}
	dnsMgr := dnsserver.NewManager(handler, tlsConf)
	// SO_REUSEPORT socket count for the plain UDP and DoQ listeners
	// (server.udp_sockets: 0 = auto, 1 = exclusive single socket, N =
	// explicit). Re-applied before every listener restart below.
	dnsMgr.SetUDPSockets(cfg.Server.UDPSockets)
	// Handler-worker count per plain-UDP socket (server.udp_workers: 0 =
	// auto, N = exactly N per socket). Same lifecycle as udp_sockets.
	dnsMgr.SetUDPWorkers(cfg.Server.UDPWorkers)
	// Per-IP concurrent-connection caps (server.max_tcp_conns_per_ip /
	// server.max_http_conns_per_ip; 0 = unlimited). Same lifecycle.
	dnsMgr.SetConnLimits(cfg.Server.MaxTCPConnsPerIP, cfg.Server.MaxHTTPConnsPerIP)
	// DoH client identification (server.trusted_proxies / xff_hop_limit):
	// which reverse-proxy peers may stamp X-Forwarded-For beyond
	// loopback/private ones, and how many trusted hops the chain may
	// contain — the client IP those rules produce drives geo/ASN blocking,
	// rate limiting and per-client policy, so a public reverse proxy in
	// front of DoH must be listed here or only the proxy's own address is
	// ever seen. Plus the per-response ASN header (server.doh_asn_header).
	// Both are re-applied on every reload below; the DoH handler reads them
	// per request, so no listener restart is needed.
	if err := dnsMgr.SetProxyConfig(cfg.Server.TrustedProxies, cfg.Server.XFFHopLimit); err != nil {
		slog.Error("invalid server.trusted_proxies", "error", err)
		os.Exit(1)
	}
	dnsMgr.SetDoHASNHeader(cfg.Server.DoHASNHeader)
	// webSharesDoH reports whether the dashboard and DoH share one HTTPS port
	// (server.web_listen == server.listen_doh with web_tls on). In that case
	// the web server also serves /dns-query and no standalone DoH listener is
	// started. Computed from cfg at call time so reloads pick up changes.
	webSharesDoH := func() bool {
		return cfg.Server.WebTLS && cfg.Server.ListenDoH != "" && cfg.Server.WebListen != "" &&
			webTLSPort(cfg.Server.ListenDoH) == webTLSPort(cfg.Server.WebListen)
	}
	// dohAddr is the address the DNS manager should bind DoH on: empty when
	// the web server serves /dns-query on the shared HTTPS port.
	dohAddr := func() string {
		if webSharesDoH() {
			return ""
		}
		return cfg.Server.ListenDoH
	}
	if webSharesDoH() {
		slog.Info("dashboard and DoH sharing listener, serving /dns-query on the dashboard HTTPS listener", "addr", cfg.Server.WebListen)
	}
	results, err := dnsMgr.Start(
		cfg.Server.ListenUDP, cfg.Server.ListenTCP,
		cfg.Server.ListenDoT, dohAddr(), cfg.Server.ListenDoH3, cfg.Server.ListenDoQ,
		cfg.Server.DoHPath,
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

	// ---- cloudflared tunnel (managed subprocess; binary auto-installed below) ----
	tunnelMgr := tunnel.NewManager(*dataDir)

	// ---- REST API + web UI ----
	var webFS fs.FS
	if web.HasFrontend() {
		webFS = web.FS()
	} else {
		slog.Warn("frontend not embedded — run `make web build` for the dashboard")
	}

	saveConfig := func() error { return cfg.Save(*configPath) }
	apiApp := &api.App{
		Config:     cfg,
		ConfigPath: *configPath,
		SaveConfig: saveConfig,
		WebFS:      webFS,
	}
	apiHandler = &api.Handler{
		Cfg:        cfg,
		ConfigPath: *configPath,
		SaveConfig: saveConfig,
		Engine:     engine,
		Lists:      lists,
		Cache:      dfly,
		Log:        ql,
		DNS:        handler,
		DNSManager: dnsMgr,
		Tunnel:     tunnelMgr,
		Upstreams:  upstreams,
		Hints:      hintsMgr,
		Catalog:    catalog.Default(),
		StartedAt:  time.Now(),
		Version:    version.Version,
		Warmer:     warmer,
		DHCP:       dhcpSrv,
	}
	// Publish the boot-time client-group ASN table (the router was built
	// with it above; the API's config-apply path reads it from here).
	apiHandler.GroupASN.Store(groupASN)
	apiApp.Handler = apiHandler
	// authorize/validSession/issueSession snapshot the auth fields under the
	// same mutex applyPayload uses, so a session-secret rotation can never be
	// read as a torn mix.
	apiApp.Mu = apiHandler.ConfigMu()

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
	fwMgr := firewall.New()
	apiHandler.Geo = geoMgr
	apiHandler.Firewall = fwMgr
	buildGeo := func(g config.GeoBlockConfig) error {
		// A silent no-op here would be confusing: honeypots/IPs/ASN rules
		// are useless unless the feature is enabled, so say so loudly (boot
		// + every config save / refresh that hits this branch).
		if !g.Enabled && (len(g.IPs) > 0 || len(g.Honeypots) > 0 || len(g.AllowASNs) > 0 || len(g.BlockASNs) > 0) {
			slog.Warn("honeypot domains / blocked IPs / ASN rules are configured but geo_block.enabled is false — nothing is being enforced")
		}
		if !g.Enabled || (len(g.Countries) == 0 && len(g.IPs) == 0 && len(g.Honeypots) == 0 && len(g.AllowASNs) == 0 && len(g.BlockASNs) == 0) {
			handler.SetGeo(nil)
			handler.SetIPBanner(nil)
			if err := fwMgr.Clear(); err != nil {
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
		allowASN, blockASN, asnErr := geoMgr.RefreshASN(ctx, g.AllowASNs, g.BlockASNs)
		if asnErr != nil {
			slog.Warn("ASN data load failed — ASN allow/block rules not enforced", "error", asnErr)
		}
		// Client-IP banner: configured block IPs/CIDRs plus honeypot
		// auto-blocks (loaded from a persisted file so they survive
		// restarts/reloads). A honeypot hit pushes the client straight into
		// the host firewall's drop set via OnBlock.
		banner := geoip.NewBanner(filepath.Join(geoDir, "blocked-ips.txt"), g.Allowlist, g.IPs, g.Honeypots)
		banner.SetASNs(allowASN, blockASN)
		handler.SetIPBanner(banner)
		// Opt-in: let plain-UDP honeypot hits auto-block their source too
		// (off by default — spoofed UDP must not be able to block victims).
		handler.SetTrustUDP(g.TrustUDP)
		// Bounded alternative to trust_udp: auto-block the source of a
		// plain-UDP honeypot hit for this window via the rate limiter
		// (expires on its own, never a permanent firewall drop).
		handler.SetHoneypotUDPBlock(g.HoneypotUDPBlock)
		banner.OnBlock = func(ip string) {
			if err := fwMgr.AddIP(ip); err != nil {
				slog.Error("firewall add blocked client failed", "ip", ip, "error", err)
			}
		}
		b, err := geoMgr.Refresh(ctx, g.Countries, g.Allowlist)
		b.SetASNs(allowASN, blockASN)
		handler.SetGeo(b)
		// Packet-level blocking: rebuild the firewall rules from the freshly
		// persisted CIDR lists plus the banner's full block set (configured
		// IPs and honeypot auto-blocks). A failure here (e.g. no cached data
		// yet, or no root) is logged and leaves the DNS-level REFUSED
		// blocking in effect — buildGeo's own error (data fetch) is what
		// the caller surfaces.
		if backend, ferr := fwMgr.Apply(g.Countries, g.Allowlist, banner.List(), geoDir); ferr != nil {
			slog.Error("firewall country rules not applied", "backend", backend, "error", ferr)
		} else {
			slog.Info("dropping inbound traffic from blocked countries", "backend", backend)
		}
		// Surface the ASN data failure alongside the country one so a
		// refresh that partially failed is reported as such.
		return errors.Join(err, asnErr)
	}
	if err := buildGeo(cfg.GeoBlock); err != nil {
		slog.Warn("initial geo load partially failed, using cached data", "error", err)
	}
	// The config-save and refresh-button paths must never stall on a
	// country-data download (multi-country fetches can take seconds), so
	// RebuildGeo runs the rebuild off the request path; the DNS handler
	// keeps serving with the previous blocker until the new one is ready.
	apiHandler.RebuildGeo = func(g config.GeoBlockConfig) error {
		go func() {
			if err := buildGeo(g); err != nil {
				slog.Error("geo background refresh failed", "error", err)
			}
		}()
		return nil
	}
	// Client-group ASN matching refreshes the same way on a config save:
	// the dataset download/parse runs off the request path, and the router
	// is rebuilt the moment the fresh table lands (until then the previous
	// table — or no ASN matching — stays in effect).
	apiHandler.RebuildClientGroups = func(c *config.Config) error {
		go func() {
			tbl := refreshGroupASN(c)
			apiHandler.GroupASN.Store(tbl)
			handler.SetClientRouter(dnsserver.BuildClientRouter(c, lists, tbl))
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
	cfgMu := apiHandler.ConfigMu()
	go func() {
		for {
			cfgMu.Lock()
			g := cfg.GeoBlock
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
			case <-ctx.Done():
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
			g = cfg.GeoBlock
			cfgMu.Unlock()
			if g.Enabled && (len(g.Countries) > 0 || len(g.AllowASNs) > 0 || len(g.BlockASNs) > 0) && g.AutoUpdate > 0 {
				if err := buildGeo(g); err != nil {
					slog.Error("geo auto-refresh failed", "error", err)
				}
			}
		}
	}()

	// ---- ACME (Let's Encrypt) auto-issuance ----
	// startACME is callable at boot AND from the reload hook so toggling
	// tls.acme.enabled in the dashboard takes effect without a restart.
	// acmeMgr is an atomic pointer: the web_redirect handler reads it on
	// every port-80 request while reload may swap it, so a plain variable
	// would be a data race.
	var acmeMgr atomic.Pointer[acme.Manager]
	// acmeExternalHTTP01 remembers the ExternalHTTP01 mode the running
	// manager was created with so a reload that toggles web_tls/web_redirect
	// can recreate the manager instead of leaving a port-80 conflict.
	acmeExternalHTTP01 := false
	stopACME := func() {
		if m := acmeMgr.Swap(nil); m != nil {
			m.Stop()
		}
		apiHandler.ACME = nil
	}
	startACME := func() {
		if !cfg.TLS.ACME.Enabled || acmeMgr.Load() != nil {
			return
		}
		dnsProvider, err := acme.NewDNSProvider(
			cfg.TLS.ACME.DNS01.Provider,
			acme.DNSProviderConfig{
				CloudflareToken:    cfg.TLS.ACME.DNS01.CloudflareToken,
				DigitalOceanToken:  cfg.TLS.ACME.DNS01.DigitalOceanToken,
				HetznerToken:       cfg.TLS.ACME.DNS01.HetznerToken,
				GoDaddyKey:         cfg.TLS.ACME.DNS01.GoDaddyKey,
				GoDaddySecret:      cfg.TLS.ACME.DNS01.GoDaddySecret,
				AWSAccessKeyID:     cfg.TLS.ACME.DNS01.AWSAccessKeyID,
				AWSSecretAccessKey: cfg.TLS.ACME.DNS01.AWSSecretAccessKey,
			},
		)
		if err != nil {
			slog.Warn("acme disabled", "error", err)
			return
		}
		// When web_redirect listens on the same port as the http-01 challenge,
		// the redirect listener serves the challenge tokens itself so the
		// manager must not bind a second listener on that port.
		httpPort := cfg.TLS.ACME.HTTP01Port
		if httpPort == 0 {
			httpPort = 80
		}
		redirectPort := cfg.Server.WebRedirectPort
		if redirectPort == 0 {
			redirectPort = 80
		}
		acmeExternalHTTP01 = cfg.Server.WebTLS && cfg.Server.WebRedirect && redirectPort == httpPort
		m := acme.New(acme.Options{
			Email:           cfg.TLS.ACME.Email,
			Domains:         cfg.TLS.ACME.Domains,
			CertDir:         cfg.TLS.CertDir,
			Staging:         cfg.TLS.ACME.Staging,
			HTTP01Port:      cfg.TLS.ACME.HTTP01Port,
			RenewBeforeDays: cfg.TLS.ACME.RenewBeforeDays,
			DNS:             dnsProvider,
			DNSProvider:     cfg.TLS.ACME.DNS01.Provider,
			DNSWait:         time.Duration(cfg.TLS.ACME.DNS01.PropagationWait) * time.Second,
			ExternalHTTP01:  acmeExternalHTTP01,
		})
		acmeMgr.Store(m)
		apiHandler.ACME = m
		if cfg.TLS.CertDir == "" {
			cfg.TLS.CertDir = "data/certs"
		}
		go m.RunLoop(ctx)
	}
	startACME()

	// webHandler returns the web-server handler: the dashboard + API router,
	// wrapped so the DoH endpoint is served from the same listener when the
	// dashboard shares its HTTPS port with DoH.
	webHandler := func() http.Handler {
		router := api.NewRouter(apiApp)
		if !webSharesDoH() {
			return router
		}
		mux := http.NewServeMux()
		mux.Handle(cfg.Server.DoHPath, dnsMgr.DoHHandler())
		mux.Handle("/", router)
		return mux
	}

	// ---- web server (dashboard + API) ----
	// ConnState enforces the per-IP connection cap (server.max_http_conns_per_ip)
	// when the dashboard shares its port with DoH — a no-op (nil) otherwise.
	webSrv := &http.Server{
		Addr:         cfg.Server.WebListen,
		Handler:      webHandler(),
		ConnState:    dnsMgr.HTTPConnState(),
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
	}
	// Track the TLS mode of the currently running web server so toggling
	// web_tls without changing the address also triggers a rebind.
	webTLSServing := cfg.Server.WebTLS
	// webMu serialises web-server rebinding between the ACME RunLoop goroutine
	// (OnIssued) and the config reload hook, which both swap webSrv.
	var webMu sync.Mutex
	startWebServer := func(srv *http.Server, useTLS bool) {
		if useTLS {
			// Serve the dashboard + API over HTTPS with the same cert that
			// secures DoT/DoH/DoQ.
			wtls, err := cert.LoadOrGenerate(cfg.TLS.CertFile, cfg.TLS.KeyFile, cfg.TLS.CertDir, cfg.TLS.SelfSignedHosts)
			if err != nil {
				slog.Error("cannot enable HTTPS, falling back to plain HTTP", "error", err)
				go func() { _ = srv.ListenAndServe() }()
				return
			}
			// When DoH shares this listener, advertise HTTP/2 (RFC 8484
			// recommends h2 for DoH clients).
			if webSharesDoH() {
				wtls = wtls.Clone()
				wtls.NextProtos = []string{"h2", "http/1.1"}
				if err := http2.ConfigureServer(srv, &http2.Server{}); err != nil {
					slog.Error("http2 setup failed", "error", err)
				}
			}
			go func() {
				// Tuned socket: the dashboard serves DoH when it shares the
				// HTTPS port, so its buffers get the same boost as the DNS
				// listeners (accepted connections inherit the settings).
				ln, err := tuning.ListenConfig().Listen(context.Background(), "tcp", srv.Addr)
				if err != nil {
					slog.Error("web server error", "error", err)
					return
				}
				slog.Info("dashboard + API listening", "addr", srv.Addr, "scheme", "https")
				if err := srv.Serve(tls.NewListener(ln, wtls)); err != nil && err != http.ErrServerClosed {
					slog.Error("web server error", "error", err)
				}
			}()
			return
		}
		go func() {
			slog.Info("dashboard + API listening", "addr", srv.Addr, "scheme", "http")
			if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				slog.Error("web server error", "error", err)
			}
		}()
	}
	startWebServer(webSrv, webTLSServing)

	// ---- optional HTTP->HTTPS redirect (web_redirect) ----
	// When the dashboard runs on HTTPS, a small plain-HTTP listener 301s
	// every request to https://<host>/. It is re-evaluated on every reload
	// so toggling web_tls / web_redirect / web_listen takes effect without
	// a process restart.
	var redirectSrv *http.Server
	startRedirect := func() {
		want := cfg.Server.WebTLS && cfg.Server.WebRedirect
		port := cfg.Server.WebRedirectPort
		if port == 0 {
			port = 80
		}
		addr := fmt.Sprintf(":%d", port)
		// Already serving the right thing — nothing to do.
		if want && redirectSrv != nil && redirectSrv.Addr == addr {
			return
		}
		// Tear down the old listener if there is one. Shutdown runs in a
		// goroutine so the reload response flushes first; the replacement
		// waits a beat so the old listener's port is actually free.
		if redirectSrv != nil {
			old := redirectSrv
			redirectSrv = nil
			go func() { _ = old.Shutdown(context.Background()) }()
		}
		if !want {
			return
		}
		host, httpsPort := hostOnly(cfg.Server.WebListen), webTLSPort(cfg.Server.WebListen)
		// When web_redirect shares the http-01 challenge port, serve the ACME
		// challenge tokens on this same listener instead of redirecting them.
		redirect := httpsRedirect(httpsPort)
		ns := &http.Server{
			Addr:              addr,
			ReadHeaderTimeout: 10 * time.Second, // gosec G112: bound slow-header clients
			Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if m := acmeMgr.Load(); m != nil && m.HandleChallenge(w, r) {
					return
				}
				redirect(w, r)
			}),
		}
		redirectSrv = ns
		go func() {
			time.Sleep(200 * time.Millisecond) // let an old listener release the port
			slog.Info("plain HTTP redirect listening", "addr", addr, "redirect_host", host)
			if err := ns.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				slog.Error("redirect listener stopped", "addr", addr, "error", err)
			}
		}()
	}
	startRedirect()

	// ---- TLS-only reload: used after the dashboard generates/uploads a
	// certificate. Rebinds the DNS listeners with the new cert; leaves the
	// cache and upstreams untouched so it works even while Dragonfly is down.
	apiHandler.ReloadTLS = func() error {
		newTLS, err := cert.LoadOrGenerate(cfg.TLS.CertFile, cfg.TLS.KeyFile, cfg.TLS.CertDir, cfg.TLS.SelfSignedHosts)
		if err != nil {
			return fmt.Errorf("tls: %w", err)
		}
		if err := dnsMgr.Restart(
			cfg.Server.ListenUDP, cfg.Server.ListenTCP,
			cfg.Server.ListenDoT, dohAddr(), cfg.Server.ListenDoH3, cfg.Server.ListenDoQ,
			cfg.Server.DoHPath, newTLS,
		); err != nil {
			return fmt.Errorf("dns listeners: %w", err)
		}
		slog.Info("certificate reloaded and listeners rebound")
		return nil
	}

	// After an ACME issuance/renewal, rebind the listeners + web server with
	// the fresh certificate. Wrap the base ReloadTLS (captured first) so the
	// ACME path also restarts an HTTPS web server. Wired unconditionally (not
	// gated on acmeMgr) because startACME may create the manager later via a
	// config reload.
	//
	// webMu serialises web-server rebinding between the ACME RunLoop goroutine
	// (OnIssued) and the config reload hook, which both swap webSrv.
	baseReloadTLS := apiHandler.ReloadTLS
	apiHandler.ReloadTLS = func() error {
		if err := baseReloadTLS(); err != nil {
			return err
		}
		// Rebind the web server too if it runs on HTTPS.
		if cfg.Server.WebTLS {
			webMu.Lock()
			oldWeb := webSrv
			newWeb := &http.Server{
				Addr:         cfg.Server.WebListen,
				Handler:      webHandler(),
				ConnState:    dnsMgr.HTTPConnState(),
				ReadTimeout:  30 * time.Second,
				WriteTimeout: 30 * time.Second,
			}
			webSrv = newWeb
			webTLSServing = true
			webMu.Unlock()
			go func() {
				time.Sleep(200 * time.Millisecond)
				_ = oldWeb.Shutdown(context.Background())
				startWebServer(newWeb, true)
			}()
			startRedirect()
		}
		return nil
	}
	// After a successful ACME issuance, rebind everything with the new cert.
	if m := acmeMgr.Load(); m != nil {
		m.OnIssued = func() {
			if err := apiHandler.ReloadTLS(); err != nil {
				slog.Error("acme reload after issuance failed", "error", err)
			}
		}
	}

	// ---- config reload: apply listener/cache/TLS/web changes in-process ----
	apiHandler.Reload = func() error {
		// Failure-atomic ordering: build every new component first and restart
		// the listeners before swapping any live references, so a bad config
		// leaves the running server untouched.

		// 1. Cache: connect to the new endpoint first; keep the old one on
		//    failure so a bad config never takes the server down.
		newCache, err := cache.New(cfg.Cache.Addr, cfg.Cache.Password, cfg.Cache.DB, cfg.Cache.TTL, cfg.Cache.NegativeTTL, cfg.Cache.ServeStale, resolveL1Entries(cfg.Cache.L1Entries))
		if err != nil {
			return fmt.Errorf("cache: %w", err)
		}
		if cfg.Cache.Prefetch {
			newCache.EnablePrefetch(handler.Refresh)
		}
		// 2. TLS: reload certificates before touching the listeners.
		newTLS, err := cert.LoadOrGenerate(cfg.TLS.CertFile, cfg.TLS.KeyFile, cfg.TLS.CertDir, cfg.TLS.SelfSignedHosts)
		if err != nil {
			_ = newCache.Close()
			return fmt.Errorf("tls: %w", err)
		}
		// 3. Upstreams: rebuild from the new specs.
		recursive.SetDefaultServerTimeout(cfg.Recursive.ServerTimeout)
		newUps := make([]*upstream.Upstream, 0, len(cfg.Upstreams))
		for _, spec := range cfg.Upstreams {
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
		newRoutes, err := dnsserver.ParseRoutes(routeSpecs(cfg.UpstreamRoutes))
		if err != nil {
			_ = newCache.Close()
			return fmt.Errorf("upstream routes: %w", err)
		}
		// A reload can introduce recursive:// upstreams when none were
		// configured at boot (hintsMgr was never created). Start the manager
		// so they get the authoritative root hints too, not just the bundled
		// fallback. Once running it keeps refreshing weekly, covering any
		// later reloads as well.
		if hintsMgr == nil {
			hasRec := false
			for _, up := range newUps {
				if up.Transport == upstream.Recursive {
					hasRec = true
					break
				}
			}
			if hasRec {
				hintsMgr = recursive.NewHintsManager(recursive.RootHintsURL, filepath.Join(*dataDir, "root-hints.txt"), recursive.DefaultRefreshInterval)
				hintsMgr.Refresh(ctx)
				hintsMgr.Start(ctx)
				apiHandler.Hints = hintsMgr
				st := hintsMgr.Status()
				slog.Info("root hints manager started on config reload", "source", st.Source, "addresses", st.Addresses, "pgp_verified", st.Verified)
			}
		}

		// 4. Restart the DNS listeners with the new addresses + TLS. This is
		//    the only step that can fail with hard bind errors, so it runs
		//    before anything is swapped. Note: UDP/TCP/DoT bind failures are
		//    reported asynchronously via the results channel, not as errors.
		dnsMgr.SetUDPSockets(cfg.Server.UDPSockets)
		dnsMgr.SetUDPWorkers(cfg.Server.UDPWorkers)
		dnsMgr.SetConnLimits(cfg.Server.MaxTCPConnsPerIP, cfg.Server.MaxHTTPConnsPerIP)
		// Proxy trust and the DoH ASN header are read per request, so they
		// are re-applied without a listener restart (the reload has already
		// validated them via the config check below, so a failure here is
		// unreachable — logged defensively only).
		if err := dnsMgr.SetProxyConfig(cfg.Server.TrustedProxies, cfg.Server.XFFHopLimit); err != nil {
			slog.Error("invalid server.trusted_proxies on reload", "error", err)
		}
		dnsMgr.SetDoHASNHeader(cfg.Server.DoHASNHeader)
		if err := dnsMgr.Restart(
			cfg.Server.ListenUDP, cfg.Server.ListenTCP,
			cfg.Server.ListenDoT, dohAddr(), cfg.Server.ListenDoH3, cfg.Server.ListenDoQ,
			cfg.Server.DoHPath, newTLS,
		); err != nil {
			_ = newCache.Close()
			return fmt.Errorf("dns listeners: %w", err)
		}

		// 5. Now swap the hot references — listeners are already serving with
		//    the new TLS config, so this only changes cache/upstreams/policy.
		handler.SetCache(newCache)
		handler.SetUpstreams(newUps)
		handler.SetUpstreamMode(cfg.UpstreamMode)
		handler.SetUpstreamRoutes(newRoutes)
		handler.SetBlockPolicy(cfg.Filter.BlockResponse, cfg.Filter.BlockTTL)
		handler.SetTimeout(time.Duration(cfg.Server.TimeoutSec) * time.Second)
		handler.SetFailureTTL(cfg.Cache.FailureTTL)
		newCache.SetLookupTimeout(cfg.Cache.LookupTimeout)
		handler.SetRewriter(dnsserver.BuildRewriter(cfg.Rewrites))
		// Reload picks up client-group ASN changes (and the data itself) from
		// the freshly re-read config, like every other hot knob below.
		groupASN = refreshGroupASN(cfg)
		apiHandler.GroupASN.Store(groupASN)
		handler.SetClientRouter(dnsserver.BuildClientRouter(cfg, lists, groupASN))
		handler.SetRateLimiter(dnsserver.BuildRateLimiter(cfg.RateLimit))
		handler.SetNXGuard(dnsserver.BuildNXGuard(cfg.RateLimit.NXGuard))
		handler.SetDNSSEC(cfg.DNSSEC.Enabled, cfg.DNSSEC.RequireAD)
		handler.SetCNAMECloakingProtection(cfg.Filter.CNAMECloakingProtection)
		handler.SetPadding(cfg.Server.Padding)
		handler.SetCookies(cfg.Server.Cookies)
		// DHCP: pool/option/static changes apply immediately (handlers read
		// them per packet); a bind change (interface, enable state, subnet)
		// restarts the packet listeners without dropping leases. Capture the
		// old bind state before SetConfig swaps the runtime config.
		wasRunning := dhcpSrv.Enabled()
		wasIface := dhcpSrv.Interface()
		newDHCP := buildDHCPRuntime(cfg.DHCP)
		dhcpSrv.SetConfig(newDHCP)
		wantRunning := cfg.DHCP.Enabled && (cfg.DHCP.Subnet != "" || (cfg.DHCP.IPv6 && cfg.DHCP.IPv6Prefix != ""))
		// Restart when the enable state flipped, or when the NIC the
		// listeners bind changed (the server itself is always running in
		// this build, so wasRunning stays true across an interface edit).
		if wasRunning != wantRunning || (wantRunning && wasIface != cfg.DHCP.Interface) {
			if wantRunning {
				var err error
				if wasRunning {
					// Already bound: rebind to the new interface without
					// dropping the lease table.
					err = dhcpSrv.RestartListeners()
				} else {
					err = dhcpSrv.Start()
				}
				if err != nil {
					slog.Error("dhcp listener start failed", "error", err)
				}
			} else {
				dhcpSrv.Stop()
			}
		}
		// Geo blocking is hot-swapped asynchronously (see RebuildGeo).
		if apiHandler.RebuildGeo != nil {
			_ = apiHandler.RebuildGeo(cfg.GeoBlock)
		}
		apiHandler.Cache = newCache
		apiHandler.Upstreams = newUps
		oldCache := dfly
		dfly = newCache
		_ = oldCache.Close()

		// 6. Rebind the web server if its address or TLS mode changed. Shutdown
		//    is run in a goroutine: calling Shutdown synchronously from inside
		//    a request served by the same server would wait on the in-flight
		//    handler and deadlock, and the delay lets the reload flush first.
		webMu.Lock()
		addrChanged := webSrv.Addr != cfg.Server.WebListen
		tlsChanged := webTLSServing != cfg.Server.WebTLS
		if addrChanged || tlsChanged {
			oldWeb := webSrv
			newWeb := &http.Server{
				Addr:         cfg.Server.WebListen,
				Handler:      webHandler(),
				ConnState:    dnsMgr.HTTPConnState(),
				ReadTimeout:  30 * time.Second,
				WriteTimeout: 30 * time.Second,
			}
			webSrv = newWeb
			webTLSServing = cfg.Server.WebTLS
			useTLS := webTLSServing
			webMu.Unlock()
			go func() {
				time.Sleep(200 * time.Millisecond) // let the reload response flush
				_ = oldWeb.Shutdown(context.Background())
				startWebServer(newWeb, useTLS)
			}()
		} else {
			webMu.Unlock()
		}
		// 7. Start/stop the ACME manager to match the new config: toggling
		//    tls.acme.enabled in the dashboard takes effect without a restart.
		if cfg.TLS.ACME.Enabled {
			// If the web_tls/web_redirect/port combination that decides
			// ExternalHTTP01 changed, recreate the manager so it doesn't keep
			// a stale challenge-listener arrangement (e.g. both listeners
			// fighting for port 80).
			httpPort := cfg.TLS.ACME.HTTP01Port
			if httpPort == 0 {
				httpPort = 80
			}
			redirectPort := cfg.Server.WebRedirectPort
			if redirectPort == 0 {
				redirectPort = 80
			}
			wantExternal := cfg.Server.WebTLS && cfg.Server.WebRedirect && redirectPort == httpPort
			if wantExternal != acmeExternalHTTP01 {
				stopACME()
				acmeExternalHTTP01 = wantExternal
			}
			startACME()
			if m := acmeMgr.Load(); m != nil && m.OnIssued == nil {
				m.OnIssued = func() {
					if err := apiHandler.ReloadTLS(); err != nil {
						slog.Error("acme reload after issuance failed", "error", err)
					}
				}
			}
		} else {
			stopACME()
		}
		// Re-evaluate the HTTP->HTTPS redirect listener on every reload: it
		// starts/stops/keeps itself based on the new web_tls/web_redirect config.
		startRedirect()
		slog.Info("config reload applied: listeners, cache, TLS, upstreams")
		return nil
	}

	// ---- keep the managed cloudflared binary up to date ----
	// Runs once per process start (i.e. on every restart), always-on and
	// best-effort: a slow or failed GitHub check must never block the rest
	// of the server, so it runs synchronously but bounded, right before the
	// tunnel would auto-start — everything else in main has already bound
	// its listeners by this point.
	{
		cfCtx, cfCancel := context.WithTimeout(context.Background(), 30*time.Second)
		cfRes, cfErr := (&cfupdate.Client{}).Install(cfCtx, tunnelMgr.BinaryPath())
		cfCancel()
		binStatus := tunnel.BinaryStatus{LastChecked: time.Now()}
		switch {
		case cfErr != nil:
			slog.Warn("cloudflared update check failed", "error", cfErr)
			binStatus.Version = cfupdate.CurrentVersion(tunnelMgr.BinaryPath())
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
		tunnelMgr.SetBinaryStatus(binStatus)
	}

	// ---- auto-start tunnel if configured ----
	if cfg.Tunnel.Enabled {
		mode := tunnel.ModeConfig
		if cfg.Tunnel.Token != "" {
			mode = tunnel.ModeToken
		} else if cfg.Tunnel.QuickTunnel {
			mode = tunnel.ModeQuick
		}
		if err := tunnelMgr.Start(mode, cfg.Tunnel.Token, cfg.Tunnel.ConfigFile, cfg.Tunnel.QuickTunnelURL, cfg.Tunnel.Hostname); err != nil {
			slog.Error("tunnel failed to start", "error", err)
		} else {
			slog.Info("tunnel started", "mode", mode)
		}
	}

	// ---- wait for shutdown ----
	<-ctx.Done()
	slog.Info("shutting down...")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	dnsMgr.Shutdown(shutdownCtx)
	tunnelMgr.Stop()
	webMu.Lock()
	currentWeb := webSrv
	webMu.Unlock()
	_ = currentWeb.Shutdown(shutdownCtx)
	ql.Close()
	slog.Info("bye")
}

// httpsRedirect returns a handler that 301s a plain-HTTP request to the same
// path over HTTPS. The hostname is taken from the request (so real domains
// and proxies work); the port is the HTTPS web server's port, with the
// default 443 omitted for clean URLs.
func httpsRedirect(httpsPort string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		host := r.Host
		if h, _, err := net.SplitHostPort(r.Host); err == nil {
			host = h
		}
		target := "https://" + host
		if httpsPort != "443" && httpsPort != "" {
			target += ":" + httpsPort
		}
		target += r.URL.RequestURI()
		//nolint:gosec // G710 open redirect: the target host is the Host
		// header the client itself sent, so this can only ever redirect a
		// client to the host it already asked for — not an attacker-chosen
		// site.
		http.Redirect(w, r, target, http.StatusMovedPermanently)
	}
}

// webTLSPort extracts the port of the HTTPS web server address
// ("0.0.0.0:8443" -> "8443", "0.0.0.0" -> "").
func webTLSPort(addr string) string {
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		return ""
	}
	return port
}

// hostOnly strips the port from a listen address ("0.0.0.0:8443" ->
// "0.0.0.0") so it can be displayed in logs.
func hostOnly(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	return host
}

// resolveL1Entries turns the cache.l1_entries config value into a concrete
// per-shard L1 cap: -1 disables the in-process cache, 0 auto-sizes it from
// the detected memory ceiling (see cache.AutoPerShard — cgroup-aware, so a
// container limit is respected), and N is an explicit per-shard entry cap.
func resolveL1Entries(v int) int {
	if v != 0 {
		return v
	}
	mem, ok := tuning.MemoryLimitBytes()
	return cache.AutoPerShard(mem, ok)
}

// buildRewriter, buildRateLimiter and buildClientRouter live in the
// dnsserver package (as BuildRewriter etc.) so the API's live config-apply
// path can share the exact same logic instead of duplicating it.

// ---- DHCP runtime config ----

// buildDHCPRuntime maps the config section into the dhcp package's runtime
// Config, discovering this host's own addresses inside the served networks
// (the default gateway/DNS options and the anchor for the server DUID). The
// mapping itself lives in dhcp.ConfigFrom so the API's live-apply path
// produces an identical config — a dashboard save can never drop fields
// (e.g. the server identifier) that boot had set.
// routeSpecs converts config-level conditional routes into the dnsserver
// package's RouteSpec form (raw upstream strings; parsing happens inside
// SetUpstreamRoutes so a bad spec is rejected before anything swaps).
func routeSpecs(routes []config.UpstreamRoute) []dnsserver.RouteSpec {
	specs := make([]dnsserver.RouteSpec, 0, len(routes))
	for _, rt := range routes {
		specs = append(specs, dnsserver.RouteSpec{Domain: rt.Domain, Upstreams: rt.Upstreams})
	}
	return specs
}

func buildDHCPRuntime(c config.DHCPConfig) dhcp.Config {
	_, subnet := parseCIDR(c.Subnet)
	_, ipv6net := parseCIDR(c.IPv6Prefix)
	var addrs dhcp.HostAddresses
	addrs.IPv4, addrs.IPv6, addrs.MAC = hostLANAddresses(subnet, ipv6net, c.Interface)
	return dhcp.ConfigFrom(c.Enabled, c.Interface, c.Subnet, c.RangeStart, c.RangeEnd,
		c.Gateway, c.DNS, c.LeaseTime, c.Domain, dhcpStatics(c.StaticLeases),
		c.IPv6, c.IPv6Prefix, c.IPv6RangeStart, c.IPv6RangeEnd, addrs)
}

// dhcpStatics converts the config's static-lease specs into the runtime type.
func dhcpStatics(leases []config.DHCPStaticLease) []dhcp.StaticLease {
	out := make([]dhcp.StaticLease, 0, len(leases))
	for _, sl := range leases {
		st := dhcp.StaticLease{MAC: sl.MAC, DUID: sl.DUID, Hostname: sl.Hostname}
		if ip := net.ParseIP(sl.IP); ip != nil {
			st.IP = ip
		}
		out = append(out, st)
	}
	return out
}

// parseCIDR returns the *net.IPNet for a CIDR string (nil when invalid — the
// config validator has already rejected bad values by the time this runs).
func parseCIDR(s string) (net.IP, *net.IPNet) {
	if s == "" {
		return nil, nil
	}
	ip, n, err := net.ParseCIDR(s)
	if err != nil {
		return nil, nil
	}
	return ip, n
}

// dhcpSummary renders a one-line description of the DHCP config for the boot
// log (only called when the server is enabled).
func dhcpSummary(c config.DHCPConfig) string {
	s := "DHCPv4 " + c.Subnet
	if c.RangeStart != "" {
		s += " (pool " + c.RangeStart + "-" + c.RangeEnd + ")"
	}
	if c.IPv6 {
		s += " + DHCPv6 " + c.IPv6Prefix
	}
	return s
}

// hostLANAddresses finds this host's own IPs (IPv4 and IPv6) inside the
// served networks and its hardware MAC, so the DHCP options can point at this
// box by default. Interface, when non-empty, restricts the search to that
// NIC. Any part can be nil — the DHCP handlers then fall back to the
// configured gateway/DNS values.
func hostLANAddresses(subnet, ipv6net *net.IPNet, iface string) (v4, v6 net.IP, mac net.HardwareAddr) {
	ifaces := []net.Interface{}
	if iface != "" {
		i, err := net.InterfaceByName(iface)
		if err != nil {
			slog.Error("dhcp interface not found", "interface", iface, "error", err)
			return nil, nil, nil
		}
		ifaces = append(ifaces, *i)
	} else {
		all, err := net.Interfaces()
		if err != nil {
			return nil, nil, nil
		}
		for _, i := range all {
			if i.Flags&net.FlagUp != 0 && i.Flags&net.FlagLoopback == 0 {
				ifaces = append(ifaces, i)
			}
		}
	}
	for _, i := range ifaces {
		if mac == nil && len(i.HardwareAddr) == 6 {
			mac = i.HardwareAddr
		}
		addrs, err := i.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ipnet, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			ip := ipnet.IP
			if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
				continue
			}
			if ip.To4() != nil && v4 == nil && subnet != nil && subnet.Contains(ip) {
				v4 = ip.To4()
			}
			if ip.To4() == nil && v6 == nil && ipv6net != nil && ipv6net.Contains(ip) {
				v6 = ip
			}
		}
	}
	return v4, v6, mac
}
