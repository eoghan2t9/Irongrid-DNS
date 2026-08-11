package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
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
	"github.com/eoghan2t9/Irongrid-DNS/internal/config"
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
			log.Fatalf("install: %v", err)
		}
		return
	}

	log.SetFlags(log.LstdFlags | log.LUTC)
	log.Printf("%s", version.String())

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
		log.Fatalf("config: %v", err)
	}
	if cfg.Web.Password == "" {
		cfg.Web.Password = "irongrid"
		log.Printf("[web] using default password %q — change it in %s", cfg.Web.Password, *configPath)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// ---- Dragonfly cache (hard requirement) ----
	dfly, err := cache.New(cfg.Cache.Addr, cfg.Cache.Password, cfg.Cache.DB, cfg.Cache.TTL, cfg.Cache.NegativeTTL, cfg.Cache.ServeStale, cfg.Cache.L1Entries)
	if err != nil {
		log.Fatalf("cache: %v\n\nDragonfly is a hard requirement — start it (see docker-compose.yml) and retry.", err)
	}
	// Note: closes the *current* cache, which reload may have swapped.
	defer func() { _ = dfly.Close() }()
	log.Printf("[cache] Dragonfly caching enabled (positive TTL %s, negative TTL %s)", cfg.Cache.TTL, cfg.Cache.NegativeTTL)

	// ---- authoritative root hints for recursive upstreams ----
	// recursive:// upstreams walk referrals from the root servers; seed them
	// from IANA's named.root file instead of the bundled snapshot so a
	// root-server address change is picked up without a release. The fetch
	// runs before upstreams are parsed (each resolver snapshots the default
	// hints at construction) and falls back to a last-known-good copy on
	// disk, then to the bundled hints, so boot never depends on network
	// access. SetDefaultRootHints also covers per-client-group upstreams and
	// any created by a later config reload.
	hasRecursive := false
	for _, spec := range cfg.Upstreams {
		if upstream.IsRecursiveSpec(spec) {
			hasRecursive = true
			break
		}
	}
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
		log.Printf("[recursive] root hints: %s, %d addresses, PGP-verified %v%s", st.Source, st.Addresses, st.Verified, detail)
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
			log.Fatalf("upstream %q: %v", spec, err)
		}
		upstreams = append(upstreams, up)
		log.Printf("[upstream] %s -> %s", up.Name(), up.Address())
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
		log.Printf("[lists] initial fetch partially failed: %v (using cached content)", err)
	} else {
		lists.ReloadAll()
	}

	// ---- query log (Dragonfly stream, same tier as the DNS cache) ----
	ql, err := querylog.New(cfg.Cache.Addr, cfg.Cache.Password, cfg.Cache.DB, cfg.Log.RetentionDays, cfg.Log.BatchSize)
	if err != nil {
		log.Fatalf("query log: %v", err)
	}
	defer ql.Close()
	ql.StartPruner(ctx)

	// ---- TLS for DoT / DoH / DoQ ----
	tlsConf, err := cert.LoadOrGenerate(
		cfg.TLS.CertFile, cfg.TLS.KeyFile,
		cfg.TLS.CertDir, cfg.TLS.SelfSignedHosts)
	if err != nil {
		log.Fatalf("tls: %v", err)
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
	handler.SetRewriter(dnsserver.BuildRewriter(cfg.Rewrites))
	handler.SetClientRouter(dnsserver.BuildClientRouter(cfg, lists))
	handler.SetRateLimiter(dnsserver.BuildRateLimiter(cfg.RateLimit))
	handler.SetDNSSEC(cfg.DNSSEC.Enabled, cfg.DNSSEC.RequireAD)
	// Multi-upstream resolution strategy (config upstream_mode: race or
	// sequential). NewHandler defaults to race; apply the configured value.
	handler.SetUpstreamMode(cfg.UpstreamMode)
	// Rebuild per-client-group engines whenever blocklist content changes
	// (auto-refresh ticker, manual "refresh all lists") — they're built from
	// the same cached content the global engine uses.
	lists.OnChange = func() { handler.SetClientRouter(dnsserver.BuildClientRouter(cfg, lists)) }
	dnsMgr := dnsserver.NewManager(handler, tlsConf)
	// SO_REUSEPORT socket count for the plain UDP and DoQ listeners
	// (server.udp_sockets: 0 = auto, 1 = exclusive single socket, N =
	// explicit). Re-applied before every listener restart below.
	dnsMgr.SetUDPSockets(cfg.Server.UDPSockets)
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
		log.Printf("[web] dashboard and DoH share %s — serving /dns-query on the dashboard HTTPS listener", cfg.Server.WebListen)
	}
	results, err := dnsMgr.Start(
		cfg.Server.ListenUDP, cfg.Server.ListenTCP,
		cfg.Server.ListenDoT, dohAddr(), cfg.Server.ListenDoQ,
		cfg.Server.DoHPath,
	)
	if err != nil {
		log.Fatalf("dns listeners: %v", err)
	}
	// Report listener bind errors (e.g. port 53 already in use).
	go func() {
		for res := range results {
			if res.Err != nil {
				log.Printf("[dns] listener %s on %s failed: %v", res.Proto, res.Addr, res.Err)
			}
		}
	}()

	// ---- cloudflared tunnel (baked in) ----
	tunnelMgr := tunnel.NewManager(*dataDir)

	// ---- REST API + web UI ----
	var webFS fs.FS
	if web.HasFrontend() {
		webFS = web.FS()
	} else {
		log.Printf("[web] frontend not embedded — run `make web build` for the dashboard")
	}

	saveConfig := func() error { return cfg.Save(*configPath) }
	apiApp := &api.App{
		Config:     cfg,
		ConfigPath: *configPath,
		SaveConfig: saveConfig,
		WebFS:      webFS,
	}
	apiHandler := &api.Handler{
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
	}
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
	geoDir := filepath.Join(*dataDir, "geo")
	geoMgr := geoip.NewManager(geoDir, cfg.GeoBlock.BaseURL)
	fwMgr := firewall.New()
	apiHandler.Geo = geoMgr
	apiHandler.Firewall = fwMgr
	buildGeo := func(g config.GeoBlockConfig) error {
		// A silent no-op here would be confusing: honeypots/IPs are useless
		// unless the feature is enabled, so say so loudly (boot + every
		// config save / refresh that hits this branch).
		if !g.Enabled && (len(g.IPs) > 0 || len(g.Honeypots) > 0) {
			log.Printf("[geo] WARNING: honeypot domains / blocked IPs are configured but geo_block.enabled is false — nothing is being enforced")
		}
		if !g.Enabled || (len(g.Countries) == 0 && len(g.IPs) == 0 && len(g.Honeypots) == 0) {
			handler.SetGeo(nil)
			handler.SetIPBanner(nil)
			if err := fwMgr.Clear(); err != nil {
				log.Printf("[firewall] clear: %v", err)
			}
			return nil
		}
		// Client-IP banner: configured block IPs/CIDRs plus honeypot
		// auto-blocks (loaded from a persisted file so they survive
		// restarts/reloads). A honeypot hit pushes the client straight into
		// the host firewall's drop set via OnBlock.
		banner := geoip.NewBanner(filepath.Join(geoDir, "blocked-ips.txt"), g.Allowlist, g.IPs, g.Honeypots)
		handler.SetIPBanner(banner)
		// Opt-in: let plain-UDP honeypot hits auto-block their source too
		// (off by default — spoofed UDP must not be able to block victims).
		handler.SetTrustUDP(g.TrustUDP)
		banner.OnBlock = func(ip string) {
			if err := fwMgr.AddIP(ip); err != nil {
				log.Printf("[firewall] add blocked client %s: %v", ip, err)
			}
		}
		b, err := geoMgr.Refresh(ctx, g.Countries, g.Allowlist)
		handler.SetGeo(b)
		// Packet-level blocking: rebuild the firewall rules from the freshly
		// persisted CIDR lists plus the banner's full block set (configured
		// IPs and honeypot auto-blocks). A failure here (e.g. no cached data
		// yet, or no root) is logged and leaves the DNS-level REFUSED
		// blocking in effect — buildGeo's own error (data fetch) is what
		// the caller surfaces.
		if backend, ferr := fwMgr.Apply(g.Countries, g.Allowlist, banner.List(), geoDir); ferr != nil {
			log.Printf("[firewall] country rules not applied (%s): %v", backend, ferr)
		} else {
			log.Printf("[firewall] dropping inbound traffic from blocked countries via %s", backend)
		}
		return err
	}
	if err := buildGeo(cfg.GeoBlock); err != nil {
		log.Printf("[geo] initial load partially failed (using cached data): %v", err)
	}
	// The config-save and refresh-button paths must never stall on a
	// country-data download (multi-country fetches can take seconds), so
	// RebuildGeo runs the rebuild off the request path; the DNS handler
	// keeps serving with the previous blocker until the new one is ready.
	apiHandler.RebuildGeo = func(g config.GeoBlockConfig) error {
		go func() {
			if err := buildGeo(g); err != nil {
				log.Printf("[geo] background refresh: %v", err)
			}
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
			if g.Enabled && len(g.Countries) > 0 && g.AutoUpdate > 0 {
				wait = g.AutoUpdate
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(wait):
			}
			// Re-read the config after the sleep: the user may have disabled
			// geo (or changed countries / the interval) while we waited, and
			// the rebuild must never act on a stale snapshot — otherwise a
			// long-interval refresh could re-enable blocking the dashboard
			// had just switched off.
			cfgMu.Lock()
			g = cfg.GeoBlock
			cfgMu.Unlock()
			if g.Enabled && len(g.Countries) > 0 && g.AutoUpdate > 0 {
				if err := buildGeo(g); err != nil {
					log.Printf("[geo] auto-refresh: %v", err)
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
			time.Duration(cfg.TLS.ACME.DNS01.PropagationWait)*time.Second,
		)
		if err != nil {
			log.Printf("[acme] disabled: %v", err)
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
	webSrv := &http.Server{
		Addr:         cfg.Server.WebListen,
		Handler:      webHandler(),
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
				log.Printf("[web] cannot enable HTTPS: %v (falling back to plain HTTP)", err)
				go func() { _ = srv.ListenAndServe() }()
				return
			}
			// When DoH shares this listener, advertise HTTP/2 (RFC 8484
			// recommends h2 for DoH clients).
			if webSharesDoH() {
				wtls = wtls.Clone()
				wtls.NextProtos = []string{"h2", "http/1.1"}
				if err := http2.ConfigureServer(srv, &http2.Server{}); err != nil {
					log.Printf("[web] http2 setup: %v", err)
				}
			}
			go func() {
				// Tuned socket: the dashboard serves DoH when it shares the
				// HTTPS port, so its buffers get the same boost as the DNS
				// listeners (accepted connections inherit the settings).
				ln, err := tuning.ListenConfig().Listen(context.Background(), "tcp", srv.Addr)
				if err != nil {
					log.Printf("[web] server error: %v", err)
					return
				}
				log.Printf("[web] dashboard + API on https://%s (HTTPS)", srv.Addr)
				if err := srv.Serve(tls.NewListener(ln, wtls)); err != nil && err != http.ErrServerClosed {
					log.Printf("[web] server error: %v", err)
				}
			}()
			return
		}
		go func() {
			log.Printf("[web] dashboard + API on http://%s", srv.Addr)
			if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				log.Printf("[web] server error: %v", err)
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
			log.Printf("[web] plain HTTP on %s redirecting to https://%s", addr, host)
			if err := ns.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				log.Printf("[web] redirect listener on %s stopped: %v", addr, err)
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
			cfg.Server.ListenDoT, dohAddr(), cfg.Server.ListenDoQ,
			cfg.Server.DoHPath, newTLS,
		); err != nil {
			return fmt.Errorf("dns listeners: %w", err)
		}
		log.Printf("[tls] certificate reloaded and listeners rebound")
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
				log.Printf("[acme] reload after issuance: %v", err)
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
		newCache, err := cache.New(cfg.Cache.Addr, cfg.Cache.Password, cfg.Cache.DB, cfg.Cache.TTL, cfg.Cache.NegativeTTL, cfg.Cache.ServeStale, cfg.Cache.L1Entries)
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
				log.Printf("[recursive] root hints manager started on config reload (%s, %d addresses, PGP-verified %v)", st.Source, st.Addresses, st.Verified)
			}
		}

		// 4. Restart the DNS listeners with the new addresses + TLS. This is
		//    the only step that can fail with hard bind errors, so it runs
		//    before anything is swapped. Note: UDP/TCP/DoT bind failures are
		//    reported asynchronously via the results channel, not as errors.
		dnsMgr.SetUDPSockets(cfg.Server.UDPSockets)
		if err := dnsMgr.Restart(
			cfg.Server.ListenUDP, cfg.Server.ListenTCP,
			cfg.Server.ListenDoT, dohAddr(), cfg.Server.ListenDoQ,
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
		handler.SetBlockPolicy(cfg.Filter.BlockResponse, cfg.Filter.BlockTTL)
		handler.SetTimeout(time.Duration(cfg.Server.TimeoutSec) * time.Second)
		handler.SetFailureTTL(cfg.Cache.FailureTTL)
		newCache.SetLookupTimeout(cfg.Cache.LookupTimeout)
		handler.SetRewriter(dnsserver.BuildRewriter(cfg.Rewrites))
		handler.SetClientRouter(dnsserver.BuildClientRouter(cfg, lists))
		handler.SetRateLimiter(dnsserver.BuildRateLimiter(cfg.RateLimit))
		handler.SetDNSSEC(cfg.DNSSEC.Enabled, cfg.DNSSEC.RequireAD)
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
						log.Printf("[acme] reload after issuance: %v", err)
					}
				}
			}
		} else {
			stopACME()
		}
		// Re-evaluate the HTTP->HTTPS redirect listener on every reload: it
		// starts/stops/keeps itself based on the new web_tls/web_redirect config.
		startRedirect()
		log.Printf("[config] reload applied: listeners, cache, TLS, upstreams")
		return nil
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
			log.Printf("[tunnel] failed to start: %v", err)
		} else {
			log.Printf("[tunnel] started in %s mode", mode)
		}
	}

	// ---- wait for shutdown ----
	<-ctx.Done()
	log.Printf("shutting down...")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	dnsMgr.Shutdown(shutdownCtx)
	tunnelMgr.Stop()
	webMu.Lock()
	currentWeb := webSrv
	webMu.Unlock()
	_ = currentWeb.Shutdown(shutdownCtx)
	ql.Close()
	log.Printf("bye")
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

// buildRewriter, buildRateLimiter and buildClientRouter live in the
// dnsserver package (as BuildRewriter etc.) so the API's live config-apply
// path can share the exact same logic instead of duplicating it.
