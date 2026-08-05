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
	"syscall"
	"time"

	"github.com/eoghan2t9/Irongrid-DNS/internal/acme"
	"github.com/eoghan2t9/Irongrid-DNS/internal/api"
	"github.com/eoghan2t9/Irongrid-DNS/internal/cache"
	"github.com/eoghan2t9/Irongrid-DNS/internal/catalog"
	"github.com/eoghan2t9/Irongrid-DNS/internal/cert"
	"github.com/eoghan2t9/Irongrid-DNS/internal/config"
	"github.com/eoghan2t9/Irongrid-DNS/internal/dnsserver"
	"github.com/eoghan2t9/Irongrid-DNS/internal/filter"
	"github.com/eoghan2t9/Irongrid-DNS/internal/installer"
	"github.com/eoghan2t9/Irongrid-DNS/internal/querylog"
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
	dfly, err := cache.New(cfg.Cache.Addr, cfg.Cache.Password, cfg.Cache.DB, cfg.Cache.TTL, cfg.Cache.NegativeTTL)
	if err != nil {
		log.Fatalf("cache: %v\n\nDragonfly is a hard requirement — start it (see docker-compose.yml) and retry.", err)
	}
	// Note: closes the *current* cache, which reload may have swapped.
	defer func() { _ = dfly.Close() }()
	log.Printf("[cache] Dragonfly caching enabled (positive TTL %s, negative TTL %s)", cfg.Cache.TTL, cfg.Cache.NegativeTTL)

	// ---- upstreams ----
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
		specs = append(specs, filter.ListSpec{ID: s.ID, Name: s.Name, URL: s.URL, Enabled: s.Enabled, AutoUpdate: s.AutoUpdate})
	}
	lists.SetSpecs(specs)
	lists.LoadCached()
	lists.ReloadAll()
	lists.StartRefresh(ctx)

	if err := lists.FetchAll(ctx); err != nil {
		log.Printf("[lists] initial fetch partially failed: %v (using cached content)", err)
	} else {
		lists.ReloadAll()
	}

	// ---- query log ----
	ql, err := querylog.New(cfg.Log.QueryLogFile, cfg.Log.RetentionDays)
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
	dnsMgr := dnsserver.NewManager(handler, tlsConf)
	results, err := dnsMgr.Start(
		cfg.Server.ListenUDP, cfg.Server.ListenTCP,
		cfg.Server.ListenDoT, cfg.Server.ListenDoH, cfg.Server.ListenDoQ,
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
		Config:      cfg,
		ConfigPath:  *configPath,
		SaveConfig:  saveConfig,
		WebFS:       webFS,
	}
	apiHandler := &api.Handler{
		Cfg:         cfg,
		ConfigPath:  *configPath,
		SaveConfig:  saveConfig,
		Engine:      engine,
		Lists:       lists,
		Cache:       dfly,
		Log:         ql,
		DNS:         handler,
		Tunnel:      tunnelMgr,
		Upstreams:   upstreams,
		Catalog:     catalog.Default(),
		StartedAt:   time.Now(),
		Version:     version.Version,
	}
	apiApp.Handler = apiHandler

	// ---- ACME (Let's Encrypt) auto-issuance ----
	var acmeMgr *acme.Manager
	if cfg.TLS.ACME.Enabled {
		dnsProvider, err := acme.NewDNSProvider(
			cfg.TLS.ACME.DNS01.Provider,
			cfg.TLS.ACME.DNS01.CloudflareToken,
			time.Duration(cfg.TLS.ACME.DNS01.PropagationWait)*time.Second,
		)
		if err != nil {
			log.Fatalf("acme: %v", err)
		}
		acmeMgr = acme.New(acme.Options{
			Email:           cfg.TLS.ACME.Email,
			Domains:         cfg.TLS.ACME.Domains,
			CertDir:         cfg.TLS.CertDir,
			Staging:         cfg.TLS.ACME.Staging,
			HTTP01Port:      cfg.TLS.ACME.HTTP01Port,
			RenewBeforeDays: cfg.TLS.ACME.RenewBeforeDays,
			DNS:             dnsProvider,
			DNSProvider:     cfg.TLS.ACME.DNS01.Provider,
		})
		apiHandler.ACME = acmeMgr
		if cfg.TLS.CertDir == "" {
			cfg.TLS.CertDir = "data/certs"
		}
		go acmeMgr.RunLoop(ctx)
	}

	// ---- web server (dashboard + API) ----
	webSrv := &http.Server{
		Addr:         cfg.Server.WebListen,
		Handler:      api.NewRouter(apiApp),
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
	}
	// Track the TLS mode of the currently running web server so toggling
	// web_tls without changing the address also triggers a rebind.
	webTLSServing := cfg.Server.WebTLS
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
			go func() {
				ln, err := net.Listen("tcp", srv.Addr)
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
		ns := &http.Server{
			Addr:    addr,
			Handler: http.HandlerFunc(httpsRedirect(httpsPort)),
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
			cfg.Server.ListenDoT, cfg.Server.ListenDoH, cfg.Server.ListenDoQ,
			cfg.Server.DoHPath, newTLS,
		); err != nil {
			return fmt.Errorf("dns listeners: %w", err)
		}
		log.Printf("[tls] certificate reloaded and listeners rebound")
		return nil
	}

	// After an ACME issuance/renewal, rebind the listeners + web server with
	// the fresh certificate. Wrap the base ReloadTLS (captured first) so the
	// ACME path also restarts an HTTPS web server.
	if acmeMgr != nil {
		baseReloadTLS := apiHandler.ReloadTLS
		apiHandler.ReloadTLS = func() error {
			if err := baseReloadTLS(); err != nil {
				return err
			}
			// Rebind the web server too if it runs on HTTPS.
			if cfg.Server.WebTLS {
				oldWeb := webSrv
				newWeb := &http.Server{
					Addr:         cfg.Server.WebListen,
					Handler:      api.NewRouter(apiApp),
					ReadTimeout:  30 * time.Second,
					WriteTimeout: 30 * time.Second,
				}
				webSrv = newWeb
				webTLSServing = true
				go func() {
					time.Sleep(200 * time.Millisecond)
					_ = oldWeb.Shutdown(context.Background())
					startWebServer(newWeb, true)
				}()
				startRedirect()
			}
			return nil
		}
	}

	// ---- config reload: apply listener/cache/TLS/web changes in-process ----
	apiHandler.Reload = func() error {
		// Failure-atomic ordering: build every new component first and restart
		// the listeners before swapping any live references, so a bad config
		// leaves the running server untouched.

		// 1. Cache: connect to the new endpoint first; keep the old one on
		//    failure so a bad config never takes the server down.
		newCache, err := cache.New(cfg.Cache.Addr, cfg.Cache.Password, cfg.Cache.DB, cfg.Cache.TTL, cfg.Cache.NegativeTTL)
		if err != nil {
			return fmt.Errorf("cache: %w", err)
		}
		// 2. TLS: reload certificates before touching the listeners.
		newTLS, err := cert.LoadOrGenerate(cfg.TLS.CertFile, cfg.TLS.KeyFile, cfg.TLS.CertDir, cfg.TLS.SelfSignedHosts)
		if err != nil {
			_ = newCache.Close()
			return fmt.Errorf("tls: %w", err)
		}
		// 3. Upstreams: rebuild from the new specs.
		newUps := make([]*upstream.Upstream, 0, len(cfg.Upstreams))
		for _, spec := range cfg.Upstreams {
			up, err := upstream.Parse(spec)
			if err != nil {
				_ = newCache.Close()
				return fmt.Errorf("upstream %q: %w", spec, err)
			}
			newUps = append(newUps, up)
		}

		// 4. Restart the DNS listeners with the new addresses + TLS. This is
		//    the only step that can fail with hard bind errors, so it runs
		//    before anything is swapped. Note: UDP/TCP/DoT bind failures are
		//    reported asynchronously via the results channel, not as errors.
		if err := dnsMgr.Restart(
			cfg.Server.ListenUDP, cfg.Server.ListenTCP,
			cfg.Server.ListenDoT, cfg.Server.ListenDoH, cfg.Server.ListenDoQ,
			cfg.Server.DoHPath, newTLS,
		); err != nil {
			_ = newCache.Close()
			return fmt.Errorf("dns listeners: %w", err)
		}

		// 5. Now swap the hot references — listeners are already serving with
		//    the new TLS config, so this only changes cache/upstreams/policy.
		handler.SetCache(newCache)
		handler.SetUpstreams(newUps)
		handler.SetBlockPolicy(cfg.Filter.BlockResponse, cfg.Filter.BlockTTL)
		handler.SetTimeout(time.Duration(cfg.Server.TimeoutSec) * time.Second)
		apiHandler.Cache = newCache
		apiHandler.Upstreams = newUps
		oldCache := dfly
		dfly = newCache
		_ = oldCache.Close()

		// 6. Rebind the web server if its address or TLS mode changed. Shutdown
		//    is run in a goroutine: calling Shutdown synchronously from inside
		//    a request served by the same server would wait on the in-flight
		//    handler and deadlock, and the delay lets the reload flush first.
		if webSrv.Addr != cfg.Server.WebListen || webTLSServing != cfg.Server.WebTLS {
			oldWeb := webSrv
			newWeb := &http.Server{
				Addr:         cfg.Server.WebListen,
				Handler:      api.NewRouter(apiApp),
				ReadTimeout:  30 * time.Second,
				WriteTimeout: 30 * time.Second,
			}
			webSrv = newWeb
			webTLSServing = cfg.Server.WebTLS
			useTLS := webTLSServing
			go func() {
				time.Sleep(200 * time.Millisecond) // let the reload response flush
				_ = oldWeb.Shutdown(context.Background())
				startWebServer(newWeb, useTLS)
			}()
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
	_ = webSrv.Shutdown(shutdownCtx)
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
