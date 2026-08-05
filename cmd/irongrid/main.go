package main

import (
	"context"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

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

	webSrv := &http.Server{
		Addr:         cfg.Server.WebListen,
		Handler:      api.NewRouter(apiApp),
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
	}
	go func() {
		log.Printf("[web] dashboard + API on http://%s", cfg.Server.WebListen)
		if err := webSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("[web] server error: %v", err)
		}
	}()

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

		// 6. Rebind the web server if its address changed. Shutdown is run in
		//    a goroutine: calling Shutdown synchronously from inside a request
		//    served by the same server would wait on the in-flight handler and
		//    deadlock, and the delay lets the reload response flush first.
		if webSrv.Addr != cfg.Server.WebListen {
			oldWeb := webSrv
			newWeb := &http.Server{
				Addr:         cfg.Server.WebListen,
				Handler:      api.NewRouter(apiApp),
				ReadTimeout:  30 * time.Second,
				WriteTimeout: 30 * time.Second,
			}
			webSrv = newWeb
			go func() {
				time.Sleep(200 * time.Millisecond) // let the reload response flush
				_ = oldWeb.Shutdown(context.Background())
				log.Printf("[web] dashboard + API on http://%s", cfg.Server.WebListen)
				if err := newWeb.ListenAndServe(); err != nil && err != http.ErrServerClosed {
					log.Printf("[web] server error: %v", err)
				}
			}()
		}
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
