package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/eoghan2t9/Irongrid-DNS/internal/acme"
	"github.com/eoghan2t9/Irongrid-DNS/internal/api"
	"github.com/eoghan2t9/Irongrid-DNS/internal/cert"
	"github.com/eoghan2t9/Irongrid-DNS/internal/tuning"
)

// setupACME starts Let's Encrypt auto-issuance when enabled.
func (a *app) setupACME() {
	// ---- ACME (Let's Encrypt) auto-issuance ----
	// startACME is callable at boot AND from the reload hook so toggling
	// tls.acme.enabled in the dashboard takes effect without a restart.
	// acmeMgr is an atomic pointer: the web_redirect handler reads it on
	// every port-80 request while reload may swap it, so a plain variable
	// would be a data race.
	// acmeExternalHTTP01 remembers the ExternalHTTP01 mode the running
	// manager was created with so a reload that toggles web_tls/web_redirect
	// can recreate the manager instead of leaving a port-80 conflict.
	a.acmeExternalHTTP01 = false
	a.startACME()
}

// stopACME stops the ACME manager, if running.
func (a *app) stopACME() {
	if m := a.acmeMgr.Swap(nil); m != nil {
		m.Stop()
	}
	a.apiHandler.ACME = nil
}

// startACME is callable at boot AND from the reload hook so toggling
// tls.acme.enabled in the dashboard takes effect without a restart.
func (a *app) startACME() {
	if !a.cfg.TLS.ACME.Enabled || a.acmeMgr.Load() != nil {
		return
	}
	dnsProvider, err := acme.NewDNSProvider(
		a.cfg.TLS.ACME.DNS01.Provider,
		acme.DNSProviderConfig{
			CloudflareToken:    a.cfg.TLS.ACME.DNS01.CloudflareToken,
			DigitalOceanToken:  a.cfg.TLS.ACME.DNS01.DigitalOceanToken,
			HetznerToken:       a.cfg.TLS.ACME.DNS01.HetznerToken,
			GoDaddyKey:         a.cfg.TLS.ACME.DNS01.GoDaddyKey,
			GoDaddySecret:      a.cfg.TLS.ACME.DNS01.GoDaddySecret,
			AWSAccessKeyID:     a.cfg.TLS.ACME.DNS01.AWSAccessKeyID,
			AWSSecretAccessKey: a.cfg.TLS.ACME.DNS01.AWSSecretAccessKey,
		},
	)
	if err != nil {
		slog.Warn("acme disabled", "error", err)
		return
	}
	// When web_redirect listens on the same port as the http-01 challenge,
	// the redirect listener serves the challenge tokens itself so the
	// manager must not bind a second listener on that port.
	httpPort := a.cfg.TLS.ACME.HTTP01Port
	if httpPort == 0 {
		httpPort = 80
	}
	redirectPort := a.cfg.Server.WebRedirectPort
	if redirectPort == 0 {
		redirectPort = 80
	}
	a.acmeExternalHTTP01 = a.cfg.Server.WebTLS && a.cfg.Server.WebRedirect && redirectPort == httpPort
	m := acme.New(acme.Options{
		Email:           a.cfg.TLS.ACME.Email,
		Domains:         a.cfg.TLS.ACME.Domains,
		CertDir:         a.cfg.TLS.CertDir,
		Staging:         a.cfg.TLS.ACME.Staging,
		HTTP01Port:      a.cfg.TLS.ACME.HTTP01Port,
		RenewBeforeDays: a.cfg.TLS.ACME.RenewBeforeDays,
		DNS:             dnsProvider,
		DNSProvider:     a.cfg.TLS.ACME.DNS01.Provider,
		DNSWait:         time.Duration(a.cfg.TLS.ACME.DNS01.PropagationWait) * time.Second,
		ExternalHTTP01:  a.acmeExternalHTTP01,
	})
	a.acmeMgr.Store(m)
	a.apiHandler.ACME = m
	if a.cfg.TLS.CertDir == "" {
		a.cfg.TLS.CertDir = "data/certs"
	}
	go m.RunLoop(a.ctx)
}

// setupWeb starts the dashboard + API server and the optional HTTP->HTTPS redirect.
func (a *app) setupWeb() {
	// ---- web server (dashboard + API) ----
	// ConnState enforces the per-IP connection cap (server.max_http_conns_per_ip)
	// when the dashboard shares its port with DoH — a no-op (nil) otherwise.
	a.webSrv = &http.Server{
		Addr:         a.cfg.Server.WebListen,
		Handler:      a.webHandler(),
		ConnState:    a.dnsMgr.HTTPConnState(),
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
	}
	// Track the TLS mode of the currently running web server so toggling
	// web_tls without changing the address also triggers a rebind.
	a.webTLSServing = a.cfg.Server.WebTLS
	// webMu serialises web-server rebinding between the ACME RunLoop goroutine
	// (OnIssued) and the config reload hook, which both swap webSrv.
	a.startWebServer(a.webSrv, a.webTLSServing)
	// ---- optional HTTP->HTTPS redirect (web_redirect) ----
	// When the dashboard runs on HTTPS, a small plain-HTTP listener 301s
	// every request to https://<host>/. It is re-evaluated on every reload
	// so toggling web_tls / web_redirect / web_listen takes effect without
	// a process restart.
	a.startRedirect()
}

// webHandler returns the web-server handler: the dashboard + API router,
// wrapped so the DoH endpoint is served from the same listener when the
// dashboard shares its HTTPS port with DoH.
func (a *app) webHandler() http.Handler {
	router := api.NewRouter(a.apiApp)
	if !a.webSharesDoH() {
		return router
	}
	mux := http.NewServeMux()
	mux.Handle(a.cfg.Server.DoHPath, a.dnsMgr.DoHHandler())
	mux.Handle("/", router)
	return mux
}

// startWebServer serves srv over HTTPS (useTLS) or plain HTTP.
func (a *app) startWebServer(srv *http.Server, useTLS bool) {
	if useTLS {
		// Serve the dashboard + API over HTTPS with the same cert that
		// secures DoT/DoH/DoQ.
		wtls, err := cert.LoadOrGenerate(a.cfg.TLS.CertFile, a.cfg.TLS.KeyFile, a.cfg.TLS.CertDir, a.cfg.TLS.SelfSignedHosts)
		if err != nil {
			slog.Error("cannot enable HTTPS, falling back to plain HTTP", "error", err)
			go func() {
				if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
					slog.Error("web server error", "error", err)
				}
			}()
			return
		}
		// When DoH shares this listener, advertise HTTP/2 (RFC 8484
		// recommends h2 for DoH clients).
		if a.webSharesDoH() {
			wtls = wtls.Clone()
			wtls.NextProtos = []string{"h2", "http/1.1"}
			srv.Protocols = new(http.Protocols)
			srv.Protocols.SetHTTP1(true)
			srv.Protocols.SetHTTP2(true)
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

// ---- optional HTTP->HTTPS redirect (web_redirect) ----
// When the dashboard runs on HTTPS, a small plain-HTTP listener 301s
// every request to https://<host>/. It is re-evaluated on every reload
// so toggling web_tls / web_redirect / web_listen takes effect without
// a process restart.
func (a *app) startRedirect() {
	want := a.cfg.Server.WebTLS && a.cfg.Server.WebRedirect
	port := a.cfg.Server.WebRedirectPort
	if port == 0 {
		port = 80
	}
	addr := fmt.Sprintf(":%d", port)
	// Already serving the right thing — nothing to do.
	if want && a.redirectSrv != nil && a.redirectSrv.Addr == addr {
		return
	}
	// Tear down the old listener if there is one. Shutdown runs in a
	// goroutine so the reload response flushes first; the replacement
	// waits a beat so the old listener's port is actually free.
	if a.redirectSrv != nil {
		old := a.redirectSrv
		a.redirectSrv = nil
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := old.Shutdown(ctx); err != nil {
				_ = old.Close()
			}
		}()
	}
	if !want {
		return
	}
	host, httpsPort := hostOnly(a.cfg.Server.WebListen), webTLSPort(a.cfg.Server.WebListen)
	// When web_redirect shares the http-01 challenge port, serve the ACME
	// challenge tokens on this same listener instead of redirecting them.
	redirect := httpsRedirect(httpsPort)
	ns := &http.Server{
		Addr:              addr,
		ReadHeaderTimeout: 10 * time.Second, // gosec G112: bound slow-header clients
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if m := a.acmeMgr.Load(); m != nil && m.HandleChallenge(w, r) {
				return
			}
			redirect(w, r)
		}),
	}
	a.redirectSrv = ns
	go func() {
		time.Sleep(200 * time.Millisecond) // let an old listener release the port
		slog.Info("plain HTTP redirect listening", "addr", addr, "redirect_host", host)
		if err := ns.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("redirect listener stopped", "addr", addr, "error", err)
		}
	}()
}

// setupTLSReload wires the TLS-only reload hook (dashboard cert changes and ACME
// issuance).
func (a *app) setupTLSReload() {
	// ---- TLS-only reload: used after the dashboard generates/uploads a
	// certificate. Rebinds the DNS listeners with the new cert; leaves the
	// cache and upstreams untouched so it works even while Dragonfly is down.
	a.apiHandler.ReloadTLS = func() error {
		newTLS, err := cert.LoadOrGenerate(a.cfg.TLS.CertFile, a.cfg.TLS.KeyFile, a.cfg.TLS.CertDir, a.cfg.TLS.SelfSignedHosts)
		if err != nil {
			return fmt.Errorf("tls: %w", err)
		}
		if err := a.dnsMgr.Restart(
			a.cfg.Server.ListenUDP, a.cfg.Server.ListenTCP,
			a.cfg.Server.ListenDoT, a.dohAddr(), a.cfg.Server.ListenDoH3, a.cfg.Server.ListenDoQ,
			a.cfg.Server.DoHPath, newTLS,
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
	baseReloadTLS := a.apiHandler.ReloadTLS
	a.apiHandler.ReloadTLS = func() error {
		if err := baseReloadTLS(); err != nil {
			return err
		}
		// Rebind the web server too if it runs on HTTPS.
		if a.cfg.Server.WebTLS {
			a.webMu.Lock()
			oldWeb := a.webSrv
			newWeb := &http.Server{
				Addr:         a.cfg.Server.WebListen,
				Handler:      a.webHandler(),
				ConnState:    a.dnsMgr.HTTPConnState(),
				ReadTimeout:  30 * time.Second,
				WriteTimeout: 30 * time.Second,
			}
			a.webSrv = newWeb
			a.webTLSServing = true
			a.webMu.Unlock()
			go func() {
				time.Sleep(200 * time.Millisecond)
				_ = oldWeb.Shutdown(context.Background())
				a.startWebServer(newWeb, true)
			}()
			a.startRedirect()
		}
		return nil
	}
	// After a successful ACME issuance, rebind everything with the new cert.
	if m := a.acmeMgr.Load(); m != nil {
		m.OnIssued = func() {
			if err := a.apiHandler.ReloadTLS(); err != nil {
				slog.Error("acme reload after issuance failed", "error", err)
			}
		}
	}
}
