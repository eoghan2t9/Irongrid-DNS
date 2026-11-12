// The directive below forces Go's own pure-Go DNS resolver for every
// outbound lookup this process makes on its own behalf — blocklist URL
// fetches, ACME DNS-01 provider APIs, VPN provider APIs, the update
// checker — skipping the cgo/libc resolver path entirely. It has no effect
// on the DNS *server* itself, which never resolves through net.Lookup*.
//
//go:debug netdns=go
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/eoghan2t9/Irongrid-DNS/internal/cache"
	"github.com/eoghan2t9/Irongrid-DNS/internal/config"
	"github.com/eoghan2t9/Irongrid-DNS/internal/dnsserver"
	"github.com/eoghan2t9/Irongrid-DNS/internal/installer"
	"github.com/eoghan2t9/Irongrid-DNS/internal/sdnotify"
	"github.com/eoghan2t9/Irongrid-DNS/internal/tuning"
	"github.com/eoghan2t9/Irongrid-DNS/internal/version"
	"github.com/eoghan2t9/Irongrid-DNS/internal/vpn"
)

// vpnRelay is the VPN Smart-DNS proxy relay's current listeners (nil when
// vpn.proxy.enabled is false or unset). Guarded by vpnRelayMu since
// applyVPNProxy runs both at boot and, asynchronously, on every config
// reload via RebuildVPN.
var (
	vpnRelayMu sync.Mutex
	vpnRelay   *vpn.Relay
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

	// Default logger (text, info level) until the config loads below and
	// can supply logging.level / logging.json — early errors (a bad
	// -config path, an unreadable YAML file) still need somewhere to go.
	slog.SetDefault(newLogger(config.LoggingConfig{}))
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
	// Reconfigure logging from the loaded config (logging.level /
	// logging.json); everything before this line used the info/text
	// default set above.
	slog.SetDefault(newLogger(cfg.Logging))
	if cfg.Web.Password == "" {
		cfg.Web.Password = "irongrid"
		slog.Warn("using default password — change it", "password", cfg.Web.Password, "config_path", *configPath)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	a := &app{cfg: cfg, ctx: ctx, configPath: *configPath, dataDir: *dataDir}
	a.setupCache()
	// Note: closes the *current* cache, which reload may have swapped.
	defer func() { _ = a.dfly.Close() }()
	a.setupRootHints()
	a.setupUpstreams()
	a.setupFilter()
	a.setupQueryLog()
	defer a.ql.Close()
	a.setupTLS()
	a.setupHandler()
	a.setupPolicy()
	a.setupDHCP()
	a.setupRouting()
	a.setupDNSListeners()
	a.setupTunnelVPN()
	a.setupAPI()
	a.setupGeo()
	a.setupACME()
	a.setupWeb()
	a.setupTLSReload()
	a.apiHandler.Reload = a.reload
	a.startCloudflared()
	a.startTunnel()

	// ---- systemd readiness + watchdog ----
	// Every listener above is bound and serving by this point. sdnotify is a
	// no-op outside of a systemd Type=notify unit, so this is safe to call
	// unconditionally on any platform/init system.
	sdnotify.StartWatchdog(a.ctx)
	if err := sdnotify.Notify("READY=1"); err != nil {
		slog.Warn("sd_notify READY failed", "error", err)
	}

	// ---- wait for shutdown ----
	<-a.ctx.Done()
	_ = sdnotify.Notify("STOPPING=1")
	slog.Info("shutting down...")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	a.dnsMgr.Shutdown(shutdownCtx)
	a.tunnelMgr.Stop()
	vpnRelayMu.Lock()
	if vpnRelay != nil {
		vpnRelay.Stop()
	}
	vpnRelayMu.Unlock()
	a.vpnMgr.Close()
	a.webMu.Lock()
	currentWeb := a.webSrv
	a.webMu.Unlock()
	_ = currentWeb.Shutdown(shutdownCtx)
	a.ql.Close()
	slog.Info("bye")
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
