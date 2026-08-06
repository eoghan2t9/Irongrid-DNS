// Package installer provides the interactive TUI setup wizard (`irongrid
// install`). It walks the user through listeners, upstreams, cache, blocklist
// and whitelist presets (from the shared catalog), web credentials and TLS,
// then completes the whole install: it writes a validated irongrid.yaml,
// installs and starts Dragonfly (the required cache) when asked, places the
// binary at the canonical path, writes platform service files (systemd /
// launchd / Windows service / Docker Compose) and installs + starts the
// chosen service where possible.
//
// The wizard renders with the Catppuccin theme on a real TTY and falls back
// to accessible (line-based) rendering when stdin is not a terminal, which
// also makes it scriptable. Setting IRONGRID_ACCESSIBLE=1 forces accessible
// mode even on a TTY (used by CI and the E2E tests).
package installer

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/charmbracelet/huh"
	"github.com/eoghan2t9/Irongrid-DNS/internal/catalog"
	"github.com/eoghan2t9/Irongrid-DNS/internal/config"
	"golang.org/x/term"
)

// Options configures a Run.
type Options struct {
	ConfigPath string    // where irongrid.yaml will be written
	DataDir    string    // runtime data directory (querylog, lists, certs)
	In         io.Reader // wizard input; nil = os.Stdin
	Out        io.Writer // wizard output; nil = os.Stdout
	// WithDragonfly forces Dragonfly installation even when the wizard's
	// "Install and start Dragonfly now?" question is declined. Without it,
	// the wizard asks (native deployments) whether to install Dragonfly.
	WithDragonfly bool
}

// wizard carries the answers plus the IO streams for one interactive run.
type wizard struct {
	a           *answers
	in          io.Reader
	out         io.Writer
	dflyStarted bool // a cache answered PING after EnsureDragonfly ran
}

// answers collects every wizard choice before the config is built.
type answers struct {
	deploy         string   // "docker" | "native"
	service        string   // "systemd" | "launchd" | "windows" | "docker" | "none"
	protos         []string // subset of {"UDP","TCP","DoT","DoH","DoQ"}
	listenHost     string
	upstreamPreset string // "cloudflare" | "google" | "quad9" | "custom"
	customUpstream string
	cacheAddr      string
	cachePass      string
	blocklists     []string // catalog IDs
	whitelists     []string // catalog IDs
	webUser        string
	webPass        string
	webConfirm     string
	// webOnDoHPort serves the dashboard on the same HTTPS port as DoH
	// (https://host, no :8080 suffix) when DoH is enabled.
	webOnDoHPort     bool
	tlsHosts         string
	installDragonfly bool // native mode: install and start Dragonfly after writing the config
	confirm          bool
}

// Run presents the wizard, writes the config and service files, and prints
// the next steps.
func Run(opts Options) error {
	if opts.ConfigPath == "" {
		opts.ConfigPath = "irongrid.yaml"
	}
	if opts.DataDir == "" {
		opts.DataDir = "data"
	}

	w := &wizard{a: &answers{}, in: opts.In, out: opts.Out}
	if w.in == nil {
		w.in = os.Stdin
	}
	if w.out == nil {
		w.out = os.Stdout
	}
	cat := catalog.Default()

	w.banner()

	if err := w.askBasics(); err != nil {
		return err
	}
	if err := w.askListeners(); err != nil {
		return err
	}
	if err := w.askUpstreams(); err != nil {
		return err
	}
	if err := w.askCache(); err != nil {
		return err
	}
	if err := w.askDragonfly(); err != nil {
		return err
	}
	if err := w.askLists(cat); err != nil {
		return err
	}
	if err := w.askWeb(); err != nil {
		return err
	}
	if err := w.askTLS(); err != nil {
		return err
	}
	if err := w.askConfirm(); err != nil {
		return err
	}
	if !w.a.confirm {
		fmt.Fprintln(w.out, "\n✓ Installation cancelled — nothing was written.")
		return nil
	}

	cfg, err := w.a.buildConfig(cat)
	if err != nil {
		return fmt.Errorf("invalid configuration: %w", err)
	}

	// Resolve absolute paths so generated service files are self-contained.
	absConfig, err := filepath.Abs(opts.ConfigPath)
	if err != nil {
		absConfig = opts.ConfigPath
	}
	absData, err := filepath.Abs(opts.DataDir)
	if err != nil {
		absData = opts.DataDir
	}

	if err := cfg.Save(absConfig); err != nil {
		return fmt.Errorf("write config: %w", err)
	}
	fmt.Fprintf(w.out, "\n✍  Config written to %s\n", absConfig)

	files, err := writeServiceFiles(w, absConfig, absData)
	if err != nil {
		return err
	}
	if len(files) > 0 {
		fmt.Fprintf(w.out, "   Service files written to %s\n", filepath.Dir(files[0]))
	}

	// Dragonfly: bundled in Docker deployments (in the compose file); on
	// native deployments it is installed/started when the user opted in (or
	// --with-dragonfly was passed). An already-running Redis-compatible
	// server on the address is detected and reused.
	if w.a.deploy == "native" && (w.a.installDragonfly || opts.WithDragonfly) {
		fmt.Fprintln(w.out)
		if err := EnsureDragonfly(cfg.Cache.Addr, w.out); err != nil {
			fmt.Fprintf(w.out, "  ⚠ Dragonfly: %v\n", err)
		} else {
			w.dflyStarted = true
		}
	}

	// Complete the install: put the binary where the generated service
	// expects it, then install and start the chosen startup service. Both are
	// best-effort — a failure prints the manual commands and never fails the
	// wizard. IRONGRID_SKIP_PRIVILEGED=1 (used by tests) keeps them to
	// file-generation only.
	if w.a.deploy == "native" && os.Getenv("IRONGRID_SKIP_PRIVILEGED") != "1" {
		ensureBinaryInstalled(w.out)
		installService(w, absConfig, absData)
	}

	w.printNextSteps(absConfig, absData)
	return nil
}

func (w *wizard) banner() {
	fmt.Fprintln(w.out, strings.TrimSpace(`
  ██╗██████╗  ██████╗ ███╗   ██╗ ██████╗ ██████╗ ██╗██████╗
  ██║██╔══██╗██╔═══██╗████╗  ██║██╔════╝ ██╔══██╗██║██╔══██╗
  ██║██████╔╝██║   ██║██╔██╗ ██║██║  ███╗██████╔╝██║██║  ██║
  ██║██╔══██╗██║   ██║██║╚██╗██║██║   ██║██╔══██╗██║██║  ██║
  ██║██║  ██║╚██████╔╝██║ ╚████║╚██████╔╝██║  ██║██║██████╔╝
  ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝ ╚═════╝ ╚═╝  ╚═╝╚═╝╚═════╝
`))
	fmt.Fprintln(w.out, "             ad-blocking DNS server — setup wizard")
	fmt.Fprintln(w.out, "     drag → select · enter → confirm · ctrl+c → cancel")
	fmt.Fprintln(w.out)
}

// newForm builds a form wired to the wizard's IO streams. On a real TTY it
// uses the Catppuccin theme; otherwise (or when IRONGRID_ACCESSIBLE=1) it
// switches to accessible line-based rendering.
func (w *wizard) newForm(groups ...*huh.Group) *huh.Form {
	f := huh.NewForm(groups...).WithInput(w.in).WithOutput(w.out)
	if os.Getenv("IRONGRID_ACCESSIBLE") == "1" {
		return f.WithAccessible(true)
	}
	if fd, ok := w.in.(interface{ Fd() uintptr }); ok && term.IsTerminal(int(fd.Fd())) {
		return f.WithTheme(huh.ThemeCatppuccin())
	}
	return f.WithAccessible(true)
}

func (w *wizard) askBasics() error {
	if err := w.newForm(
		huh.NewGroup(
			huh.NewNote().
				Title("How will you run Irongrid DNS?").
				Description("Native runs the single binary on this machine. Docker runs the container alongside a bundled Dragonfly cache."),
			huh.NewSelect[string]().
				Title("Deployment").
				Options(
					huh.NewOption("Docker Compose (container + Dragonfly cache)", "docker"),
					huh.NewOption("Native binary (on this machine)", "native"),
				).
				Value(&w.a.deploy),
		),
	).Run(); err != nil {
		return err
	}
	// Docker deployments always get a compose file with the bundled cache.
	if w.a.deploy == "docker" {
		w.a.service = "docker"
		return nil
	}
	// Native deployments: pre-select the service manager that matches this platform.
	w.a.service = "none"
	switch runtime.GOOS {
	case "linux":
		w.a.service = "systemd"
	case "darwin":
		w.a.service = "launchd"
	case "windows":
		w.a.service = "windows"
	}
	// The one-line installer sets IRONGRID_NO_SERVICE=1 for --no-service.
	if os.Getenv("IRONGRID_NO_SERVICE") == "1" {
		w.a.service = "none"
		return nil
	}
	return w.newForm(
		huh.NewGroup(
			huh.NewSelect[string]().
				Title("Service manager").
				Description("Generate a startup service so Irongrid DNS auto-starts on boot.").
				Options(
					huh.NewOption("systemd (Linux)", "systemd"),
					huh.NewOption("launchd (macOS)", "launchd"),
					huh.NewOption("Windows Service (sc)", "windows"),
					huh.NewOption("None — I'll run it manually", "none"),
				).
				Value(&w.a.service),
		),
	).Run()
}

func (w *wizard) askListeners() error {
	// Sensible defaults: plain DNS on UDP+TCP covers routers; the rest can be
	// toggled on for encrypted DNS.
	if w.a.protos == nil {
		w.a.protos = []string{"UDP", "TCP"}
	}
	if err := w.newForm(
		huh.NewGroup(
			huh.NewNote().
				Title("DNS listeners").
				Description("Pick the protocols to serve. Plain UDP is all most routers need. DoT / DoH / DoQ add encrypted DNS for phones and laptops."),
			huh.NewMultiSelect[string]().
				Title("Protocols").
				Options(
					huh.NewOption("UDP — plain DNS on :53 (routers)", "UDP"),
					huh.NewOption("TCP — plain DNS over TCP on :53", "TCP"),
					huh.NewOption("DoT — DNS over TLS on :853 (Android Private DNS)", "DoT"),
					huh.NewOption("DoH — DNS over HTTPS on :443 (browsers)", "DoH"),
					huh.NewOption("DoQ — DNS over QUIC on :853 (RFC 9250)", "DoQ"),
				).
				Value(&w.a.protos),
			huh.NewInput().
				Title("Listen address").
				Description("Bind host (empty = all interfaces). Ports are fixed per protocol.").
				Placeholder("0.0.0.0").
				Value(&w.a.listenHost),
		),
	).Run(); err != nil {
		return err
	}
	// When DoH is enabled, offer to serve the dashboard on the same HTTPS
	// port so it is reachable at https://host (no :8080 suffix).
	if containsStr(w.a.protos, "DoH") {
		if err := w.newForm(
			huh.NewGroup(
				huh.NewConfirm().
					Title("Serve the dashboard on the DoH port too?").
					Description("Put the web dashboard on https://<host> (port 443, shared with DoH) instead of :8080, so it opens without a port suffix. Requires HTTPS (web_tls) which uses the TLS certificate.").
					Affirmative("Yes — dashboard at https://host").
					Negative("No — keep :8080").
					Value(&w.a.webOnDoHPort),
			),
		).Run(); err != nil {
			return err
		}
	}
	return nil
}

// containsStr reports whether a slice contains the given string.
func containsStr(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}

func (w *wizard) askUpstreams() error {
	return w.newForm(
		huh.NewGroup(
			huh.NewNote().
				Title("Upstream resolvers").
				Description("These are the servers Irongrid DNS forwards to after filtering and caching. You can pick a preset or type your own (udp://, tls://, https://, quic://)."),
			huh.NewSelect[string]().
				Title("Upstream preset").
				Options(
					huh.NewOption("Cloudflare 1.1.1.1 + 1.0.0.1 (fast)", "cloudflare"),
					huh.NewOption("Google 8.8.8.8 + 8.8.4.4", "google"),
					huh.NewOption("Quad9 9.9.9.9 (threat blocking)", "quad9"),
					huh.NewOption("Custom — I'll type them", "custom"),
				).
				Value(&w.a.upstreamPreset),
			huh.NewInput().
				Title("Custom upstreams").
				Description("Comma-separated, e.g. tls://dns.quad9.net, udp://10.0.0.1:53").
				Placeholder("(optional)").
				Value(&w.a.customUpstream),
		),
	).Run()
}

func (w *wizard) askCache() error {
	// Docker deployments get the compose service hostname; native gets localhost.
	addrDefault := "localhost:6379"
	if w.a.deploy == "docker" {
		addrDefault = "dragonfly:6379"
	}
	return w.newForm(
		huh.NewGroup(
			huh.NewNote().
				Title("Dragonfly cache").
				Description("Irongrid DNS uses a Dragonfly (Redis-compatible) server as its response cache — it is a hard requirement. In Docker mode the installer adds it to the compose file automatically."),
			huh.NewInput().
				Title("Dragonfly address").
				Placeholder(addrDefault).
				Value(&w.a.cacheAddr).
				Validate(func(s string) error {
					if strings.TrimSpace(s) == "" {
						return fmt.Errorf("Dragonfly address is required")
					}
					return nil
				}), huh.NewInput().
				Title("Dragonfly password").
				Description("Leave empty if Dragonfly has no auth.").
				Placeholder("(optional)").
				Password(true).
				Value(&w.a.cachePass),
		),
	).Run()
}

// askDragonfly offers to install and start Dragonfly (native deployments
// only). Docker deployments bundle Dragonfly in the compose file, so there is
// nothing to install on the host.
func (w *wizard) askDragonfly() error {
	if w.a.deploy != "native" {
		w.a.installDragonfly = false
		return nil
	}
	// The one-line installer sets IRONGRID_SKIP_DRAGONFLY=1 for
	// --skip-dragonfly (the user runs their own cache).
	if os.Getenv("IRONGRID_SKIP_DRAGONFLY") == "1" {
		w.a.installDragonfly = false
		return nil
	}
	addr := w.a.cacheAddr
	if addr == "" {
		addr = "localhost:6379"
	}
	install := true
	if err := w.newForm(
		huh.NewGroup(
			huh.NewConfirm().
				Title("Install and start Dragonfly now?").
				Description("Irongrid DNS needs a Redis-compatible cache answering at " + addr + ". " +
					"The installer can download and start Dragonfly for you (native binary on Linux, " +
					"Docker on macOS/Windows). Choose no if you already run a Redis-compatible server there.").
				Affirmative("Install Dragonfly").
				Negative("I already have a cache").
				Value(&install),
		),
	).Run(); err != nil {
		return err
	}
	w.a.installDragonfly = install
	return nil
}

func (w *wizard) askLists(cat *catalog.Catalog) error {
	blockOpts := make([]huh.Option[string], 0, len(cat.Blocklists))
	for _, b := range cat.Blocklists {
		blockOpts = append(blockOpts, huh.NewOption(fmt.Sprintf("%s — %s", b.Name, b.Description), b.ID))
	}
	whiteOpts := make([]huh.Option[string], 0, len(cat.Whitelists))
	for _, wl := range cat.Whitelists {
		whiteOpts = append(whiteOpts, huh.NewOption(fmt.Sprintf("%s — %s", wl.Name, wl.Description), wl.ID))
	}
	return w.newForm(
		huh.NewGroup(
			huh.NewNote().
				Title("Blocking presets").
				Description("Select curated blocklists to enable (space to toggle, enter to continue). Whitelist presets add always-allow domains so updates and cloud services keep working."),
			huh.NewMultiSelect[string]().
				Title("Blocklists").
				Options(blockOpts...).
				Value(&w.a.blocklists),
			huh.NewMultiSelect[string]().
				Title("Always-allow presets (whitelist)").
				Options(whiteOpts...).
				Value(&w.a.whitelists),
		),
	).Run()
}

func (w *wizard) askWeb() error {
	return w.newForm(
		huh.NewGroup(
			huh.NewNote().
				Title("Dashboard access").
				Description("The web dashboard and API use HTTP Basic auth. Pick a username and a strong password."),
			huh.NewInput().
				Title("Username").
				Placeholder("admin").
				Value(&w.a.webUser).
				Validate(func(s string) error {
					if strings.TrimSpace(s) == "" {
						return fmt.Errorf("username is required")
					}
					return nil
				}),
			huh.NewInput().
				Title("Password").
				Password(true).
				Value(&w.a.webPass).
				Validate(func(s string) error {
					if len(s) < 8 {
						return fmt.Errorf("use at least 8 characters")
					}
					return nil
				}),
			huh.NewInput().
				Title("Confirm password").
				Password(true).
				Value(&w.a.webConfirm).
				Validate(func(s string) error {
					if s != w.a.webPass {
						return fmt.Errorf("passwords do not match")
					}
					return nil
				}),
		),
	).Run()
}

func (w *wizard) askTLS() error {
	return w.newForm(
		huh.NewGroup(
			huh.NewNote().
				Title("TLS certificates").
				Description("A self-signed certificate is generated automatically and is fine for testing. For real devices, put a CA-signed cert at tls.cert_file / tls.key_file later."),
			huh.NewInput().
				Title("Self-signed certificate hosts").
				Description("Comma-separated SANs, e.g. dns.example.com, localhost").
				Placeholder("localhost, dns.example.com").
				Value(&w.a.tlsHosts),
		),
	).Run()
}

func (w *wizard) askConfirm() error {
	a := w.a
	var summary strings.Builder
	summary.WriteString(fmt.Sprintf("Deployment : %s\n", a.deploy))
	summary.WriteString(fmt.Sprintf("Service    : %s\n", a.service))
	summary.WriteString(fmt.Sprintf("Protocols  : %s\n", strings.Join(a.protos, ", ")))
	summary.WriteString(fmt.Sprintf("Upstreams  : %s\n", strings.Join(a.upstreams(), ", ")))
	cacheLine := a.cacheAddr
	if a.deploy == "native" && a.installDragonfly {
		cacheLine += " (Dragonfly will be installed & started)"
	}
	summary.WriteString(fmt.Sprintf("Cache      : %s\n", cacheLine))
	summary.WriteString(fmt.Sprintf("Blocklists : %d selected\n", len(a.blocklists)))
	summary.WriteString(fmt.Sprintf("Whitelists : %d presets\n", len(a.whitelists)))
	dashURL := "http://host:8080"
	if a.webOnDoHPort {
		dashURL = "https://host (shared with DoH)"
	}
	summary.WriteString(fmt.Sprintf("Dashboard  : %s / %s  → %s\n", a.webUser, "********", dashURL))
	return w.newForm(
		huh.NewGroup(
			huh.NewNote().
				Title("Ready to install?").
				Description(summary.String()),
			huh.NewConfirm().
				Title("Write configuration and service files?").
				Affirmative("Install").
				Negative("Cancel").
				Value(&a.confirm),
		),
	).Run()
}

// upstreams resolves the final list of upstream specs from the preset + custom input.
func (a *answers) upstreams() []string {
	presets := map[string][]string{
		"cloudflare": {"udp://1.1.1.1:53", "udp://1.0.0.1:53"},
		"google":     {"udp://8.8.8.8:53", "udp://8.8.4.4:53"},
		"quad9":      {"udp://9.9.9.9:53", "udp://149.112.112.112:53"},
	}
	var out []string
	out = append(out, presets[a.upstreamPreset]...)
	for _, s := range strings.Split(a.customUpstream, ",") {
		s = strings.TrimSpace(s)
		if s != "" {
			out = append(out, s)
		}
	}
	if len(out) == 0 {
		out = []string{"udp://1.1.1.1:53"}
	}
	return out
}

// buildConfig assembles a validated config.Config from the wizard answers.
func (a *answers) buildConfig(cat *catalog.Catalog) (*config.Config, error) {
	cfg := config.Default()

	// Only keep the selected listeners; disable everything else.
	cfg.Server.ListenUDP = ""
	cfg.Server.ListenTCP = ""
	cfg.Server.ListenDoT = ""
	cfg.Server.ListenDoH = ""
	cfg.Server.ListenDoQ = ""
	for _, p := range a.protos {
		switch p {
		case "UDP":
			cfg.Server.ListenUDP = hostPort(a.listenHost, "53")
		case "TCP":
			cfg.Server.ListenTCP = hostPort(a.listenHost, "53")
		case "DoT":
			cfg.Server.ListenDoT = hostPort(a.listenHost, "853")
		case "DoH":
			cfg.Server.ListenDoH = hostPort(a.listenHost, "443")
		case "DoQ":
			cfg.Server.ListenDoQ = hostPort(a.listenHost, "853")
		}
	}

	cfg.Upstreams = a.upstreams()

	if a.cacheAddr != "" {
		cfg.Cache.Addr = a.cacheAddr
	}
	cfg.Cache.Password = a.cachePass

	// Map selected catalog presets onto the filter config.
	blockByID := make(map[string]catalog.Blocklist, len(cat.Blocklists))
	for _, b := range cat.Blocklists {
		blockByID[b.ID] = b
	}
	for _, id := range a.blocklists {
		b, ok := blockByID[id]
		if !ok {
			continue
		}
		cfg.Filter.Blocklists = append(cfg.Filter.Blocklists, config.BlocklistSpec{
			ID:      b.ID,
			Name:    b.Name,
			URL:     b.URL,
			Enabled: true,
		})
	}
	whiteByID := make(map[string]catalog.Whitelist, len(cat.Whitelists))
	for _, wl := range cat.Whitelists {
		whiteByID[wl.ID] = wl
	}
	seen := make(map[string]bool)
	for _, id := range a.whitelists {
		wl, ok := whiteByID[id]
		if !ok {
			continue
		}
		for _, d := range wl.Domains {
			d = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(d), "."))
			if d != "" && !seen[d] {
				seen[d] = true
				cfg.Filter.Whitelist = append(cfg.Filter.Whitelist, d)
			}
		}
	}

	cfg.Web.Username = a.webUser
	cfg.Web.Password = a.webPass

	// Dashboard on the DoH port (https://host, no :8080).
	if a.webOnDoHPort && cfg.Server.ListenDoH != "" {
		cfg.Server.WebListen = cfg.Server.ListenDoH
		cfg.Server.WebTLS = true
		cfg.Server.WebRedirect = true
	}

	if a.tlsHosts != "" {
		var hosts []string
		for _, h := range strings.Split(a.tlsHosts, ",") {
			if h = strings.TrimSpace(h); h != "" {
				hosts = append(hosts, h)
			}
		}
		if len(hosts) > 0 {
			cfg.TLS.SelfSignedHosts = hosts
		}
	}

	return cfg, cfg.Validate()
}

func hostPort(host, port string) string {
	if host == "" {
		return ":" + port
	}
	return host + ":" + port
}
