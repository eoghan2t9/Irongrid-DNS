// Package installer provides the interactive TUI setup wizard (`irongrid
// install`). It walks the user through listeners, upstreams, cache, blocklist
// and whitelist presets (from the shared catalog), web credentials and TLS,
// then writes a validated irongrid.yaml plus platform service files
// (systemd / launchd / Windows service / Docker Compose).
package installer

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/charmbracelet/huh"
	"github.com/eoghan2t9/Irongrid-DNS/internal/catalog"
	"github.com/eoghan2t9/Irongrid-DNS/internal/config"
	"golang.org/x/term"
)

// Options configures a Run.
type Options struct {
	ConfigPath string // where irongrid.yaml will be written
	DataDir    string // runtime data directory (querylog, lists, certs)
}

// answers collects every wizard choice before the config is built.
type answers struct {
	deploy         string   // "docker" | "native"
	service        string   // "systemd" | "launchd" | "windows" | "none"
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
	tlsHosts       string
	confirm        bool
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

	a := &answers{}
	cat := catalog.Default()

	banner()

	if err := a.askBasics(); err != nil {
		return err
	}
	if err := a.askListeners(); err != nil {
		return err
	}
	if err := a.askUpstreams(); err != nil {
		return err
	}
	if err := a.askCache(); err != nil {
		return err
	}
	if err := a.askLists(cat); err != nil {
		return err
	}
	if err := a.askWeb(); err != nil {
		return err
	}
	if err := a.askTLS(); err != nil {
		return err
	}
	if err := a.askConfirm(); err != nil {
		return err
	}
	if !a.confirm {
		fmt.Println("\n✓ Installation cancelled — nothing was written.")
		return nil
	}

	cfg, err := a.buildConfig(cat)
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
	fmt.Printf("\n✍  Config written to %s\n", absConfig)

	files, err := writeServiceFiles(a, absConfig, absData)
	if err != nil {
		return err
	}
	if len(files) > 0 {
		fmt.Printf("   Service files written to %s\n", filepath.Dir(files[0]))
	}

	printNextSteps(a, absConfig, absData)
	return nil
}

func banner() {
	fmt.Println(strings.TrimSpace(`
  ██╗██████╗  ██████╗ ███╗   ██╗ ██████╗ ██████╗ ██╗██████╗
  ██║██╔══██╗██╔═══██╗████╗  ██║██╔════╝ ██╔══██╗██║██╔══██╗
  ██║██████╔╝██║   ██║██╔██╗ ██║██║  ███╗██████╔╝██║██║  ██║
  ██║██╔══██╗██║   ██║██║╚██╗██║██║   ██║██╔══██╗██║██║  ██║
  ██║██║  ██║╚██████╔╝██║ ╚████║╚██████╔╝██║  ██║██║██████╔╝
  ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝ ╚═════╝ ╚═╝  ╚═╝╚═╝╚═════╝
`))
	fmt.Println("             ad-blocking DNS server — setup wizard")
	fmt.Println("     drag → select · enter → confirm · ctrl+c → cancel")
	fmt.Println()
}

// newForm builds a form with the Catppuccin theme on a real TTY, or switches
// to accessible (line-based) rendering when stdin is not a terminal, which
// also makes the wizard scriptable for non-interactive installs.
func newForm(groups ...*huh.Group) *huh.Form {
	f := huh.NewForm(groups...)
	if term.IsTerminal(int(os.Stdin.Fd())) {
		return f.WithTheme(huh.ThemeCatppuccin())
	}
	return f.WithAccessible(true)
}

func (a *answers) askBasics() error {
	if err := newForm(
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
				Value(&a.deploy),
		),
	).Run(); err != nil {
		return err
	}
	// Docker deployments always get a compose file with the bundled cache.
	if a.deploy == "docker" {
		a.service = "docker"
		return nil
	}
	// Native deployments: pre-select the service manager that matches this platform.
	a.service = "none"
	switch runtime.GOOS {
	case "linux":
		a.service = "systemd"
	case "darwin":
		a.service = "launchd"
	case "windows":
		a.service = "windows"
	}
	return newForm(
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
				Value(&a.service),
		),
	).Run()
}

func (a *answers) askListeners() error {
	// Sensible defaults: plain DNS on UDP+TCP covers routers; the rest can be
	// toggled on for encrypted DNS.
	if a.protos == nil {
		a.protos = []string{"UDP", "TCP"}
	}
	return newForm(
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
				Value(&a.protos),
			huh.NewInput().
				Title("Listen address").
				Description("Bind host (empty = all interfaces). Ports are fixed per protocol.").
				Placeholder("0.0.0.0").
				Value(&a.listenHost),
		),
	).Run()
}

func (a *answers) askUpstreams() error {
	return newForm(
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
				Value(&a.upstreamPreset),
			huh.NewInput().
				Title("Custom upstreams").
				Description("Comma-separated, e.g. tls://dns.quad9.net, udp://10.0.0.1:53").
				Placeholder("(optional)").
				Value(&a.customUpstream),
		),
	).Run()
}

func (a *answers) askCache() error {
	// Docker deployments get the compose service hostname; native gets localhost.
	addrDefault := "localhost:6379"
	if a.deploy == "docker" {
		addrDefault = "dragonfly:6379"
	}
	return newForm(
		huh.NewGroup(
			huh.NewNote().
				Title("Dragonfly cache").
				Description("Irongrid DNS uses a Dragonfly (Redis-compatible) server as its response cache — it is a hard requirement. In Docker mode the installer adds it to the compose file automatically."),
			huh.NewInput().
				Title("Dragonfly address").
				Placeholder(addrDefault).
				Value(&a.cacheAddr).
				Validate(func(s string) error {
					if strings.TrimSpace(s) == "" {
						return fmt.Errorf("Dragonfly address is required")
					}
					return nil
				}),
			huh.NewInput().
				Title("Dragonfly password").
				Description("Leave empty if Dragonfly has no auth.").
				Placeholder("(optional)").
				Password(true).
				Value(&a.cachePass),
		),
	).Run()
}

func (a *answers) askLists(cat *catalog.Catalog) error {
	blockOpts := make([]huh.Option[string], 0, len(cat.Blocklists))
	for _, b := range cat.Blocklists {
		blockOpts = append(blockOpts, huh.NewOption(fmt.Sprintf("%s — %s", b.Name, b.Description), b.ID))
	}
	whiteOpts := make([]huh.Option[string], 0, len(cat.Whitelists))
	for _, w := range cat.Whitelists {
		whiteOpts = append(whiteOpts, huh.NewOption(fmt.Sprintf("%s — %s", w.Name, w.Description), w.ID))
	}
	return newForm(
		huh.NewGroup(
			huh.NewNote().
				Title("Blocking presets").
				Description("Select curated blocklists to enable (space to toggle, enter to continue). Whitelist presets add always-allow domains so updates and cloud services keep working."),
			huh.NewMultiSelect[string]().
				Title("Blocklists").
				Options(blockOpts...).
				Value(&a.blocklists),
			huh.NewMultiSelect[string]().
				Title("Always-allow presets (whitelist)").
				Options(whiteOpts...).
				Value(&a.whitelists),
		),
	).Run()
}

func (a *answers) askWeb() error {
	return newForm(
		huh.NewGroup(
			huh.NewNote().
				Title("Dashboard access").
				Description("The web dashboard and API use HTTP Basic auth. Pick a username and a strong password."),
			huh.NewInput().
				Title("Username").
				Placeholder("admin").
				Value(&a.webUser).
				Validate(func(s string) error {
					if strings.TrimSpace(s) == "" {
						return fmt.Errorf("username is required")
					}
					return nil
				}),
			huh.NewInput().
				Title("Password").
				Password(true).
				Value(&a.webPass).
				Validate(func(s string) error {
					if len(s) < 8 {
						return fmt.Errorf("use at least 8 characters")
					}
					return nil
				}),
			huh.NewInput().
				Title("Confirm password").
				Password(true).
				Value(&a.webConfirm).
				Validate(func(s string) error {
					if s != a.webPass {
						return fmt.Errorf("passwords do not match")
					}
					return nil
				}),
		),
	).Run()
}

func (a *answers) askTLS() error {
	return newForm(
		huh.NewGroup(
			huh.NewNote().
				Title("TLS certificates").
				Description("A self-signed certificate is generated automatically and is fine for testing. For real devices, put a CA-signed cert at tls.cert_file / tls.key_file later."),
			huh.NewInput().
				Title("Self-signed certificate hosts").
				Description("Comma-separated SANs, e.g. dns.example.com, localhost").
				Placeholder("localhost, dns.example.com").
				Value(&a.tlsHosts),
		),
	).Run()
}

func (a *answers) askConfirm() error {
	var summary strings.Builder
	summary.WriteString(fmt.Sprintf("Deployment : %s\n", a.deploy))
	summary.WriteString(fmt.Sprintf("Service    : %s\n", a.service))
	summary.WriteString(fmt.Sprintf("Protocols  : %s\n", strings.Join(a.protos, ", ")))
	summary.WriteString(fmt.Sprintf("Upstreams  : %s\n", strings.Join(a.upstreams(), ", ")))
	summary.WriteString(fmt.Sprintf("Cache      : %s\n", a.cacheAddr))
	summary.WriteString(fmt.Sprintf("Blocklists : %d selected\n", len(a.blocklists)))
	summary.WriteString(fmt.Sprintf("Whitelists : %d presets\n", len(a.whitelists)))
	summary.WriteString(fmt.Sprintf("Dashboard  : %s / %s\n", a.webUser, "********"))
	return newForm(
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
		var au time.Duration
		if d, err := time.ParseDuration(b.AutoUpdate); err == nil {
			au = d
		}
		cfg.Filter.Blocklists = append(cfg.Filter.Blocklists, config.BlocklistSpec{
			ID:         b.ID,
			Name:       b.Name,
			URL:        b.URL,
			Enabled:    true,
			AutoUpdate: au,
		})
	}
	whiteByID := make(map[string]catalog.Whitelist, len(cat.Whitelists))
	for _, w := range cat.Whitelists {
		whiteByID[w.ID] = w
	}
	seen := make(map[string]bool)
	for _, id := range a.whitelists {
		w, ok := whiteByID[id]
		if !ok {
			continue
		}
		for _, d := range w.Domains {
			d = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(d), "."))
			if d != "" && !seen[d] {
				seen[d] = true
				cfg.Filter.Whitelist = append(cfg.Filter.Whitelist, d)
			}
		}
	}

	cfg.Web.Username = a.webUser
	cfg.Web.Password = a.webPass

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
