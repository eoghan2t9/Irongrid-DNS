package installer

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/eoghan2t9/Irongrid-DNS/internal/catalog"
)

// build answers with a mix of presets that share domains (OS updates and
// Cloud both include microsoft/apple/amazon domains) to verify dedup.
func testAnswers() *answers {
	return &answers{
		deploy:         "docker",
		service:        "docker",
		protos:         []string{"UDP", "DoH"},
		listenHost:     "0.0.0.0",
		upstreamPreset: "quad9",
		cacheAddr:      "dragonfly:6379",
		blocklists:     []string{"oisd-big", "stevenblack"},
		whitelists:     []string{"os-updates", "cloud"},
		webUser:        "admin",
		webPass:        "testpass123",
		tlsHosts:       "localhost, dns.example.com",
	}
}

func TestBuildConfigValid(t *testing.T) {
	a := testAnswers()
	cfg, err := a.buildConfig(catalog.Default())
	if err != nil {
		t.Fatalf("buildConfig: %v", err)
	}
	if cfg.Server.ListenUDP != "0.0.0.0:53" {
		t.Errorf("ListenUDP = %q, want 0.0.0.0:53", cfg.Server.ListenUDP)
	}
	if cfg.Server.ListenDoH != "0.0.0.0:443" {
		t.Errorf("ListenDoH = %q, want 0.0.0.0:443", cfg.Server.ListenDoH)
	}
	if cfg.Server.ListenTCP != "" {
		t.Errorf("ListenTCP = %q, want disabled", cfg.Server.ListenTCP)
	}
	if len(cfg.Upstreams) != 2 {
		t.Errorf("upstreams = %v, want Quad9 pair", cfg.Upstreams)
	}
	if len(cfg.Filter.Blocklists) != 2 {
		t.Errorf("blocklists = %d, want 2", len(cfg.Filter.Blocklists))
	}
	if cfg.Web.Password != "testpass123" {
		t.Errorf("web password not captured")
	}
	if len(cfg.TLS.SelfSignedHosts) != 2 {
		t.Errorf("self-signed hosts = %v, want 2", cfg.TLS.SelfSignedHosts)
	}
}

func TestBuildConfigWhitelistDedup(t *testing.T) {
	a := testAnswers()
	cfg, err := a.buildConfig(catalog.Default())
	if err != nil {
		t.Fatalf("buildConfig: %v", err)
	}
	seen := map[string]bool{}
	for _, d := range cfg.Filter.Whitelist {
		if seen[d] {
			t.Errorf("duplicate whitelist entry %q", d)
		}
		seen[d] = true
	}
	// os-updates and cloud presets both contain microsoft.com and apple.com.
	if !seen["microsoft.com"] {
		t.Errorf("expected microsoft.com from the cloud preset")
	}
}

// webOnDoHPort puts the dashboard on the same HTTPS port as DoH
// (https://host, no :8080 suffix).
func TestBuildConfigWebOnDoHPort(t *testing.T) {
	a := testAnswers()
	a.webOnDoHPort = true
	cfg, err := a.buildConfig(catalog.Default())
	if err != nil {
		t.Fatalf("buildConfig: %v", err)
	}
	if cfg.Server.WebListen != cfg.Server.ListenDoH {
		t.Errorf("WebListen = %q, want shared with ListenDoH %q", cfg.Server.WebListen, cfg.Server.ListenDoH)
	}
	if !cfg.Server.WebTLS {
		t.Error("WebTLS should be enabled when the dashboard shares the DoH port")
	}
	if !cfg.Server.WebRedirect {
		t.Error("WebRedirect should be enabled when the dashboard shares the DoH port")
	}
	// The generated config must pass validation (web_tls required on shared port).
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

func TestBuildConfigNoProtocolsFails(t *testing.T) {
	a := testAnswers()
	a.protos = []string{}
	if _, err := a.buildConfig(catalog.Default()); err == nil {
		t.Fatal("expected validation error when no listeners are enabled")
	}
}

// The one-line installer sets IRONGRID_SKIP_DRAGONFLY=1 for --skip-dragonfly;
// the wizard must then not offer (or run) the Dragonfly install.
func TestAskDragonflySkipEnv(t *testing.T) {
	t.Setenv("IRONGRID_SKIP_DRAGONFLY", "1")
	w := &wizard{a: &answers{deploy: "native", cacheAddr: "localhost:6379"}, in: strings.NewReader(""), out: io.Discard}
	if err := w.askDragonfly(); err != nil {
		t.Fatalf("askDragonfly: %v", err)
	}
	if w.a.installDragonfly {
		t.Error("installDragonfly should be false with IRONGRID_SKIP_DRAGONFLY=1")
	}
}

// Default behaviour (no skip env) is to ask, defaulting to yes.
func TestAskDragonflyDefaultsYes(t *testing.T) {
	t.Setenv("IRONGRID_ACCESSIBLE", "1")
	w := &wizard{a: &answers{deploy: "native", cacheAddr: "localhost:6379"}, in: strings.NewReader("y\n"), out: io.Discard}
	if err := w.askDragonfly(); err != nil {
		t.Fatalf("askDragonfly: %v", err)
	}
	if !w.a.installDragonfly {
		t.Error("installDragonfly should default to true when the user confirms")
	}
}

// TestGeneratedUnitsNoTrailingComments guards against systemd/launchd unit
// generators emitting inline comments after a directive value. systemd treats
// the whole line as the value, so `WorkingDirectory=/data   # note` breaks
// startup with status=200/CHDIR (the service crash-loops forever).
func TestGeneratedUnitsNoTrailingComments(t *testing.T) {
	w := &wizard{out: os.Stdout}
	dir := t.TempDir()
	configPath := filepath.Join(dir, "irongrid.yaml")
	dataDir := filepath.Join(dir, "data")

	files, err := writeSystemd(w, dir, configPath, dataDir)
	if err != nil {
		t.Fatalf("writeSystemd: %v", err)
	}
	data, err := os.ReadFile(files[0])
	if err != nil {
		t.Fatalf("read unit: %v", err)
	}
	for i, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "#") || strings.TrimSpace(line) == "" {
			continue
		}
		if strings.Contains(line, "#") {
			t.Errorf("unit line %d has an inline comment (systemd treats it as part of the value): %q", i+1, line)
		}
	}
	if !strings.Contains(string(data), "WorkingDirectory="+dataDir+"\n") {
		t.Errorf("expected clean WorkingDirectory=%s line, got:\n%s", dataDir, string(data))
	}

	files, err = writeLaunchd(w, dir, configPath, dataDir)
	if err != nil {
		t.Fatalf("writeLaunchd: %v", err)
	}
	plist, err := os.ReadFile(files[0])
	if err != nil {
		t.Fatalf("read plist: %v", err)
	}
	if !strings.Contains(string(plist), "<string>"+dataDir+"</string>") {
		t.Errorf("expected clean WorkingDirectory string in plist, got:\n%s", string(plist))
	}
}

func TestWriteDockerCompose(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "..", "irongrid.yaml") // one level above deploy/
	w := &wizard{a: &answers{service: "docker"}, out: os.Stdout}
	files, err := writeServiceFiles(w, configPath, filepath.Join(dir, "data"))
	if err != nil {
		t.Fatalf("writeServiceFiles: %v", err)
	}
	if len(files) != 1 || !strings.HasSuffix(files[0], "docker-compose.yml") {
		t.Fatalf("expected one docker-compose.yml, got %v", files)
	}
	raw, err := os.ReadFile(files[0])
	if err != nil {
		t.Fatalf("read compose: %v", err)
	}
	body := string(raw)
	if !strings.Contains(body, "../irongrid.yaml:/app/irongrid.yaml:ro") {
		t.Errorf("compose volume should mount ../irongrid.yaml, got:\n%s", body)
	}
	if !strings.Contains(body, "dragonfly") {
		t.Errorf("compose should bundle dragonfly:\n%s", body)
	}
}
