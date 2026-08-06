// Package tunnel embeds Cloudflare's cloudflared source (imported as Go
// modules) so tunnel lifecycle is managed entirely from within the Irongrid
// DNS binary — no external cloudflared installation required.
package tunnel

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/urfave/cli/v2"

	"github.com/cloudflare/cloudflared/cmd/cloudflared/cliutil"
	cftunnel "github.com/cloudflare/cloudflared/cmd/cloudflared/tunnel"
	"github.com/cloudflare/cloudflared/metrics"
)

// Mode describes how the tunnel authenticates to Cloudflare.
type Mode string

const (
	// ModeQuick runs an unauthenticated trycloudflare.com quick tunnel.
	ModeQuick Mode = "quick"
	// ModeToken runs a remote-managed named tunnel using a tunnel token.
	ModeToken Mode = "token"
	// ModeConfig runs a named tunnel from a cloudflared config file.
	ModeConfig Mode = "config"
)

// Status is the current tunnel state.
type Status struct {
	Running bool      `json:"running"`
	Mode    Mode      `json:"mode"`
	Started time.Time `json:"started"`
	Error   string    `json:"error"`
	LastLog string    `json:"last_log"`
	LogFile string    `json:"log_file"`
}

// Manager controls the embedded cloudflared process.
type Manager struct {
	mu       sync.Mutex
	running  bool
	started  time.Time
	mode     Mode
	lastErr  string
	lastLog  string
	shutdown chan struct{}
	logFile  string
	stopOnce sync.Once
}

// NewManager creates a tunnel manager writing logs under dataDir.
func NewManager(dataDir string) *Manager {
	return &Manager{logFile: filepath.Join(dataDir, "cloudflared.log")}
}

// Start launches the tunnel in the given mode. origin is used for quick
// tunnels (the local URL to expose, e.g. http://localhost:8080).
func (m *Manager) Start(mode Mode, token, configFile, origin, hostname string) error {
	m.mu.Lock()
	if m.running {
		m.mu.Unlock()
		return fmt.Errorf("tunnel already running")
	}
	shutdownC := make(chan struct{})
	m.shutdown = shutdownC
	m.running = true
	m.started = time.Now()
	m.mode = mode
	m.lastErr = ""
	m.mu.Unlock()

	os.Setenv("QUIC_GO_DISABLE_ECN", "1")
	metrics.RegisterBuildInfo("IrongridDNS", time.Now().Format(time.RFC3339), "v0.1.0")

	// cloudflared's command packages keep package-level state; re-init on
	// every start so restarting works.
	cftunnel.Init(cliutil.GetBuildInfo("IrongridDNS", ""), shutdownC)

	app := &cli.App{
		Name:     "cloudflared",
		Usage:    "embedded in Irongrid DNS",
		Flags:    cftunnel.Flags(),
		Commands: cftunnel.Commands(),
		Version:  "2024.12.1 (embedded)",
	}

	args := []string{"cloudflared"}
	switch mode {
	case ModeQuick:
		if origin == "" {
			origin = "http://localhost:8080"
		}
		args = append(args, "tunnel", "--url", origin)
	case ModeToken:
		if token == "" {
			m.failStart("tunnel token required for token mode")
			return fmt.Errorf("tunnel token required")
		}
		args = append(args, "tunnel", "run", "--token", token)
	case ModeConfig:
		if configFile == "" {
			m.failStart("cloudflared config file required for config mode")
			return fmt.Errorf("cloudflared config file required")
		}
		args = append(args, "tunnel", "run", "--config", configFile)
	default:
		m.failStart("unknown tunnel mode")
		return fmt.Errorf("unknown tunnel mode %q", mode)
	}
	// Persist logs to a file we can tail for status; never auto-update.
	args = append(args, "--no-autoupdate")
	if m.logFile != "" {
		args = append(args, "--logfile", m.logFile)
	}
	_ = hostname

	go func() {
		err := app.Run(args)
		m.mu.Lock()
		m.running = false
		if err != nil {
			m.lastErr = err.Error()
		}
		if tail := m.tailLog(); tail != "" {
			m.lastLog = tail
		}
		m.mu.Unlock()
	}()

	// Give the tunnel a moment to fail fast on bad credentials.
	time.Sleep(500 * time.Millisecond)
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.lastErr != "" {
		return fmt.Errorf("tunnel failed to start: %s", m.lastErr)
	}
	return nil
}

func (m *Manager) failStart(msg string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.running = false
	m.lastErr = msg
}

// safeClose closes ch, tolerating a close performed by cloudflared's own
// signal handler (waitForSignal) which may fire first on SIGTERM.
func safeClose(ch chan struct{}) {
	defer func() { _ = recover() }()
	close(ch)
}

// Stop gracefully shuts the tunnel down by closing cloudflared's shutdown
// channel (the same mechanism its SIGTERM handler uses).
func (m *Manager) Stop() {
	m.mu.Lock()
	shutdown := m.shutdown
	running := m.running
	m.mu.Unlock()
	if !running {
		return
	}
	m.stopOnce.Do(func() {
		safeClose(shutdown)
	})
	// Wait for the goroutine to observe shutdown.
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		m.mu.Lock()
		done := !m.running
		m.mu.Unlock()
		if done {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// Status returns a snapshot for the API.
func (m *Manager) Status() Status {
	m.mu.Lock()
	defer m.mu.Unlock()
	return Status{
		Running: m.running,
		Mode:    m.mode,
		Started: m.started,
		Error:   m.lastErr,
		LastLog: m.lastLog,
		LogFile: m.logFile,
	}
}

// TailLog returns the most recent lines of the cloudflared log.
func (m *Manager) TailLog(n int) []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return tailFile(m.logFile, n)
}

func (m *Manager) tailLog() string {
	lines := tailFile(m.logFile, 3)
	if len(lines) == 0 {
		return ""
	}
	return strings.Join(lines, "\n")
}

func tailFile(path string, n int) []string {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return lines
}
