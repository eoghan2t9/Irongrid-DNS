// Package tunnel manages a Cloudflare cloudflared subprocess so a tunnel can
// be started/stopped from the dashboard. The cloudflared binary itself is
// downloaded and kept up to date by internal/cfupdate — see NewManager.
package tunnel

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/eoghan2t9/Irongrid-DNS/internal/cfupdate"
)

// ErrNotRunning is returned by Restart when there is no running tunnel to
// restart (a stopped tunnel is deliberately not started by a restart).
var ErrNotRunning = errors.New("tunnel is not running")

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

// BinaryStatus reports the state of the managed cloudflared binary, as last
// observed by internal/cfupdate. Set via Manager.SetBinaryStatus.
type BinaryStatus struct {
	Version         string    `json:"version"`
	LatestVersion   string    `json:"latest_version,omitempty"`
	UpdateAvailable bool      `json:"update_available"`
	LastChecked     time.Time `json:"last_checked"`
	LastError       string    `json:"last_error,omitempty"`
}

// Status is the current tunnel state.
type Status struct {
	Running bool `json:"running"`
	// RunningVersion is the cloudflared release the live process was started
	// from. It can lag the installed binary after an update until the tunnel
	// is restarted; empty when the tunnel is not running.
	RunningVersion string       `json:"running_version,omitempty"`
	Mode           Mode         `json:"mode"`
	Started        time.Time    `json:"started"`
	Error          string       `json:"error"`
	LastLog        string       `json:"last_log"`
	LogFile        string       `json:"log_file"`
	Binary         BinaryStatus `json:"binary"`
}

// startArgs are the arguments of the last successful Start, kept so Restart
// can relaunch the tunnel exactly as it was configured.
type startArgs struct {
	mode                                Mode
	token, configFile, origin, hostname string
}

// Manager controls the managed cloudflared subprocess.
type Manager struct {
	// restartMu serialises Restart calls so two clicks cannot interleave a
	// stop with another stop and a double start.
	restartMu    sync.Mutex
	mu           sync.Mutex
	runVersion   string
	last         startArgs
	haveLast     bool
	running      bool
	started      time.Time
	mode         Mode
	lastErr      string
	lastLog      string
	logFile      string
	binPath      string
	cmd          *exec.Cmd
	binaryStatus BinaryStatus
}

// NewManager creates a tunnel manager writing logs and the managed
// cloudflared binary under dataDir.
func NewManager(dataDir string) *Manager {
	binDir := filepath.Join(dataDir, "bin")
	_ = os.MkdirAll(binDir, 0o755)
	binName := "cloudflared"
	if runtime.GOOS == "windows" {
		binName += ".exe"
	}
	return &Manager{
		logFile: filepath.Join(dataDir, "cloudflared.log"),
		binPath: filepath.Join(binDir, binName),
	}
}

// BinaryPath returns where the managed cloudflared binary is expected —
// internal/cfupdate installs to this exact path.
func (m *Manager) BinaryPath() string {
	return m.binPath
}

// SetBinaryStatus records the outcome of the last cfupdate check/install so
// Status can report it alongside the tunnel's own run state.
func (m *Manager) SetBinaryStatus(s BinaryStatus) {
	m.mu.Lock()
	m.binaryStatus = s
	m.mu.Unlock()
}

// Start launches the tunnel in the given mode. origin is used for quick
// tunnels (the local URL to expose, e.g. http://localhost:8080).
func (m *Manager) Start(mode Mode, token, configFile, origin, hostname string) (err error) {
	m.mu.Lock()
	if m.running {
		m.mu.Unlock()
		return fmt.Errorf("tunnel already running")
	}
	m.running = true
	m.started = time.Now()
	m.mode = mode
	m.lastErr = ""
	m.mu.Unlock()
	_ = hostname

	// Validate inputs before touching the running state further.
	switch mode {
	case ModeToken:
		if token == "" {
			m.failStart("tunnel token required for token mode")
			return fmt.Errorf("tunnel token required")
		}
	case ModeConfig:
		if configFile == "" {
			m.failStart("cloudflared config file required for config mode")
			return fmt.Errorf("cloudflared config file required")
		}
	case ModeQuick:
	default:
		m.failStart("unknown tunnel mode")
		return fmt.Errorf("unknown tunnel mode %q", mode)
	}

	if _, statErr := os.Stat(m.binPath); statErr != nil {
		m.failStart("cloudflared binary not installed yet")
		return fmt.Errorf("cloudflared binary not installed at %s: %w", m.binPath, statErr)
	}

	// Ask the binary which release it is before launching it: that is the
	// version the new process will run, even if the file is swapped by an
	// update a moment later.
	runVersion := cfupdate.BinaryVersion(context.Background(), m.binPath)

	args := buildArgs(mode, token, configFile, origin, m.logFile)
	cmd := exec.Command(m.binPath, args...)
	cmd.Env = append(os.Environ(), "QUIC_GO_DISABLE_ECN=1")
	if startErr := cmd.Start(); startErr != nil {
		m.failStart(fmt.Sprintf("failed to start cloudflared: %v", startErr))
		return fmt.Errorf("start cloudflared: %w", startErr)
	}

	m.mu.Lock()
	m.cmd = cmd
	m.runVersion = runVersion
	m.last = startArgs{mode: mode, token: token, configFile: configFile, origin: origin, hostname: hostname}
	m.haveLast = true
	m.mu.Unlock()

	go func() {
		waitErr := cmd.Wait()
		m.mu.Lock()
		m.running = false
		m.runVersion = ""
		m.cmd = nil
		if waitErr != nil {
			m.lastErr = waitErr.Error()
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

// buildArgs assembles the cloudflared flag list for the given mode (argv[0]
// is supplied separately by exec.Command). Global flags must precede the
// subcommand: cloudflared's flag parsing only knows --no-autoupdate /
// --logfile as app-level flags, not as flags of the `tunnel run` subcommand
// (which defines only credentials and proxy flags). Passing them after
// `tunnel run ...` fails with "flag provided but not defined: -no-autoupdate".
func buildArgs(mode Mode, token, configFile, origin, logFile string) []string {
	args := []string{"--no-autoupdate"}
	if logFile != "" {
		args = append(args, "--logfile", logFile)
	}
	switch mode {
	case ModeQuick:
		if origin == "" {
			origin = "http://localhost:8080"
		}
		args = append(args, "tunnel", "--url", origin)
	case ModeToken:
		args = append(args, "tunnel", "run", "--token", token)
	case ModeConfig:
		args = append(args, "tunnel", "run", "--config", configFile)
	default:
		args = append(args, "tunnel") // unreachable: Start validates mode first
	}
	return args
}

func (m *Manager) failStart(msg string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.running = false
	m.lastErr = msg
}

// Stop gracefully shuts the tunnel down by sending SIGTERM to the cloudflared
// process (the same signal its own shutdown handler expects), falling back
// to SIGKILL if it hasn't exited within the grace period.
func (m *Manager) Stop() {
	m.mu.Lock()
	cmd := m.cmd
	running := m.running
	m.mu.Unlock()
	if !running || cmd == nil || cmd.Process == nil {
		return
	}
	_ = cmd.Process.Signal(syscall.SIGTERM)

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

	m.mu.Lock()
	stillRunning := m.running
	m.mu.Unlock()
	if stillRunning {
		_ = cmd.Process.Kill()
	}
}

// Restart stops the running tunnel and starts it again with the arguments it
// was last started with, so a cloudflared binary that was swapped in by an
// update takes effect. It returns ErrNotRunning (and does nothing) when the
// tunnel is not running: a restart never turns a stopped tunnel on.
func (m *Manager) Restart() error {
	m.restartMu.Lock()
	defer m.restartMu.Unlock()

	m.mu.Lock()
	running, args, ok := m.running, m.last, m.haveLast
	m.mu.Unlock()
	if !running {
		return ErrNotRunning
	}
	if !ok {
		return errors.New("tunnel was not started by this process; stop and start it from the Tunnel page")
	}

	m.Stop()
	// Stop returns once the process is gone or has been killed; the exit is
	// recorded asynchronously, and Start refuses while it still looks running.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		m.mu.Lock()
		still := m.running
		m.mu.Unlock()
		if !still {
			return m.Start(args.mode, args.token, args.configFile, args.origin, args.hostname)
		}
		time.Sleep(50 * time.Millisecond)
	}
	return errors.New("tunnel did not stop in time; not restarting it")
}

// Status returns a snapshot for the API.
func (m *Manager) Status() Status {
	m.mu.Lock()
	defer m.mu.Unlock()
	s := Status{
		Running: m.running,
		Mode:    m.mode,
		Started: m.started,
		Error:   m.lastErr,
		LastLog: m.lastLog,
		LogFile: m.logFile,
		Binary:  m.binaryStatus,
	}
	if m.running {
		s.RunningVersion = m.runVersion
	}
	return s
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
