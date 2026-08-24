package tuning

import (
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// DragonflyState holds the current configuration of a running Dragonfly instance,
// as reported by the Dragonfly INFO command.
type DragonflyState struct {
	MaxMemoryBytes uint64 // current maxmemory in bytes
	ThreadCount    int    // current proactor thread count
	Version        string // e.g. "df-v1.40.1"
}

// ValidateDragonfly checks whether the running Dragonfly instance has
// configuration that matches what AutoDragonflyFlags() would compute for
// this system. If the flags are outdated (e.g. the old hardcoded 512mb/2
// threads), it attempts to restart Dragonfly with the correct values.
//
// This is best-effort: failures are logged but never prevent irongrid from
// starting. The function handles three deployment modes:
//   - systemd service (Linux, detected via systemctl)
//   - Docker container (detected via docker inspect)
//   - background process (fallback on Linux)
func ValidateDragonfly(addr string) {
	state, err := inspectDragonfly(addr)
	if err != nil {
		slog.Warn("dragonfly validation skipped — could not inspect running instance", "error", err)
		return
	}

	want := AutoDragonflyFlags()
	wantBytes := parseMemoryString(want.MaxMemory)

	changed := false
	var reasons []string

	if state.MaxMemoryBytes != wantBytes {
		reasons = append(reasons, fmt.Sprintf("maxmemory: %s -> %s", formatBytesV(state.MaxMemoryBytes), want.MaxMemory))
		changed = true
	}
	if state.ThreadCount != want.ProactorThreads {
		reasons = append(reasons, fmt.Sprintf("proactor_threads: %d -> %d", state.ThreadCount, want.ProactorThreads))
		changed = true
	}

	if !changed {
		slog.Info("dragonfly config up to date",
			"maxmemory", want.MaxMemory,
			"proactor_threads", want.ProactorThreads,
			"version", state.Version)
		return
	}

	slog.Warn("dragonfly config outdated — restarting with corrected flags",
		"reasons", reasons,
		"current_maxmemory", formatBytesV(state.MaxMemoryBytes),
		"current_threads", state.ThreadCount,
		"new_maxmemory", want.MaxMemory,
		"new_threads", want.ProactorThreads)

	if err := restartDragonfly(want); err != nil {
		slog.Error("dragonfly restart failed — continuing with outdated config",
			"error", err,
			"action_required", "update the dragonfly systemd unit or docker container manually")
		return
	}

	slog.Info("dragonfly restarted with corrected flags",
		"maxmemory", want.MaxMemory,
		"proactor_threads", want.ProactorThreads)
}

// inspectDragonfly queries a running Dragonfly instance for its current config
// via the INFO command over the Redis protocol.
func inspectDragonfly(addr string) (*DragonflyState, error) {
	info, err := redisCommand(addr, "INFO")
	if err != nil {
		return nil, err
	}

	state := &DragonflyState{ThreadCount: 2}
	for _, line := range strings.Split(info, "\n") {
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "maxmemory:"):
			v, _ := strconv.ParseUint(strings.TrimPrefix(line, "maxmemory:"), 10, 64)
			state.MaxMemoryBytes = v
		case strings.HasPrefix(line, "thread_count:"):
			v, _ := strconv.Atoi(strings.TrimPrefix(line, "thread_count:"))
			state.ThreadCount = v
		case strings.HasPrefix(line, "dragonfly_version:"):
			state.Version = strings.TrimPrefix(line, "dragonfly_version:")
		}
	}
	return state, nil
}

// redisCommand sends a Redis command via a subprocess and returns the response.
// Uses python3 as a portable Redis protocol client to avoid importing net
// in the tuning package.
func redisCommand(addr, cmd string) (string, error) {
	host := "127.0.0.1"
	port := "6379"
	if parts := strings.SplitN(addr, ":", 2); len(parts) == 2 {
		host = parts[0]
		port = parts[1]
	}

	script := fmt.Sprintf(`import socket, time
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(3)
s.connect(('%s', %s))
s.send(b'*1\r\n$%d\r\n%s\r\n')
time.sleep(0.3)
data = s.recv(65536)
s.close()
print(data.decode('latin-1', errors='replace'))`, host, port, len(cmd), cmd)

	out, err := exec.Command("python3", "-c", script).CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("redis %s to %s failed: %w (output: %s)", cmd, addr, err, string(out))
	}
	return string(out), nil
}

// ---- restart logic ----

func restartDragonfly(flags DragonflyFlags) error {
	switch runtime.GOOS {
	case "linux":
		return restartDragonflyLinux(flags)
	case "darwin", "windows":
		return restartDragonflyDocker(flags)
	default:
		return fmt.Errorf("dragonfly restart not supported on %s", runtime.GOOS)
	}
}

func restartDragonflyLinux(flags DragonflyFlags) error {
	if isSystemdUnitActive("dragonfly") {
		return restartDragonflySystemd(flags)
	}
	if isDockerContainerRunning("dragonfly") {
		return restartDragonflyDocker(flags)
	}
	return restartDragonflyBackground(flags)
}

// isSystemdUnitActive checks if a systemd unit is currently active.
func isSystemdUnitActive(name string) bool {
	out, err := exec.Command("systemctl", "is-active", name).CombinedOutput()
	return err == nil && strings.TrimSpace(string(out)) == "active"
}

// isDockerContainerRunning checks if a Docker container is running.
func isDockerContainerRunning(name string) bool {
	out, err := exec.Command("docker", "inspect", "-f", "{{.State.Running}}", name).CombinedOutput()
	return err == nil && strings.TrimSpace(string(out)) == "true"
}

// restartDragonflySystemd updates the systemd unit file and restarts the service.
func restartDragonflySystemd(flags DragonflyFlags) error {
	unitPath := "/etc/systemd/system/dragonfly.service"

	data, err := os.ReadFile(unitPath)
	if err != nil {
		return fmt.Errorf("read %s: %w", unitPath, err)
	}

	content := string(data)
	basePath, oldArgs := parseExecStart(content)
	if basePath == "" {
		return fmt.Errorf("could not parse ExecStart from %s", unitPath)
	}

	newArgs := updateDflyArgs(oldArgs, flags)
	newExecStart := fmt.Sprintf("ExecStart=%s %s", basePath, newArgs)

	lines := strings.Split(content, "\n")
	for i, line := range lines {
		if strings.HasPrefix(line, "ExecStart=") {
			lines[i] = newExecStart
			break
		}
	}

	if err := os.WriteFile(unitPath, []byte(strings.Join(lines, "\n")), 0o644); err != nil {
		return fmt.Errorf("write %s: %w", unitPath, err)
	}
	slog.Info("dragonfly systemd unit updated", "path", unitPath, "new_exec", newExecStart)

	if out, err := exec.Command("systemctl", "daemon-reload").CombinedOutput(); err != nil {
		slog.Warn("systemctl daemon-reload failed", "output", string(out), "error", err)
	}
	if out, err := exec.Command("systemctl", "restart", "dragonfly").CombinedOutput(); err != nil {
		return fmt.Errorf("systemctl restart dragonfly: %w (output: %s)", err, string(out))
	}

	if !waitForDragonfly("localhost:6379", 30*time.Second) {
		return fmt.Errorf("dragonfly did not come back up after restart")
	}
	return nil
}

// restartDragonflyDocker stops and recreates the Docker container.
func restartDragonflyDocker(flags DragonflyFlags) error {
	_ = exec.Command("docker", "rm", "-f", "dragonfly").Run()

	args := []string{
		"run", "-d", "--name", "dragonfly", "--restart", "unless-stopped",
		"-p", "127.0.0.1:6379:6379",
		"docker.dragonflydb.io/dragonfly/dragonfly",
		"--cache_mode=true",
		"--maxmemory=" + flags.MaxMemory,
		"--proactor_threads=" + fmt.Sprintf("%d", flags.ProactorThreads),
		"--port=6379",
	}
	if out, err := exec.Command("docker", args...).CombinedOutput(); err != nil {
		return fmt.Errorf("docker run failed: %w (output: %s)", err, string(out))
	}
	if !waitForDragonfly("localhost:6379", 60*time.Second) {
		return fmt.Errorf("dragonfly container did not come back up")
	}
	return nil
}

// restartDragonflyBackground kills and restarts a background Dragonfly process.
func restartDragonflyBackground(flags DragonflyFlags) error {
	out, err := exec.Command("pgrep", "-f", "dragonfly").CombinedOutput()
	if err != nil || strings.TrimSpace(string(out)) == "" {
		return fmt.Errorf("could not find running dragonfly process")
	}
	pidStr := strings.TrimSpace(strings.Split(string(out), "\n")[0])
	pid, _ := strconv.Atoi(pidStr)

	dataDir := getDataDirFromProc(pid)
	proc, err := os.FindProcess(pid)
	if err == nil {
		_ = proc.Kill()
	}
	time.Sleep(2 * time.Second)

	bin := "/usr/local/bin/dragonfly"
	if dataDir == "" {
		home, _ := os.UserHomeDir()
		dataDir = filepath.Join(home, ".local", "share", "irongrid", "dragonfly")
	}

	args := []string{
		"--port=6379", "--bind=127.0.0.1", "--cache_mode=true",
		"--maxmemory=" + flags.MaxMemory,
		"--proactor_threads=" + fmt.Sprintf("%d", flags.ProactorThreads),
		"--dir=" + dataDir,
	}
	cmd := exec.Command(bin, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start dragonfly: %w", err)
	}
	if !waitForDragonfly("localhost:6379", 30*time.Second) {
		return fmt.Errorf("dragonfly did not come back up after restart")
	}
	return nil
}

// ---- helpers ----

// parseExecStart extracts the binary path and arguments from an ExecStart= line.
func parseExecStart(content string) (basePath, args string) {
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "ExecStart=") {
			continue
		}
		line = strings.TrimPrefix(line, "ExecStart=")
		parts := strings.SplitN(line, " ", 2)
		basePath = parts[0]
		if len(parts) > 1 {
			args = parts[1]
		}
		return
	}
	return
}

// updateDflyArgs replaces --maxmemory and --proactor_threads in existing args.
func updateDflyArgs(oldArgs string, flags DragonflyFlags) string {
	args := splitArgs(oldArgs)
	var result []string
	sawMaxmem, sawThreads := false, false

	for _, arg := range args {
		switch {
		case strings.HasPrefix(arg, "--maxmemory="):
			result = append(result, "--maxmemory="+flags.MaxMemory)
			sawMaxmem = true
		case strings.HasPrefix(arg, "--proactor_threads="):
			result = append(result, "--proactor_threads="+fmt.Sprintf("%d", flags.ProactorThreads))
			sawThreads = true
		default:
			result = append(result, arg)
		}
	}
	if !sawMaxmem {
		result = append(result, "--maxmemory="+flags.MaxMemory)
	}
	if !sawThreads {
		result = append(result, "--proactor_threads="+fmt.Sprintf("%d", flags.ProactorThreads))
	}
	return strings.Join(result, " ")
}

// splitArgs splits a shell-like argument string, handling quoted values.
func splitArgs(s string) []string {
	var args []string
	var current strings.Builder
	inQuote := false
	quoteChar := byte(0)

	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case inQuote:
			if c == quoteChar {
				inQuote = false
			} else {
				current.WriteByte(c)
			}
		case c == '"' || c == '\'':
			inQuote = true
			quoteChar = c
		case c == ' ':
			if current.Len() > 0 {
				args = append(args, current.String())
				current.Reset()
			}
		default:
			current.WriteByte(c)
		}
	}
	if current.Len() > 0 {
		args = append(args, current.String())
	}
	return args
}

// getDataDirFromProc reads /proc/<pid>/cmdline to extract the --dir flag.
func getDataDirFromProc(pid int) string {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	if err != nil {
		return ""
	}
	for _, arg := range strings.Split(string(data), "\000") {
		if strings.HasPrefix(arg, "--dir=") {
			return strings.TrimPrefix(arg, "--dir=")
		}
	}
	return ""
}

// parseMemoryString converts "2917mb" or "2gb" to bytes.
func parseMemoryString(s string) uint64 {
	s = strings.TrimSpace(strings.ToLower(s))
	if strings.HasSuffix(s, "gb") {
		v, _ := strconv.ParseUint(strings.TrimSuffix(s, "gb"), 10, 64)
		return v << 30
	}
	if strings.HasSuffix(s, "mb") {
		v, _ := strconv.ParseUint(strings.TrimSuffix(s, "mb"), 10, 64)
		return v << 20
	}
	v, _ := strconv.ParseUint(s, 10, 64)
	return v
}

// formatBytesV formats bytes into a human-readable string (validation module).
func formatBytesV(b uint64) string {
	const gib = 1 << 30
	if b >= gib {
		return fmt.Sprintf("%.1fGiB", float64(b)/gib)
	}
	return fmt.Sprintf("%.0fMiB", float64(b)/(1<<20))
}

// waitForDragonfly polls until Dragonfly answers PING.
func waitForDragonfly(addr string, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if _, err := redisCommand(addr, "PING"); err == nil {
			return true
		}
		time.Sleep(500 * time.Millisecond)
	}
	return false
}
