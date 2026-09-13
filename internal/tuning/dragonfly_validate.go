package tuning

import (
	"fmt"
	"log/slog"
	"os/exec"
	"strconv"
	"strings"
)

// DragonflyState holds the current configuration of a running Dragonfly instance,
// as reported by the Dragonfly INFO command.
type DragonflyState struct {
	MaxMemoryBytes uint64 // current maxmemory in bytes
	ThreadCount    int    // current proactor thread count
	Version        string // e.g. "df-v1.40.1"
}

// ValidateDragonfly checks whether the running Dragonfly instance's
// maxmemory/proactor_threads match what AutoDragonflyFlags() computes for
// this system (e.g. the box was resized since Dragonfly was first set up)
// and logs a warning with the corrected values if not.
//
// It deliberately does not rewrite Dragonfly's unit file or restart it:
// irongrid's own systemd hardening (ProtectSystem=full) makes /etc
// read-only inside its sandbox, so it never had real write access here —
// and extending that access would let a compromised irongrid rewrite what
// Dragonfly runs as root on its next restart. Apply the suggested flags by
// hand: edit dragonfly.service's ExecStart, then
// `systemctl daemon-reload && systemctl restart dragonfly`.
//
// Best-effort: an inspection failure is logged but never prevents irongrid
// from starting.
func ValidateDragonfly(addr string) {
	state, err := inspectDragonfly(addr)
	if err != nil {
		slog.Warn("dragonfly validation skipped — could not inspect running instance", "error", err)
		return
	}

	want := AutoDragonflyFlags()
	wantBytes := parseMemoryString(want.MaxMemory)

	var reasons []string
	if state.MaxMemoryBytes != wantBytes {
		reasons = append(reasons, fmt.Sprintf("maxmemory: %s -> %s", formatBytesV(state.MaxMemoryBytes), want.MaxMemory))
	}
	if state.ThreadCount != want.ProactorThreads {
		reasons = append(reasons, fmt.Sprintf("proactor_threads: %d -> %d", state.ThreadCount, want.ProactorThreads))
	}

	if len(reasons) == 0 {
		slog.Info("dragonfly config up to date",
			"maxmemory", want.MaxMemory,
			"proactor_threads", want.ProactorThreads,
			"version", state.Version)
		return
	}

	slog.Warn("dragonfly config outdated for this host's resources — update it manually",
		"reasons", reasons,
		"current_maxmemory", formatBytesV(state.MaxMemoryBytes),
		"current_threads", state.ThreadCount,
		"new_maxmemory", want.MaxMemory,
		"new_threads", want.ProactorThreads,
		"action_required", "edit dragonfly.service's ExecStart, then: systemctl daemon-reload && systemctl restart dragonfly")
}

// inspectDragonfly queries a running Dragonfly instance for its current config
// via the INFO command over the Redis protocol.
func inspectDragonfly(addr string) (*DragonflyState, error) {
	info, err := redisCommand(addr, "INFO")
	if err != nil {
		return nil, err
	}

	state := &DragonflyState{ThreadCount: 2}
	for line := range strings.SplitSeq(info, "\n") {
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "maxmemory:"):
			rest, _ := strings.CutPrefix(line, "maxmemory:")
			v, _ := strconv.ParseUint(rest, 10, 64)
			state.MaxMemoryBytes = v
		case strings.HasPrefix(line, "thread_count:"):
			rest, _ := strings.CutPrefix(line, "thread_count:")
			v, _ := strconv.Atoi(rest)
			state.ThreadCount = v
		case strings.HasPrefix(line, "dragonfly_version:"):
			state.Version, _ = strings.CutPrefix(line, "dragonfly_version:")
		}
	}
	return state, nil
}

// redisCommand sends a Redis command via a subprocess and returns the response.
// Uses python3 as a portable Redis protocol client to avoid importing net
// in the tuning package.
func redisCommand(addr, cmd string) (string, error) {
	host, port, ok := strings.Cut(addr, ":")
	if !ok {
		host = "127.0.0.1"
		port = "6379"
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

// parseMemoryString converts "2917mb" or "2gb" to bytes.
func parseMemoryString(s string) uint64 {
	s = strings.TrimSpace(strings.ToLower(s))
	if rest, ok := strings.CutSuffix(s, "gb"); ok {
		v, _ := strconv.ParseUint(rest, 10, 64)
		return v << 30
	}
	if rest, ok := strings.CutSuffix(s, "mb"); ok {
		v, _ := strconv.ParseUint(rest, 10, 64)
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
