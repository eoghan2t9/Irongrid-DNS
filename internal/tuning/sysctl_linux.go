//go:build linux

package tuning

import (
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// sysctlCoreDir and sysctlTunings are package vars (not consts) so tests can
// point them at a fixture directory instead of the real /proc/sys.
var (
	sysctlCoreDir = "/proc/sys/net/core"
	sysctlTunings = []sysctlTuning{
		// The kernel clamps SO_RCVBUF/SO_SNDBUF to net.core.{r,w}mem_max
		// (default ~208 KiB) unless the ceiling is raised first — without
		// this, the 2 MiB socket buffers would be dead on arrival.
		{"rmem_max", 4 << 20},
		{"wmem_max", 4 << 20},
		// somaxconn is the listen backlog ceiling; a busy public listener
		// (or a DoH endpoint behind a slow client) can exceed the default.
		{"somaxconn", 65535},
	}
)

type sysctlTuning struct {
	key   string
	value uint64
}

// applySysctls raises the kernel socket-buffer ceilings so the per-socket
// buffers actually take effect. Best-effort and never fatal: the writes need
// CAP_NET_ADMIN, so as root on the host they always work, while inside a
// default Docker container (no CAP_NET_ADMIN, read-only /proc/sys) they fail
// with a single log line — containers can get the same effect via
// docker-compose's sysctls, which the daemon applies at container start. Only
// ever raises a knob; a sysctl already above the target is left alone.
func applySysctls() {
	for _, t := range sysctlTunings {
		path := filepath.Join(sysctlCoreDir, t.key)
		b, err := os.ReadFile(path)
		if err != nil {
			recordSysctl(SysctlState{Key: t.key, Target: t.value, Note: "not readable on this system"})
			continue
		}
		cur, err := strconv.ParseUint(strings.TrimSpace(string(b)), 10, 64)
		if err != nil {
			recordSysctl(SysctlState{Key: t.key, Target: t.value, Note: "unreadable value"})
			continue
		}
		if cur >= t.value {
			recordSysctl(SysctlState{Key: t.key, Value: cur, Target: t.value, Note: "already at or above target"})
			continue
		}
		// 0o600 is only to satisfy gosec G306 — the mode is meaningless for a
		// /proc/sys file, which the kernel never reads.
		if err := os.WriteFile(path, []byte(strconv.FormatUint(t.value, 10)), 0o600); err != nil {
			recordSysctl(SysctlState{Key: t.key, Value: cur, Target: t.value, Note: "not applied — needs root / CAP_NET_ADMIN (or set it via docker --sysctl / compose sysctls)"})
			log.Printf("[tune] sysctl %s: %v (running unprivileged? set it with docker --sysctl / compose sysctls, or as root)", t.key, err)
			continue
		}
		recordSysctl(SysctlState{Key: t.key, Value: t.value, Target: t.value, Note: "raised at boot"})
		log.Printf("[tune] sysctl %s raised: %d -> %d", t.key, cur, t.value)
	}
}

// currentSysctlValue re-reads one knob's live value (used by Status so the
// dashboard shows the value right now, not just what boot recorded).
func currentSysctlValue(key string) (uint64, bool) {
	b, err := os.ReadFile(filepath.Join(sysctlCoreDir, key))
	if err != nil {
		return 0, false
	}
	v, err := strconv.ParseUint(strings.TrimSpace(string(b)), 10, 64)
	if err != nil {
		return 0, false
	}
	return v, true
}
