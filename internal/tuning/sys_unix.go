//go:build !windows

package tuning

import (
	"log/slog"

	"golang.org/x/sys/unix"
)

// maxFileLimit is the preferred RLIMIT_NOFILE soft limit Irongrid raises
// itself to when the hard limit is unbounded (common on macOS), so infinity
// can't become an unbounded value.
const maxFileLimit = 1 << 20 // 1,048,576

// softLimitCandidates lists the RLIMIT_NOFILE soft-limit targets in order of
// preference: the hard limit when finite (capped at maxFileLimit), otherwise
// maxFileLimit, then progressively lower values. macOS caps per-process fds
// at kern.maxfilesperproc (as low as 10,240 on older releases), where
// setrlimit rejects a 1M raise — the lower candidates keep the raise useful
// instead of just logging an error on every boot.
func softLimitCandidates(hard uint64) []uint64 {
	first := uint64(maxFileLimit)
	if hard != unix.RLIM_INFINITY {
		first = hard
	}
	seen := make(map[uint64]bool, 4)
	var out []uint64
	for _, c := range []uint64{first, maxFileLimit, 1 << 18, 1 << 16} {
		if !seen[c] {
			seen[c] = true
			out = append(out, c)
		}
	}
	return out
}

// raiseFileLimit raises the RLIMIT_NOFILE soft limit toward the hard limit so
// a busy resolver isn't throttled by a low default: Docker ships a 1024 soft
// limit and some distros ship 256, which a server holding thousands of
// upstream connections and client sockets can brush up against. Raising the
// soft limit needs no privileges. The systemd unit's LimitNOFILE and
// docker-compose's ulimits cover the service/container paths; this covers
// bare runs.
func raiseFileLimit() {
	var rl unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_NOFILE, &rl); err != nil {
		slog.Warn("nofile getrlimit failed", "error", err)
		return
	}
	old := rl.Cur
	for _, target := range softLimitCandidates(rl.Max) {
		if target <= old {
			continue
		}
		if rl.Max != unix.RLIM_INFINITY && target > rl.Max {
			continue
		}
		next := rl
		next.Cur = target
		if err := unix.Setrlimit(unix.RLIMIT_NOFILE, &next); err != nil {
			// A rejected raise (macOS kern.maxfilesperproc cap) falls through
			// to the next-lower candidate.
			continue
		}
		recordFDRaised(old)
		slog.Info("file-descriptor soft limit raised", "from", old, "to", target)
		return
	}
}

// readFileLimit reports the current RLIMIT_NOFILE soft and hard limits.
func readFileLimit() (soft, hard uint64, ok bool) {
	var rl unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_NOFILE, &rl); err != nil {
		return 0, 0, false
	}
	return rl.Cur, rl.Max, true
}

// setSocketBufferSizes applies SocketBufferSize as both SO_RCVBUF and
// SO_SNDBUF on a raw socket fd (called from a syscall.RawConn.Control hook).
func setSocketBufferSizes(fd uintptr) error {
	s := int(fd)
	if err := unix.SetsockoptInt(s, unix.SOL_SOCKET, unix.SO_RCVBUF, SocketBufferSize); err != nil {
		return err
	}
	return unix.SetsockoptInt(s, unix.SOL_SOCKET, unix.SO_SNDBUF, SocketBufferSize)
}
