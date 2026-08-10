//go:build !linux

package tuning

// applySysctls is a no-op outside Linux: macOS has no net.core.rmem_max
// equivalent to raise (its sockbuf ceiling is kern.ipc.maxsockbuf, which the
// per-socket setsockopt already respects), and Windows sizes Winsock buffers
// automatically. The socket buffers themselves are still raised everywhere.
func applySysctls() {}

// currentSysctlValue never succeeds outside Linux; there are no recorded
// sysctl notes to pair with a live value anyway.
func currentSysctlValue(key string) (uint64, bool) { return 0, false }
