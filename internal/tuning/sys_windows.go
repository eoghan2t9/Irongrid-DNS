//go:build windows

package tuning

import "golang.org/x/sys/windows"

// raiseFileLimit is a no-op on Windows: Go uses I/O completion ports there and
// there is no per-process file-descriptor limit to raise.
func raiseFileLimit() {}

// readFileLimit reports ok=false on Windows: there is no RLIMIT_NOFILE.
func readFileLimit() (soft, hard uint64, ok bool) { return 0, 0, false }

// setSocketBufferSizes applies SocketBufferSize as both SO_RCVBUF and
// SO_SNDBUF on a raw socket fd (called from a syscall.RawConn.Control hook).
// Winsock accepts the same SO_RCVBUF/SO_SNDBUF options as the Unix APIs.
func setSocketBufferSizes(fd uintptr) error {
	s := windows.Handle(fd)
	if err := windows.SetsockoptInt(s, windows.SOL_SOCKET, windows.SO_RCVBUF, SocketBufferSize); err != nil {
		return err
	}
	return windows.SetsockoptInt(s, windows.SOL_SOCKET, windows.SO_SNDBUF, SocketBufferSize)
}
