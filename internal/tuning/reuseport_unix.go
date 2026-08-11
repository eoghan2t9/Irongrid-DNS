//go:build aix || darwin || dragonfly || freebsd || linux || netbsd || openbsd || zos

package tuning

import (
	"log"
	"syscall"

	"golang.org/x/sys/unix"
)

// ReuseportControl is a net.ListenConfig.Control hook that enables
// SO_REUSEPORT on a socket so several listeners can bind one UDP address and
// the kernel spreads incoming datagrams across them — each socket gets its
// own receive queue and read goroutine, so receive processing runs on many
// cores instead of one socket serialising every recvfrom.
//
// SO_REUSEADDR is set first: BSD-family platforms (macOS in particular)
// require it alongside SO_REUSEPORT for a second bind to succeed, and Linux
// ignores it harmlessly. The error is surfaced to the caller — it signals the
// platform can't do reuseport, so the listener falls back to a single socket;
// the socket-buffer sizing stays in SetPacketBuffers, applied after bind.
//
// Note: vanilla SO_REUSEPORT hashes by flow, so a Linux < 6.6 kernel can drop
// on one hot socket while its siblings idle under extreme overload; the
// kernel's SO_REUSEPORT_LOAD_BALANCE (6.6+) fixes that but isn't exposed by
// the pinned x/sys — a candidate follow-up if a bump lands.
func ReuseportControl(network, address string, c syscall.RawConn) error {
	var err error
	if cerr := c.Control(func(fd uintptr) {
		s := int(fd)
		if serr := unix.SetsockoptInt(s, unix.SOL_SOCKET, unix.SO_REUSEADDR, 1); serr != nil {
			err = serr
			return
		}
		err = unix.SetsockoptInt(s, unix.SOL_SOCKET, unix.SO_REUSEPORT, 1)
	}); cerr != nil {
		return cerr
	}
	if err != nil {
		log.Printf("[tune] SO_REUSEPORT for %s %s: %v", network, address, err)
	}
	return err
}
