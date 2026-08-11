//go:build !aix && !darwin && !dragonfly && !freebsd && !linux && !netbsd && !openbsd && !zos

package tuning

import (
	"errors"
	"syscall"
)

// errNoReuseport reports that this platform has no SO_REUSEPORT (Windows in
// particular): the caller falls back to serving the address from a single
// socket, so a DNS listener always comes up everywhere.
var errNoReuseport = errors.New("SO_REUSEPORT not supported on this platform")

// ReuseportControl is unavailable on this platform: it reports an error so
// the caller serves the address from a single socket instead.
func ReuseportControl(network, address string, c syscall.RawConn) error {
	return errNoReuseport
}
