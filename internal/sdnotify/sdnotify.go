// Package sdnotify implements the systemd sd_notify(3) protocol without a
// cgo/C dependency: it's just a single datagram written to $NOTIFY_SOCKET.
// Every function here is a safe no-op when not running under systemd (or
// under a unit that doesn't set Type=notify), so callers can invoke them
// unconditionally.
package sdnotify

import (
	"context"
	"net"
	"os"
	"strconv"
	"time"
)

// Notify sends a state string (e.g. "READY=1", "WATCHDOG=1", "STOPPING=1")
// to systemd via $NOTIFY_SOCKET. A no-op returning nil when NOTIFY_SOCKET is
// unset, which is the normal case outside of a systemd Type=notify unit.
func Notify(state string) error {
	addr := os.Getenv("NOTIFY_SOCKET")
	if addr == "" {
		return nil
	}
	conn, err := net.Dial("unixgram", addr)
	if err != nil {
		return err
	}
	defer conn.Close()
	_, err = conn.Write([]byte(state))
	return err
}

// watchdogInterval reports how often WATCHDOG=1 must be sent to avoid
// systemd killing the unit (WatchdogSec in the unit file), and whether the
// watchdog applies to this process at all. Per sd_watchdog_enabled(3): if
// WATCHDOG_PID is set, it must match our own PID, since a supervising shell
// between systemd and the real process would otherwise see the watchdog
// meant for a different process in its own environment.
func watchdogInterval() (time.Duration, bool) {
	usecStr := os.Getenv("WATCHDOG_USEC")
	if usecStr == "" {
		return 0, false
	}
	usec, err := strconv.ParseInt(usecStr, 10, 64)
	if err != nil || usec <= 0 {
		return 0, false
	}
	if pidStr := os.Getenv("WATCHDOG_PID"); pidStr != "" {
		if pid, err := strconv.Atoi(pidStr); err == nil && pid != os.Getpid() {
			return 0, false
		}
	}
	return time.Duration(usec) * time.Microsecond, true
}

// StartWatchdog pings systemd at half the unit's configured WatchdogSec
// (systemd's own recommended margin) until ctx is done. A no-op — no
// goroutine started — when the unit doesn't enable a watchdog.
func StartWatchdog(ctx context.Context) {
	interval, ok := watchdogInterval()
	if !ok {
		return
	}
	go func() {
		ticker := time.NewTicker(interval / 2)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				_ = Notify("WATCHDOG=1")
			}
		}
	}()
}
