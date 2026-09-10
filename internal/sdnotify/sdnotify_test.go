package sdnotify

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestNotifyNoopWithoutSocket(t *testing.T) {
	t.Setenv("NOTIFY_SOCKET", "")
	if err := Notify("READY=1"); err != nil {
		t.Fatalf("Notify without NOTIFY_SOCKET: %v", err)
	}
}

func TestNotifySendsToSocket(t *testing.T) {
	dir := t.TempDir()
	sockPath := dir + "/notify.sock"
	pc, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: sockPath, Net: "unixgram"})
	if err != nil {
		t.Fatalf("ListenUnixgram: %v", err)
	}
	defer pc.Close()
	t.Setenv("NOTIFY_SOCKET", sockPath)

	if err := Notify("READY=1"); err != nil {
		t.Fatalf("Notify: %v", err)
	}

	buf := make([]byte, 64)
	_ = pc.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := pc.Read(buf)
	if err != nil {
		t.Fatalf("reading from notify socket: %v", err)
	}
	if got := string(buf[:n]); got != "READY=1" {
		t.Fatalf("received %q, want %q", got, "READY=1")
	}
}

func TestStartWatchdogNoopWithoutEnv(t *testing.T) {
	t.Setenv("WATCHDOG_USEC", "")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	StartWatchdog(ctx) // must not panic or start a goroutine that outlives the test
}

func TestStartWatchdogPingsSocket(t *testing.T) {
	dir := t.TempDir()
	sockPath := dir + "/notify.sock"
	pc, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: sockPath, Net: "unixgram"})
	if err != nil {
		t.Fatalf("ListenUnixgram: %v", err)
	}
	defer pc.Close()
	t.Setenv("NOTIFY_SOCKET", sockPath)
	t.Setenv("WATCHDOG_USEC", "100000") // 100ms -> pings every 50ms
	t.Setenv("WATCHDOG_PID", "")        // unset: applies to this process

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	StartWatchdog(ctx)

	buf := make([]byte, 64)
	_ = pc.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := pc.Read(buf)
	if err != nil {
		t.Fatalf("expected a watchdog ping, got error: %v", err)
	}
	if got := string(buf[:n]); got != "WATCHDOG=1" {
		t.Fatalf("received %q, want %q", got, "WATCHDOG=1")
	}
}

func TestStartWatchdogSkippedForOtherPID(t *testing.T) {
	dir := t.TempDir()
	sockPath := dir + "/notify.sock"
	pc, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: sockPath, Net: "unixgram"})
	if err != nil {
		t.Fatalf("ListenUnixgram: %v", err)
	}
	defer pc.Close()
	t.Setenv("NOTIFY_SOCKET", sockPath)
	t.Setenv("WATCHDOG_USEC", "100000")
	t.Setenv("WATCHDOG_PID", "1") // never our own PID in a test process

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	StartWatchdog(ctx)

	buf := make([]byte, 64)
	_ = pc.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	if _, err := pc.Read(buf); err == nil {
		t.Fatal("expected no watchdog ping when WATCHDOG_PID doesn't match this process")
	}
}
