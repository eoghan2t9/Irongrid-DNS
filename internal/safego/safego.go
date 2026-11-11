// Package safego provides panic containment for background goroutines.
//
// A panic in a goroutine that nothing recovers terminates the whole process,
// so one bug in a periodic refresh loop would take DNS down with it. Deferring
// Recover at the top of such a goroutine logs the panic and stack and lets the
// rest of the server keep serving.
package safego

import (
	"log/slog"
	"runtime/debug"
)

// Recover must be deferred directly: defer safego.Recover("name").
func Recover(name string) {
	if r := recover(); r != nil {
		slog.Error("background goroutine panicked", "goroutine", name, "panic", r, "stack", string(debug.Stack()))
	}
}
