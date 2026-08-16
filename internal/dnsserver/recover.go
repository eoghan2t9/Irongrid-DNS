package dnsserver

import (
	"log"
	"runtime/debug"
)

// recoverPanic logs and swallows a panic recovered on a background or
// per-connection goroutine. Every listener (UDP/TCP/DoT/DoH/DoH3/DoQ)
// shares one process, and Go terminates the whole process on an
// unrecovered panic in any goroutine — not just the one that panicked — so
// a bug reachable from a single query or background task would otherwise
// take down DNS resolution for every client on every protocol at once.
// Call as `defer recoverPanic("where")` at the top of any goroutine entry
// point that isn't already covered by Handler.serve's own recover (which
// only catches panics on its own goroutine, not ones it spawns).
func recoverPanic(where string) {
	if r := recover(); r != nil {
		log.Printf("[dns] recovered panic in %s: %v\n%s", where, r, debug.Stack())
	}
}
