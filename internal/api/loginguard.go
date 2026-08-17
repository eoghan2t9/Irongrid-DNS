package api

import (
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/eoghan2t9/Irongrid-DNS/internal/shardutil"
)

const (
	loginGuardShards      = 64
	loginMaxFailures      = 5
	loginFailureWindow    = 5 * time.Minute
	loginLockoutFor       = 10 * time.Minute
	loginGuardMaxPerShard = 4096
	loginGuardIdleEvict   = 30 * time.Minute
)

type loginEntry struct {
	failures     int
	firstFailure time.Time
	lockedUntil  time.Time
	lastSeen     time.Time
}

type loginShard struct {
	mu      sync.Mutex
	entries map[string]*loginEntry
}

// LoginGuard throttles failed dashboard login attempts per client IP — a
// fail2ban-style lockout: valid session checks are never throttled, but
// repeated wrong-password Basic Auth attempts from one IP within
// loginFailureWindow trip a loginLockoutFor lockout, so a brute-force
// password guesser can't just keep hammering. A correct password submitted
// while locked out is still rejected — the lockout has to actually run its
// course, or a fast-enough guesser could brute-force through it.
type LoginGuard struct {
	shards [loginGuardShards]*loginShard
}

// NewLoginGuard returns an empty guard (no client is locked out).
func NewLoginGuard() *LoginGuard {
	g := &LoginGuard{}
	for i := range g.shards {
		g.shards[i] = &loginShard{entries: make(map[string]*loginEntry, 64)}
	}
	return g
}

func (g *LoginGuard) shard(key string) *loginShard {
	return g.shards[shardutil.FNV1a(key)&(loginGuardShards-1)]
}

// Locked reports whether client is currently locked out and, if so, how
// much longer.
func (g *LoginGuard) Locked(client string) (bool, time.Duration) {
	if client == "" {
		return false, 0
	}
	s := g.shard(client)
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.entries[client]
	if !ok {
		return false, 0
	}
	if now := time.Now(); now.Before(e.lockedUntil) {
		return true, e.lockedUntil.Sub(now)
	}
	return false, 0
}

// RecordFailure counts a wrong-password attempt from client, locking the IP
// out once failures cross the threshold within the sliding window.
func (g *LoginGuard) RecordFailure(client string) {
	if client == "" {
		return
	}
	s := g.shard(client)
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.entries) >= loginGuardMaxPerShard {
		for k, e := range s.entries {
			if now.Sub(e.lastSeen) > loginGuardIdleEvict {
				delete(s.entries, k)
			}
		}
	}
	e, ok := s.entries[client]
	if !ok || now.Sub(e.firstFailure) > loginFailureWindow {
		e = &loginEntry{firstFailure: now}
		s.entries[client] = e
	}
	e.failures++
	e.lastSeen = now
	if e.failures >= loginMaxFailures {
		e.lockedUntil = now.Add(loginLockoutFor)
	}
}

// RecordSuccess clears client's failure history. Only reached once Locked
// has already returned false, so this never cuts an active lockout short —
// it just stops a stale run of typos from carrying into a later, unrelated
// one.
func (g *LoginGuard) RecordSuccess(client string) {
	if client == "" {
		return
	}
	s := g.shard(client)
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.entries, client)
}

// clientIPFromRequest returns the real client IP for a dashboard request.
// X-Forwarded-For is trusted ONLY when the immediate TCP peer is loopback —
// i.e. the request arrived through the baked-in Cloudflare Tunnel, which
// always connects to this web server over localhost. A remote attacker
// connecting directly could set X-Forwarded-For to anything (a fresh IP on
// every request would dodge the lockout entirely), so it must never be
// trusted from a non-loopback peer.
func clientIPFromRequest(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			first := strings.TrimSpace(strings.Split(xff, ",")[0])
			if net.ParseIP(first) != nil {
				return first
			}
		}
	}
	return host
}
