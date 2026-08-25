package api

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestLoginGuardLocksOutAfterThreshold(t *testing.T) {
	t.Parallel()
	g := NewLoginGuard()
	for i := range loginMaxFailures - 1 {
		g.RecordFailure("1.2.3.4")
		if locked, _ := g.Locked("1.2.3.4"); locked {
			t.Fatalf("locked out after only %d failures, want %d", i+1, loginMaxFailures)
		}
	}
	g.RecordFailure("1.2.3.4")
	locked, remaining := g.Locked("1.2.3.4")
	if !locked {
		t.Fatalf("expected lockout after %d failures", loginMaxFailures)
	}
	if remaining <= 0 || remaining > loginLockoutFor {
		t.Fatalf("remaining = %v, want (0, %v]", remaining, loginLockoutFor)
	}
}

func TestLoginGuardPerClientIndependent(t *testing.T) {
	t.Parallel()
	g := NewLoginGuard()
	for range loginMaxFailures {
		g.RecordFailure("1.2.3.4")
	}
	if locked, _ := g.Locked("1.2.3.4"); !locked {
		t.Fatal("expected 1.2.3.4 to be locked out")
	}
	if locked, _ := g.Locked("5.6.7.8"); locked {
		t.Fatal("a different client IP must not be affected by another's lockout")
	}
}

func TestLoginGuardSuccessClearsFailures(t *testing.T) {
	t.Parallel()
	g := NewLoginGuard()
	for range loginMaxFailures - 1 {
		g.RecordFailure("1.2.3.4")
	}
	g.RecordSuccess("1.2.3.4")
	// One more failure now should not immediately lock out — the counter
	// was reset by the success, not carried over.
	g.RecordFailure("1.2.3.4")
	if locked, _ := g.Locked("1.2.3.4"); locked {
		t.Fatal("a successful login should have cleared the prior failure count")
	}
}

// TestLoginGuardWindowExpiryResetsCount verifies a stale run of failures
// (older than loginFailureWindow) doesn't count toward a fresh lockout —
// seeded directly rather than sleeping loginFailureWindow in a test.
func TestLoginGuardWindowExpiryResetsCount(t *testing.T) {
	t.Parallel()
	g := NewLoginGuard()
	s := g.shard("1.2.3.4")
	s.entries["1.2.3.4"] = &loginEntry{
		failures:     loginMaxFailures - 1,
		firstFailure: time.Now().Add(-loginFailureWindow - time.Second),
		lastSeen:     time.Now().Add(-loginFailureWindow - time.Second),
	}
	g.RecordFailure("1.2.3.4")
	if locked, _ := g.Locked("1.2.3.4"); locked {
		t.Fatal("a failure after the window expired should start a fresh count, not lock out immediately")
	}
}

func TestClientIPFromRequestTrustsXFFOnlyFromLoopback(t *testing.T) {
	t.Parallel()
	// Direct connection (no tunnel): a self-reported XFF must be ignored —
	// otherwise a remote attacker could claim a fresh IP on every request
	// and dodge the lockout entirely.
	req := httptest.NewRequest(http.MethodGet, "/api/status", nil)
	req.RemoteAddr = "203.0.113.9:5555"
	req.Header.Set("X-Forwarded-For", "9.9.9.9")
	if got := clientIPFromRequest(req); got != "203.0.113.9" {
		t.Fatalf("clientIPFromRequest = %q, want the real peer 203.0.113.9 (XFF must be ignored from a non-loopback peer)", got)
	}

	// Through the tunnel (cloudflared connects over loopback): XFF is the
	// real visitor IP and must be trusted.
	req2 := httptest.NewRequest(http.MethodGet, "/api/status", nil)
	req2.RemoteAddr = "127.0.0.1:41000"
	req2.Header.Set("X-Forwarded-For", "198.51.100.7, 10.0.0.1")
	if got := clientIPFromRequest(req2); got != "198.51.100.7" {
		t.Fatalf("clientIPFromRequest = %q, want the first XFF hop 198.51.100.7 when the peer is loopback", got)
	}
}

// TestAuthorizeLocksOutAfterFailedAttempts is the end-to-end path through
// authorize() itself: repeated wrong passwords from one IP eventually get
// a 429 even for the CORRECT password, while a different IP is unaffected.
func TestAuthorizeLocksOutAfterFailedAttempts(t *testing.T) {
	t.Parallel()
	a := testApp(t)
	const attacker = "203.0.113.50:1111"

	for i := range loginMaxFailures {
		req := httptest.NewRequest(http.MethodGet, "/api/status", nil)
		req.RemoteAddr = attacker
		req.SetBasicAuth("admin", "wrong-password")
		rr := httptest.NewRecorder()
		if a.authorize(rr, req) {
			t.Fatalf("wrong password accepted on attempt %d", i+1)
		}
	}

	// Now even the CORRECT password from the same IP must be rejected —
	// the lockout has to run its course.
	req := httptest.NewRequest(http.MethodGet, "/api/status", nil)
	req.RemoteAddr = attacker
	req.SetBasicAuth("admin", "secret123")
	rr := httptest.NewRecorder()
	if a.authorize(rr, req) {
		t.Fatal("correct password accepted while the IP should be locked out")
	}
	if rr.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusTooManyRequests)
	}

	// A different client IP must be able to log in normally.
	req2 := httptest.NewRequest(http.MethodGet, "/api/status", nil)
	req2.RemoteAddr = "198.51.100.20:2222"
	req2.SetBasicAuth("admin", "secret123")
	rr2 := httptest.NewRecorder()
	if !a.authorize(rr2, req2) {
		t.Fatal("a different, well-behaved client IP was rejected — lockout must be per-IP")
	}
}

// TestAuthorizeDoesNotCountCredentialFreeRequests verifies background
// requests with no Authorization header at all (e.g. a poller whose
// session just expired) never count toward the lockout — only requests
// that actually presented a wrong password should.
func TestAuthorizeDoesNotCountCredentialFreeRequests(t *testing.T) {
	t.Parallel()
	a := testApp(t)
	for range loginMaxFailures * 2 {
		req := httptest.NewRequest(http.MethodGet, "/api/status", nil)
		req.RemoteAddr = "203.0.113.60:3333"
		rr := httptest.NewRecorder()
		a.authorize(rr, req)
	}
	if locked, _ := a.loginGuard.Locked("203.0.113.60"); locked {
		t.Fatal("credential-free requests must never trigger the login lockout")
	}
}
