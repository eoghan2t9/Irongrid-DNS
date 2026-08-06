package api

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/eoghan2t9/Irongrid-DNS/internal/config"
)

// testApp returns an App wired with a valid config for auth tests.
func testApp(t *testing.T) *App {
	t.Helper()
	return &App{
		Config: &config.Config{
			Web: config.WebConfig{
				Username:      "admin",
				Password:      "secret123",
				SessionSecret: "0123456789abcdef0123456789abcdef",
			},
		},
	}
}

// TestSessionCookieRoundTrip verifies the full login persistence flow: Basic
// login sets a signed cookie, and a subsequent request carrying only that
// cookie (as a page reload would) is authorized.
func TestSessionCookieRoundTrip(t *testing.T) {
	a := testApp(t)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/status", nil)
	req.SetBasicAuth("admin", "secret123")

	if !a.authorize(rr, req) {
		t.Fatal("basic login rejected")
	}
	cookies := rr.Result().Cookies()
	var sess *http.Cookie
	for _, c := range cookies {
		if c.Name == sessionCookie {
			sess = c
		}
	}
	if sess == nil {
		t.Fatal("no session cookie set on login")
	}
	if !sess.HttpOnly {
		t.Error("session cookie should be HttpOnly")
	}

	// Simulate a page reload: same cookie, no Authorization header.
	req2 := httptest.NewRequest(http.MethodGet, "/api/status", nil)
	req2.AddCookie(sess)
	rr2 := httptest.NewRecorder()
	if !a.authorize(rr2, req2) {
		t.Fatal("reload with session cookie rejected — login does not persist across refreshes")
	}
}

// TestSessionCookieRejectsUnauthenticated verifies requests with no valid
// credentials and tampered cookies are rejected.
func TestSessionCookieRejectsUnauthenticated(t *testing.T) {
	a := testApp(t)
	rr := httptest.NewRecorder()
	if a.authorize(rr, httptest.NewRequest(http.MethodGet, "/api/status", nil)) {
		t.Fatal("request with no credentials accepted")
	}

	// Tampered cookie: a validly-signed cookie with a corrupted signature hex
	// (genuinely exercises the HMAC-rejection path, unlike the old raw format).
	good := validCookie(t, a, "admin")
	badSig := good[:len(good)-4] + "0000"
	req := httptest.NewRequest(http.MethodGet, "/api/status", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookie, Value: badSig})
	rr2 := httptest.NewRecorder()
	if a.authorize(rr2, req) {
		t.Fatal("tampered session cookie accepted")
	}

	// Wrong username in a well-signed cookie must also be rejected.
	a2 := testApp(t)
	req3 := httptest.NewRequest(http.MethodGet, "/api/status", nil)
	req3.AddCookie(&http.Cookie{Name: sessionCookie, Value: validCookie(t, a2, "other")})
	rr3 := httptest.NewRecorder()
	if a2.authorize(rr3, req3) {
		t.Fatal("session cookie for a different user accepted")
	}
}

// TestSessionCookieDottedUsername verifies the base64url payload encoding
// keeps login persistence working when the configured username contains dots
// (e.g. "john.doe") — the old raw "user.exp.sig" format would mis-split.
func TestSessionCookieDottedUsername(t *testing.T) {
	a := testApp(t)
	a.Config.Web.Username = "john.doe"
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/status", nil)
	req.SetBasicAuth("john.doe", "secret123")
	if !a.authorize(rr, req) {
		t.Fatal("dotted-username basic login rejected")
	}
	var sess *http.Cookie
	for _, c := range rr.Result().Cookies() {
		if c.Name == sessionCookie {
			sess = c
		}
	}
	if sess == nil {
		t.Fatal("no session cookie set for dotted username")
	}
	req2 := httptest.NewRequest(http.MethodGet, "/api/status", nil)
	req2.AddCookie(sess)
	rr2 := httptest.NewRecorder()
	if !a.authorize(rr2, req2) {
		t.Fatal("reload with dotted-username session cookie rejected")
	}
}

// TestSessionSecretRotation verifies the session-rotation rule: the secret is
// kept when no new password is supplied, but rotated to a fresh value whenever
// a new plaintext password is — invalidating every previously issued cookie.
func TestSessionSecretRotation(t *testing.T) {
	const current = "0123456789abcdef0123456789abcdef"

	// No new password: keep the current secret (existing sessions survive).
	same, err := sessionSecretFor("", current)
	if err != nil {
		t.Fatalf("sessionSecretFor(\"\") error: %v", err)
	}
	if same != current {
		t.Fatalf("expected existing secret to be kept, got %q", same)
	}

	// New password: the secret must rotate (and never equal the old one).
	rotated, err := sessionSecretFor("newpass123", current)
	if err != nil {
		t.Fatalf("sessionSecretFor(new password) error: %v", err)
	}
	if rotated == "" {
		t.Fatal("rotated secret is empty")
	}
	if rotated == current {
		t.Fatal("session secret was not rotated on password change")
	}
	// Two consecutive rotations must produce different secrets.
	rotated2, err := sessionSecretFor("anotherpass", rotated)
	if err != nil {
		t.Fatalf("second rotation error: %v", err)
	}
	if rotated2 == rotated {
		t.Fatal("second rotation produced the same secret")
	}
}

// TestLogoutClearsSessionCookie verifies POST /api/logout expires the session
// cookie so the browser drops it.
func TestLogoutClearsSessionCookie(t *testing.T) {
	h := &Handler{Cfg: &config.Config{}}
	rr := httptest.NewRecorder()
	h.logout(rr)

	var sess *http.Cookie
	for _, c := range rr.Result().Cookies() {
		if c.Name == sessionCookie {
			sess = c
		}
	}
	if sess == nil {
		t.Fatal("logout did not set a session cookie")
	}
	if sess.Value != "" {
		t.Errorf("logout cookie value = %q, want empty", sess.Value)
	}
	if sess.MaxAge != -1 {
		t.Errorf("logout cookie MaxAge = %d, want -1", sess.MaxAge)
	}
}

// validCookie builds a properly signed session cookie value for the given user.
func validCookie(t *testing.T, a *App, user string) string {
	t.Helper()
	rr := httptest.NewRecorder()
	a.issueSession(rr, user)
	for _, c := range rr.Result().Cookies() {
		if c.Name == sessionCookie {
			return c.Value
		}
	}
	t.Fatal("issueSession set no cookie")
	return ""
}
