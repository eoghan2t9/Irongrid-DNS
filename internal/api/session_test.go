package api

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/eoghan2t9/Irongrid-DNS/internal/config"
)

// testApp returns an App wired with a valid config (one admin user) for auth
// tests.
func testApp(t *testing.T) *App {
	t.Helper()
	return &App{
		Config: &config.Config{
			Web: config.WebConfig{
				Users:         []config.WebUser{{ID: "u1", Username: "admin", Password: "secret123", Role: "admin"}},
				SessionSecret: "0123456789abcdef0123456789abcdef",
			},
		},
	}
}

// TestSessionCookieRoundTrip verifies the full login persistence flow: Basic
// login sets a signed cookie, and a subsequent request carrying only that
// cookie (as a page reload would) is authorized.
func TestSessionCookieRoundTrip(t *testing.T) {
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
	a := testApp(t)
	a.Config.Web.Users[0].Username = "john.doe"
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

// TestLogoutClearsSessionCookie verifies POST /api/logout expires the session
// cookie so the browser drops it.
func TestLogoutClearsSessionCookie(t *testing.T) {
	t.Parallel()
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

// testAppWithViewer returns an App with one admin and one viewer user.
func testAppWithViewer(t *testing.T) *App {
	t.Helper()
	a := testApp(t)
	a.Config.Web.Users = append(a.Config.Web.Users, config.WebUser{ID: "u2", Username: "readonly", Password: "viewpass", Role: "viewer"})
	return a
}

// TestAuthorizeViewerAllowsGet verifies a viewer-role user can read via Basic
// auth, mirroring the equivalent read-only-APIToken test.
func TestAuthorizeViewerAllowsGet(t *testing.T) {
	t.Parallel()
	a := testAppWithViewer(t)
	req := httptest.NewRequest(http.MethodGet, "/api/status", nil)
	req.SetBasicAuth("readonly", "viewpass")
	rr := httptest.NewRecorder()
	if !a.authorize(rr, req) {
		t.Fatalf("viewer login should authorize a GET, got status %d", rr.Code)
	}
}

// TestAuthorizeViewerRejectsWrite verifies a viewer-role user is refused any
// non-GET/HEAD request with 403, exactly like a read-only APIToken.
func TestAuthorizeViewerRejectsWrite(t *testing.T) {
	t.Parallel()
	a := testAppWithViewer(t)
	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch} {
		req := httptest.NewRequest(method, "/api/config", nil)
		req.SetBasicAuth("readonly", "viewpass")
		rr := httptest.NewRecorder()
		if a.authorize(rr, req) {
			t.Fatalf("viewer login should not authorize %s", method)
		}
		if rr.Code != http.StatusForbidden {
			t.Errorf("%s as viewer: status = %d, want %d", method, rr.Code, http.StatusForbidden)
		}
	}
}

// TestAuthorizeViewerSessionCookieRejectsWrite verifies the same restriction
// applies to a session cookie (not just Basic auth), and that a viewer's
// existing session cookie still authorizes reads.
func TestAuthorizeViewerSessionCookieRejectsWrite(t *testing.T) {
	t.Parallel()
	a := testAppWithViewer(t)
	sessValue := validCookie(t, a, "readonly")

	getReq := httptest.NewRequest(http.MethodGet, "/api/status", nil)
	getReq.AddCookie(&http.Cookie{Name: sessionCookie, Value: sessValue})
	if !a.authorize(httptest.NewRecorder(), getReq) {
		t.Fatal("viewer session cookie should authorize a GET")
	}

	postReq := httptest.NewRequest(http.MethodPost, "/api/config", nil)
	postReq.AddCookie(&http.Cookie{Name: sessionCookie, Value: sessValue})
	rr := httptest.NewRecorder()
	if a.authorize(rr, postReq) {
		t.Fatal("viewer session cookie should not authorize a POST")
	}
	if rr.Code != http.StatusForbidden {
		t.Errorf("viewer POST via session cookie: status = %d, want %d", rr.Code, http.StatusForbidden)
	}
}

// TestAuthorizeRoleChangeTakesEffectImmediately verifies that a role change
// (or removal) is reflected on the very next request without needing to
// reissue the session cookie — validSession looks up the user fresh each
// time rather than trusting a role baked into the cookie payload.
func TestAuthorizeRoleChangeTakesEffectImmediately(t *testing.T) {
	t.Parallel()
	a := testApp(t)
	sessValue := validCookie(t, a, "admin")

	postReq := httptest.NewRequest(http.MethodPost, "/api/config", nil)
	postReq.AddCookie(&http.Cookie{Name: sessionCookie, Value: sessValue})
	if !a.authorize(httptest.NewRecorder(), postReq) {
		t.Fatal("admin session should authorize a POST before demotion")
	}

	// Demote the same account to viewer — no new login, same cookie.
	a.Config.Web.Users[0].Role = "viewer"
	postReq2 := httptest.NewRequest(http.MethodPost, "/api/config", nil)
	postReq2.AddCookie(&http.Cookie{Name: sessionCookie, Value: sessValue})
	rr := httptest.NewRecorder()
	if a.authorize(rr, postReq2) {
		t.Fatal("demoted account's existing session should no longer authorize a POST")
	}
	if rr.Code != http.StatusForbidden {
		t.Errorf("demoted-account POST: status = %d, want %d", rr.Code, http.StatusForbidden)
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
