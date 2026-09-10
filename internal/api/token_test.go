package api

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/eoghan2t9/Irongrid-DNS/internal/config"
)

func hashTokenForTest(plain string) string {
	sum := sha256.Sum256([]byte(plain))
	return hex.EncodeToString(sum[:])
}

func TestTokenMatches(t *testing.T) {
	hashed := hashTokenForTest("s3cr3t-token")
	tests := []struct {
		name      string
		presented string
		stored    string
		want      bool
	}{
		{"matches hashed form", "s3cr3t-token", hashed, true},
		{"wrong token against hashed form", "wrong", hashed, false},
		{"matches plaintext form", "plain-token", "plain-token", true},
		{"wrong token against plaintext form", "wrong", "plain-token", false},
		{"empty stored never matches", "anything", "", false},
		{"empty presented never matches", "", hashed, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tokenMatches(tt.presented, tt.stored); got != tt.want {
				t.Errorf("tokenMatches(%q, %q) = %v, want %v", tt.presented, tt.stored, got, tt.want)
			}
		})
	}
}

func testAppWithTokens(t *testing.T) *App {
	t.Helper()
	a := testApp(t)
	a.Config.Web.Tokens = []config.APIToken{
		{Name: "admin-integration", Token: hashTokenForTest("admin-tok"), ReadOnly: false},
		{Name: "read-only-integration", Token: hashTokenForTest("ro-tok"), ReadOnly: true},
	}
	return a
}

func TestAuthorizeAcceptsAdminToken(t *testing.T) {
	t.Parallel()
	a := testAppWithTokens(t)
	req := httptest.NewRequest(http.MethodPost, "/api/config", nil)
	req.Header.Set("Authorization", "Bearer admin-tok")
	rr := httptest.NewRecorder()
	if !a.authorize(rr, req) {
		t.Fatalf("admin token should authorize a POST, got status %d", rr.Code)
	}
}

func TestAuthorizeReadOnlyTokenAllowsGet(t *testing.T) {
	t.Parallel()
	a := testAppWithTokens(t)
	req := httptest.NewRequest(http.MethodGet, "/api/status", nil)
	req.Header.Set("Authorization", "Bearer ro-tok")
	rr := httptest.NewRecorder()
	if !a.authorize(rr, req) {
		t.Fatalf("read-only token should authorize a GET, got status %d", rr.Code)
	}
}

func TestAuthorizeReadOnlyTokenRejectsWrite(t *testing.T) {
	t.Parallel()
	a := testAppWithTokens(t)
	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch} {
		req := httptest.NewRequest(method, "/api/config", nil)
		req.Header.Set("Authorization", "Bearer ro-tok")
		rr := httptest.NewRecorder()
		if a.authorize(rr, req) {
			t.Fatalf("read-only token should not authorize %s", method)
		}
		if rr.Code != http.StatusForbidden {
			t.Errorf("%s with read-only token: status = %d, want %d", method, rr.Code, http.StatusForbidden)
		}
	}
}

func TestAuthorizeRejectsUnknownToken(t *testing.T) {
	t.Parallel()
	a := testAppWithTokens(t)
	req := httptest.NewRequest(http.MethodGet, "/api/status", nil)
	req.Header.Set("Authorization", "Bearer not-a-real-token")
	rr := httptest.NewRecorder()
	if a.authorize(rr, req) {
		t.Fatal("unknown token must not authorize")
	}
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusUnauthorized)
	}
}

func TestAuthorizeTokenFailureDoesNotTriggerLoginLockout(t *testing.T) {
	t.Parallel()
	a := testAppWithTokens(t)
	for range loginMaxFailures * 2 {
		req := httptest.NewRequest(http.MethodGet, "/api/status", nil)
		req.RemoteAddr = "203.0.113.70:1111"
		req.Header.Set("Authorization", "Bearer wrong-token")
		rr := httptest.NewRecorder()
		a.authorize(rr, req)
	}
	if locked, _ := a.loginGuard.Locked("203.0.113.70"); locked {
		t.Fatal("a wrong bearer token must never trigger the Basic-auth login lockout")
	}
}
