// Package api implements the REST API and serves the embedded web UI.
package api

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"log"
	"mime"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/eoghan2t9/Irongrid-DNS/internal/config"
)

// App bundles every dependency the API exposes.
type App struct {
	Config *config.Config
	// Mu, when non-nil, is the same mutex the API Handler uses to guard
	// config mutations (cfgMu). authorize/issueSession/validSession snapshot
	// the auth fields under it so a concurrent config apply — which rotates
	// the session secret in place via *h.Cfg = *cfg — can never be observed
	// as a torn read (e.g. a cookie signed with the new secret validated
	// against the old one).
	Mu *sync.Mutex
	// Set by main: live components.
	Handler    APIHandler
	WebFS      fs.FS // embedded frontend build
	ConfigPath string
	SaveConfig func() error

	// loginGuard throttles failed login attempts; lazily created on first
	// use so callers don't need to wire it up, and preserved across the
	// several NewRouter calls a config/TLS reload triggers over the
	// process's life (re-creating it on every reload would silently clear
	// an active lockout).
	loginGuardOnce sync.Once
	loginGuard     *LoginGuard
}

// APIHandler is implemented by the API to reach into the running services.
type APIHandler interface {
	HandleAPI(w http.ResponseWriter, r *http.Request)
}

//go:embed static/*
var staticFS embed.FS

// NewRouter wires up all routes.
func NewRouter(a *App) http.Handler {
	mux := http.NewServeMux()

	// REST API (JSON).
	mux.HandleFunc("/api/", func(w http.ResponseWriter, r *http.Request) {
		if !a.authorize(w, r) {
			return
		}
		a.Handler.HandleAPI(w, r)
	})

	// Static web UI.
	var webRoot fs.FS
	if a.WebFS != nil {
		webRoot = a.WebFS
	} else if sub, err := fs.Sub(staticFS, "static"); err == nil {
		webRoot = sub
	}
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		serveFromFS(w, r, webRoot)
	})

	return logRequests(mux)
}

// sessionCookie is the signed login cookie. It keeps the dashboard logged in
// across page reloads without the browser needing to resend the password.
const sessionCookie = "irongrid_session"

const sessionLifetime = 30 * 24 * time.Hour

// authSnapshot copies the auth-relevant config fields under the shared mutex
// (when set) so every check in a single request sees one consistent snapshot,
// even while a config apply is rotating the session secret mid-request.
func (a *App) authSnapshot() (username, password, secret string, secure bool) {
	if a.Mu != nil {
		a.Mu.Lock()
		defer a.Mu.Unlock()
	}
	cfg := a.Config
	return cfg.Web.Username, cfg.Web.Password, cfg.Web.SessionSecret, cfg.Server.WebTLS
}

// authorize allows requests carrying a valid signed session cookie (login
// persists across reloads) or valid HTTP Basic credentials. A successful
// Basic login also issues the session cookie for the next request.
func (a *App) authorize(w http.ResponseWriter, r *http.Request) bool {
	username, password, secret, secure := a.authSnapshot()
	if a.validSession(r, username, secret) {
		return true
	}

	a.loginGuardOnce.Do(func() { a.loginGuard = NewLoginGuard() })
	client := clientIPFromRequest(r)
	if locked, remaining := a.loginGuard.Locked(client); locked {
		w.Header().Set("Retry-After", strconv.Itoa(int(remaining.Seconds())+1))
		writeJSON(w, http.StatusTooManyRequests, map[string]string{
			"error": fmt.Sprintf("too many failed login attempts — try again in %d minutes", int(remaining.Minutes())+1),
		})
		return false
	}

	user, pass, ok := r.BasicAuth()
	if ok && user == username && passwordMatches(pass, password) {
		a.loginGuard.RecordSuccess(client)
		a.issueSessionWith(w, user, secret, secure)
		return true
	}
	// Only count requests that actually presented credentials — background
	// polling from a tab whose session expired sends no Authorization
	// header at all and isn't a password guess, so it must not consume the
	// same budget as a real wrong-password attempt.
	if ok {
		a.loginGuard.RecordFailure(client)
	}
	// No WWW-Authenticate header on purpose: the dashboard has its own login
	// form (Basic auth + signed cookie) and never relies on the browser's
	// native prompt. Emitting the header makes some mobile browsers pop their
	// built-in HTTP-auth dialog over the page instead of letting the user use
	// the login form.
	http.Error(w, "unauthorized", http.StatusUnauthorized)
	return false
}

// issueSession sets a signed, HttpOnly login cookie valid for sessionLifetime.
// The payload ("user.exp") is base64url-encoded so usernames containing dots
// can't break the "payload.sig" split.
func (a *App) issueSession(w http.ResponseWriter, user string) {
	_, _, secret, secure := a.authSnapshot()
	a.issueSessionWith(w, user, secret, secure)
}

// issueSessionWith writes the signed cookie using an already-snapshotted
// secret and Secure flag, keeping one request consistent.
func (a *App) issueSessionWith(w http.ResponseWriter, user, secret string, secure bool) {
	if secret == "" {
		return
	}
	exp := time.Now().Add(sessionLifetime).Unix()
	payload := base64.RawURLEncoding.EncodeToString([]byte(fmt.Sprintf("%s.%d", user, exp)))
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(payload))
	val := payload + "." + hex.EncodeToString(mac.Sum(nil))
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    val,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		// Only send over HTTPS when the dashboard runs on TLS.
		Secure: secure,
		MaxAge: int(sessionLifetime.Seconds()),
	})
}

// validSession reports whether the request carries a valid, unexpired login
// cookie for the configured user.
func (a *App) validSession(r *http.Request, username, secret string) bool {
	c, err := r.Cookie(sessionCookie)
	if err != nil {
		return false
	}
	if secret == "" {
		return false
	}
	parts := strings.SplitN(c.Value, ".", 2)
	if len(parts) != 2 {
		return false
	}
	payload, sig := parts[0], parts[1]
	raw, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil {
		return false
	}
	// The payload is "<user>.<exp>"; usernames may themselves contain dots,
	// so split on the last dot (the expiry is always the final field).
	idx := strings.LastIndexByte(string(raw), '.')
	if idx < 0 {
		return false
	}
	user := string(raw[:idx])
	exp, err := strconv.ParseInt(string(raw[idx+1:]), 10, 64)
	if err != nil || time.Now().Unix() > exp {
		return false
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(payload))
	if !hmac.Equal([]byte(sig), []byte(hex.EncodeToString(mac.Sum(nil)))) {
		return false
	}
	return user == username
}

// passwordMatches compares a plaintext password against a stored value that
// is either a bcrypt hash or plaintext (hashed lazily on first save).
func passwordMatches(plain, stored string) bool {
	if stored == "" {
		return false
	}
	if strings.HasPrefix(stored, "$2a$") || strings.HasPrefix(stored, "$2b$") || strings.HasPrefix(stored, "$2y$") {
		return bcrypt.CompareHashAndPassword([]byte(stored), []byte(plain)) == nil
	}
	return subtle.ConstantTimeCompare([]byte(plain), []byte(stored)) == 1
}

func logRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		if strings.HasPrefix(r.URL.Path, "/api/") {
			log.Printf("[api] %s %s (%s)", r.Method, r.URL.Path, time.Since(start).Round(time.Millisecond))
		}
	})
}

// serveFromFS serves static assets, falling back to index.html for SPA routes.
// Files are served directly (no http.FileServer) to avoid its /index.html
// redirect behaviour, which would loop with client-side routing.
func serveFromFS(w http.ResponseWriter, r *http.Request, root fs.FS) {
	path := strings.TrimPrefix(r.URL.Path, "/")
	fallback := false
	data, err := fs.ReadFile(root, path)
	if err != nil {
		// SPA fallback: unknown path (and the root) -> index.html.
		fallback = true
		data, err = fs.ReadFile(root, "index.html")
	}
	if err != nil {
		http.NotFound(w, r)
		return
	}
	ct := mime.TypeByExtension(filepath.Ext(path))
	// The content type must describe the file actually served: when the SPA
	// fallback returned index.html (e.g. a refresh on /blocklists), the URL
	// path has no extension, so the extension-based lookup would yield
	// application/octet-stream and the browser would download the page
	// instead of rendering it.
	if fallback || path == "" || path == "index.html" {
		ct = "text/html; charset=utf-8"
	}
	if ct == "" {
		ct = "application/octet-stream"
	}
	w.Header().Set("Content-Type", ct)
	w.Header().Set("Cache-Control", "no-cache")
	w.Write(data)
}

// writeJSON is a small helper.
func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.Printf("[api] encode error: %v", err)
	}
}
