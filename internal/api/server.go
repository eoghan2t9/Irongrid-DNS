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
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/eoghan2t9/Irongrid-DNS/internal/config"
)

// App bundles every dependency the API exposes.
type App struct {
	Config *config.Config
	// Set by main: live components.
	Handler     APIHandler
	WebFS       fs.FS // embedded frontend build
	ConfigPath  string
	SaveConfig  func() error
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

// authorize allows requests carrying a valid signed session cookie (login
// persists across reloads) or valid HTTP Basic credentials. A successful
// Basic login also issues the session cookie for the next request.
func (a *App) authorize(w http.ResponseWriter, r *http.Request) bool {
	if a.validSession(r) {
		return true
	}
	user, pass, ok := r.BasicAuth()
	cfg := a.Config
	if ok && user == cfg.Web.Username && passwordMatches(pass, cfg.Web.Password) {
		a.issueSession(w, user)
		return true
	}
	w.Header().Set("WWW-Authenticate", `Basic realm="Irongrid DNS"`)
	http.Error(w, "unauthorized", http.StatusUnauthorized)
	return false
}

// issueSession sets a signed, HttpOnly login cookie valid for sessionLifetime.
// The payload ("user.exp") is base64url-encoded so usernames containing dots
// can't break the "payload.sig" split.
func (a *App) issueSession(w http.ResponseWriter, user string) {
	secret := a.Config.Web.SessionSecret
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
		Secure: a.Config.Server.WebTLS,
		MaxAge: int(sessionLifetime.Seconds()),
	})
}

// validSession reports whether the request carries a valid, unexpired login
// cookie for the configured user.
func (a *App) validSession(r *http.Request) bool {
	c, err := r.Cookie(sessionCookie)
	if err != nil {
		return false
	}
	secret := a.Config.Web.SessionSecret
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
	return user == a.Config.Web.Username
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
	data, err := fs.ReadFile(root, path)
	if err != nil {
		// SPA fallback: unknown path (and the root) -> index.html.
		data, err = fs.ReadFile(root, "index.html")
	}
	if err != nil {
		http.NotFound(w, r)
		return
	}
	ct := mime.TypeByExtension(filepath.Ext(path))
	if path == "" || path == "index.html" {
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
