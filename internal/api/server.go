// Package api implements the REST API and serves the embedded web UI.
package api

import (
	"crypto/subtle"
	"embed"
	"encoding/json"
	"io/fs"
	"log"
	"mime"
	"net/http"
	"path/filepath"
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

// authorize checks HTTP Basic auth against the configured credentials.
func (a *App) authorize(w http.ResponseWriter, r *http.Request) bool {
	user, pass, ok := r.BasicAuth()
	cfg := a.Config
	if ok && user == cfg.Web.Username && passwordMatches(pass, cfg.Web.Password) {
		return true
	}
	w.Header().Set("WWW-Authenticate", `Basic realm="Irongrid DNS"`)
	http.Error(w, "unauthorized", http.StatusUnauthorized)
	return false
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
