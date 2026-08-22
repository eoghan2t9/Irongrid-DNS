package api

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/andybalholm/brotli"

	"github.com/eoghan2t9/Irongrid-DNS/internal/config"
	"github.com/eoghan2t9/Irongrid-DNS/internal/tunnel"
	"github.com/eoghan2t9/Irongrid-DNS/internal/version"
)

func TestStatusIncludesMachineReadableVersion(t *testing.T) {
	h := &Handler{
		Cfg:       &config.Config{},
		Tunnel:    &tunnel.Manager{},
		StartedAt: time.Now(),
	}
	rr := httptest.NewRecorder()
	h.getStatus(rr)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	var body struct {
		Version    string `json:"version"`
		VersionTag string `json:"version_tag"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode status: %v", err)
	}
	if body.VersionTag != version.Version {
		t.Fatalf("version_tag = %q, want %q", body.VersionTag, version.Version)
	}
	if body.Version == "" {
		t.Fatal("human-readable version is empty")
	}
}

// TestPprofDisabledByDefault verifies /debug/pprof/ isn't registered at all
// when server.debug_pprof is left at its zero-value default: an
// unauthenticated request must fall through to the SPA catch-all (200, the
// same as any other unknown path) rather than hit pprof's own auth check
// (401) — 401 here would mean the route exists and just happens to reject
// this particular request, not that it's absent.
func TestPprofDisabledByDefault(t *testing.T) {
	a := testApp(t)
	router := NewRouter(a)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/debug/pprof/", nil))
	if rr.Code == http.StatusUnauthorized {
		t.Fatal("pprof route responded 401 while disabled — it must not be registered at all")
	}
	if strings.Contains(rr.Body.String(), "Types of profiles available") {
		t.Fatal("pprof index content served while disabled")
	}
}

// TestPprofRequiresAuth verifies that once enabled, every pprof endpoint
// still sits behind the same auth as the REST API — an unauthenticated
// request must never see profiling data.
func TestPprofRequiresAuth(t *testing.T) {
	a := testApp(t)
	a.Config.Server.DebugPprof = true
	router := NewRouter(a)

	for _, path := range []string{"/debug/pprof/", "/debug/pprof/cmdline", "/debug/pprof/profile?seconds=0", "/debug/pprof/symbol", "/debug/pprof/heap"} {
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, path, nil))
		if rr.Code != http.StatusUnauthorized {
			t.Errorf("%s: status = %d, want 401 without credentials", path, rr.Code)
		}
	}
}

// TestPprofServesWhenAuthorized verifies an authenticated request to the
// pprof index actually reaches the handler (not just "not 401").
func TestPprofServesWhenAuthorized(t *testing.T) {
	a := testApp(t)
	a.Config.Server.DebugPprof = true
	router := NewRouter(a)

	req := httptest.NewRequest(http.MethodGet, "/debug/pprof/", nil)
	req.SetBasicAuth("admin", "secret123")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 for an authorized pprof index request", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "pprof") {
		t.Fatalf("body doesn't look like the pprof index: %q", rr.Body.String())
	}
}

// TestServeFromFSContentType guards the SPA fallback: refreshing a client-side
// route like /blocklists hits the server directly, which falls back to serving
// index.html. The fallback must be served as text/html — serving it as
// application/octet-stream makes browsers download the page as a file instead
// of rendering it (regression test for the "refresh downloads a file" bug).
// TestServeFromFSAssetCachingAndGzip verifies the loading-speed behaviour of
// static serving: hashed /assets/* files are immutable-cached (repeat loads
// hit the browser cache), the HTML shell stays no-cache so new builds are
// picked up, and compressible assets are served with the best encoding the
// client accepts — Brotli when offered, otherwise gzip, else raw.
func TestServeFromFSAssetCachingAndGzip(t *testing.T) {
	big := strings.Repeat("const data = 'x'; ", 200) // > compressThreshold bytes
	root := fstest.MapFS{
		"index.html":         &fstest.MapFile{Data: []byte("<html>dashboard</html>")},
		"assets/app-hash.js": &fstest.MapFile{Data: []byte(big)},
	}

	// The HTML shell: no-cache, never compressed, Vary advertised.
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Accept-Encoding", "gzip")
	serveFromFS(rr, req, root)
	if cc := rr.Header().Get("Cache-Control"); cc != "no-cache" {
		t.Errorf("index Cache-Control = %q, want no-cache", cc)
	}
	if ce := rr.Header().Get("Content-Encoding"); ce != "" {
		t.Errorf("index Content-Encoding = %q, want none", ce)
	}
	if v := rr.Header().Get("Vary"); v != "Accept-Encoding" {
		t.Errorf("index Vary = %q, want Accept-Encoding", v)
	}

	// A hashed asset with gzip accepted: immutable cache + gzipped body that
	// round-trips to the original.
	rr2 := httptest.NewRecorder()
	req2 := httptest.NewRequest(http.MethodGet, "/assets/app-hash.js", nil)
	req2.Header.Set("Accept-Encoding", "gzip")
	serveFromFS(rr2, req2, root)
	if cc := rr2.Header().Get("Cache-Control"); cc != "public, max-age=31536000, immutable" {
		t.Errorf("asset Cache-Control = %q, want immutable", cc)
	}
	if ce := rr2.Header().Get("Content-Encoding"); ce != "gzip" {
		t.Fatalf("asset Content-Encoding = %q, want gzip", ce)
	}
	zr, err := gzip.NewReader(bytes.NewReader(rr2.Body.Bytes()))
	if err != nil {
		t.Fatalf("gzip reader: %v", err)
	}
	uncompressed, err := io.ReadAll(zr)
	if err != nil {
		t.Fatalf("gunzip: %v", err)
	}
	if string(uncompressed) != big {
		t.Fatal("gzipped asset must round-trip to the original content")
	}

	// The same asset with brotli offered alongside gzip: br wins (the browser
	// would pick it too), decodes back to the original, and beats gzip's size
	// on real text.
	rrB := httptest.NewRecorder()
	reqB := httptest.NewRequest(http.MethodGet, "/assets/app-hash.js", nil)
	reqB.Header.Set("Accept-Encoding", "br, gzip")
	serveFromFS(rrB, reqB, root)
	if ce := rrB.Header().Get("Content-Encoding"); ce != "br" {
		t.Fatalf("asset with br+gzip: Content-Encoding = %q, want br (preferred)", ce)
	}
	ub, err := io.ReadAll(brotli.NewReader(bytes.NewReader(rrB.Body.Bytes())))
	if err != nil {
		t.Fatalf("brotli decode: %v", err)
	}
	if string(ub) != big {
		t.Fatal("brotli asset must round-trip to the original content")
	}
	if rrB.Body.Len() >= rr2.Body.Len() {
		t.Errorf("brotli size %d not smaller than gzip size %d", rrB.Body.Len(), rr2.Body.Len())
	}

	// Without Accept-Encoding the same asset is served raw.
	rr3 := httptest.NewRecorder()
	serveFromFS(rr3, httptest.NewRequest(http.MethodGet, "/assets/app-hash.js", nil), root)
	if ce := rr3.Header().Get("Content-Encoding"); ce != "" {
		t.Errorf("asset without accept-encoding: Content-Encoding = %q, want none", ce)
	}
	if rr3.Body.String() != big {
		t.Fatal("uncompressed asset must match the original bytes")
	}
}

func TestServeFromFSContentType(t *testing.T) {
	root := fstest.MapFS{
		"index.html":    &fstest.MapFile{Data: []byte("<html>dashboard</html>")},
		"assets/app.js": &fstest.MapFile{Data: []byte("console.log('hi')")},
		// A real extensionless file must NOT be forced to text/html — only the
		// SPA fallback is. It keeps the fix from being over-broad.
		"LICENSE": &fstest.MapFile{Data: []byte("MIT")},
	}
	// Any unknown path is itself an SPA route and falls back to index.html, so
	// the 404 path only triggers when index.html is missing entirely.
	noIndex := fstest.MapFS{}

	cases := []struct {
		name     string
		path     string
		root     fs.FS
		wantType string
		wantBody string
		wantCode int
	}{
		{name: "root", path: "/", root: root, wantType: "text/html; charset=utf-8", wantBody: "<html>dashboard</html>", wantCode: http.StatusOK},
		{name: "spa route fallback", path: "/blocklists", root: root, wantType: "text/html; charset=utf-8", wantBody: "<html>dashboard</html>", wantCode: http.StatusOK},
		{name: "real asset", path: "/assets/app.js", root: root, wantType: "text/javascript", wantBody: "console.log('hi')", wantCode: http.StatusOK},
		{name: "extensionless real file", path: "/LICENSE", root: root, wantType: "application/octet-stream", wantBody: "MIT", wantCode: http.StatusOK},
		{name: "no index", path: "/anything", root: noIndex, wantCode: http.StatusNotFound},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rr := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, tc.path, nil)
			serveFromFS(rr, req, tc.root)

			if rr.Code != tc.wantCode {
				t.Fatalf("status = %d, want %d", rr.Code, tc.wantCode)
			}
			if tc.wantCode != http.StatusOK {
				return
			}
			ct := rr.Header().Get("Content-Type")
			if !strings.HasPrefix(ct, tc.wantType) {
				t.Errorf("Content-Type = %q, want prefix %q", ct, tc.wantType)
			}
			if body := rr.Body.String(); body != tc.wantBody {
				t.Errorf("body = %q, want %q", body, tc.wantBody)
			}
		})
	}
}
