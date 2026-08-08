package api

import (
	"bytes"
	"compress/gzip"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"
)

// TestServeFromFSContentType guards the SPA fallback: refreshing a client-side
// route like /blocklists hits the server directly, which falls back to serving
// index.html. The fallback must be served as text/html — serving it as
// application/octet-stream makes browsers download the page as a file instead
// of rendering it (regression test for the "refresh downloads a file" bug).
// TestServeFromFSAssetCachingAndGzip verifies the loading-speed behaviour of
// static serving: hashed /assets/* files are immutable-cached (repeat loads
// hit the browser cache), the HTML shell stays no-cache so new builds are
// picked up, and compressible assets are gzipped when the client asks for it.
func TestServeFromFSAssetCachingAndGzip(t *testing.T) {
	big := strings.Repeat("const data = 'x'; ", 200) // > gzipThreshold bytes
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
