package api

import (
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
