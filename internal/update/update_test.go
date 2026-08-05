package update

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestParseSemver(t *testing.T) {
	cases := []struct {
		in  string
		ok  bool
		maj int
		min int
		pat int
		pre string
	}{
		{"v1.2.3", true, 1, 2, 3, ""},
		{"1.2.3", true, 1, 2, 3, ""},
		{"v1.0.1", true, 1, 0, 1, ""},
		{"v1.1.0-rc.1", true, 1, 1, 0, "rc.1"},
		{"v0.1.0+build.5", true, 0, 1, 0, ""},
		{"dev", false, 0, 0, 0, ""},
		{"v1.2", false, 0, 0, 0, ""},
		{"", false, 0, 0, 0, ""},
	}
	for _, c := range cases {
		v, err := parseSemver(c.in)
		if c.ok != (err == nil) {
			t.Errorf("parseSemver(%q) ok=%v err=%v", c.in, c.ok, err)
			continue
		}
		if err != nil {
			continue
		}
		if v.major != c.maj || v.minor != c.min || v.patch != c.pat || v.pre != c.pre {
			t.Errorf("parseSemver(%q) = %+v", c.in, v)
		}
	}
}

func TestNewer(t *testing.T) {
	cases := []struct {
		latest, current string
		want            bool
	}{
		{"v1.0.1", "v1.0.0", true},
		{"v1.0.1", "v1.0.1", false},
		{"v1.0.0", "v1.0.1", false},
		{"v1.1.0", "v1.0.9", true},
		{"v2.0.0", "v1.99.99", true},
		{"v0.2.0", "v0.2.0", false},
		{"1.0.2", "v1.0.1", true},        // mixed prefix
		{"v1.1.0-rc.1", "v1.1.0", false}, // pre-release is not newer than its release
		{"v1.1.0", "v1.1.0-rc.1", true},  // release beats pre-release
		{"v1.1.0-rc.2", "v1.1.0-rc.1", true},
		{"v1.0.0", "dev", true}, // fallback: unparseable current
		{"v1.0.0", "v1.0.0", false},
	}
	for _, c := range cases {
		if got := Newer(c.latest, c.current); got != c.want {
			t.Errorf("Newer(%q, %q) = %v, want %v", c.latest, c.current, got, c.want)
		}
	}
}

func TestAssetName(t *testing.T) {
	cases := []struct {
		goos, goarch, want string
	}{
		{"linux", "amd64", "irongrid-linux-amd64"},
		{"linux", "arm64", "irongrid-linux-arm64"},
		{"darwin", "arm64", "irongrid-darwin-arm64"},
		{"windows", "amd64", "irongrid-windows-amd64.exe"},
	}
	for _, c := range cases {
		if got := assetName(c.goos, c.goarch); got != c.want {
			t.Errorf("assetName(%q, %q) = %q, want %q", c.goos, c.goarch, got, c.want)
		}
	}
}

func fakeRelease(t *testing.T, body string, status int) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		w.Write([]byte(body))
	}))
}

const releaseJSON = `{
  "tag_name": "v1.0.1",
  "published_at": "2026-08-04T10:00:00Z",
  "html_url": "https://github.com/eoghan2t9/Irongrid-DNS/releases/tag/v1.0.1",
  "body": "## What's Changed\n- fix: a bug",
  "assets": [
    {"name": "irongrid-linux-amd64", "browser_download_url": "https://example.com/irongrid-linux-amd64", "size": 42},
    {"name": "irongrid-windows-arm64.exe", "browser_download_url": "https://example.com/irongrid-windows-arm64.exe", "size": 43}
  ]
}`

func TestCheckFindsUpdate(t *testing.T) {
	srv := fakeRelease(t, releaseJSON, http.StatusOK)
	defer srv.Close()
	c := &Client{HTTPClient: srv.Client(), Current: "v1.0.0", latestURL: srv.URL}

	info := c.Check(context.Background())
	if info.Error != "" {
		t.Fatalf("unexpected error: %s", info.Error)
	}
	if !info.Available {
		t.Fatal("expected update to be available")
	}
	if info.LatestVersion != "v1.0.1" {
		t.Errorf("LatestVersion = %q", info.LatestVersion)
	}
	if info.Changelog == "" || info.ReleaseURL == "" {
		t.Errorf("changelog/release_url missing: %+v", info)
	}
	if info.DownloadURL == "" || info.AssetName == "" {
		t.Errorf("expected a matching asset for this platform: %+v", info)
	}
}

func TestCheckUpToDate(t *testing.T) {
	srv := fakeRelease(t, releaseJSON, http.StatusOK)
	defer srv.Close()
	c := &Client{HTTPClient: srv.Client(), Current: "v1.0.1", latestURL: srv.URL}

	info := c.Check(context.Background())
	if info.Available {
		t.Fatal("expected no update when current == latest")
	}
}

const releasesJSON = `[
  {"tag_name":"v1.1.0","name":"Irongrid DNS v1.1.0","published_at":"2026-08-05T10:00:00Z","html_url":"https://github.com/eoghan2t9/Irongrid-DNS/releases/tag/v1.1.0","body":"## What's Changed\n- feat: wizard handles the install","prerelease":false},
  {"tag_name":"v1.1.0-rc.1","name":"v1.1.0-rc.1","published_at":"2026-08-04T10:00:00Z","html_url":"https://github.com/eoghan2t9/Irongrid-DNS/releases/tag/v1.1.0-rc.1","body":"rc notes","prerelease":true},
  {"tag_name":"v1.0.2","name":"Irongrid DNS v1.0.2","published_at":"2026-08-03T10:00:00Z","html_url":"https://github.com/eoghan2t9/Irongrid-DNS/releases/tag/v1.0.2","body":"## What's Changed\n- fix: ci pipeline","prerelease":false}
]`

func TestListFiltersPrereleases(t *testing.T) {
	srv := fakeRelease(t, releasesJSON, http.StatusOK)
	defer srv.Close()
	c := &Client{HTTPClient: srv.Client(), listURL: srv.URL}

	rels, err := c.List(context.Background())
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(rels) != 2 {
		t.Fatalf("List returned %d releases, want 2 (prerelease filtered): %+v", len(rels), rels)
	}
	if rels[0].TagName != "v1.1.0" || rels[1].TagName != "v1.0.2" {
		t.Errorf("unexpected releases/order: %+v", rels)
	}
	if rels[0].Name == "" || rels[0].HTMLURL == "" || rels[0].Body == "" {
		t.Errorf("release fields missing: %+v", rels[0])
	}
}

func TestListHTTPError(t *testing.T) {
	srv := fakeRelease(t, `{"message":"rate limited"}`, http.StatusForbidden)
	defer srv.Close()
	c := &Client{HTTPClient: srv.Client(), listURL: srv.URL}
	if _, err := c.List(context.Background()); err == nil {
		t.Fatal("expected error on non-200 response")
	}
}

func TestCheckHTTPError(t *testing.T) {
	srv := fakeRelease(t, `{"message":"rate limited"}`, http.StatusForbidden)
	defer srv.Close()
	c := &Client{HTTPClient: srv.Client(), Current: "v1.0.0", latestURL: srv.URL}

	info := c.Check(context.Background())
	if info.Error == "" {
		t.Fatal("expected an error to be reported")
	}
	if info.Available {
		t.Fatal("must not report an update when the check failed")
	}
}

// installTestServer serves a fake "v9.9.9" release with a platform binary
// asset and a matching SHA256SUMS.txt.
func installTestServer(t *testing.T, bin []byte, goodSum bool) *httptest.Server {
	t.Helper()
	name := assetName(runtime.GOOS, runtime.GOARCH)
	sum := sha256.Sum256(bin)
	want := hex.EncodeToString(sum[:])
	if !goodSum {
		want = strings.Repeat("0", 64)
	}
	var srv *httptest.Server
	mux := http.NewServeMux()
	mux.HandleFunc("/release", func(w http.ResponseWriter, r *http.Request) {
		body := fmt.Sprintf(`{
		  "tag_name":"v9.9.9",
		  "published_at":"2026-08-06T10:00:00Z",
		  "html_url":"https://example.com/r/9",
		  "body":"n",
		  "assets":[
		    {"name":%q,"browser_download_url":%q,"size":%d},
		    {"name":"SHA256SUMS.txt","browser_download_url":%q,"size":100}
		  ]}`, name, srv.URL+"/binary", len(bin), srv.URL+"/sums")
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(body))
	})
	mux.HandleFunc("/binary", func(w http.ResponseWriter, r *http.Request) { w.Write(bin) })
	mux.HandleFunc("/sums", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "%s  %s\n", want, name)
	})
	srv = httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func TestInstall(t *testing.T) {
	bin := []byte("#!/bin/sh\necho fake binary v9.9.9\n")
	srv := installTestServer(t, bin, true)

	dir := t.TempDir()
	execPath := filepath.Join(dir, "irongrid")
	if err := os.WriteFile(execPath, []byte("old binary"), 0o755); err != nil {
		t.Fatal(err)
	}

	c := &Client{HTTPClient: srv.Client(), Current: "v1.0.0", latestURL: srv.URL + "/release"}
	res, err := c.Install(context.Background(), execPath)
	if err != nil {
		t.Fatalf("Install: %v", err)
	}
	if res.NewVersion != "v9.9.9" || res.PreviousVersion != "v1.0.0" {
		t.Errorf("unexpected result: %+v", res)
	}
	if res.InstalledTo != execPath {
		t.Errorf("InstalledTo = %q", res.InstalledTo)
	}
	got, err := os.ReadFile(execPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, bin) {
		t.Error("binary was not replaced with the downloaded asset")
	}
	// Rollback copy must be preserved and temp files cleaned up.
	if _, err := os.Stat(execPath + ".prev"); err != nil {
		t.Errorf("expected .prev backup: %v", err)
	}
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".irongrid-update-") {
			t.Errorf("temp file not cleaned up: %s", e.Name())
		}
	}
}

func TestInstallChecksumMismatch(t *testing.T) {
	bin := []byte("new binary")
	srv := installTestServer(t, bin, false) // wrong checksum served

	dir := t.TempDir()
	execPath := filepath.Join(dir, "irongrid")
	if err := os.WriteFile(execPath, []byte("old binary"), 0o755); err != nil {
		t.Fatal(err)
	}

	c := &Client{HTTPClient: srv.Client(), Current: "v1.0.0", latestURL: srv.URL + "/release"}
	if _, err := c.Install(context.Background(), execPath); err == nil || !strings.Contains(err.Error(), "checksum mismatch") {
		t.Fatalf("expected checksum mismatch, got %v", err)
	}
	// The old binary must be untouched.
	got, _ := os.ReadFile(execPath)
	if string(got) != "old binary" {
		t.Error("binary changed despite failed checksum")
	}
}

func TestInstallUpToDate(t *testing.T) {
	bin := []byte("new binary")
	srv := installTestServer(t, bin, true)
	c := &Client{HTTPClient: srv.Client(), Current: "v9.9.9", latestURL: srv.URL + "/release"}
	if _, err := c.Install(context.Background(), filepath.Join(t.TempDir(), "irongrid")); err == nil {
		t.Fatal("expected an error when already up to date")
	}
}

func TestInfoJSONShape(t *testing.T) {
	// The frontend consumes these exact keys; lock the shape down.
	raw, err := json.Marshal(Info{CurrentVersion: "v1.0.0", LatestVersion: "v1.0.1", Available: true})
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"current_version", "latest_version", "available"} {
		if _, ok := m[k]; !ok {
			t.Errorf("Info JSON missing key %q", k)
		}
	}
	if _, ok := m["error"]; ok {
		t.Error("Info JSON should omit empty error (omitempty)")
	}
	// When an error is set, it must be serialised.
	rawErr, err := json.Marshal(Info{Error: "offline"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(rawErr), "\"error\":\"offline\"") {
		t.Errorf("Info JSON missing error field: %s", rawErr)
	}
}
