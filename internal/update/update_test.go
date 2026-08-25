package update

import (
	"bytes"
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
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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

func TestV3AssetName(t *testing.T) {
	t.Parallel()
	cases := []struct {
		goos, goarch, want string
	}{
		{"linux", "amd64", "irongrid-linux-amd64-v3"},
		{"darwin", "amd64", "irongrid-darwin-amd64-v3"},
		{"windows", "amd64", "irongrid-windows-amd64-v3.exe"},
	}
	for _, c := range cases {
		if got := v3AssetName(c.goos, c.goarch); got != c.want {
			t.Errorf("v3AssetName(%q, %q) = %q, want %q", c.goos, c.goarch, got, c.want)
		}
	}
}

// withSupportsGOAMD64V3 temporarily overrides the package-level CPU-support
// var and restores it on cleanup, so tests don't depend on the actual CI
// runner's CPU.
func withSupportsGOAMD64V3(t *testing.T, v bool) {
	t.Helper()
	orig := supportsGOAMD64V3
	supportsGOAMD64V3 = func() bool { return v }
	t.Cleanup(func() { supportsGOAMD64V3 = orig })
}

func TestPreferredAssetNames(t *testing.T) {
	withSupportsGOAMD64V3(t, true)
	if got := preferredAssetNames("linux", "amd64"); len(got) != 2 || got[0] != "irongrid-linux-amd64-v3" || got[1] != "irongrid-linux-amd64" {
		t.Errorf("amd64+supported: got %v", got)
	}
	if got := preferredAssetNames("linux", "arm64"); len(got) != 1 || got[0] != "irongrid-linux-arm64" {
		t.Errorf("arm64 must never prefer v3 regardless of CPU support: got %v", got)
	}

	withSupportsGOAMD64V3(t, false)
	if got := preferredAssetNames("linux", "amd64"); len(got) != 1 || got[0] != "irongrid-linux-amd64" {
		t.Errorf("amd64+unsupported: got %v", got)
	}
}

func fakeRelease(t *testing.T, body string, status int) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
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
	t.Parallel()
	srv := fakeRelease(t, releaseJSON, http.StatusOK)
	defer srv.Close()
	c := &Client{HTTPClient: srv.Client(), Current: "v1.0.0", latestURL: srv.URL}

	info := c.Check(t.Context())
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

// v3ReleaseServer serves a fake release JSON offering both the baseline and
// the GOAMD64=v3 asset for the current platform, so it exercises the real
// preference order Check/Install use — meaningful only on amd64 hosts,
// since preferredAssetNames never offers a v3 candidate on any other arch.
func v3ReleaseServer(t *testing.T, includeV3 bool) *httptest.Server {
	t.Helper()
	base := assetName(runtime.GOOS, runtime.GOARCH)
	v3 := v3AssetName(runtime.GOOS, runtime.GOARCH)
	assets := fmt.Sprintf(`{"name":%q,"browser_download_url":"https://example.com/%s","size":1}`, base, base)
	if includeV3 {
		assets += fmt.Sprintf(`,{"name":%q,"browser_download_url":"https://example.com/%s","size":2}`, v3, v3)
	}
	body := fmt.Sprintf(`{"tag_name":"v1.0.1","published_at":"2026-08-04T10:00:00Z","html_url":"https://example.com/r","body":"n","assets":[%s]}`, assets)
	return fakeRelease(t, body, http.StatusOK)
}

func TestCheckPrefersV3AssetWhenSupported(t *testing.T) {
	if runtime.GOARCH != "amd64" {
		t.Skip("v3 preference only applies on amd64")
	}
	srv := v3ReleaseServer(t, true)
	defer srv.Close()

	withSupportsGOAMD64V3(t, true)
	c := &Client{HTTPClient: srv.Client(), Current: "v1.0.0", latestURL: srv.URL}
	info := c.Check(t.Context())
	want := v3AssetName(runtime.GOOS, runtime.GOARCH)
	if info.AssetName != want {
		t.Errorf("AssetName = %q, want %q (v3 preferred)", info.AssetName, want)
	}
}

func TestCheckUsesBaselineWhenCPUDoesNotSupportV3(t *testing.T) {
	if runtime.GOARCH != "amd64" {
		t.Skip("v3 preference only applies on amd64")
	}
	srv := v3ReleaseServer(t, true)
	defer srv.Close()

	withSupportsGOAMD64V3(t, false)
	c := &Client{HTTPClient: srv.Client(), Current: "v1.0.0", latestURL: srv.URL}
	info := c.Check(t.Context())
	want := assetName(runtime.GOOS, runtime.GOARCH)
	if info.AssetName != want {
		t.Errorf("AssetName = %q, want %q (baseline — CPU lacks v3)", info.AssetName, want)
	}
}

func TestCheckFallsBackWhenReleaseHasNoV3Asset(t *testing.T) {
	if runtime.GOARCH != "amd64" {
		t.Skip("v3 preference only applies on amd64")
	}
	srv := v3ReleaseServer(t, false) // pre-18958f3-style release: baseline only
	defer srv.Close()

	withSupportsGOAMD64V3(t, true) // CPU supports v3, but this release has no v3 asset
	c := &Client{HTTPClient: srv.Client(), Current: "v1.0.0", latestURL: srv.URL}
	info := c.Check(t.Context())
	want := assetName(runtime.GOOS, runtime.GOARCH)
	if info.AssetName != want {
		t.Errorf("AssetName = %q, want %q (fall back to baseline, no error)", info.AssetName, want)
	}
	if info.Error != "" {
		t.Errorf("expected no error on graceful fallback, got %q", info.Error)
	}
}

func TestCheckUpToDate(t *testing.T) {
	t.Parallel()
	srv := fakeRelease(t, releaseJSON, http.StatusOK)
	defer srv.Close()
	c := &Client{HTTPClient: srv.Client(), Current: "v1.0.1", latestURL: srv.URL}

	info := c.Check(t.Context())
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
	t.Parallel()
	srv := fakeRelease(t, releasesJSON, http.StatusOK)
	defer srv.Close()
	c := &Client{HTTPClient: srv.Client(), listURL: srv.URL}

	rels, err := c.List(t.Context())
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
	t.Parallel()
	srv := fakeRelease(t, `{"message":"rate limited"}`, http.StatusForbidden)
	defer srv.Close()
	c := &Client{HTTPClient: srv.Client(), listURL: srv.URL}
	if _, err := c.List(t.Context()); err == nil {
		t.Fatal("expected error on non-200 response")
	}
}

func TestCheckHTTPError(t *testing.T) {
	t.Parallel()
	srv := fakeRelease(t, `{"message":"rate limited"}`, http.StatusForbidden)
	defer srv.Close()
	c := &Client{HTTPClient: srv.Client(), Current: "v1.0.0", latestURL: srv.URL}

	info := c.Check(t.Context())
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
		_, _ = w.Write([]byte(body))
	})
	mux.HandleFunc("/binary", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(bin) })
	mux.HandleFunc("/sums", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "%s  %s\n", want, name)
	})
	srv = httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func TestInstall(t *testing.T) {
	t.Parallel()
	bin := []byte("#!/bin/sh\necho fake binary v9.9.9\n")
	srv := installTestServer(t, bin, true)

	dir := t.TempDir()
	execPath := filepath.Join(dir, "irongrid")
	if err := os.WriteFile(execPath, []byte("old binary"), 0o755); err != nil {
		t.Fatal(err)
	}

	c := &Client{HTTPClient: srv.Client(), Current: "v1.0.0", latestURL: srv.URL + "/release"}
	res, err := c.Install(t.Context(), execPath)
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

// installV3TestServer serves a fake "v9.9.9" release offering both the
// baseline and GOAMD64=v3 binaries (each with its own SHA256SUMS.txt line),
// so Install's preference-order search can be exercised end to end.
func installV3TestServer(t *testing.T, baseBin, v3Bin []byte) *httptest.Server {
	t.Helper()
	baseName := assetName(runtime.GOOS, runtime.GOARCH)
	v3Name := v3AssetName(runtime.GOOS, runtime.GOARCH)
	baseSum := sha256.Sum256(baseBin)
	v3Sum := sha256.Sum256(v3Bin)
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
		    {"name":%q,"browser_download_url":%q,"size":%d},
		    {"name":"SHA256SUMS.txt","browser_download_url":%q,"size":100}
		  ]}`, baseName, srv.URL+"/binary", len(baseBin),
			v3Name, srv.URL+"/binary-v3", len(v3Bin), srv.URL+"/sums")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	})
	mux.HandleFunc("/binary", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(baseBin) })
	mux.HandleFunc("/binary-v3", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(v3Bin) })
	mux.HandleFunc("/sums", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "%s  %s\n%s  %s\n", hex.EncodeToString(baseSum[:]), baseName, hex.EncodeToString(v3Sum[:]), v3Name)
	})
	srv = httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func TestInstallPrefersV3Asset(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Install is unsupported on Windows")
	}
	if runtime.GOARCH != "amd64" {
		t.Skip("v3 preference only applies on amd64")
	}
	baseBin := []byte("baseline binary v9.9.9")
	v3Bin := []byte("v3 binary v9.9.9 (longer, different content)")
	srv := installV3TestServer(t, baseBin, v3Bin)

	dir := t.TempDir()
	execPath := filepath.Join(dir, "irongrid")
	if err := os.WriteFile(execPath, []byte("old binary"), 0o755); err != nil {
		t.Fatal(err)
	}

	withSupportsGOAMD64V3(t, true)
	c := &Client{HTTPClient: srv.Client(), Current: "v1.0.0", latestURL: srv.URL + "/release"}
	res, err := c.Install(t.Context(), execPath)
	if err != nil {
		t.Fatalf("Install: %v", err)
	}
	want := v3AssetName(runtime.GOOS, runtime.GOARCH)
	if res.AssetName != want {
		t.Errorf("AssetName = %q, want %q (v3 preferred)", res.AssetName, want)
	}
	got, err := os.ReadFile(execPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, v3Bin) {
		t.Error("installed binary is not the v3 asset's content")
	}
}

// releaseWithoutSums serves a release whose assets lack SHA256SUMS.txt —
// such releases must be refused as unverified.
func releaseWithoutSums(t *testing.T, bin []byte) *httptest.Server {
	t.Helper()
	name := assetName(runtime.GOOS, runtime.GOARCH)
	var srv *httptest.Server
	mux := http.NewServeMux()
	mux.HandleFunc("/release", func(w http.ResponseWriter, r *http.Request) {
		body := fmt.Sprintf(`{"tag_name":"v9.9.9","assets":[{"name":%q,"browser_download_url":%q,"size":%d}]}`,
			name, srv.URL+"/binary", len(bin))
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	})
	mux.HandleFunc("/binary", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(bin) })
	srv = httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func TestInstallRefusesReleaseWithoutChecksums(t *testing.T) {
	t.Parallel()
	bin := []byte("new binary")
	srv := releaseWithoutSums(t, bin)

	dir := t.TempDir()
	execPath := filepath.Join(dir, "irongrid")
	if err := os.WriteFile(execPath, []byte("old binary"), 0o755); err != nil {
		t.Fatal(err)
	}

	c := &Client{HTTPClient: srv.Client(), Current: "v1.0.0", latestURL: srv.URL + "/release"}
	if _, err := c.Install(t.Context(), execPath); err == nil || !strings.Contains(err.Error(), "SHA256SUMS.txt") {
		t.Fatalf("expected refusal for release without checksums, got %v", err)
	}
	// The old binary must be untouched.
	got, _ := os.ReadFile(execPath)
	if string(got) != "old binary" {
		t.Error("binary changed despite failed install")
	}
}

func TestUnitName(t *testing.T) {
	t.Parallel()
	// On a systemd host the cgroup or executable name always yields a
	// *.service; otherwise it falls back to the executable basename, which
	// is never empty for a running test binary.
	name := UnitName()
	if name == "" {
		t.Fatal("UnitName returned empty")
	}
	if !strings.HasSuffix(name, ".service") {
		t.Errorf("UnitName = %q, want a *.service unit name", name)
	}
}

func TestUnitFromCgroupData(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		data string
		want string
		ok   bool
	}{
		// The real /proc/self/cgroup content of a systemd-managed unit that
		// used to panic with "slice bounds out of range [:30] with length 16".
		{"systemd unified", "0::/system.slice/irongrid.service\n", "irongrid.service", true},
		{"nested slice", "0::/user.slice/user-1000.slice/session-1.scope/irongrid.service\n", "irongrid.service", true},
		{"cgroup v1 multi-line", "12:pids:/system.slice/irongrid.service\n11:cpu,cpuacct:/system.slice/irongrid.service\n", "irongrid.service", true},
		{"no service unit", "0::/user.slice/user-1000.slice/session-1.scope\n", "", false},
		{"empty", "", "", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, ok := unitFromCgroupData(c.data)
			if ok != c.ok || got != c.want {
				t.Errorf("unitFromCgroupData(%q) = (%q, %v), want (%q, %v)", c.data, got, ok, c.want, c.ok)
			}
		})
	}
}

func TestInstallChecksumMismatch(t *testing.T) {
	t.Parallel()
	bin := []byte("new binary")
	srv := installTestServer(t, bin, false) // wrong checksum served

	dir := t.TempDir()
	execPath := filepath.Join(dir, "irongrid")
	if err := os.WriteFile(execPath, []byte("old binary"), 0o755); err != nil {
		t.Fatal(err)
	}

	c := &Client{HTTPClient: srv.Client(), Current: "v1.0.0", latestURL: srv.URL + "/release"}
	if _, err := c.Install(t.Context(), execPath); err == nil || !strings.Contains(err.Error(), "checksum mismatch") {
		t.Fatalf("expected checksum mismatch, got %v", err)
	}
	// The old binary must be untouched.
	got, _ := os.ReadFile(execPath)
	if string(got) != "old binary" {
		t.Error("binary changed despite failed checksum")
	}
}

func TestInstallUpToDate(t *testing.T) {
	t.Parallel()
	bin := []byte("new binary")
	srv := installTestServer(t, bin, true)
	c := &Client{HTTPClient: srv.Client(), Current: "v9.9.9", latestURL: srv.URL + "/release"}
	if _, err := c.Install(t.Context(), filepath.Join(t.TempDir(), "irongrid")); err == nil {
		t.Fatal("expected an error when already up to date")
	}
}

func TestInfoJSONShape(t *testing.T) {
	t.Parallel()
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
