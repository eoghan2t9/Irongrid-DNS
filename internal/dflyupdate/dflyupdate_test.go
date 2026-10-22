package dflyupdate

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// fakeBinary is a shell script standing in for the dragonfly binary: it prints
// the same coloured "dragonfly vX.Y.Z-<commit>" line the real one does.
func fakeBinary(ver string) string {
	return "#!/bin/sh\nprintf 'dragonfly \\033[0;32m" + ver + "-abc123\\033[m\\n'\n"
}

// releaseTarball packs script as the arch-named dragonfly binary plus a
// LICENSE, like the real release asset.
func releaseTarball(t *testing.T, script string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, f := range []struct {
		name string
		body string
		mode int64
	}{
		{"dragonfly-" + archName(runtime.GOARCH), script, 0o755},
		{"LICENSE.md", "license", 0o644},
	} {
		if err := tw.WriteHeader(&tar.Header{Name: f.name, Mode: f.mode, Size: int64(len(f.body)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(f.body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// releaseServer serves a "latest release" JSON for tag whose asset is tgz,
// advertising digest (pass "" to derive the correct one from tgz).
func releaseServer(t *testing.T, tag string, tgz []byte, digest string) *Client {
	t.Helper()
	if digest == "" {
		sum := sha256.Sum256(tgz)
		digest = "sha256:" + hex.EncodeToString(sum[:])
	}
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	assetName := "dragonfly-" + archName(runtime.GOARCH) + ".tar.gz"
	mux.HandleFunc("/latest", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(release{TagName: tag, Assets: []Asset{{
			Name: assetName, URL: srv.URL + "/asset", Size: int64(len(tgz)), Digest: digest,
		}}})
	})
	mux.HandleFunc("/asset", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(tgz) })
	return &Client{HTTPClient: srv.Client(), latestURL: srv.URL + "/latest"}
}

func installedBinary(t *testing.T, ver string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "dragonfly")
	if err := os.WriteFile(p, []byte(fakeBinary(ver)), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

func skipUnlessLinuxSh(t *testing.T) {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("dragonfly updates are Linux-only")
	}
}

func TestInstalledVersion(t *testing.T) {
	t.Parallel()
	skipUnlessLinuxSh(t)
	if got := InstalledVersion(t.Context(), installedBinary(t, "v1.40.1")); got != "v1.40.1" {
		t.Fatalf("InstalledVersion = %q, want v1.40.1 (ANSI codes and commit suffix stripped)", got)
	}
	if got := InstalledVersion(t.Context(), filepath.Join(t.TempDir(), "missing")); got != "" {
		t.Fatalf("missing binary reported %q, want empty", got)
	}
}

func TestCheck(t *testing.T) {
	t.Parallel()
	skipUnlessLinuxSh(t)
	c := releaseServer(t, "v9.9.9", releaseTarball(t, fakeBinary("v9.9.9")), "")

	info := c.Check(t.Context(), installedBinary(t, "v1.40.1"))
	if !info.Available || info.CurrentVersion != "v1.40.1" || info.LatestVersion != "v9.9.9" {
		t.Fatalf("Check = %+v, want update available v1.40.1 -> v9.9.9", info)
	}
	info = c.Check(t.Context(), installedBinary(t, "v9.9.9"))
	if info.Available {
		t.Fatalf("Check = %+v, want no update when current", info)
	}
}

func TestInstallSwapsBinaryKeepingPrev(t *testing.T) {
	t.Parallel()
	skipUnlessLinuxSh(t)
	c := releaseServer(t, "v9.9.9", releaseTarball(t, fakeBinary("v9.9.9")), "")
	bin := installedBinary(t, "v1.40.1")

	res, err := c.Install(t.Context(), bin)
	if err != nil {
		t.Fatalf("Install: %v", err)
	}
	if !res.Installed || res.PreviousVersion != "v1.40.1" || res.NewVersion != "v9.9.9" {
		t.Fatalf("result = %+v", res)
	}
	if got := InstalledVersion(t.Context(), bin); got != "v9.9.9" {
		t.Fatalf("installed binary reports %q, want v9.9.9", got)
	}
	if got := InstalledVersion(t.Context(), bin+".prev"); got != "v1.40.1" {
		t.Fatalf(".prev reports %q, want v1.40.1 (rollback copy)", got)
	}
	if left, _ := filepath.Glob(filepath.Join(filepath.Dir(bin), ".dragonfly-*")); len(left) != 0 {
		t.Fatalf("temp files left behind: %v", left)
	}
}

func TestInstallNoopWhenCurrent(t *testing.T) {
	t.Parallel()
	skipUnlessLinuxSh(t)
	c := releaseServer(t, "v9.9.9", releaseTarball(t, fakeBinary("v9.9.9")), "")
	bin := installedBinary(t, "v9.9.9")

	res, err := c.Install(t.Context(), bin)
	if err != nil || res.Installed {
		t.Fatalf("Install = %+v, %v; want no-op", res, err)
	}
	if _, err := os.Stat(bin + ".prev"); err == nil {
		t.Fatal("no-op must not create a .prev copy")
	}
}

func TestInstallRefusesBadChecksum(t *testing.T) {
	t.Parallel()
	skipUnlessLinuxSh(t)
	c := releaseServer(t, "v9.9.9", releaseTarball(t, fakeBinary("v9.9.9")), "sha256:"+strings.Repeat("0", 64))
	bin := installedBinary(t, "v1.40.1")

	if _, err := c.Install(t.Context(), bin); err == nil || !strings.Contains(err.Error(), "checksum mismatch") {
		t.Fatalf("Install err = %v, want checksum mismatch", err)
	}
	if got := InstalledVersion(t.Context(), bin); got != "v1.40.1" {
		t.Fatalf("binary changed to %q despite failed verification", got)
	}
}

func TestInstallRefusesMissingDigest(t *testing.T) {
	t.Parallel()
	skipUnlessLinuxSh(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(release{TagName: "v9.9.9", Assets: []Asset{{
			Name: "dragonfly-" + archName(runtime.GOARCH) + ".tar.gz", URL: "http://invalid/asset",
		}}})
	}))
	t.Cleanup(srv.Close)
	c := &Client{HTTPClient: srv.Client(), latestURL: srv.URL}

	if _, err := c.Install(t.Context(), installedBinary(t, "v1.40.1")); err == nil || !strings.Contains(err.Error(), "no digest") {
		t.Fatalf("Install err = %v, want refusal for missing digest", err)
	}
}

func TestInstallRefusesWrongVersionBinary(t *testing.T) {
	t.Parallel()
	skipUnlessLinuxSh(t)
	// The release claims v9.9.9 but the binary inside reports v8.0.0.
	c := releaseServer(t, "v9.9.9", releaseTarball(t, fakeBinary("v8.0.0")), "")
	bin := installedBinary(t, "v1.40.1")

	if _, err := c.Install(t.Context(), bin); err == nil || !strings.Contains(err.Error(), "not installing") {
		t.Fatalf("Install err = %v, want refusal of a mismatched binary", err)
	}
	if got := InstalledVersion(t.Context(), bin); got != "v1.40.1" {
		t.Fatalf("binary changed to %q despite failed sanity check", got)
	}
}

func TestAssetFor(t *testing.T) {
	t.Parallel()
	rel := &release{TagName: "v2.0.2", Assets: []Asset{{Name: "dragonfly-x86_64.tar.gz"}, {Name: "dragonfly-aarch64.tar.gz"}}}
	if a, err := assetFor(rel, "linux", "arm64"); err != nil || a.Name != "dragonfly-aarch64.tar.gz" {
		t.Fatalf("arm64 asset = %+v, %v", a, err)
	}
	if _, err := assetFor(rel, "darwin", "arm64"); err == nil {
		t.Fatal("darwin must be rejected: no native macOS build")
	}
	if _, err := assetFor(rel, "linux", "386"); err == nil {
		t.Fatal("unsupported arch must be rejected")
	}
}
