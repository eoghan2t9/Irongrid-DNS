package cfupdate

import (
	"context"
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

// fakeBinary writes an executable shell script that behaves like cloudflared
// for `--version`. These tests need a POSIX shell, so they skip elsewhere.
func fakeBinary(t *testing.T, path, ver string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("fake cloudflared binary is a shell script")
	}
	if err := os.WriteFile(path, scriptFor(ver), 0o755); err != nil {
		t.Fatal(err)
	}
}

func scriptFor(ver string) []byte {
	return []byte("#!/bin/sh\nif [ \"$1\" = \"--version\" ]; then echo \"cloudflared version " + ver + " (built 2026-10-30-17:05 UTC)\"; fi\n")
}

func TestBinaryVersionParsesReportedRelease(t *testing.T) {
	t.Parallel()
	bin := filepath.Join(t.TempDir(), "cloudflared")
	fakeBinary(t, bin, "2026.10.7")
	if got := BinaryVersion(context.Background(), bin); got != "2026.10.7" {
		t.Errorf("BinaryVersion = %q, want 2026.10.7", got)
	}
	if got := BinaryVersion(context.Background(), filepath.Join(t.TempDir(), "missing")); got != "" {
		t.Errorf("BinaryVersion of a missing file = %q, want empty", got)
	}
}

// The marker used to be the only source of truth, so a binary replaced by
// hand (or a stale marker) was misreported. The binary must win.
func TestCurrentVersionPrefersBinaryOverMarker(t *testing.T) {
	t.Parallel()
	bin := filepath.Join(t.TempDir(), "cloudflared")
	fakeBinary(t, bin, "2026.11.1")
	if err := os.WriteFile(versionPath(bin), []byte("2026.9.0"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := CurrentVersion(bin); got != "2026.11.1" {
		t.Errorf("CurrentVersion = %q, want the binary's 2026.11.1, not the stale marker", got)
	}
}

func TestCurrentVersionFallsBackToMarkerWhenBinaryCannotReport(t *testing.T) {
	t.Parallel()
	bin := filepath.Join(t.TempDir(), "cloudflared")
	if err := os.WriteFile(bin, []byte("not an executable"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(versionPath(bin), []byte("2026.10.7\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := CurrentVersion(bin); got != "2026.10.7" {
		t.Errorf("CurrentVersion = %q, want marker fallback 2026.10.7", got)
	}
}

func TestCurrentVersionEmptyWhenBinaryMissingEvenWithMarker(t *testing.T) {
	t.Parallel()
	bin := filepath.Join(t.TempDir(), "cloudflared")
	if err := os.WriteFile(versionPath(bin), []byte("2026.10.7"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := CurrentVersion(bin); got != "" {
		t.Errorf("CurrentVersion = %q, want empty: a leftover marker must not claim an install", got)
	}
}

// releaseServer serves a GitHub-style "latest release" document for the
// host's own platform, with the binary at /asset. digest overrides the
// advertised sha256 ("" = the real one, "none" = omit it).
func releaseServer(t *testing.T, tag string, binary []byte, digest string) *Client {
	t.Helper()
	name, isTarGz, err := assetName(runtime.GOOS, runtime.GOARCH)
	if err != nil || isTarGz {
		t.Skipf("no raw cloudflared asset for %s/%s", runtime.GOOS, runtime.GOARCH)
	}
	sum := sha256.Sum256(binary)
	d := "sha256:" + hex.EncodeToString(sum[:])
	switch digest {
	case "":
	case "none":
		d = ""
	default:
		d = digest
	}
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	mux.HandleFunc("/latest", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"tag_name": tag,
			"assets": []map[string]any{{
				"name": name, "browser_download_url": srv.URL + "/asset", "size": len(binary), "digest": d,
			}},
		})
	})
	mux.HandleFunc("/asset", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(binary) })
	return &Client{HTTPClient: srv.Client(), latestURL: srv.URL + "/latest"}
}

func TestCheckReportsUpdateFromTheBinaryNotTheMarker(t *testing.T) {
	t.Parallel()
	c := releaseServer(t, "2026.11.2", scriptFor("2026.11.2"), "")
	bin := filepath.Join(t.TempDir(), "cloudflared")
	fakeBinary(t, bin, "2026.11.1")
	// A marker that already claims the latest must not hide the update.
	if err := os.WriteFile(versionPath(bin), []byte("2026.11.2"), 0o600); err != nil {
		t.Fatal(err)
	}
	info := c.Check(context.Background(), bin)
	if info.Error != "" {
		t.Fatalf("Check error: %s", info.Error)
	}
	if info.CurrentVersion != "2026.11.1" || info.LatestVersion != "2026.11.2" || !info.Available {
		t.Errorf("Check = %+v, want current 2026.11.1, latest 2026.11.2, available", info)
	}
}

func TestInstallSwapsBinaryKeepsPrevAndVerifiesVersion(t *testing.T) {
	t.Parallel()
	c := releaseServer(t, "2026.11.2", scriptFor("2026.11.2"), "")
	bin := filepath.Join(t.TempDir(), "cloudflared")
	fakeBinary(t, bin, "2026.11.1")

	res, err := c.Install(context.Background(), bin)
	if err != nil {
		t.Fatalf("Install: %v", err)
	}
	if !res.Installed || res.PreviousVersion != "2026.11.1" || res.NewVersion != "2026.11.2" {
		t.Errorf("result = %+v", res)
	}
	if got := CurrentVersion(bin); got != "2026.11.2" {
		t.Errorf("installed version = %q, want 2026.11.2", got)
	}
	if got := BinaryVersion(context.Background(), bin+".prev"); got != "2026.11.1" {
		t.Errorf("rollback copy reports %q, want 2026.11.1", got)
	}
}

// A download that passes the checksum but is the wrong release (or cannot
// run) must never replace the working binary.
func TestInstallRefusesBinaryThatReportsTheWrongVersion(t *testing.T) {
	t.Parallel()
	c := releaseServer(t, "2026.11.2", scriptFor("2026.9.9"), "")
	bin := filepath.Join(t.TempDir(), "cloudflared")
	fakeBinary(t, bin, "2026.11.1")

	_, err := c.Install(context.Background(), bin)
	if err == nil || !strings.Contains(err.Error(), "not installing") {
		t.Fatalf("Install error = %v, want a refusal", err)
	}
	if got := CurrentVersion(bin); got != "2026.11.1" {
		t.Errorf("working binary was replaced: now %q", got)
	}
	if _, statErr := os.Stat(bin + ".prev"); statErr == nil {
		t.Error("a .prev copy exists although nothing was swapped")
	}
}

func TestInstallRefusesBinaryThatCannotRun(t *testing.T) {
	t.Parallel()
	c := releaseServer(t, "2026.11.2", []byte("\x7fELF-but-not-really"), "")
	bin := filepath.Join(t.TempDir(), "cloudflared")
	fakeBinary(t, bin, "2026.11.1")

	if _, err := c.Install(context.Background(), bin); err == nil {
		t.Fatal("Install accepted a binary that cannot report a version")
	}
	if got := CurrentVersion(bin); got != "2026.11.1" {
		t.Errorf("working binary was replaced: now %q", got)
	}
}

func TestInstallRefusesBadChecksumAndMissingDigest(t *testing.T) {
	t.Parallel()
	bin := filepath.Join(t.TempDir(), "cloudflared")
	fakeBinary(t, bin, "2026.11.1")

	bad := releaseServer(t, "2026.11.2", scriptFor("2026.11.2"), "sha256:"+strings.Repeat("0", 64))
	if _, err := bad.Install(context.Background(), bin); err == nil || !strings.Contains(err.Error(), "checksum mismatch") {
		t.Errorf("bad checksum: error = %v", err)
	}
	none := releaseServer(t, "2026.11.2", scriptFor("2026.11.2"), "none")
	if _, err := none.Install(context.Background(), bin); err == nil || !strings.Contains(err.Error(), "no digest") {
		t.Errorf("missing digest: error = %v", err)
	}
	if got := CurrentVersion(bin); got != "2026.11.1" {
		t.Errorf("working binary was replaced: now %q", got)
	}
}

func TestInstallIsANoOpWhenAlreadyCurrent(t *testing.T) {
	t.Parallel()
	c := releaseServer(t, "2026.11.1", scriptFor("2026.11.1"), "")
	bin := filepath.Join(t.TempDir(), "cloudflared")
	fakeBinary(t, bin, "2026.11.1")

	res, err := c.Install(context.Background(), bin)
	if err != nil || res.Installed {
		t.Fatalf("Install = %+v, %v; want a no-op", res, err)
	}
}

// With the old marker-only logic a missing marker meant "not installed" and
// the same release would be downloaded again.
func TestInstallDoesNotReinstallWhenOnlyTheMarkerIsMissing(t *testing.T) {
	t.Parallel()
	c := releaseServer(t, "2026.11.1", scriptFor("2026.11.1"), "")
	bin := filepath.Join(t.TempDir(), "cloudflared")
	fakeBinary(t, bin, "2026.11.1") // no marker file at all

	res, err := c.Install(context.Background(), bin)
	if err != nil || res.Installed {
		t.Fatalf("Install = %+v, %v; want a no-op for a current binary without a marker", res, err)
	}
}

func TestAssetNameCoversLinuxAmd64(t *testing.T) {
	t.Parallel()
	name, isTarGz, err := assetName("linux", "amd64")
	if err != nil || name != "cloudflared-linux-amd64" || isTarGz {
		t.Errorf("assetName(linux, amd64) = %q, %v, %v", name, isTarGz, err)
	}
	if _, _, err := assetName("plan9", "amd64"); err == nil {
		t.Error("assetName accepted an unsupported OS")
	}
}
