// Package cfupdate downloads, verifies and installs the cloudflared binary
// that internal/tunnel manages as a subprocess, keeping it current against
// cloudflare/cloudflared's GitHub releases.
package cfupdate

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"

	"github.com/eoghan2t9/Irongrid-DNS/internal/update"
	"github.com/eoghan2t9/Irongrid-DNS/internal/version"
)

const (
	// DefaultRepo is the GitHub owner/repo that publishes cloudflared releases.
	DefaultRepo = "cloudflare/cloudflared"
	// defaultAPIURL is the template for the "latest release" endpoint.
	defaultAPIURL = "https://api.github.com/repos/%s/releases/latest"
	// versionFileName is the sidecar file recording the installed release
	// tag, written next to the binary. It is only a fallback now: the
	// binary itself is asked first (see CurrentVersion), so a binary that
	// was replaced by hand is never misreported from a stale marker.
	versionFileName = "cloudflared.version"
)

// sharedTransport pools TCP/TLS connections across every latest()/
// downloadAndVerify() call for the life of the process, instead of each
// call (when Client.HTTPClient is unset, the common case) allocating its
// own http.Client — and therefore its own throwaway connection pool — that
// gets GC'd right after. api.github.com and the release CDN are hit
// repeatedly over the process's life, so reusing keep-alive connections
// saves a TLS handshake on every update check.
var sharedTransport = &http.Transport{
	MaxIdleConns:        20,
	MaxIdleConnsPerHost: 4,
	IdleConnTimeout:     90 * time.Second,
}

// defaultAPIClient and defaultDownloadClient are the fallbacks used when
// Client.HTTPClient is nil, sharing sharedTransport's connection pool but
// keeping their own per-call timeouts (a release-asset download needs far
// more time than a small JSON API call).
var (
	defaultAPIClient      = &http.Client{Transport: sharedTransport, Timeout: 10 * time.Second}
	defaultDownloadClient = &http.Client{Transport: sharedTransport, Timeout: 5 * time.Minute}
)

// Asset is the subset of a GitHub release asset we care about. Digest is a
// GitHub-computed "sha256:<hex>" content hash, present on modern releases —
// cloudflared does not publish its own SHA256SUMS.txt, so this is the only
// verification source available.
type Asset struct {
	Name   string `json:"name"`
	URL    string `json:"browser_download_url"`
	Size   int64  `json:"size"`
	Digest string `json:"digest"`
}

type release struct {
	TagName string  `json:"tag_name"`
	Assets  []Asset `json:"assets"`
}

// Info is the result of a Check, serialisable straight to the API.
type Info struct {
	CurrentVersion string `json:"current_version"`
	LatestVersion  string `json:"latest_version"`
	Available      bool   `json:"available"`
	AssetName      string `json:"asset_name,omitempty"`
	Error          string `json:"error,omitempty"`
}

// InstallResult describes an install Install performed (or skipped because
// the managed binary was already current).
type InstallResult struct {
	PreviousVersion string `json:"previous_version"`
	NewVersion      string `json:"new_version"`
	Installed       bool   `json:"installed"`
	AssetName       string `json:"asset_name,omitempty"`
	AssetSize       int64  `json:"asset_size,omitempty"`
}

// Client checks for and installs cloudflared updates from GitHub Releases.
type Client struct {
	// Repo in "owner/name" form. Empty means DefaultRepo.
	Repo string
	// HTTPClient is used for API/download calls. A sane default is used
	// when nil.
	HTTPClient *http.Client

	// latestURL overrides the API endpoint (used by tests).
	latestURL string
}

// versionRe pulls the release out of `cloudflared --version`, which prints
// e.g. "cloudflared version 2026.10.7 (built 2026-10-30-17:05 UTC)".
var versionRe = regexp.MustCompile(`(?i)\bversion\s+v?([0-9][^\s]*)`)

// BinaryVersion runs `binPath --version` and returns the release it reports
// (e.g. "2026.10.7"), or "" if the file is missing, cannot run, or prints
// nothing recognisable.
func BinaryVersion(ctx context.Context, binPath string) string {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	// Executing a file that was written moments ago can fail with ETXTBSY
	// while another goroutine's fork still holds the write descriptor, so a
	// failed run is retried briefly before giving up.
	for range 3 {
		//nolint:gosec // binPath is the managed cloudflared binary, not user input
		out, err := exec.CommandContext(ctx, binPath, "--version").Output()
		if err == nil {
			if m := versionRe.FindStringSubmatch(string(out)); m != nil {
				return m[1]
			}
			return ""
		}
		select {
		case <-ctx.Done():
			return ""
		case <-time.After(50 * time.Millisecond):
		}
	}
	return ""
}

// sameVersion compares two release strings ignoring a leading "v".
func sameVersion(a, b string) bool {
	return a != "" && strings.TrimPrefix(a, "v") == strings.TrimPrefix(b, "v")
}

// CurrentVersion returns the installed cloudflared release at binPath, or ""
// if cloudflared is not installed there. The binary is asked first so the
// answer is always about the file that will actually run; the sidecar marker
// is only a fallback for a binary that exists but cannot report a version.
// binPath should come from internal/tunnel.Manager.BinaryPath — that is the
// single source of truth for where the managed binary lives.
func CurrentVersion(binPath string) string {
	if _, err := os.Stat(binPath); err != nil {
		// No binary means not installed, whatever a leftover marker says.
		return ""
	}
	if v := BinaryVersion(context.Background(), binPath); v != "" {
		return v
	}
	data, err := os.ReadFile(versionPath(binPath))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

func versionPath(binPath string) string {
	return filepath.Join(filepath.Dir(binPath), versionFileName)
}

// Check fetches the latest cloudflared release and reports whether it is
// newer than the installed binary, without downloading anything. binPath
// should come from internal/tunnel.Manager.BinaryPath.
func (c *Client) Check(ctx context.Context, binPath string) Info {
	cur := CurrentVersion(binPath)
	info := Info{CurrentVersion: cur}

	rel, err := c.latest(ctx)
	if err != nil {
		info.Error = err.Error()
		return info
	}
	info.LatestVersion = rel.TagName
	if rel.TagName != "" && (cur == "" || update.Newer(rel.TagName, cur)) {
		info.Available = true
	}
	if asset, _, aerr := assetFor(rel, runtime.GOOS, runtime.GOARCH); aerr == nil {
		info.AssetName = asset.Name
	}
	return info
}

// Install downloads the release asset for the current platform, verifies it
// against the GitHub API's reported sha256 digest, and atomically installs
// it to binPath (keeping the previous binary as ".prev"). binPath should
// come from internal/tunnel.Manager.BinaryPath — that is the single source
// of truth for where the managed binary lives, so Manager.Start (which
// execs it) and Install (which writes it) can never disagree. A no-op
// (Installed=false) is returned, not an error, when already current.
func (c *Client) Install(ctx context.Context, binPath string) (*InstallResult, error) {
	cur := CurrentVersion(binPath)
	rel, err := c.latest(ctx)
	if err != nil {
		return nil, err
	}
	if rel.TagName == "" {
		return nil, fmt.Errorf("cloudflared release has no tag")
	}
	if cur != "" && !update.Newer(rel.TagName, cur) {
		return &InstallResult{PreviousVersion: cur, NewVersion: cur, Installed: false}, nil
	}

	asset, isTarGz, err := assetFor(rel, runtime.GOOS, runtime.GOARCH)
	if err != nil {
		return nil, err
	}
	if asset.Digest == "" {
		return nil, fmt.Errorf("release %s asset %s has no digest — refusing unverified install", rel.TagName, asset.Name)
	}

	binDir := filepath.Dir(binPath)
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		return nil, fmt.Errorf("create %s: %w", binDir, err)
	}

	tmp, err := os.CreateTemp(binDir, ".cloudflared-update-*")
	if err != nil {
		return nil, fmt.Errorf("create temp file in %s: %w", binDir, err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)

	sum, err := c.downloadAndVerify(ctx, asset, tmp)
	tmp.Close()
	if err != nil {
		return nil, err
	}
	wantSum := strings.TrimPrefix(asset.Digest, "sha256:")
	if !strings.EqualFold(sum, wantSum) {
		return nil, fmt.Errorf("checksum mismatch for %s (want %s, got %s)", asset.Name, wantSum, sum)
	}

	installFrom := tmpName
	if isTarGz {
		extracted, err := extractBinaryFromTarGz(tmpName, binDir)
		if err != nil {
			return nil, fmt.Errorf("extract %s: %w", asset.Name, err)
		}
		defer os.Remove(extracted)
		installFrom = extracted
	}
	if err := os.Chmod(installFrom, 0o755); err != nil {
		return nil, err
	}
	// The checksum only proves the download matches what GitHub published;
	// running the binary proves it is the right architecture, starts at all,
	// and is the release we meant to install. Without this a bad asset would
	// replace a working tunnel binary with one that cannot even start.
	if got := BinaryVersion(ctx, installFrom); !sameVersion(got, rel.TagName) {
		return nil, fmt.Errorf("downloaded binary reports version %q, expected %s — not installing", got, rel.TagName)
	}

	if _, err := os.Stat(binPath); err == nil {
		_ = os.Rename(binPath, binPath+".prev")
	}
	if err := os.Rename(installFrom, binPath); err != nil {
		// The previous binary (if any) was already moved aside to
		// binPath+".prev" above, so a failure here would otherwise leave
		// nothing at all installed at binPath — attempt to restore it
		// rather than just reporting the install as failed. Mirrors the
		// rollback internal/update's analogous swap performs.
		if _, statErr := os.Stat(binPath + ".prev"); statErr == nil {
			if restoreErr := os.Rename(binPath+".prev", binPath); restoreErr != nil {
				return nil, fmt.Errorf("install %s: %w (restoring the previous binary also failed: %v — %s is now missing, restore manually from %s)", asset.Name, err, restoreErr, binPath, binPath+".prev")
			}
		}
		return nil, fmt.Errorf("install %s: %w", asset.Name, err)
	}

	// Best effort: the binary is the source of truth for its version, the
	// marker is only a fallback, so failing to write it must not turn a
	// completed install into an error.
	_ = os.WriteFile(versionPath(binPath), []byte(rel.TagName), 0o600)

	return &InstallResult{
		PreviousVersion: cur,
		NewVersion:      rel.TagName,
		Installed:       true,
		AssetName:       asset.Name,
		AssetSize:       asset.Size,
	}, nil
}

func (c *Client) latest(ctx context.Context) (*release, error) {
	repo := c.Repo
	if repo == "" {
		repo = DefaultRepo
	}
	url := c.latestURL
	if url == "" {
		url = fmt.Sprintf(defaultAPIURL, repo)
	}
	client := c.HTTPClient
	if client == nil {
		client = defaultAPIClient
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "irongrid-dns/"+version.Version)
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
		return nil, fmt.Errorf("cloudflared releases API returned %s: %s", resp.Status, strings.TrimSpace(string(body)))
	}
	var rel release
	if err := json.NewDecoder(resp.Body).Decode(&rel); err != nil {
		return nil, fmt.Errorf("decoding cloudflared release: %w", err)
	}
	return &rel, nil
}

// downloadAndVerify streams the asset into w (bounded to 128 MB — well over
// the largest published cloudflared binary) while hashing it, returning the
// hex sha256.
func (c *Client) downloadAndVerify(ctx context.Context, asset Asset, w io.Writer) (string, error) {
	client := c.HTTPClient
	if client == nil {
		client = defaultDownloadClient
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, asset.URL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "irongrid-dns/"+version.Version)
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("download %s returned %s", asset.Name, resp.Status)
	}
	h := sha256.New()
	if _, err := io.Copy(io.MultiWriter(w, h), io.LimitReader(resp.Body, 128<<20)); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// extractBinaryFromTarGz pulls the single "cloudflared" entry out of a
// darwin release tarball into a new temp file in dir, returning its path.
func extractBinaryFromTarGz(tgzPath, dir string) (string, error) {
	f, err := os.Open(tgzPath)
	if err != nil {
		return "", err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return "", err
	}
	defer gz.Close()

	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return "", fmt.Errorf("no cloudflared binary found in archive")
		}
		if err != nil {
			return "", err
		}
		if filepath.Base(hdr.Name) != "cloudflared" {
			continue
		}
		out, err := os.CreateTemp(dir, ".cloudflared-extracted-*")
		if err != nil {
			return "", err
		}
		if _, err := io.Copy(out, io.LimitReader(tr, 128<<20)); err != nil {
			out.Close()
			os.Remove(out.Name())
			return "", err
		}
		out.Close()
		return out.Name(), nil
	}
}

// assetFor picks the release asset for goos/goarch, per cloudflared's
// published naming scheme (github.com/cloudflare/cloudflared releases).
// isTarGz reports whether the asset is a .tgz archive (darwin) that needs
// extraction rather than a raw binary.
func assetFor(rel *release, goos, goarch string) (Asset, bool, error) {
	name, isTarGz, err := assetName(goos, goarch)
	if err != nil {
		return Asset{}, false, err
	}
	for _, a := range rel.Assets {
		if a.Name == name {
			return a, isTarGz, nil
		}
	}
	return Asset{}, false, fmt.Errorf("no %s asset in cloudflared release %s", name, rel.TagName)
}

func assetName(goos, goarch string) (name string, isTarGz bool, err error) {
	switch goos {
	case "linux":
		switch goarch {
		case "amd64":
			return "cloudflared-linux-amd64", false, nil
		case "arm64":
			return "cloudflared-linux-arm64", false, nil
		case "arm":
			return "cloudflared-linux-arm", false, nil
		case "386":
			return "cloudflared-linux-386", false, nil
		}
	case "darwin":
		switch goarch {
		case "amd64":
			return "cloudflared-darwin-amd64.tgz", true, nil
		case "arm64":
			return "cloudflared-darwin-arm64.tgz", true, nil
		}
	case "windows":
		switch goarch {
		case "amd64":
			return "cloudflared-windows-amd64.exe", false, nil
		case "386":
			return "cloudflared-windows-386.exe", false, nil
		}
	}
	return "", false, fmt.Errorf("cloudflared publishes no release asset for %s/%s", goos, goarch)
}
