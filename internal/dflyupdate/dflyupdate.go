// Package dflyupdate downloads, verifies and installs the Dragonfly cache
// server binary that Irongrid talks to over the Redis protocol, keeping it
// current against dragonflydb/dragonfly's GitHub releases.
//
// Installing only swaps the binary on disk. The running server keeps using
// the old (unlinked) inode until it is restarted, which is the caller's job —
// see internal/api's Dragonfly update handler.
package dflyupdate

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
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
	// DefaultRepo is the GitHub owner/repo that publishes Dragonfly releases.
	DefaultRepo = "dragonflydb/dragonfly"
	// defaultAPIURL is the template for the "latest release" endpoint.
	defaultAPIURL = "https://api.github.com/repos/%s/releases/latest"
	// maxBinary bounds the extracted binary (the largest release is ~40 MB).
	maxBinary = 256 << 20
)

// versionRe pulls the release tag out of `dragonfly --version`, which prints
// ANSI colour codes around a "v1.2.3-<commit>" token.
var versionRe = regexp.MustCompile(`v\d+\.\d+\.\d+`)

var (
	defaultAPIClient      = &http.Client{Timeout: 10 * time.Second}
	defaultDownloadClient = &http.Client{Timeout: 5 * time.Minute}
)

// Asset is the subset of a GitHub release asset we care about. Digest is a
// GitHub-computed "sha256:<hex>" content hash, the verification source for
// releases (Dragonfly publishes no separate checksum file).
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
// the binary on disk was already current).
type InstallResult struct {
	PreviousVersion string `json:"previous_version"`
	NewVersion      string `json:"new_version"`
	Installed       bool   `json:"installed"`
	AssetName       string `json:"asset_name,omitempty"`
	AssetSize       int64  `json:"asset_size,omitempty"`
}

// Client checks for and installs Dragonfly updates from GitHub Releases.
type Client struct {
	// Repo in "owner/name" form. Empty means DefaultRepo.
	Repo string
	// HTTPClient is used for API/download calls. A sane default is used
	// when nil.
	HTTPClient *http.Client

	// latestURL overrides the API endpoint (used by tests).
	latestURL string
}

// InstalledVersion returns the release tag of the Dragonfly binary at binPath
// (e.g. "v2.0.2"), or "" if it is missing or does not report a version.
func InstalledVersion(ctx context.Context, binPath string) string {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	//nolint:gosec // binPath is the operator's own configured Dragonfly binary
	out, err := exec.CommandContext(ctx, binPath, "--version").Output()
	if err != nil {
		return ""
	}
	return versionRe.FindString(string(out))
}

// Check fetches the latest Dragonfly release and reports whether it is newer
// than the binary at binPath, without downloading anything.
func (c *Client) Check(ctx context.Context, binPath string) Info {
	cur := InstalledVersion(ctx, binPath)
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
	if asset, aerr := assetFor(rel, runtime.GOOS, runtime.GOARCH); aerr == nil {
		info.AssetName = asset.Name
	}
	return info
}

// Install downloads the release asset for this platform, verifies it against
// the GitHub-reported sha256 digest, checks the extracted binary reports the
// release's version, and swaps it into binPath, keeping the previous binary as
// binPath+".prev". A no-op (Installed=false) is returned, not an error, when
// binPath is already current.
func (c *Client) Install(ctx context.Context, binPath string) (*InstallResult, error) {
	cur := InstalledVersion(ctx, binPath)
	rel, err := c.latest(ctx)
	if err != nil {
		return nil, err
	}
	if rel.TagName == "" {
		return nil, errors.New("dragonfly release has no tag")
	}
	if cur != "" && !update.Newer(rel.TagName, cur) {
		return &InstallResult{PreviousVersion: cur, NewVersion: cur}, nil
	}

	asset, err := assetFor(rel, runtime.GOOS, runtime.GOARCH)
	if err != nil {
		return nil, err
	}
	if asset.Digest == "" {
		return nil, fmt.Errorf("release %s asset %s has no digest — refusing unverified install", rel.TagName, asset.Name)
	}

	binDir := filepath.Dir(binPath)
	tgz, err := os.CreateTemp(binDir, ".dragonfly-update-*.tgz")
	if err != nil {
		return nil, fmt.Errorf("create temp file in %s: %w", binDir, err)
	}
	tgzName := tgz.Name()
	defer os.Remove(tgzName)

	sum, err := c.downloadAndVerify(ctx, asset, tgz)
	tgz.Close()
	if err != nil {
		return nil, err
	}
	if want := strings.TrimPrefix(asset.Digest, "sha256:"); !strings.EqualFold(sum, want) {
		return nil, fmt.Errorf("checksum mismatch for %s (want %s, got %s)", asset.Name, want, sum)
	}

	newBin, err := extractBinary(tgzName, binDir, "dragonfly-"+archName(runtime.GOARCH))
	if err != nil {
		return nil, fmt.Errorf("extract %s: %w", asset.Name, err)
	}
	defer os.Remove(newBin)
	if err := os.Chmod(newBin, 0o755); err != nil {
		return nil, err
	}
	// A truncated or wrong-arch download would otherwise replace a working
	// server with one that cannot even start.
	if got := InstalledVersion(ctx, newBin); got != rel.TagName {
		return nil, fmt.Errorf("downloaded binary reports version %q, expected %s — not installing", got, rel.TagName)
	}

	if _, err := os.Stat(binPath); err == nil {
		_ = os.Rename(binPath, binPath+".prev")
	}
	if err := os.Rename(newBin, binPath); err != nil {
		if _, statErr := os.Stat(binPath + ".prev"); statErr == nil {
			if restoreErr := os.Rename(binPath+".prev", binPath); restoreErr != nil {
				return nil, fmt.Errorf("install %s: %w (restoring the previous binary also failed: %v — %s is now missing, restore manually from %s)", asset.Name, err, restoreErr, binPath, binPath+".prev")
			}
		}
		return nil, fmt.Errorf("install %s: %w", asset.Name, err)
	}

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
		return nil, fmt.Errorf("dragonfly releases API returned %s: %s", resp.Status, strings.TrimSpace(string(body)))
	}
	var rel release
	if err := json.NewDecoder(resp.Body).Decode(&rel); err != nil {
		return nil, fmt.Errorf("decoding dragonfly release: %w", err)
	}
	return &rel, nil
}

// downloadAndVerify streams the asset into w (bounded to 128 MB — far above
// the ~17 MB tarball) while hashing it, returning the hex sha256.
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

// extractBinary pulls the named regular file out of the release tarball into a
// new temp file in dir, returning its path (the tarball also holds a LICENSE).
func extractBinary(tgzPath, dir, want string) (string, error) {
	f, err := os.Open(tgzPath)
	if err != nil {
		return "", err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return "", fmt.Errorf("read tarball: %w", err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return "", fmt.Errorf("binary %s not found in tarball", want)
		}
		if err != nil {
			return "", err
		}
		if hdr.Typeflag != tar.TypeReg || hdr.Name != want {
			continue
		}
		out, err := os.CreateTemp(dir, ".dragonfly-bin-*")
		if err != nil {
			return "", err
		}
		n, err := io.Copy(out, io.LimitReader(tr, maxBinary))
		out.Close()
		if err != nil || n == 0 {
			os.Remove(out.Name())
			if err == nil {
				err = fmt.Errorf("extracted %s is empty", want)
			}
			return "", err
		}
		return out.Name(), nil
	}
}

// archName maps GOARCH to the architecture suffix Dragonfly uses in asset names.
func archName(goarch string) string {
	if goarch == "arm64" {
		return "aarch64"
	}
	return "x86_64"
}

// assetFor picks the release tarball for goos/goarch. Dragonfly publishes
// native builds for Linux only (macOS/Windows run it in Docker).
func assetFor(rel *release, goos, goarch string) (Asset, error) {
	if goos != "linux" {
		return Asset{}, fmt.Errorf("dragonfly publishes no native build for %s", goos)
	}
	if goarch != "amd64" && goarch != "arm64" {
		return Asset{}, fmt.Errorf("dragonfly publishes no build for %s/%s", goos, goarch)
	}
	name := "dragonfly-" + archName(goarch) + ".tar.gz"
	for _, a := range rel.Assets {
		if a.Name == name {
			return a, nil
		}
	}
	return Asset{}, fmt.Errorf("dragonfly release %s has no asset %s", rel.TagName, name)
}
