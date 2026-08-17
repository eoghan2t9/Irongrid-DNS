// Package update checks GitHub Releases for newer versions of Irongrid DNS
// and reports what the dashboard should surface to the user.
package update

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/klauspost/cpuid/v2"

	"github.com/eoghan2t9/Irongrid-DNS/internal/version"
)

const (
	// DefaultRepo is the GitHub owner/repo that hosts releases.
	DefaultRepo = "eoghan2t9/Irongrid-DNS"
	// DefaultAPIURL is the template for the "latest release" endpoint.
	DefaultAPIURL = "https://api.github.com/repos/%s/releases/latest"
	// ChangelogAPIURL is the template for the recent-releases list endpoint
	// (drafts are excluded by GitHub; prereleases are filtered client-side).
	ChangelogAPIURL = "https://api.github.com/repos/%s/releases?per_page=%d"
	// changelogLimit is how many releases the changelog page shows.
	changelogLimit = 10
)

// Asset is the subset of a GitHub release asset we care about.
type Asset struct {
	Name string `json:"name"`
	URL  string `json:"browser_download_url"`
	Size int64  `json:"size"`
}

// Release is the subset of a GitHub release shown on the changelog page.
type Release struct {
	TagName     string `json:"tag_name"`
	Name        string `json:"name"`
	PublishedAt string `json:"published_at"`
	HTMLURL     string `json:"html_url"`
	Body        string `json:"body"`
	Prerelease  bool   `json:"prerelease"`
}

// release is the subset of the GitHub "latest release" payload we consume.
type release struct {
	TagName     string  `json:"tag_name"`
	PublishedAt string  `json:"published_at"`
	HTMLURL     string  `json:"html_url"`
	Body        string  `json:"body"`
	Assets      []Asset `json:"assets"`
}

// Info is the result of an update check, serialised straight to the API.
type Info struct {
	CurrentVersion string `json:"current_version"`
	LatestVersion  string `json:"latest_version"`
	Available      bool   `json:"available"`
	PublishedAt    string `json:"published_at,omitempty"`
	ReleaseURL     string `json:"release_url,omitempty"`
	DownloadURL    string `json:"download_url,omitempty"`
	AssetName      string `json:"asset_name,omitempty"`
	Changelog      string `json:"changelog,omitempty"`
	// Error is non-empty when the check itself failed (offline, rate limit,
	// no releases yet). The UI shows a quiet notice rather than a popup.
	Error string `json:"error,omitempty"`
}

// Client checks for updates against the GitHub Releases API.
type Client struct {
	// Repo in "owner/name" form. Empty means DefaultRepo.
	Repo string
	// Current is the running version (e.g. "v1.0.1"). Empty means the
	// compile-time version.Version.
	Current string
	// HTTPClient is used for the API call. A default 10s client is used when
	// nil (the handler always passes a context with a timeout anyway).
	HTTPClient *http.Client

	// latestURL overrides the API endpoint (used by tests).
	latestURL string
	// listURL overrides the releases-list endpoint (used by tests).
	listURL string
}

// Check fetches the latest release and reports whether it is newer than the
// running version. Network errors are folded into Info.Error so callers can
// always serialise the result.
func (c *Client) Check(ctx context.Context) Info {
	cur := c.Current
	if cur == "" {
		cur = version.Version
	}
	info := Info{CurrentVersion: cur}

	rel, err := c.latest(ctx)
	if err != nil {
		info.Error = err.Error()
		return info
	}

	info.LatestVersion = rel.TagName
	info.PublishedAt = rel.PublishedAt
	info.ReleaseURL = rel.HTMLURL
	info.Changelog = rel.Body
	if rel.TagName != "" && Newer(rel.TagName, cur) {
		info.Available = true
	}
	for _, want := range preferredAssetNames(runtime.GOOS, runtime.GOARCH) {
		found := false
		for _, a := range rel.Assets {
			if a.Name == want {
				info.DownloadURL = a.URL
				info.AssetName = a.Name
				found = true
				break
			}
		}
		if found {
			break
		}
	}
	return info
}

// List returns the most recent stable releases, newest first, for the
// changelog page. Prereleases are filtered out; drafts are never returned by
// the API.
func (c *Client) List(ctx context.Context) ([]Release, error) {
	repo := c.Repo
	if repo == "" {
		repo = DefaultRepo
	}
	url := fmt.Sprintf(ChangelogAPIURL, repo, changelogLimit)
	if c.listURL != "" {
		url = c.listURL
	}
	var rels []Release
	if err := c.getJSON(ctx, url, &rels); err != nil {
		return nil, err
	}
	out := make([]Release, 0, len(rels))
	for _, r := range rels {
		if r.Prerelease {
			continue
		}
		out = append(out, r)
	}
	return out, nil
}

func (c *Client) latest(ctx context.Context) (*release, error) {
	repo := c.Repo
	if repo == "" {
		repo = DefaultRepo
	}
	url := fmt.Sprintf(DefaultAPIURL, repo)
	if c.latestURL != "" {
		url = c.latestURL
	}
	var rel release
	if err := c.getJSON(ctx, url, &rel); err != nil {
		return nil, err
	}
	return &rel, nil
}

// getJSON performs an authenticated-style GitHub API GET and decodes the JSON
// body, normalising transport and HTTP errors into a single error.
func (c *Client) getJSON(ctx context.Context, url string, out any) error {
	client := c.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "irongrid-dns/"+version.Version)
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
		return fmt.Errorf("releases API returned %s: %s", resp.Status, strings.TrimSpace(string(body)))
	}
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return fmt.Errorf("decoding release: %w", err)
	}
	return nil
}

// assetName maps GOOS/GOARCH to the release asset name produced by the
// release pipeline (see Makefile / .github/workflows/release.yml).
func assetName(goos, goarch string) string {
	name := fmt.Sprintf("irongrid-%s-%s", goos, goarch)
	if goos == "windows" {
		name += ".exe"
	}
	return name
}

// v3AssetName is the GOAMD64=v3 opt-in variant of assetName (see Makefile /
// .github/workflows/release.yml), built for CPUs supporting AVX, AVX2,
// BMI1, BMI2, F16C, FMA3, LZCNT, MOVBE and OSXSAVE.
func v3AssetName(goos, goarch string) string {
	name := fmt.Sprintf("irongrid-%s-%s-v3", goos, goarch)
	if goos == "windows" {
		name += ".exe"
	}
	return name
}

// supportsGOAMD64V3 reports whether the running CPU supports the x86-64-v3
// microarchitecture level that Irongrid's "-v3" release binaries are
// compiled for. golang.org/x/sys/cpu (already a direct dependency
// elsewhere) is missing 3 of the 9 required feature bits (F16C, LZCNT,
// MOVBE), which would misdetect some real CPUs as v3-capable when they
// aren't — a wrong answer here means an illegal-instruction crash on
// install. klauspost/cpuid/v2's X64Level checks exactly the official
// x86-64-v3 feature set and returns 0 safely on any non-x64 CPU rather than
// panicking. A var, not a func, so tests can override it.
var supportsGOAMD64V3 = func() bool {
	return cpuid.CPU.X64Level() >= 3
}

// preferredAssetNames returns release asset names to search for, in
// preference order: the GOAMD64=v3 build first when the target is amd64
// and the running CPU actually supports it, then always the baseline
// build as a fallback — covering releases published before the v3
// artifacts existed, or a release where the v3 build for this OS/arch was
// skipped (each platform's v3 build is a separate step; see release.yml).
func preferredAssetNames(goos, goarch string) []string {
	base := assetName(goos, goarch)
	if goarch == "amd64" && supportsGOAMD64V3() {
		return []string{v3AssetName(goos, goarch), base}
	}
	return []string{base}
}

// InstallResult describes an in-place update that was applied.
type InstallResult struct {
	PreviousVersion string `json:"previous_version"`
	NewVersion      string `json:"new_version"`
	InstalledTo     string `json:"installed_to"`
	AssetName       string `json:"asset_name"`
	AssetSize       int64  `json:"asset_size"`
}

// Install downloads the release asset for the current platform, verifies it
// against the release's SHA256SUMS.txt and atomically replaces the running
// binary at executable ("" = os.Executable()). The previous binary is kept
// as "<path>.prev" for rollback. Install does NOT restart the service — the
// caller decides how and when to restart after responding.
func (c *Client) Install(ctx context.Context, executable string) (*InstallResult, error) {
	cur := c.Current
	if cur == "" {
		cur = version.Version
	}
	rel, err := c.latest(ctx)
	if err != nil {
		return nil, err
	}
	if !Newer(rel.TagName, cur) {
		return nil, fmt.Errorf("already running the latest version (%s)", cur)
	}
	if runtime.GOOS == "windows" {
		return nil, fmt.Errorf("in-place update is not supported on Windows — use the manual download")
	}
	// Install already refuses on Windows above, so a v3 preference here only
	// ever matters on Linux/macOS in-place updates — Check (above) still
	// surfaces a v3 download link for Windows users doing a manual install.
	wants := preferredAssetNames(runtime.GOOS, runtime.GOARCH)
	var asset *Asset
	for _, want := range wants {
		for i := range rel.Assets {
			if rel.Assets[i].Name == want {
				asset = &rel.Assets[i]
				break
			}
		}
		if asset != nil {
			break
		}
	}
	if asset == nil {
		return nil, fmt.Errorf("no %s asset in release %s", strings.Join(wants, " or "), rel.TagName)
	}

	execPath := executable
	if execPath == "" {
		execPath, err = os.Executable()
		if err != nil {
			return nil, fmt.Errorf("locate running binary: %w", err)
		}
	}
	if resolved, err := filepath.EvalSymlinks(execPath); err == nil {
		execPath = resolved
	}

	// Download into the same directory as the binary so the final rename is
	// atomic (a rename across filesystems would fail with EXDEV). Fail fast
	// with a clear message when the directory is not writable instead of
	// surfacing a confusing temp-file error. Checked unconditionally, even as
	// root: systemd's ProtectSystem=full (or an immutable-distro /usr mount)
	// makes the directory read-only regardless of uid.
	dir := filepath.Dir(execPath)
	if runtime.GOOS != "windows" && !isWritableDir(dir) {
		if os.Geteuid() != 0 {
			return nil, fmt.Errorf("cannot write to %s — run as root (or the user owning the install) to update in place", dir)
		}
		return nil, fmt.Errorf("cannot write to %s even as root — it looks read-only (e.g. systemd's ProtectSystem sandboxing, or an immutable-distro /usr mount). If running under systemd, add 'ReadWritePaths=%s' to the unit's [Service] section and run 'systemctl daemon-reload && systemctl restart <unit>', then retry the update", dir, dir)
	}
	tmp, err := os.CreateTemp(dir, ".irongrid-update-*")
	if err != nil {
		return nil, fmt.Errorf("create temp file in %s: %w", dir, err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := c.downloadTo(ctx, asset.URL, tmp); err != nil {
		tmp.Close()
		return nil, fmt.Errorf("download %s: %w", asset.Name, err)
	}
	if err := tmp.Close(); err != nil {
		return nil, err
	}
	if err := os.Chmod(tmpName, 0o755); err != nil {
		return nil, err
	}

	// Verify against the SHA256SUMS.txt published with the release. The
	// checksum file is mandatory: a release without it is treated as
	// untrusted and the install is refused.
	sum, err := c.checksumFor(ctx, rel, asset.Name)
	if err != nil {
		return nil, err
	}
	have, err := sha256File(tmpName)
	if err != nil {
		return nil, err
	}
	if !strings.EqualFold(have, sum) {
		return nil, fmt.Errorf("checksum mismatch for %s (want %s, got %s)", asset.Name, sum, have)
	}

	// Atomic swap with a rollback copy.
	backup := execPath + ".prev"
	if err := os.Rename(execPath, backup); err != nil {
		return nil, fmt.Errorf("back up current binary: %w", err)
	}
	if err := os.Rename(tmpName, execPath); err != nil {
		_ = os.Rename(backup, execPath) // restore the old binary
		return nil, fmt.Errorf("install new binary: %w", err)
	}

	return &InstallResult{
		PreviousVersion: cur,
		NewVersion:      rel.TagName,
		InstalledTo:     execPath,
		AssetName:       asset.Name,
		AssetSize:       asset.Size,
	}, nil
}

// downloadTo streams url into w (bounded to 256 MB).
func (c *Client) downloadTo(ctx context.Context, url string, w io.Writer) error {
	client := c.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Minute}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "irongrid-dns/"+version.Version)
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download returned %s", resp.Status)
	}
	_, err = io.Copy(w, io.LimitReader(resp.Body, 256<<20))
	return err
}

// checksumFor finds the sha256 of the named asset in the release's
// SHA256SUMS.txt. A release without a checksum file is an error — every
// published release must ship one.
func (c *Client) checksumFor(ctx context.Context, rel *release, asset string) (string, error) {
	var sumsURL string
	for _, a := range rel.Assets {
		if a.Name == "SHA256SUMS.txt" {
			sumsURL = a.URL
			break
		}
	}
	if sumsURL == "" {
		return "", fmt.Errorf("release %s has no SHA256SUMS.txt — refusing unverified install", rel.TagName)
	}
	client := c.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, sumsURL, nil)
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
		return "", fmt.Errorf("checksums download returned %s", resp.Status)
	}
	sc := bufio.NewScanner(io.LimitReader(resp.Body, 1<<20))
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 2 {
			continue
		}
		name := strings.TrimPrefix(fields[1], "./")
		if name == asset {
			return fields[0], nil
		}
	}
	return "", fmt.Errorf("no checksum entry for %s in SHA256SUMS.txt", asset)
}

// isWritableDir reports whether the current user may create files in dir.
// The real create test happens later; this is a cheap pre-check for a clear
// error message.
func isWritableDir(dir string) bool {
	tmp, err := os.CreateTemp(dir, ".irongrid-write-test-*")
	if err != nil {
		return false
	}
	name := tmp.Name()
	tmp.Close()
	os.Remove(name)
	return true
}

// UnitName discovers the systemd unit that manages the current process,
// used to restart the service after an in-place update. It reads the
// process cgroup (/proc/self/cgroup), falling back to the executable's
// basename and finally a fixed candidate list. An empty result means the
// process is not (obviously) systemd-managed — callers should treat the
// service as manually restarted.
func UnitName() string {
	// 1. cgroup: the unit is the *.service component of the slice path.
	if data, err := os.ReadFile("/proc/self/cgroup"); err == nil {
		if unit, ok := unitFromCgroupData(string(data)); ok {
			return unit
		}
	}
	// 2. Executable basename ("irongrid" → "irongrid.service"). Strip a
	// possible ".prev" suffix — after an in-place swap the running process
	// reports its backup path, which must not leak into the unit name.
	if exe, err := os.Executable(); err == nil {
		base := strings.TrimSuffix(filepath.Base(exe), ".exe")
		base = strings.TrimSuffix(base, ".prev")
		if base != "" {
			return base + ".service"
		}
	}
	// 3. Fixed candidates (the unit name used by the official installer).
	if _, err := os.Stat("/etc/systemd/system/irongrid.service"); err == nil {
		return "irongrid.service"
	}
	return ""
}

// unitFromCgroupData scans the contents of /proc/self/cgroup for a
// "*.service" path component, e.g. "0::/system.slice/irongrid.service" ->
// "irongrid.service". Each colon-separated field is trimmed to its last
// path segment *before* searching for ".service" in it — searching the
// untrimmed field and slicing the trimmed one used two different indices
// into two different-length strings and panicked with a slice-bounds error
// on every real systemd cgroup path.
func unitFromCgroupData(data string) (string, bool) {
	for line := range strings.SplitSeq(data, "\n") {
		for part := range strings.SplitSeq(line, ":") {
			p := strings.TrimSpace(part)
			unit := p[strings.LastIndex(p, "/")+1:]
			if i := strings.Index(unit, ".service"); i >= 0 {
				return unit[:i+len(".service")], true
			}
		}
	}
	return "", false
}

// sha256File returns the hex sha256 of a file.
func sha256File(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// Newer reports whether the latest tag is newer than the current version.
// Tags and current versions may carry a "v" prefix and optional pre-release
// suffixes ("v1.1.0-rc.1"). When the latest tag cannot be parsed we refuse to
// claim an update; an unparseable current build (e.g. "dev") counts as older
// than any distinct parseable release tag.
func Newer(latest, current string) bool {
	a, errA := parseSemver(latest)
	b, errB := parseSemver(current)
	if errA != nil || errB != nil {
		if errA != nil {
			return false
		}
		return latest != current
	}
	return b.less(a)
}

// semver is a minimal semantic version with pre-release support.
type semver struct {
	major, minor, patch int
	pre                 string
}

func parseSemver(s string) (semver, error) {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "v")
	if s == "" {
		return semver{}, fmt.Errorf("empty version")
	}
	if i := strings.Index(s, "+"); i >= 0 { // drop build metadata
		s = s[:i]
	}
	core, pre := s, ""
	if before, after, ok := strings.Cut(s, "-"); ok {
		core, pre = before, after
	}
	parts := strings.Split(core, ".")
	if len(parts) != 3 {
		return semver{}, fmt.Errorf("not a semantic version: %q", s)
	}
	var v semver
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return semver{}, fmt.Errorf("not a semantic version: %q", s)
		}
		switch i {
		case 0:
			v.major = n
		case 1:
			v.minor = n
		case 2:
			v.patch = n
		}
	}
	v.pre = pre
	return v, nil
}

// less reports whether a sorts before b per semver precedence: a release
// (no pre-release) is newer than any pre-release of the same core version.
func (a semver) less(b semver) bool {
	if a.major != b.major {
		return a.major < b.major
	}
	if a.minor != b.minor {
		return a.minor < b.minor
	}
	if a.patch != b.patch {
		return a.patch < b.patch
	}
	switch {
	case a.pre == "" && b.pre == "":
		return false
	case a.pre == "":
		return false // a is the release, b is a pre-release of it
	case b.pre == "":
		return true
	default:
		return a.pre < b.pre
	}
}
