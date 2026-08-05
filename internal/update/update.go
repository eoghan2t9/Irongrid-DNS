// Package update checks GitHub Releases for newer versions of Irongrid DNS
// and reports what the dashboard should surface to the user.
package update

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"runtime"
	"strconv"
	"strings"
	"time"

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
	for _, a := range rel.Assets {
		if a.Name == assetName(runtime.GOOS, runtime.GOARCH) {
			info.DownloadURL = a.URL
			info.AssetName = a.Name
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
	if i := strings.Index(s, "-"); i >= 0 {
		core, pre = s[:i], s[i+1:]
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
