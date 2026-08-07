// Package geoip implements country-based blocking of DNS clients. Country
// data comes from per-country CIDR lists (ipverse/rir-ip aggregates the five
// RIR delegated databases into "<CC>/ipv4_agg.txt" + "<CC>/ipv6_agg.txt"
// files), fetched and cached like blocklists — no accounts, no API keys and
// no per-query network calls. Lookups are served from an in-memory range
// table.
package geoip

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// DefaultBaseURL is where per-country CIDR lists come from. ipverse/rir-ip
// aggregates the RIPE/ARIN/APNIC/LACNIC/AFRINIC delegated files into one
// ipv4_agg.txt + ipv6_agg.txt per country, refreshed regularly.
const DefaultBaseURL = "https://raw.githubusercontent.com/ipverse/rir-ip/master/country"

// Blocker decides whether a client source IP is geo-blocked. It is safe for
// concurrent use and hot-swappable: the DNS handler calls Blocked on every
// query while config reloads or data refreshes rebuild it.
type Blocker struct {
	mu        sync.RWMutex
	blocked   map[string]bool // enabled country codes
	allowlist []*net.IPNet    // parsed allowlist entries
	tables    map[string]*Table
	combined  *Table // merged ranges of every enabled country that has data
}

// NewBlocker returns an empty blocker (nothing blocked until SetConfig).
func NewBlocker() *Blocker {
	return &Blocker{
		blocked:  map[string]bool{},
		tables:   map[string]*Table{},
		combined: &Table{},
	}
}

// SetConfig installs the enabled country codes and the client allowlist,
// then rebuilds the combined lookup. Entries are IPs or CIDRs.
func (b *Blocker) SetConfig(countries, allowlist []string) error {
	var nets []*net.IPNet
	for _, e := range allowlist {
		e = strings.TrimSpace(e)
		if e == "" {
			continue
		}
		if ip := net.ParseIP(e); ip != nil {
			bits := 32
			if ip.To4() == nil {
				bits = 128
			}
			nets = append(nets, &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)})
			continue
		}
		_, n, err := net.ParseCIDR(e)
		if err != nil {
			return fmt.Errorf("allowlist %q: %w", e, err)
		}
		nets = append(nets, n)
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.blocked = map[string]bool{}
	for _, c := range countries {
		if c = strings.ToUpper(strings.TrimSpace(c)); c != "" {
			b.blocked[c] = true
		}
	}
	b.allowlist = nets
	b.rebuildCombinedLocked()
	return nil
}

// AddTable installs the range table for a country, rebuilding the combined
// lookup if the country is currently enabled.
func (b *Blocker) AddTable(cc string, t *Table) {
	b.mu.Lock()
	defer b.mu.Unlock()
	cc = strings.ToUpper(cc)
	b.tables[cc] = t
	if b.blocked[cc] {
		b.rebuildCombinedLocked()
	}
}

// RemoveTable drops a country's table.
func (b *Blocker) RemoveTable(cc string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	cc = strings.ToUpper(cc)
	if _, ok := b.tables[cc]; !ok {
		return
	}
	delete(b.tables, cc)
	if b.blocked[cc] {
		b.rebuildCombinedLocked()
	}
}

// rebuildCombinedLocked merges the tables of every enabled country. The
// caller holds b.mu.
func (b *Blocker) rebuildCombinedLocked() {
	out := &Table{}
	for cc := range b.blocked {
		if t, ok := b.tables[cc]; ok {
			out.v4 = append(out.v4, t.v4...)
			out.v6 = append(out.v6, t.v6...)
		}
	}
	out.sortMerge()
	b.combined = out
}

// Blocked reports whether clientIP is geo-blocked: allowlisted clients are
// never blocked; everyone else is checked against the combined ranges of the
// enabled countries. An unparseable IP (e.g. the web dashboard's own
// connections) is never blocked.
func (b *Blocker) Blocked(clientIP string) bool {
	ip := net.ParseIP(clientIP)
	if ip == nil {
		return false
	}
	b.mu.RLock()
	defer b.mu.RUnlock()
	for _, n := range b.allowlist {
		if n.Contains(ip) {
			return false
		}
	}
	return b.combined.Contains(ip)
}

// Countries returns the enabled country codes in sorted order.
func (b *Blocker) Countries() []string {
	b.mu.RLock()
	defer b.mu.RUnlock()
	out := make([]string, 0, len(b.blocked))
	for cc := range b.blocked {
		out = append(out, cc)
	}
	sort.Strings(out)
	return out
}

// CountryStatus describes one country's loaded data for the dashboard.
type CountryStatus struct {
	Code       string    `json:"code"`
	IPv4Ranges int       `json:"ipv4_ranges"`
	IPv6Ranges int       `json:"ipv6_ranges"`
	LastFetch  time.Time `json:"last_fetch"`
	Error      string    `json:"error,omitempty"`
}

// Manager downloads and caches per-country CIDR lists, and can rebuild a
// Blocker from them. Network failures fall back to the last successfully
// downloaded copy on disk, so a restart with no connectivity still enforces
// the last known data.
type Manager struct {
	dir     string
	baseURL string
	client  *http.Client

	mu        sync.Mutex
	status    map[string]CountryStatus
	refreshMu sync.Mutex // serialises Refresh calls (boot + async rebuilds)
}

// NewManager returns a manager that caches country data under dir. An empty
// baseURL selects the ipverse/rir-ip default.
func NewManager(dir, baseURL string) *Manager {
	if baseURL == "" {
		baseURL = DefaultBaseURL
	}
	return &Manager{
		dir:     dir,
		baseURL: strings.TrimSuffix(baseURL, "/"),
		client:  &http.Client{Timeout: 60 * time.Second},
		status:  map[string]CountryStatus{},
	}
}

// Refresh (re)downloads data for the given countries and returns a Blocker
// configured with them plus the allowlist. Every country whose data is
// available — fresh or from cache — is loaded; countries with neither are
// skipped and their error recorded. The returned error is non-nil only if at
// least one enabled country could not be loaded; the Blocker is still valid.
func (m *Manager) Refresh(ctx context.Context, countries, allowlist []string) (*Blocker, error) {
	m.refreshMu.Lock()
	defer m.refreshMu.Unlock()
	b := NewBlocker()
	var firstErr error
	for _, code := range countries {
		cc := strings.ToUpper(strings.TrimSpace(code))
		if cc == "" {
			continue
		}
		v4, v6, err := m.fetchCountry(ctx, cc)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			m.setStatus(cc, CountryStatus{Code: cc, Error: err.Error()})
			continue
		}
		t, err := LoadTable(v4, v6)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			m.setStatus(cc, CountryStatus{Code: cc, Error: err.Error()})
			continue
		}
		b.AddTable(cc, t)
		m.setStatus(cc, CountryStatus{Code: cc, IPv4Ranges: len(t.v4), IPv6Ranges: len(t.v6), LastFetch: time.Now()})
	}
	if err := b.SetConfig(countries, allowlist); err != nil {
		return b, err
	}
	return b, firstErr
}

// setStatus records a country's refresh outcome.
func (m *Manager) setStatus(cc string, st CountryStatus) {
	m.mu.Lock()
	m.status[cc] = st
	m.mu.Unlock()
}

// Status returns the per-country refresh status, sorted by code.
func (m *Manager) Status() []CountryStatus {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]CountryStatus, 0, len(m.status))
	for _, st := range m.status {
		out = append(out, st)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Code < out[j].Code })
	return out
}

// fetchCountry downloads (or loads from cache) both family lists for cc.
func (m *Manager) fetchCountry(ctx context.Context, cc string) ([]byte, []byte, error) {
	v4, err4 := m.fetchURL(ctx, m.baseURL+"/"+cc+"/ipv4_agg.txt", filepath.Join(m.dir, cc+".ipv4.txt"))
	v6, err6 := m.fetchURL(ctx, m.baseURL+"/"+cc+"/ipv6_agg.txt", filepath.Join(m.dir, cc+".ipv6.txt"))
	if err4 != nil && err6 != nil {
		return nil, nil, fmt.Errorf("country %s: ipv4: %v; ipv6: %v", cc, err4, err6)
	}
	return v4, v6, nil
}

// fetchURL returns url's content, persisting it to cachePath; on a download
// failure it falls back to the cached copy, failing only when there is none.
func (m *Manager) fetchURL(ctx context.Context, url, cachePath string) ([]byte, error) {
	if strings.HasPrefix(url, "file://") {
		content, err := os.ReadFile(strings.TrimPrefix(url, "file://"))
		if err != nil {
			return nil, err
		}
		_ = m.persist(cachePath, content)
		return content, nil
	}
	content, err := m.download(ctx, url)
	if err != nil {
		if cached, cerr := os.ReadFile(cachePath); cerr == nil {
			return cached, nil
		}
		return nil, err
	}
	_ = m.persist(cachePath, content)
	return content, nil
}

func (m *Manager) download(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Irongrid-DNS/0.1 (+https://github.com/eoghan2t9/Irongrid-DNS)")
	resp, err := m.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 64<<20)) // 64 MB cap
}

func (m *Manager) persist(path string, content []byte) error {
	if m.dir == "" {
		return nil
	}
	if err := os.MkdirAll(m.dir, 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, content, 0o644)
}
