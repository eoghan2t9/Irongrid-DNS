// Package geoip implements country-based blocking of DNS clients. Country
// data comes from per-country CIDR lists (ipverse/rir-ip aggregates the five
// RIR delegated databases into "<cc>/ipv4-aggregated.txt" +
// "<cc>/ipv6-aggregated.txt" files, lowercase country code), fetched and
// cached like blocklists — no accounts, no API keys and no per-query
// network calls. Lookups are served from an in-memory range table.
package geoip

import (
	"bytes"
	"cmp"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"
)

// DefaultBaseURL is where per-country CIDR lists come from. ipverse/rir-ip
// aggregates the RIPE/ARIN/APNIC/LACNIC/AFRINIC delegated files into one
// "<cc>/ipv4-aggregated.txt" + "<cc>/ipv6-aggregated.txt" per country
// (lowercase country code), refreshed regularly.
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
	// asnAllow/asnBlock are the pruned IP→ASN tables for the configured
	// allow-listed and block-listed ASNs (nil disables each side). A hit in
	// asnAllow means the client's ISP is never blocked — it wins over the
	// country ranges exactly like the CIDR allowlist. A hit in asnBlock
	// means the ISP is always blocked, even if its ranges aren't in any
	// enabled country's list.
	asnAllow *ASNTable
	asnBlock *ASNTable
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

// SetASNs installs the allow/block ASN tables (nil disables each side).
func (b *Blocker) SetASNs(allow, block *ASNTable) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.asnAllow, b.asnBlock = allow, block
}

// ASNOf returns the ASN attributed to ip by the allow or block ASN tables,
// when the client's ISP is in one of the configured ASN lists (used by the
// DoH X-Irongrid-Client-ASN response header).
func (b *Blocker) ASNOf(ip net.IP) (uint32, bool) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	if b.asnAllow != nil {
		if asn, ok := b.asnAllow.Lookup(ip); ok {
			return asn, true
		}
	}
	if b.asnBlock != nil {
		return b.asnBlock.Lookup(ip)
	}
	return 0, false
}

// Blocked reports whether clientIP is geo-blocked (see BlockedAs for the
// blocking source).
func (b *Blocker) Blocked(clientIP string) bool {
	blocked, _ := b.BlockedAs(clientIP)
	return blocked
}

// BlockedAs reports whether clientIP is geo-blocked and why: "asn" when a
// block-listed ASN refused the client, "country" when the combined country
// ranges did. Allowlisted clients are never blocked — by the ASN allowlist
// (an allow-listed ISP wins over everything, mirroring the CIDR allowlist)
// or by an explicit CIDR. An unparseable IP (e.g. the web dashboard's own
// connections) is never blocked.
func (b *Blocker) BlockedAs(clientIP string) (blocked bool, source string) {
	ip := net.ParseIP(clientIP)
	if ip == nil {
		return false, ""
	}
	b.mu.RLock()
	defer b.mu.RUnlock()
	if b.asnAllow != nil && b.asnAllow.Contains(ip) {
		return false, ""
	}
	for _, n := range b.allowlist {
		if n.Contains(ip) {
			return false, ""
		}
	}
	if b.asnBlock != nil && b.asnBlock.Contains(ip) {
		return true, "asn"
	}
	if b.combined.Contains(ip) {
		return true, "country"
	}
	return false, ""
}

// Countries returns the enabled country codes in sorted order.
func (b *Blocker) Countries() []string {
	b.mu.RLock()
	defer b.mu.RUnlock()
	out := make([]string, 0, len(b.blocked))
	for cc := range b.blocked {
		out = append(out, cc)
	}
	slices.Sort(out)
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
	dir        string
	baseURL    string
	asnBaseURL string
	client     *http.Client

	mu     sync.Mutex
	status map[string]CountryStatus
	// lastRefresh is when the most recent Refresh attempt finished (even a
	// partially-failed one), for the dashboard's "next refresh" display.
	lastRefresh time.Time
	refreshMu   sync.Mutex // serialises Refresh calls (boot + async rebuilds)
}

// NewManager returns a manager that caches country data under dir. An empty
// baseURL selects the ipverse/rir-ip default; the ASN dataset defaults to
// iptoasn.com (see SetASNBaseURL).
func NewManager(dir, baseURL string) *Manager {
	if baseURL == "" {
		baseURL = DefaultBaseURL
	}
	return &Manager{
		dir:        dir,
		baseURL:    strings.TrimSuffix(baseURL, "/"),
		asnBaseURL: DefaultASNBaseURL,
		client:     &http.Client{Timeout: 60 * time.Second},
		status:     map[string]CountryStatus{},
	}
}

// SetASNBaseURL overrides where the ip2asn dataset is fetched from; empty
// keeps the iptoasn.com default. Like baseURL it is read once at boot —
// call it before the first Refresh, and changing it at runtime requires a
// restart.
func (m *Manager) SetASNBaseURL(u string) {
	if u == "" {
		return
	}
	m.asnBaseURL = strings.TrimSuffix(u, "/")
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
	m.mu.Lock()
	m.lastRefresh = time.Now()
	m.mu.Unlock()
	return b, firstErr
}

// LastRefresh returns when the most recent Refresh attempt finished (zero if
// Refresh has never run).
func (m *Manager) LastRefresh() time.Time {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.lastRefresh
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
	slices.SortFunc(out, func(a, b CountryStatus) int { return cmp.Compare(a.Code, b.Code) })
	return out
}

// fetchCountry downloads (or loads from cache) both family lists for cc.
// ipverse keeps its per-country directories lowercase ("country/ru/"), so
// the code is lowercased for the URL regardless of how it was configured.
func (m *Manager) fetchCountry(ctx context.Context, cc string) ([]byte, []byte, error) {
	// Country codes are ISO 3166-1 alpha-2; anything longer (e.g. a path
	// separator) would be a traversal attempt on the cache dir (G703).
	if len(cc) != 2 {
		return nil, nil, fmt.Errorf("invalid country code %q", cc)
	}
	dir := strings.ToLower(cc)
	v4, err4 := m.fetchURL(ctx, m.baseURL+"/"+dir+"/ipv4-aggregated.txt", filepath.Join(m.dir, cc+".ipv4.txt"))
	v6, err6 := m.fetchURL(ctx, m.baseURL+"/"+dir+"/ipv6-aggregated.txt", filepath.Join(m.dir, cc+".ipv6.txt"))
	if err4 != nil && err6 != nil {
		return nil, nil, fmt.Errorf("country %s: ipv4: %v; ipv6: %v", cc, err4, err6)
	}
	return v4, v6, nil
}

// fetchURL returns url's content, persisting it to cachePath; on a download
// failure it falls back to the cached copy, failing only when there is none.
func (m *Manager) fetchURL(ctx context.Context, url, cachePath string) ([]byte, error) {
	if after, ok := strings.CutPrefix(url, "file://"); ok {
		content, err := os.ReadFile(after)
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
	//nolint:gosec // G703: path is built only from validated 2-letter country
	// codes (see fetchCountry), joined under m.dir.
	return os.WriteFile(path, content, 0o600)
}

// RefreshASN downloads the IP→ASN dataset (iptoasn.com by default — the
// same free, no-key, download-and-cache model as the country lists) and
// returns two tables pruned to exactly the configured ASNs: the ranges of
// the allow-listed ASNs and of the block-listed ASNs. When neither list is
// configured both are nil and nothing is fetched. The pruned ranges are
// also persisted as CIDR lists (asn-allowed.txt / asn-blocked.txt) under
// the data dir so buildGeo's firewall pass can exempt allowed ISPs and
// drop blocked ones at the packet level, mirroring the country files. A
// download failure falls back to the last cached copy, failing only when
// there is none.
func (m *Manager) RefreshASN(ctx context.Context, allowASNs, blockASNs []string) (allow, block *ASNTable, err error) {
	// Serialised like Refresh: boot, the config-save rebuild and the
	// auto-refresh goroutine can overlap, and concurrent writes to the same
	// cache files must not interleave.
	m.refreshMu.Lock()
	defer m.refreshMu.Unlock()
	allowSet, blockSet := map[uint32]bool{}, map[uint32]bool{}
	for _, s := range allowASNs {
		if n, ok := ParseASN(s); ok {
			allowSet[n] = true
		}
	}
	for _, s := range blockASNs {
		if n, ok := ParseASN(s); ok {
			blockSet[n] = true
		}
	}
	if len(allowSet) == 0 && len(blockSet) == 0 {
		// Clear any firewall files left over from an earlier configuration
		// so a removed ASN list stops exempting/blocking at the packet
		// level, not just at DNS.
		_ = m.persistASNCIDRs(nil, nil)
		return nil, nil, nil
	}
	v4, err := m.fetchASNFile(ctx, m.asnBaseURL+"/"+asnV4File, filepath.Join(m.dir, asnV4File))
	if err != nil {
		return nil, nil, fmt.Errorf("asn v4: %w", err)
	}
	v6, err := m.fetchASNFile(ctx, m.asnBaseURL+"/"+asnV6File, filepath.Join(m.dir, asnV6File))
	if err != nil {
		return nil, nil, fmt.Errorf("asn v6: %w", err)
	}
	allow, block, err = LoadASNTables(v4, v6, allowSet, blockSet)
	if err != nil {
		return nil, nil, err
	}
	// The firewall files are best-effort, like the country-list persist: a
	// write failure leaves the DNS-level ASN rules fully enforced, and the
	// firewall pass simply reads nothing.
	_ = m.persistASNCIDRs(allow, block)
	return allow, block, nil
}

// persistASNCIDRs writes the pruned allow/block ASN ranges as CIDR lists
// the firewall can consume; a nil table removes its file so a list removed
// from the config stops being enforced at the packet level.
func (m *Manager) persistASNCIDRs(allow, block *ASNTable) error {
	if m.dir == "" {
		return nil
	}
	if err := m.persistASNSide(allow, "asn-allowed.txt"); err != nil {
		return err
	}
	return m.persistASNSide(block, "asn-blocked.txt")
}

func (m *Manager) persistASNSide(t *ASNTable, name string) error {
	path := filepath.Join(m.dir, name)
	if t == nil {
		_ = os.Remove(path) // stale file from an earlier configuration
		return nil
	}
	return m.persist(path, []byte(strings.Join(t.CIDRs(), "\n")+"\n"))
}

// fetchASNFile returns url's content — downloading it like the country
// lists, or falling back to the cached copy on failure — decompressed if it
// carries the gzip magic (the ip2asn files ship gzipped). The decompressed
// form is persisted, so a later cache load skips the decompress step.
// file:// sources are supported like the country lists.
func (m *Manager) fetchASNFile(ctx context.Context, url, cachePath string) ([]byte, error) {
	var content []byte
	var err error
	if after, ok := strings.CutPrefix(url, "file://"); ok {
		content, err = os.ReadFile(after)
	} else {
		content, err = m.download(ctx, url)
		if err != nil {
			if cached, cerr := os.ReadFile(cachePath); cerr == nil {
				content, err = cached, nil
			}
		}
	}
	if err != nil {
		return nil, err
	}
	content, err = gunzipIfNeeded(content)
	if err != nil {
		return nil, err
	}
	_ = m.persist(cachePath, content)
	return content, nil
}

// gunzipIfNeeded returns content unchanged when it is not gzip, otherwise
// decompresses it.
func gunzipIfNeeded(content []byte) ([]byte, error) {
	if len(content) < 2 || content[0] != 0x1f || content[1] != 0x8b {
		return content, nil
	}
	r, err := gzip.NewReader(bytes.NewReader(content))
	if err != nil {
		return nil, err
	}
	defer r.Close()
	// The uncompressed v4 dataset is ~150 MB; the cap is generous slack.
	return io.ReadAll(io.LimitReader(r, 512<<20))
}
