// Package firewall installs country-based packet filtering on the host's
// native firewall. It is the packet-level complement to the DNS handler's
// geo blocking: the same blocked-country CIDR lists (cached under the geo
// data dir) are turned into a DROP for all new inbound traffic, while
// allowlisted IPs/CIDRs and already-established connections are always
// accepted.
//
// The backend is chosen automatically from what the system actually has:
// nftables when the nft binary is present, otherwise iptables + ipset.
// Every object the package creates is namespaced under "irongrid" so Clear
// can remove exactly what Apply installed, and nothing else.
package firewall

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
)

const (
	// nftTable is the nftables table + base chain (hook input, priority 0,
	// policy accept so non-blocked traffic falls through to the rest of the
	// stack unchanged).
	nftTable = "inet irongrid"
	nftChain = "geo_input"

	// iptables path: one jump rule in INPUT pointing at a dedicated chain,
	// with the country CIDRs kept in ipsets (a single rule + a set beats
	// thousands of per-CIDR rules).
	iptChain = "irongrid-geo"

	ipsetV4      = "irongrid_geo_v4"
	ipsetV6      = "irongrid_geo_v6"
	ipsetAllowV4 = "irongrid_geo_allow_v4"
	ipsetAllowV6 = "irongrid_geo_allow_v6"
)

// Runner abstracts process execution so tests can record the exact commands
// the package issues without touching the real firewall.
type Runner interface {
	LookPath(name string) (string, error)
	Run(name string, args ...string) error
	RunStdin(name string, args []string, stdin []byte) error
}

type execRunner struct{}

func (execRunner) LookPath(name string) (string, error) { return exec.LookPath(name) }

func (execRunner) Run(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s %s: %w (%s)", name, strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return nil
}

func (execRunner) RunStdin(name string, args []string, stdin []byte) error {
	cmd := exec.Command(name, args...)
	cmd.Stdin = bytes.NewReader(stdin)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s %s: %w (%s)", name, strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return nil
}

// Manager installs and removes the country firewall rules. It is safe for
// concurrent use: Apply/Clear/Status all take the same lock, so overlapping
// callers (main's rebuild path and the API status handler) can't corrupt
// backend detection or interleave rule updates.
type Manager struct {
	mu      sync.Mutex
	runner  Runner
	backend string // "nft" | "iptables"; empty = auto-detect on first use
}

// New returns a Manager backed by the system's binaries.
func New() *Manager { return &Manager{runner: execRunner{}} }

// NewWithRunner returns a Manager with an injected runner (tests).
func NewWithRunner(r Runner) *Manager { return &Manager{runner: r} }

// detect picks the backend this system can actually drive: nftables when
// available, otherwise iptables (which also needs ipset for the set-based
// approach, and ip6tables for the IPv6 half of the rules). The choice is
// memoised so Apply/Clear/Status agree. Callers hold m.mu.
func (m *Manager) detect() (string, error) {
	if m.backend != "" {
		return m.backend, nil
	}
	if _, err := m.runner.LookPath("nft"); err == nil {
		m.backend = "nft"
		return m.backend, nil
	}
	if _, err := m.runner.LookPath("ipset"); err == nil {
		if _, err := m.runner.LookPath("iptables"); err == nil {
			if _, err := m.runner.LookPath("ip6tables"); err == nil {
				m.backend = "iptables"
				return m.backend, nil
			}
		}
	}
	return "", fmt.Errorf("no supported firewall backend found — install nftables, or ipset + iptables + ip6tables (required for country sets)")
}

// Apply programs the firewall to drop all new inbound traffic from the given
// countries, reading their cached CIDR lists from dir (the geo data dir,
// populated by the geoip Manager). Allowlisted IPs/CIDRs always pass and
// established connections are never interrupted. Returns the backend used
// ("nft" or "iptables"). Repeated calls are idempotent — each Apply rebuilds
// the rules from the current data.
func (m *Manager) Apply(countries, allowlist []string, dir string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	backend, err := m.detect()
	if err != nil {
		return "", err
	}
	v4, v6 := loadCountryCIDRs(dir, countries)
	if len(v4) == 0 && len(v6) == 0 {
		return backend, fmt.Errorf("no cached country CIDRs found in %s — refresh geo data first", dir)
	}
	a4, a6 := classifyAllowlist(allowlist)
	switch backend {
	case "nft":
		return backend, m.applyNft(v4, v6, a4, a6)
	case "iptables":
		return backend, m.applyIptables(v4, v6, a4, a6)
	}
	return backend, fmt.Errorf("unsupported backend %q", backend)
}

// Clear removes every rule and set Apply installed. Safe to call when
// nothing is installed (errors from missing objects are ignored).
func (m *Manager) Clear() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	backend, err := m.detect()
	if err != nil {
		return err
	}
	switch backend {
	case "nft":
		return m.clearNft()
	case "iptables":
		return m.clearIptables()
	}
	return nil
}

// Status reports the backend and whether the country rules are currently
// installed.
func (m *Manager) Status() (backend string, active bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	backend, err := m.detect()
	if err != nil {
		return "", false
	}
	switch backend {
	case "nft":
		if err := m.runner.Run("nft", "list", "table", nftTable); err == nil {
			return backend, true
		}
	case "iptables":
		if err := m.runner.Run("iptables", "-C", "INPUT", "-j", iptChain); err == nil {
			return backend, true
		}
	}
	return backend, false
}

// ---- nftables backend ----

func (m *Manager) applyNft(v4, v6, a4, a6 []string) error {
	// Create is idempotent-intent: re-running reports "File exists", which
	// is fine — the flush below rebuilds the contents anyway.
	_ = m.runner.Run("nft", "add", "table", nftTable)
	_ = m.runner.Run("nft", "add", "chain", nftTable, nftChain, "{ type filter hook input priority 0; policy accept; }")
	for _, set := range []string{"geo_v4", "geo_v6", "geo_allow_v4", "geo_allow_v6"} {
		fam := "ipv4_addr"
		if strings.HasSuffix(set, "_v6") {
			fam = "ipv6_addr"
		}
		_ = m.runner.Run("nft", "add", "set", nftTable, set, fmt.Sprintf("{ type %s; flags interval; auto-merge; }", fam))
	}
	_ = m.runner.Run("nft", "flush", "chain", nftTable, nftChain)
	for _, set := range []string{"geo_v4", "geo_v6", "geo_allow_v4", "geo_allow_v6"} {
		_ = m.runner.Run("nft", "flush", "set", nftTable, set)
	}

	// Order matters: the country DROPs must come BEFORE the
	// established/related ACCEPT. A client that held an ESTABLISHED
	// conntrack flow when the rules were applied (e.g. it was querying
	// before geo blocking went live) would otherwise be exempted by the
	// first rule forever: the DNS server answers geo-blocked queries with
	// REFUSED, and each reply refreshes the conntrack timer, keeping the
	// flow ESTABLISHED and matching the accept — so the DROP never fires.
	// Dropping blocked countries first closes that loop.
	var rules []string
	rules = append(rules, `iif "lo" accept`)
	if len(a4) > 0 {
		rules = append(rules, "ip saddr @geo_allow_v4 accept")
	}
	if len(a6) > 0 {
		rules = append(rules, "ip6 saddr @geo_allow_v6 accept")
	}
	if len(v4) > 0 {
		rules = append(rules, "ip saddr @geo_v4 drop")
	}
	if len(v6) > 0 {
		rules = append(rules, "ip6 saddr @geo_v6 drop")
	}
	// Established/related connections pass for everyone else, after the
	// country DROPs above have had their say.
	rules = append(rules, "ct state established,related accept")
	for _, r := range rules {
		if err := m.runner.Run("nft", "add", "rule", nftTable, nftChain, r); err != nil {
			return err
		}
	}
	// Bulk-load the sets; batches keep each command far below ARG_MAX even
	// for the largest countries (~130 KB of CIDRs).
	for _, set := range []struct {
		name string
		elts []string
	}{{"geo_v4", v4}, {"geo_v6", v6}, {"geo_allow_v4", a4}, {"geo_allow_v6", a6}} {
		for start := 0; start < len(set.elts); start += 500 {
			end := start + 500
			if end > len(set.elts) {
				end = len(set.elts)
			}
			payload := strings.Join(set.elts[start:end], ", ")
			if err := m.runner.Run("nft", "add", "element", nftTable, set.name, "{ "+payload+" }"); err != nil {
				return err
			}
		}
	}
	return nil
}

func (m *Manager) clearNft() error {
	// Missing table → "No such file or directory", which is the desired end
	// state; ignore it.
	_ = m.runner.Run("nft", "delete", "table", nftTable)
	return nil
}

// ---- iptables + ipset backend ----

func (m *Manager) applyIptables(v4, v6, a4, a6 []string) error {
	for _, s := range []struct{ name, family string }{
		{ipsetV4, "inet"}, {ipsetV6, "inet6"}, {ipsetAllowV4, "inet"}, {ipsetAllowV6, "inet6"},
	} {
		_ = m.runner.Run("ipset", "create", s.name, "hash:net", "family", s.family, "hashsize", "4096", "maxelem", "131072", "-exist")
		_ = m.runner.Run("ipset", "flush", s.name)
	}
	if err := m.restoreIpset(ipsetV4, v4); err != nil {
		return err
	}
	if err := m.restoreIpset(ipsetV6, v6); err != nil {
		return err
	}
	if err := m.restoreIpset(ipsetAllowV4, a4); err != nil {
		return err
	}
	if err := m.restoreIpset(ipsetAllowV6, a6); err != nil {
		return err
	}

	// One dedicated chain per family, jumped from INPUT; rebuilt each Apply.
	for _, bin := range []string{"iptables", "ip6tables"} {
		_ = m.runner.Run(bin, "-N", iptChain)
		_ = m.runner.Run(bin, "-F", iptChain)
	}
	// Same ordering as the nft backend: country DROPs before the
	// established/related ACCEPT, so a pre-existing conntrack flow can't
	// exempt a blocked client forever (each REFUSED reply would refresh the
	// flow timer and keep it matching the accept).
	if len(a4) > 0 {
		_ = m.runner.Run("iptables", "-A", iptChain, "-m", "set", "--match-set", ipsetAllowV4, "src", "-j", "ACCEPT")
	}
	if len(a6) > 0 {
		_ = m.runner.Run("ip6tables", "-A", iptChain, "-m", "set", "--match-set", ipsetAllowV6, "src", "-j", "ACCEPT")
	}
	if len(v4) > 0 {
		_ = m.runner.Run("iptables", "-A", iptChain, "-m", "set", "--match-set", ipsetV4, "src", "-j", "DROP")
	}
	if len(v6) > 0 {
		_ = m.runner.Run("ip6tables", "-A", iptChain, "-m", "set", "--match-set", ipsetV6, "src", "-j", "DROP")
	}
	_ = m.runner.Run("iptables", "-A", iptChain, "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT")
	_ = m.runner.Run("ip6tables", "-A", iptChain, "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT")
	// Single jump from INPUT; -C check keeps it idempotent across applies.
	if err := m.runner.Run("iptables", "-C", "INPUT", "-j", iptChain); err != nil {
		if err := m.runner.Run("iptables", "-I", "INPUT", "1", "-j", iptChain); err != nil {
			return err
		}
	}
	if err := m.runner.Run("ip6tables", "-C", "INPUT", "-j", iptChain); err != nil {
		if err := m.runner.Run("ip6tables", "-I", "INPUT", "1", "-j", iptChain); err != nil {
			return err
		}
	}
	return nil
}

// restoreIpset loads set entries in one ipset restore call (chunked), far
// cheaper than one add command per CIDR.
func (m *Manager) restoreIpset(set string, elts []string) error {
	for start := 0; start < len(elts); start += 1000 {
		end := start + 1000
		if end > len(elts) {
			end = len(elts)
		}
		var buf strings.Builder
		for _, e := range elts[start:end] {
			buf.WriteString("add " + set + " " + e + "\n")
		}
		if err := m.runner.RunStdin("ipset", []string{"restore", "-exist"}, []byte(buf.String())); err != nil {
			return err
		}
	}
	return nil
}

func (m *Manager) clearIptables() error {
	_ = m.runner.Run("iptables", "-D", "INPUT", "-j", iptChain)
	_ = m.runner.Run("ip6tables", "-D", "INPUT", "-j", iptChain)
	_ = m.runner.Run("iptables", "-F", iptChain)
	_ = m.runner.Run("ip6tables", "-F", iptChain)
	_ = m.runner.Run("iptables", "-X", iptChain)
	_ = m.runner.Run("ip6tables", "-X", iptChain)
	for _, s := range []string{ipsetV4, ipsetV6, ipsetAllowV4, ipsetAllowV6} {
		_ = m.runner.Run("ipset", "destroy", s)
	}
	return nil
}

// ---- data helpers ----

// loadCountryCIDRs reads the cached CIDR lists for the countries from dir
// (files "<CC>.ipv4.txt" / "<CC>.ipv6.txt" as persisted by the geoip
// Manager). Families with no cached file are skipped.
func loadCountryCIDRs(dir string, countries []string) (v4, v6 []string) {
	for _, code := range countries {
		cc := strings.ToUpper(strings.TrimSpace(code))
		if cc == "" {
			continue
		}
		if d, err := os.ReadFile(filepath.Join(dir, cc+".ipv4.txt")); err == nil {
			v4 = append(v4, parseCIDRs(string(d))...)
		}
		if d, err := os.ReadFile(filepath.Join(dir, cc+".ipv6.txt")); err == nil {
			v6 = append(v6, parseCIDRs(string(d))...)
		}
	}
	return
}

// parseCIDRs extracts CIDR prefixes from a list file, skipping comment lines
// ('#' or ';' prefix or trailing) and blanks — the same format the
// ipverse/rir-ip aggregates use.
func parseCIDRs(s string) []string {
	var out []string
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if i := strings.IndexAny(line, "#;"); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		if line != "" {
			out = append(out, line)
		}
	}
	return out
}

// classifyAllowlist splits allowlist entries (IPs or CIDRs) into v4 and v6.
func classifyAllowlist(entries []string) (v4, v6 []string) {
	for _, e := range entries {
		e = strings.TrimSpace(e)
		if e == "" {
			continue
		}
		var ip net.IP
		if parsed, _, err := net.ParseCIDR(e); err == nil {
			ip = parsed
		} else {
			ip = net.ParseIP(e)
		}
		if ip == nil {
			continue
		}
		if ip.To4() != nil {
			v4 = append(v4, e)
		} else {
			v6 = append(v6, e)
		}
	}
	return
}
