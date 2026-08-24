package geoip

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"

	"github.com/eoghan2t9/Irongrid-DNS/internal/dnsname"
)

// Banner blocks specific client IPs/CIDRs and auto-blocks the clients that
// query configured "honeypot" domains. Configured entries come from config;
// honeypot-triggered auto-blocks persist to a file so they survive restarts
// and config reloads (each rebuild constructs a fresh Banner and re-reads
// the file). It is safe for concurrent use: the DNS handler checks Blocked
// and LookupHoneypot on the hot path while the API lists and unblocks.
type Banner struct {
	mu        sync.RWMutex
	nets      []*net.IPNet    // everything currently blocked (configured + auto)
	raw       map[string]bool // canonical raw forms (List / firewall / persistence)
	auto      map[string]bool // raw entries added at runtime (unblockable)
	honeypots map[string]bool // lowercase honeypot domains, no trailing dot
	path      string          // persistence file for auto-blocked entries
	// allow holds the never-blocked client IPs/CIDRs. An allowlisted client
	// passes every block source: geo countries, the configured IP list, and
	// honeypot auto-blocks (a honeypot hit refuses the query but never
	// auto-blocks or firewall-drops an allowlisted source). This is what
	// makes the operator's own servers genuinely whitelisted.
	allow []*net.IPNet
	// asnAllow/asnBlock are the pruned IP→ASN tables for the configured
	// allow-listed and block-listed ASNs (nil disables each side). An
	// allow-listed ISP's client passes every block source exactly like a
	// CIDR-allowlisted one; a block-listed ISP's client is always blocked.
	// Set via SetASNs by the caller that also wires the geo Blocker.
	asnAllow *ASNTable
	asnBlock *ASNTable

	// OnBlock is invoked (never under the lock) after a honeypot hit
	// auto-blocks a client, so main can push the IP into the host firewall.
	OnBlock func(ip string)
}

// NewBanner returns a banner that always blocks the configured IPs/CIDRs,
// never blocks the allowlisted IPs/CIDRs, and treats the configured domains
// as honeypots. Runtime auto-blocks are loaded from path when present
// (best-effort; a missing file is fine). Allowlist entries are honoured over
// the configured IP list and persisted auto-blocks alike.
func NewBanner(path string, allowlist, ips, honeypots []string) *Banner {
	b := &Banner{
		raw:       map[string]bool{},
		auto:      map[string]bool{},
		honeypots: map[string]bool{},
		path:      path,
	}
	for _, e := range allowlist {
		b.addAllow(e)
	}
	for _, e := range ips {
		b.addRaw(strings.TrimSpace(e), false)
	}
	for _, d := range honeypots {
		if d = dnsname.CanonicalDomain(d); d != "" {
			b.honeypots[d] = true
		}
	}
	b.loadAuto()
	return b
}

// addRaw parses and records a raw entry (IP or CIDR), skipping invalid
// entries. runtime marks entries added by honeypot hits (unblockable).
func (b *Banner) addRaw(e string, runtime bool) {
	if e == "" {
		return
	}
	_, n, err := net.ParseCIDR(e)
	if err != nil {
		ip := net.ParseIP(e)
		if ip == nil {
			return
		}
		bits := 32
		if ip.To4() == nil {
			bits = 128
		}
		n = &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)}
		e = ip.String()
	} else {
		// Store the canonical form (aligned network + prefix): equivalent
		// entries like 10.0.0.1/8 and 10.0.0.0/8 dedupe to one, and the
		// firewall always receives clean, aligned prefixes.
		e = n.String()
	}
	if b.raw[e] {
		return
	}
	b.raw[e] = true
	if runtime {
		b.auto[e] = true
	}
	b.nets = append(b.nets, n)
}

// addAllow parses and records an allowlist entry (IP or CIDR), skipping
// invalid entries.
func (b *Banner) addAllow(e string) {
	e = strings.TrimSpace(e)
	if e == "" {
		return
	}
	_, n, err := net.ParseCIDR(e)
	if err != nil {
		ip := net.ParseIP(e)
		if ip == nil {
			return
		}
		bits := 32
		if ip.To4() == nil {
			bits = 128
		}
		n = &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)}
	}
	b.allow = append(b.allow, n)
}

// SetASNs installs the allow/block ASN tables (nil disables each side).
// It also re-prunes persisted auto-blocks: SetASNs runs after NewBanner
// (which already loaded the persisted file), so a source that is only now
// known to be ASN-allowlisted is dropped from the block list the same way
// the construction-time CIDR-allowlist pruning drops CIDR-allowlisted
// sources.
func (b *Banner) SetASNs(allow, block *ASNTable) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.asnAllow, b.asnBlock = allow, block
	b.pruneAutoLocked()
}

// allowed reports whether ip is on the allowlist; caller holds the lock.
func (b *Banner) allowed(ip net.IP) bool {
	for _, n := range b.allow {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// asnAllowed reports whether ip belongs to an allow-listed ASN; caller
// holds the lock.
func (b *Banner) asnAllowed(ip net.IP) bool {
	return b.asnAllow != nil && b.asnAllow.Contains(ip)
}

// asnBlocked reports whether ip belongs to a block-listed ASN; caller holds
// the lock.
func (b *Banner) asnBlocked(ip net.IP) bool {
	return b.asnBlock != nil && b.asnBlock.Contains(ip)
}

// Blocked reports whether clientIP is on the banner's block list (see
// BlockedAs for the blocking source).
func (b *Banner) Blocked(clientIP string) bool {
	blocked, _ := b.BlockedAs(clientIP)
	return blocked
}

// BlockedAs reports whether clientIP is on the banner's block list and why:
// "asn" when a block-listed ASN refused the client, "ip" when an explicit
// IP/CIDR entry or a persisted honeypot auto-block did. Allowlisted clients
// are never blocked — by ASN allowlist or the configured IP list — and a
// block-listed ASN's client is always blocked, even without an explicit IP
// entry.
func (b *Banner) BlockedAs(clientIP string) (blocked bool, source string) {
	ip := net.ParseIP(clientIP)
	if ip == nil {
		return false, ""
	}
	b.mu.RLock()
	defer b.mu.RUnlock()
	if b.asnAllowed(ip) {
		return false, ""
	}
	if b.allowed(ip) {
		return false, ""
	}
	for _, n := range b.nets {
		if n.Contains(ip) {
			return true, "ip"
		}
	}
	if b.asnBlocked(ip) {
		return true, "asn"
	}
	return false, ""
}

// LookupHoneypot reports whether qname (lowercase, no trailing dot) is a
// configured honeypot domain or falls under one: a trap configured as
// "trap.example.com" also catches "sub.trap.example.com". Subtree matching
// matters because DDoS floods almost always randomise the label under the
// attacked domain (x1.example.com, a3b9.example.com, …), and the trap must
// refuse those before they ever reach an upstream. The bare top-level label
// (e.g. "com") is never tested, so a single-label trap can't swallow an
// entire TLD.
func (b *Banner) LookupHoneypot(qname string) bool {
	b.mu.RLock()
	defer b.mu.RUnlock()
	if b.honeypots[qname] {
		return true
	}
	// Walk parent suffixes (Go string slicing, zero allocation) and stop
	// before the bare top-level label, mirroring the blocklist engine's
	// ancestor walk.
	lastDot := strings.LastIndexByte(qname, '.')
	for i := range lastDot {
		if qname[i] != '.' {
			continue
		}
		if b.honeypots[qname[i+1:]] {
			return true
		}
	}
	return false
}

// Block auto-blocks a client IP after a honeypot hit: it is added to the
// in-memory set, persisted, and OnBlock is invoked so the firewall can drop
// it immediately. Bare IPs only; CIDRs are not auto-added. Already-blocked
// entries are a no-op (returns nil). Unblockable via Unblock. The caller
// decides whether the source is trustworthy: the DNS handler only auto-blocks
// clients over connection-oriented transports (TCP/DoT/DoH/DoQ), never a
// spoofable UDP source.
func (b *Banner) Block(ip string) error {
	parsed := net.ParseIP(strings.TrimSpace(ip))
	if parsed == nil {
		return fmt.Errorf("honeypot block: %q is not an IP", ip)
	}
	raw := parsed.String()
	b.mu.Lock()
	// An allowlisted source — by CIDR or by ASN — is never auto-blocked:
	// the honeypot query is refused at the DNS layer but the client (the
	// operator's own server, or an unblocked ISP) must not be dropped from
	// the network.
	if b.allowed(parsed) || b.asnAllowed(parsed) {
		b.mu.Unlock()
		return nil
	}
	if b.raw[raw] {
		b.mu.Unlock()
		return nil
	}
	b.addRaw(raw, true)
	entries := b.autoListLocked()
	b.mu.Unlock()
	if err := b.persist(entries); err != nil {
		return err
	}
	if b.OnBlock != nil {
		b.OnBlock(raw)
	}
	return nil
}

// List returns every blocked entry (configured + auto), sorted — the full
// set the host firewall should drop.
func (b *Banner) List() []string {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.rawListLocked()
}

// AutoList returns only the runtime (honeypot-auto-blocked) entries, sorted
// — the ones the dashboard can unblock. Configured IPs are excluded: they
// come from config and are reinstated on every rebuild.
func (b *Banner) AutoList() []string {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.autoListLocked()
}

// Unblock removes a runtime auto-blocked IP. Configured entries are left
// alone (they come from config and are reinstated on the next rebuild).
func (b *Banner) Unblock(ip string) error {
	parsed := net.ParseIP(strings.TrimSpace(ip))
	if parsed == nil {
		return fmt.Errorf("unblock: %q is not an IP", ip)
	}
	raw := parsed.String()
	b.mu.Lock()
	if !b.auto[raw] {
		b.mu.Unlock()
		return nil // not a runtime block; nothing to do
	}
	delete(b.auto, raw)
	delete(b.raw, raw)
	// Rebuild nets from the remaining raw entries.
	b.nets = b.nets[:0]
	for e := range b.raw {
		_, n, err := net.ParseCIDR(e)
		if err != nil {
			if p := net.ParseIP(e); p != nil {
				bits := 32
				if p.To4() == nil {
					bits = 128
				}
				n = &net.IPNet{IP: p, Mask: net.CIDRMask(bits, bits)}
			}
		}
		if n != nil {
			b.nets = append(b.nets, n)
		}
	}
	entries := b.autoListLocked()
	b.mu.Unlock()
	// Persist outside the lock, like Block: a disk write must never stall
	// the DNS hot path (Blocked/LookupHoneypot take only the read lock).
	return b.persist(entries)
}

// rawListLocked returns the sorted raw entries; caller holds the lock.
func (b *Banner) rawListLocked() []string {
	out := make([]string, 0, len(b.raw))
	for e := range b.raw {
		out = append(out, e)
	}
	slices.Sort(out)
	return out
}

// autoListLocked returns the sorted runtime entries; caller holds the lock.
func (b *Banner) autoListLocked() []string {
	out := make([]string, 0, len(b.auto))
	for e := range b.auto {
		out = append(out, e)
	}
	slices.Sort(out)
	return out
}

// loadAuto re-reads the persisted auto-blocked entries at construction.
func (b *Banner) loadAuto() {
	if b.path == "" {
		return
	}
	data, err := os.ReadFile(b.path)
	if err != nil {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	for ln := range strings.SplitSeq(string(data), "\n") {
		ln = strings.TrimSpace(ln)
		if ln == "" || strings.HasPrefix(ln, "#") {
			continue
		}
		b.addRaw(ln, true)
	}
	b.pruneAutoLocked()
}

// pruneAutoLocked drops auto-blocked entries whose source is allowlisted
// (by CIDR or by ASN) and rebuilds the net list. An operator's own server
// that was auto-blocked before being allowlisted must not stay on the list
// — it would keep showing as blocked and keep feeding the firewall. The
// persisted file is left alone; the entry is simply never loaded or kept.
// Caller holds the lock.
func (b *Banner) pruneAutoLocked() {
	changed := false
	for e := range b.auto {
		ip := net.ParseIP(e)
		if ip != nil && (b.allowed(ip) || b.asnAllowed(ip)) {
			delete(b.auto, e)
			delete(b.raw, e)
			changed = true
		}
	}
	if !changed {
		return
	}
	// Rebuild nets from the remaining raw entries (configured IPs included).
	b.nets = b.nets[:0]
	for e := range b.raw {
		_, n, err := net.ParseCIDR(e)
		if err != nil {
			if p := net.ParseIP(e); p != nil {
				bits := 32
				if p.To4() == nil {
					bits = 128
				}
				n = &net.IPNet{IP: p, Mask: net.CIDRMask(bits, bits)}
			}
		}
		if n != nil {
			b.nets = append(b.nets, n)
		}
	}
}

// persist rewrites the auto-blocked entries file. A write failure is
// reported but never fatal — the in-memory set still enforces the block.
func (b *Banner) persist(entries []string) error {
	if b.path == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(b.path), 0o755); err != nil {
		return err
	}
	var sb strings.Builder
	sb.WriteString("# Auto-blocked clients (honeypot hits) — managed by Irongrid. One IP per line.\n")
	for _, e := range entries {
		sb.WriteString(e + "\n")
	}
	return os.WriteFile(b.path, []byte(sb.String()), 0o600)
}
