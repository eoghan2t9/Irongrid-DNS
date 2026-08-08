package geoip

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBannerConfiguredIPs(t *testing.T) {
	b := NewBanner("", nil, []string{"38.11.106.3", "203.0.113.0/24", "2001:db8::/32", "not-an-ip"}, nil)
	if !b.Blocked("38.11.106.3") {
		t.Error("explicit IP must be blocked")
	}
	if !b.Blocked("203.0.113.77") {
		t.Error("configured CIDR must be blocked")
	}
	if !b.Blocked("2001:db8::1") {
		t.Error("configured v6 CIDR must be blocked")
	}
	if b.Blocked("8.8.8.8") {
		t.Error("unrelated IP must not be blocked")
	}
	if b.Blocked("") || b.Blocked("not-an-ip") {
		t.Error("empty/unparseable clients must never be blocked")
	}
	if got := b.List(); len(got) != 3 {
		t.Fatalf("List() = %v, want the 3 valid configured entries", got)
	}
}

func TestBannerHoneypotAutoBlockPersistsAndReloads(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "blocked-ips.txt")
	var fired []string
	b := NewBanner(path, nil, nil, []string{"trap.example.com."})
	b.OnBlock = func(ip string) { fired = append(fired, ip) }

	if !b.LookupHoneypot("trap.example.com") {
		t.Fatal("honeypot domain must be found (trailing dot stripped, lowercased)")
	}
	// Subtree match: DDoS floods randomise the label under the trap, so a
	// configured trap must catch its subdomains too.
	if !b.LookupHoneypot("sub.trap.example.com") {
		t.Error("honeypot must match subdomains of the trap domain")
	}
	if !b.LookupHoneypot("a.b.trap.example.com") {
		t.Error("honeypot must match deep subdomains of the trap domain")
	}
	// Unrelated names must not match, and the bare TLD must never be tested.
	for _, name := range []string{"example.com", "com", "trap.example.net", "trap.com"} {
		if b.LookupHoneypot(name) {
			t.Errorf("%q must not match the trap", name)
		}
	}

	if err := b.Block("38.11.106.3"); err != nil {
		t.Fatalf("Block: %v", err)
	}
	if !b.Blocked("38.11.106.3") {
		t.Fatal("client not blocked after honeypot hit")
	}
	if len(fired) != 1 || fired[0] != "38.11.106.3" {
		t.Fatalf("OnBlock fired %v, want [38.11.106.3]", fired)
	}
	// Double-block is a no-op (no duplicate firewall push).
	if err := b.Block("38.11.106.3"); err != nil {
		t.Fatalf("second Block: %v", err)
	}
	if len(fired) != 1 {
		t.Fatalf("duplicate block fired OnBlock again: %v", fired)
	}
	// The auto-block is persisted.
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("persisted file missing: %v", err)
	}
	if !strings.Contains(string(data), "38.11.106.3") {
		t.Fatalf("persisted file missing the blocked IP:\n%s", data)
	}
	// A rebuilt banner (config reload / restart) re-reads the file.
	b2 := NewBanner(path, nil, nil, nil)
	if !b2.Blocked("38.11.106.3") {
		t.Fatal("rebuilt banner must reload the persisted auto-block")
	}
	if got := b2.List(); len(got) != 1 || got[0] != "38.11.106.3" {
		t.Fatalf("rebuilt List() = %v", got)
	}
}

func TestBannerUnblock(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "blocked-ips.txt")
	b := NewBanner(path, nil, []string{"198.51.100.7"}, nil)
	if err := b.Block("203.0.113.9"); err != nil {
		t.Fatalf("Block: %v", err)
	}
	if err := b.Unblock("203.0.113.9"); err != nil {
		t.Fatalf("Unblock: %v", err)
	}
	if b.Blocked("203.0.113.9") {
		t.Error("unblocked IP must no longer be blocked")
	}
	if !b.Blocked("198.51.100.7") {
		t.Error("configured IP must survive an unblock of an auto-blocked one")
	}
	if got := b.List(); len(got) != 1 || got[0] != "198.51.100.7" {
		t.Fatalf("List() after unblock = %v, want only the configured entry", got)
	}
	if _, err := os.Stat(path); err == nil {
		data, _ := os.ReadFile(path)
		if strings.Contains(string(data), "203.0.113.9") {
			t.Fatalf("persisted file still holds the unblocked IP:\n%s", data)
		}
	}
	if err := b.Unblock("not-an-ip"); err == nil {
		t.Error("Unblock of a non-IP should fail")
	}
}

// TestBannerAllowlistNeverBlocked verifies that allowlisted clients are
// exempt from every block source: the configured IP list, honeypot
// auto-blocks (Block is a no-op and OnBlock never fires, so the firewall is
// never told to drop them), and persisted auto-block entries left over from
// before the allowlist existed.
func TestBannerAllowlistNeverBlocked(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "blocked-ips.txt")
	var fired []string
	// The same IP is both configured-blocked and allowlisted: allowlist wins.
	b := NewBanner(path, []string{"198.51.100.9"}, []string{"198.51.100.9", "203.0.113.0/24"}, []string{"trap.example.com"})
	b.OnBlock = func(ip string) { fired = append(fired, ip) }
	if b.Blocked("198.51.100.9") {
		t.Fatal("allowlisted client must not be blocked even when configured in ips")
	}
	// A non-allowlisted member of a configured CIDR is still blocked.
	if !b.Blocked("203.0.113.42") {
		t.Fatal("configured CIDR must still block non-allowlisted clients")
	}
	// A honeypot hit from the allowlisted client must not auto-block it.
	if err := b.Block("198.51.100.9"); err != nil {
		t.Fatalf("Block: %v", err)
	}
	if b.Blocked("198.51.100.9") {
		t.Fatal("allowlisted client auto-blocked by a honeypot hit")
	}
	if len(fired) != 0 {
		t.Fatalf("OnBlock fired for an allowlisted client: %v", fired)
	}
	// A honeypot hit from a non-allowlisted client still auto-blocks.
	if err := b.Block("203.0.113.42"); err != nil {
		t.Fatalf("Block non-allowlisted: %v", err)
	}
	if len(fired) != 1 || fired[0] != "203.0.113.42" {
		t.Fatalf("OnBlock fired %v, want [203.0.113.42]", fired)
	}
	if b.Blocked("198.51.100.9") {
		t.Fatal("allowlisted client blocked after another client's honeypot hit")
	}

	// A rebuilt banner (restart) skips a persisted auto-block of the
	// allowlisted IP: it must not load it as blocked or list it.
	if err := os.WriteFile(path, []byte("# auto\n198.51.100.9\n"), 0o644); err != nil {
		t.Fatalf("write file: %v", err)
	}
	b2 := NewBanner(path, []string{"198.51.100.9"}, nil, []string{"trap.example.com"})
	if b2.Blocked("198.51.100.9") {
		t.Fatal("rebuilt banner must not block an allowlisted IP from the persisted file")
	}
	for _, e := range b2.List() {
		if e == "198.51.100.9" {
			t.Fatal("allowlisted IP must not appear in List()")
		}
	}
}

func TestBannerBlockRejectsCIDR(t *testing.T) {
	b := NewBanner("", nil, nil, nil)
	// Auto-blocks are bare IPs only; a CIDR is refused (defence in depth —
	// the handler only ever passes client source IPs).
	if err := b.Block("203.0.113.0/24"); err == nil {
		t.Error("Block of a CIDR should fail")
	}
}
