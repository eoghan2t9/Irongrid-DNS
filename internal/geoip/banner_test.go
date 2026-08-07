package geoip

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBannerConfiguredIPs(t *testing.T) {
	b := NewBanner("", []string{"38.11.106.3", "203.0.113.0/24", "2001:db8::/32", "not-an-ip"}, nil)
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
	b := NewBanner(path, nil, []string{"trap.example.com."})
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
	b2 := NewBanner(path, nil, nil)
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
	b := NewBanner(path, []string{"198.51.100.7"}, nil)
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

func TestBannerBlockRejectsCIDR(t *testing.T) {
	b := NewBanner("", nil, nil)
	// Auto-blocks are bare IPs only; a CIDR is refused (defence in depth —
	// the handler only ever passes client source IPs).
	if err := b.Block("203.0.113.0/24"); err == nil {
		t.Error("Block of a CIDR should fail")
	}
}
