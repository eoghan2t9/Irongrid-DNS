package geoip

import (
	"compress/gzip"
	"net"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func TestParseASN(t *testing.T) {
	cases := []struct {
		in   string
		want uint32
		ok   bool
	}{
		{"AS13335", 13335, true},
		{"13335", 13335, true},
		{"as15169", 15169, true},
		{" AS4134 ", 4134, true},
		{"AS4294967295", 4294967295, true}, // top of the 32-bit ASN space
		{"", 0, false},
		{"AS", 0, false},
		{"AS0", 0, false},
		{"AS4294967296", 0, false}, // out of range
		{"AS13X", 0, false},
		{"AS 13335", 0, false},
		{"-5", 0, false},
	}
	for _, c := range cases {
		got, ok := ParseASN(c.in)
		if ok != c.ok || got != c.want {
			t.Errorf("ParseASN(%q) = %d,%v want %d,%v", c.in, got, ok, c.want, c.ok)
		}
	}
}

// sampleASNData is a tiny ip2asn-style dataset covering both families:
// 15169 (Google), 13335 (Cloudflare), 3257 (GTT) plus ASN-0 junk that must
// never be kept. 203.0.113.0/24 (TEST-NET-3) is deliberately AS13335 so the
// banner tests can exercise an ASN allow beating an explicit block entry.
const sampleASNData = `1.2.3.0	1.2.3.255	15169	US	GOOGLE
8.8.8.0	8.8.8.255	15169	US	GOOGLE
104.16.0.0	104.31.255.255	13335	US	CLOUDFLARENET
91.0.0.0	91.255.255.255	13335	RU	CLOUDFLARE-RU
203.0.113.0	203.0.113.255	13335	US	CLOUDFLARE-TEST
93.0.0.0	93.255.255.255	3257	RU	GTT
10.0.0.0	10.0.0.255	3257	US	GTT-TEST
0.0.0.0	0.255.255.255	0	ZZ	Not routed
2001:4860::	2001:4860:ffff:ffff:ffff:ffff:ffff:ffff	15169	US	GOOGLE-V6
2001:db8::	2001:db8:ffff:ffff:ffff:ffff:ffff:ffff	13335	US	CLOUDFLARE-V6
not a line
`

// TestLoadASNTablesPrunesAndSplits verifies the dataset is pruned to exactly
// the configured ASNs and split into the allow/block sides.
func TestLoadASNTablesPrunesAndSplits(t *testing.T) {
	allow, block, err := LoadASNTables([]byte(sampleASNData), []byte(sampleASNData), map[uint32]bool{13335: true}, map[uint32]bool{3257: true})
	if err != nil {
		t.Fatalf("LoadASNTables: %v", err)
	}
	// Allow side: only AS13335 ranges (v4 + v6), not AS15169.
	if !allow.Contains(net.ParseIP("104.16.0.1")) {
		t.Error("104.16.0.1 (AS13335) should be in the allow table")
	}
	if !allow.Contains(net.ParseIP("91.1.2.3")) {
		t.Error("91.1.2.3 (AS13335) should be in the allow table")
	}
	if allow.Contains(net.ParseIP("8.8.8.8")) {
		t.Error("8.8.8.8 (AS15169) must not leak into the allow table")
	}
	if !allow.Contains(net.ParseIP("2001:db8::1")) {
		t.Error("2001:db8::1 (AS13335 v6) should be in the allow table")
	}
	if allow.Contains(net.ParseIP("2001:4860::1")) {
		t.Error("2001:4860::1 (AS15169 v6) must not leak into the allow table")
	}
	// Block side: only AS3257 ranges.
	if !block.Contains(net.ParseIP("93.0.0.1")) {
		t.Error("93.0.0.1 (AS3257) should be in the block table")
	}
	if !block.Contains(net.ParseIP("10.0.0.5")) {
		t.Error("10.0.0.5 (AS3257) should be in the block table")
	}
	if block.Contains(net.ParseIP("104.16.0.1")) {
		t.Error("104.16.0.1 (AS13335) must not leak into the block table")
	}
	// Unknown IPs and ASN-0 junk must never match.
	for _, tbl := range []*ASNTable{allow, block} {
		if tbl.Contains(net.ParseIP("1.2.3.4")) {
			t.Error("1.2.3.4 (AS15169) must not match either table")
		}
		if tbl.Contains(net.ParseIP("0.1.2.3")) {
			t.Error("ASN-0 space must never be kept")
		}
	}
}

func TestLoadASNTablesEmptyLists(t *testing.T) {
	allow, block, err := LoadASNTables([]byte(sampleASNData), nil, map[uint32]bool{}, map[uint32]bool{})
	if err != nil {
		t.Fatalf("LoadASNTables: %v", err)
	}
	if allow.Contains(net.ParseIP("8.8.8.8")) || block.Contains(net.ParseIP("8.8.8.8")) {
		t.Error("nothing should match with empty keep sets")
	}
}

// TestASNTableCIDRs verifies ranges expand to the minimal aligned CIDR set.
func TestASNTableCIDRs(t *testing.T) {
	allow, _, err := LoadASNTables([]byte(sampleASNData), []byte(sampleASNData), map[uint32]bool{13335: true}, map[uint32]bool{})
	if err != nil {
		t.Fatalf("LoadASNTables: %v", err)
	}
	got := allow.CIDRs()
	want := []string{"91.0.0.0/8", "104.16.0.0/12", "203.0.113.0/24", "2001:db8::/32"}
	if len(got) != len(want) {
		t.Fatalf("CIDRs() = %v, want exactly %v", got, want)
	}
	for _, w := range want {
		if !slices.Contains(got, w) {
			t.Errorf("CIDRs() missing %s (got %v)", w, got)
		}
	}
}

// TestCIDRs4UnalignedRange verifies an unaligned v4 range splits into the
// minimal set of aligned prefixes covering exactly [start,end].
func TestCIDRs4UnalignedRange(t *testing.T) {
	// 10.1.2.5 .. 10.1.2.9 = 5 addresses, not a single prefix: the minimal
	// aligned cover is 10.1.2.5/32 + 10.1.2.6/31 + 10.1.2.8/31.
	start, end := uint32(10)<<24|1<<16|2<<8|5, uint32(10)<<24|1<<16|2<<8|9
	got := cidrs4(start, end)
	if len(got) != 3 {
		t.Fatalf("expected 3 prefixes, got %v", got)
	}
	var nets []*net.IPNet
	for _, g := range got {
		_, n, err := net.ParseCIDR(g)
		if err != nil {
			t.Fatalf("bad CIDR %q: %v", g, err)
		}
		nets = append(nets, n)
	}
	// Every address in [start,end] is covered exactly once; the neighbours
	// outside the range are not covered at all.
	for x := start - 1; x <= end+1; x++ {
		ip := net.IPv4(byte(x>>24), byte(x>>16), byte(x>>8), byte(x))
		n := 0
		for _, p := range nets {
			if p.Contains(ip) {
				n++
			}
		}
		inRange := x >= start && x <= end
		if inRange && n != 1 {
			t.Errorf("%s covered %d times, want exactly 1", ip, n)
		}
		if !inRange && n != 0 {
			t.Errorf("%s covered %d times, want 0", ip, n)
		}
	}
}

// TestCIDRs6UnalignedRange verifies the same for a v6 range.
func TestCIDRs6UnalignedRange(t *testing.T) {
	var start, end [16]byte
	copy(start[:], net.ParseIP("2001:db8:1:2:3:4:5:6").To16())
	copy(end[:], net.ParseIP("2001:db8:1:2:3:4:5:9").To16())
	got := cidrs6(start, end)
	if len(got) != 2 { // ...:5:6/127 + ...:5:8/127
		t.Fatalf("expected 2 prefixes, got %v", got)
	}
	var nets []*net.IPNet
	for _, g := range got {
		_, n, err := net.ParseCIDR(g)
		if err != nil {
			t.Fatalf("bad CIDR %q: %v", g, err)
		}
		nets = append(nets, n)
	}
	// The 4 addresses inside the range are covered exactly once; the two
	// neighbours are not.
	addrs := []string{
		"2001:db8:1:2:3:4:5:5", "2001:db8:1:2:3:4:5:6", "2001:db8:1:2:3:4:5:7",
		"2001:db8:1:2:3:4:5:8", "2001:db8:1:2:3:4:5:9", "2001:db8:1:2:3:4:5:a",
	}
	for i, a := range addrs {
		ip := net.ParseIP(a)
		n := 0
		for _, p := range nets {
			if p.Contains(ip) {
				n++
			}
		}
		inRange := i >= 1 && i <= 4
		if inRange && n != 1 {
			t.Errorf("%s covered %d times, want exactly 1", a, n)
		}
		if !inRange && n != 0 {
			t.Errorf("%s covered %d times, want 0", a, n)
		}
	}
}

// TestBlockerASNRules covers the allow/block ASN precedence inside the geo
// blocker: allow beats country and block; block beats country; both are
// checked before the combined country ranges.
func TestBlockerASNRules(t *testing.T) {
	b := NewBlocker()
	tbl, _ := LoadTable([]byte("93.0.0.0/8\n91.0.0.0/8\n"), nil)
	b.AddTable("RU", tbl)
	if err := b.SetConfig([]string{"RU"}, []string{"5.6.7.8"}); err != nil {
		t.Fatalf("SetConfig: %v", err)
	}
	allow, block, err := LoadASNTables([]byte(sampleASNData), nil, map[uint32]bool{13335: true}, map[uint32]bool{3257: true})
	if err != nil {
		t.Fatalf("LoadASNTables: %v", err)
	}
	b.SetASNs(allow, block)

	// ASN allow beats the country block: 91.0.0.0/8 is RU and AS13335.
	if b.Blocked("91.1.2.3") {
		t.Error("an ASN-allowlisted client inside a blocked country must pass")
	}
	// ASN block beats an absent country: 10.0.0.0/24 is AS3257, not RU.
	if !b.Blocked("10.0.0.5") {
		t.Error("an ASN-blocklisted client must be blocked even outside every blocked country")
	}
	// ASN block and country agree.
	if !b.Blocked("93.0.0.1") {
		t.Error("93.0.0.1 is AS3257 and RU — must be blocked")
	}
	// Unrelated client, not blocked.
	if b.Blocked("8.8.8.8") {
		t.Error("8.8.8.8 must not be blocked")
	}
	// CIDR allowlist still applies.
	if b.Blocked("5.6.7.8") {
		t.Error("CIDR-allowlisted client must pass")
	}
	// Clearing the ASN tables restores plain country behaviour.
	b.SetASNs(nil, nil)
	if !b.Blocked("91.1.2.3") {
		t.Error("with ASN rules cleared, the RU country block must apply again")
	}
	if b.Blocked("10.0.0.5") {
		t.Error("with ASN rules cleared, 10.0.0.5 (not RU) must pass")
	}
}

// TestBannerASNRules covers the banner side: ASN allow beats the explicit
// block list and honeypot auto-blocks; ASN block blocks without an explicit
// IP entry.
func TestBannerASNRules(t *testing.T) {
	allow, block, err := LoadASNTables([]byte(sampleASNData), nil, map[uint32]bool{13335: true}, map[uint32]bool{3257: true})
	if err != nil {
		t.Fatalf("LoadASNTables: %v", err)
	}
	b := NewBanner("", nil, []string{"203.0.113.9", "198.51.100.7"}, []string{"trap.example.com"})
	b.SetASNs(allow, block)

	// Explicit block list entry on a client outside every configured ASN.
	if !b.Blocked("198.51.100.7") {
		t.Error("198.51.100.7 is on the block list — must be blocked")
	}
	// ASN allow beats the explicit block list: 203.0.113.9 is both on the
	// list and AS13335.
	if b.Blocked("203.0.113.9") {
		t.Error("an ASN-allowlisted client must pass even when its IP is on the block list")
	}
	// ASN block without an explicit entry.
	if !b.Blocked("10.0.0.5") {
		t.Error("an ASN-blocklisted client must be blocked without an explicit IP entry")
	}
	// Unrelated client passes.
	if b.Blocked("104.16.0.1") {
		t.Error("104.16.0.1 (AS13335) must not be blocked")
	}
	// An ASN-allowlisted source is never auto-blocked by a honeypot hit —
	// even when its IP is on the explicit block list.
	if err := b.Block("203.0.113.9"); err != nil {
		t.Fatalf("Block: %v", err)
	}
	if b.Blocked("203.0.113.9") {
		t.Error("honeypot auto-block must not block an ASN-allowlisted source")
	}
}

// TestBannerSetASNsPrunesPersistedAutoBlocks verifies that installing the
// ASN tables drops persisted auto-blocks of now-ASN-allowlisted sources.
func TestBannerSetASNsPrunesPersistedAutoBlocks(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "blocked-ips.txt")
	// A persisted auto-block of a Cloudflare (AS13335) address.
	_ = os.WriteFile(path, []byte("104.16.0.1\n"), 0o600)

	allow, _, err := LoadASNTables([]byte(sampleASNData), nil, map[uint32]bool{13335: true}, map[uint32]bool{})
	if err != nil {
		t.Fatalf("LoadASNTables: %v", err)
	}
	b := NewBanner(path, nil, nil, []string{"trap.example.com"})
	if !b.Blocked("104.16.0.1") {
		t.Fatal("the persisted auto-block should be active before SetASNs")
	}
	b.SetASNs(allow, nil)
	if b.Blocked("104.16.0.1") {
		t.Error("SetASNs must prune the persisted auto-block of an ASN-allowlisted source")
	}
	if got := b.AutoList(); len(got) != 0 {
		t.Errorf("auto list = %v, want empty", got)
	}
}

// TestManagerRefreshASN verifies the full refresh path: file:// source,
// gzip decompression, pruning, and the firewall CIDR files.
func TestManagerRefreshASN(t *testing.T) {
	dir := t.TempDir()
	src := t.TempDir()
	// The v4 file is gzipped (as shipped), the v6 file plain — both must
	// parse.
	writeGzip := func(path, content string) {
		t.Helper()
		f, err := os.Create(path)
		if err != nil {
			t.Fatal(err)
		}
		gz := gzip.NewWriter(f)
		if _, err := gz.Write([]byte(content)); err != nil {
			t.Fatal(err)
		}
		if err := gz.Close(); err != nil {
			t.Fatal(err)
		}
		if err := f.Close(); err != nil {
			t.Fatal(err)
		}
	}
	writeGzip(filepath.Join(src, "ip2asn-v4.tsv.gz"), sampleASNData)
	_ = os.WriteFile(filepath.Join(src, "ip2asn-v6.tsv.gz"), []byte(sampleASNData), 0o644)

	m := NewManager(dir, "")
	m.SetASNBaseURL("file://" + src)
	allow, block, err := m.RefreshASN(t.Context(), []string{"AS13335"}, []string{"AS3257"})
	if err != nil {
		t.Fatalf("RefreshASN: %v", err)
	}
	if !allow.Contains(net.ParseIP("104.16.0.1")) || !block.Contains(net.ParseIP("93.0.0.1")) {
		t.Fatal("RefreshASN tables wrong")
	}
	// The pruned CIDR files were persisted for the firewall pass (sorted by
	// range start, v4 before v6).
	allowed, err := os.ReadFile(filepath.Join(dir, "asn-allowed.txt"))
	if err != nil {
		t.Fatalf("asn-allowed.txt not written: %v", err)
	}
	if string(allowed) != "91.0.0.0/8\n104.16.0.0/12\n203.0.113.0/24\n2001:db8::/32\n" {
		t.Errorf("asn-allowed.txt = %q", allowed)
	}
	blocked, err := os.ReadFile(filepath.Join(dir, "asn-blocked.txt"))
	if err != nil {
		t.Fatalf("asn-blocked.txt not written: %v", err)
	}
	if string(blocked) != "10.0.0.0/24\n93.0.0.0/8\n" {
		t.Errorf("asn-blocked.txt = %q", blocked)
	}
	// No ASNs configured: nothing fetched, nil tables, and the earlier
	// firewall files are removed so a cleared list stops being enforced at
	// the packet level.
	allow2, block2, err := m.RefreshASN(t.Context(), nil, nil)
	if err != nil || allow2 != nil || block2 != nil {
		t.Fatalf("empty ASN lists: got %v, %v, %v; want nil,nil,nil", allow2, block2, err)
	}
	if _, err := os.Stat(filepath.Join(dir, "asn-allowed.txt")); err == nil {
		t.Error("asn-allowed.txt should be removed when allow_asns is cleared")
	}
	if _, err := os.Stat(filepath.Join(dir, "asn-blocked.txt")); err == nil {
		t.Error("asn-blocked.txt should be removed when block_asns is cleared")
	}
}

// TestManagerRefreshASNFallbackToCache verifies a dead source still loads
// the cached dataset, and that a dead source with no cache fails.
func TestManagerRefreshASNFallbackToCache(t *testing.T) {
	dir := t.TempDir()
	src := t.TempDir()
	_ = os.WriteFile(filepath.Join(src, "ip2asn-v4.tsv.gz"), []byte(sampleASNData), 0o644)
	_ = os.WriteFile(filepath.Join(src, "ip2asn-v6.tsv.gz"), []byte(sampleASNData), 0o644)

	m := NewManager(dir, "")
	m.SetASNBaseURL("file://" + src)
	if _, _, err := m.RefreshASN(t.Context(), []string{"AS13335"}, nil); err != nil {
		t.Fatalf("seed refresh: %v", err)
	}
	// Now point at a dead source with the same cache dir: the cached copy
	// (already decompressed) must carry the refresh.
	m2 := NewManager(dir, "")
	m2.SetASNBaseURL("http://127.0.0.1:1")
	allow, _, err := m2.RefreshASN(t.Context(), []string{"AS13335"}, nil)
	if err != nil {
		t.Fatalf("refresh should fall back to cache: %v", err)
	}
	if !allow.Contains(net.ParseIP("104.16.0.1")) {
		t.Error("cached ASN data should still resolve")
	}
	// A fresh dir with a dead source fails.
	m3 := NewManager(t.TempDir(), "")
	m3.SetASNBaseURL("http://127.0.0.1:1")
	if _, _, err := m3.RefreshASN(t.Context(), []string{"AS13335"}, nil); err == nil {
		t.Fatal("expected an error when the source is dead and there is no cache")
	}
}
