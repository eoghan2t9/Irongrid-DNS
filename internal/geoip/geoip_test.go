package geoip

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestLoadTableAndContains(t *testing.T) {
	ipv4 := []byte("1.2.3.0/24\n# comment line\n10.0.0.0/8\n1.2.3.4/32\n")
	ipv6 := []byte("2001:db8::/32\n")
	tbl, err := LoadTable(ipv4, ipv6)
	if err != nil {
		t.Fatalf("LoadTable: %v", err)
	}
	if !tbl.Contains(net.ParseIP("1.2.3.55")) {
		t.Error("1.2.3.55 should be inside 1.2.3.0/24")
	}
	if !tbl.Contains(net.ParseIP("10.200.5.1")) {
		t.Error("10.200.5.1 should be inside 10.0.0.0/8")
	}
	if tbl.Contains(net.ParseIP("8.8.8.8")) {
		t.Error("8.8.8.8 must not match any range")
	}
	if !tbl.Contains(net.ParseIP("2001:db8::1")) {
		t.Error("2001:db8::1 should match the v6 range")
	}
	if tbl.Contains(net.ParseIP("2001:db9::1")) {
		t.Error("2001:db9::1 must not match")
	}
	if tbl.Contains(net.ParseIP("not-an-ip")) {
		t.Error("nil parse must not match")
	}
}

func TestTableAdjacentRangesMerge(t *testing.T) {
	// 1.2.3.0/24 + 1.2.4.0/24 are adjacent: they must merge so a lookup in
	// either half still hits (and the table stays small).
	tbl, err := LoadTable([]byte("1.2.3.0/24\n1.2.4.0/24\n"), nil)
	if err != nil {
		t.Fatalf("LoadTable: %v", err)
	}
	if len(tbl.v4) != 1 {
		t.Fatalf("adjacent /24s should merge into one range, got %d", len(tbl.v4))
	}
	if !tbl.Contains(net.ParseIP("1.2.3.200")) || !tbl.Contains(net.ParseIP("1.2.4.200")) {
		t.Error("merged range must still contain both halves")
	}
}

func TestBlockerConfigAllowlistAndUnknownIPs(t *testing.T) {
	b := NewBlocker()
	tbl, _ := LoadTable([]byte("93.0.0.0/8\n"), nil)
	b.AddTable("RU", tbl)
	if err := b.SetConfig([]string{"ru", "CN"}, []string{"93.184.0.1"}); err != nil {
		t.Fatalf("SetConfig: %v", err)
	}
	if !b.Blocked("93.1.2.3") {
		t.Error("93.1.2.3 should be geo-blocked (RU data loaded, lowercase code normalized)")
	}
	if b.Blocked("93.184.0.1") {
		t.Error("an allowlisted IP must never be geo-blocked")
	}
	if b.Blocked("8.8.8.8") {
		t.Error("8.8.8.8 must not be geo-blocked")
	}
	if b.Blocked("") {
		t.Error("an empty client must never be geo-blocked")
	}
	if b.Blocked("not-an-ip") {
		t.Error("an unparseable client must never be geo-blocked")
	}
}

func TestManagerRefreshFromSource(t *testing.T) {
	dir := t.TempDir()
	src := t.TempDir()
	ruDir := filepath.Join(src, "RU")
	if err := os.MkdirAll(ruDir, 0o755); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(ruDir, "ipv4_agg.txt"), []byte("93.0.0.0/8\n"), 0o644)
	os.WriteFile(filepath.Join(ruDir, "ipv6_agg.txt"), []byte("2001:db8::/32\n"), 0o644)

	m := NewManager(dir, "file://"+src)
	b, err := m.Refresh(context.Background(), []string{"RU"}, nil)
	if err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	if !b.Blocked("93.7.7.7") {
		t.Error("RU data should block 93.7.7.7")
	}
	if !b.Blocked("2001:db8::1") {
		t.Error("RU v6 data should block 2001:db8::1")
	}
	if b.Blocked("1.1.1.1") {
		t.Error("1.1.1.1 must not be blocked")
	}
	st := m.Status()
	if len(st) != 1 || st[0].Code != "RU" || st[0].Error != "" || st[0].IPv4Ranges == 0 {
		t.Fatalf("unexpected status: %+v", st)
	}
	// Data was cached for an offline restart.
	if _, err := os.Stat(filepath.Join(dir, "RU.ipv4.txt")); err != nil {
		t.Fatalf("country data not persisted: %v", err)
	}
}

func TestManagerHTTPFallbackToCache(t *testing.T) {
	dir := t.TempDir()
	// Seed the disk cache (as a previous successful refresh would have).
	os.WriteFile(filepath.Join(dir, "CN.ipv4.txt"), []byte("1.0.1.0/24\n"), 0o644)
	os.WriteFile(filepath.Join(dir, "CN.ipv6.txt"), nil, 0o644)

	// A source that always fails must not lose the cached data.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer srv.Close()

	m := NewManager(dir, srv.URL)
	b, err := m.Refresh(context.Background(), []string{"CN"}, nil)
	if err != nil {
		t.Fatalf("Refresh should fall back to the cached copy: %v", err)
	}
	if !b.Blocked("1.0.1.5") {
		t.Error("cached CN data should block 1.0.1.5")
	}
	st := m.Status()
	if len(st) != 1 || st[0].Code != "CN" || st[0].Error != "" {
		t.Fatalf("cached fallback should look healthy, got %+v", st)
	}

	// With no cache either, the country is skipped and an error is recorded.
	m2 := NewManager(t.TempDir(), srv.URL)
	if _, err := m2.Refresh(context.Background(), []string{"CN"}, nil); err == nil {
		t.Fatal("expected an error when the source is dead and there is no cache")
	}
	if st := m2.Status(); len(st) != 1 || st[0].Error == "" {
		t.Fatalf("expected a recorded error, got %+v", st)
	}
}

func TestBlockerRebuildOnEnable(t *testing.T) {
	// A country loaded before it was enabled must take effect once enabled.
	b := NewBlocker()
	tbl, _ := LoadTable([]byte("203.0.113.0/24\n"), nil)
	b.AddTable("XX", tbl)
	if b.Blocked("203.0.113.9") {
		t.Error("XX is not enabled yet — must not block")
	}
	if err := b.SetConfig([]string{"XX"}, nil); err != nil {
		t.Fatal(err)
	}
	if !b.Blocked("203.0.113.9") {
		t.Error("enabling XX must pick up its already-loaded table")
	}
}
