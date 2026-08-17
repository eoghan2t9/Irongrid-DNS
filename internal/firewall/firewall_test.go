package firewall

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeRunner records every command and lets tests control LookPath results.
type fakeRunner struct {
	cmds      []string // one string per Run: "name arg1 arg2..."
	available map[string]bool
	// failWhen makes Run error when the joined command contains the string.
	// nil = never fail.
	failWhen string
}

func (f *fakeRunner) LookPath(name string) (string, error) {
	if f.available[name] {
		return "/usr/sbin/" + name, nil
	}
	return "", os.ErrNotExist
}

func (f *fakeRunner) Run(name string, args ...string) error {
	cmd := strings.Join(append([]string{name}, args...), " ")
	f.cmds = append(f.cmds, cmd)
	if f.failWhen != "" && strings.Contains(cmd, f.failWhen) {
		return os.ErrNotExist
	}
	return nil
}

func (f *fakeRunner) RunStdin(name string, args []string, stdin []byte) error {
	f.cmds = append(f.cmds, name+" "+strings.Join(args, " ")+" <<< "+string(stdin))
	return nil
}

func (f *fakeRunner) last() string {
	if len(f.cmds) == 0 {
		return ""
	}
	return f.cmds[len(f.cmds)-1]
}

func writeCountry(t *testing.T, dir, cc, fam, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, cc+"."+fam+".txt"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// TestApplyASNRules verifies the pruned ASN CIDR files written by the geoip
// Manager feed the firewall: block-listed ISPs join the drop sets next to
// the country CIDRs, allow-listed ISPs join the allow sets.
func TestApplyASNRules(t *testing.T) {
	dir := t.TempDir()
	writeCountry(t, dir, "RU", "ipv4", "93.0.0.0/8\n")
	if err := os.WriteFile(filepath.Join(dir, "asn-blocked.txt"), []byte("10.0.0.0/24\n2001:db8::/32\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "asn-allowed.txt"), []byte("91.0.0.0/8\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	f := &fakeRunner{available: map[string]bool{"nft": true}}
	m := NewWithRunner(f)
	if _, err := m.Apply([]string{"RU"}, nil, nil, dir); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	joined := strings.Join(f.cmds, "\n")
	// Blocked ASN ranges join the v4 drop set next to the country CIDRs.
	if !strings.Contains(joined, "93.0.0.0/8, 10.0.0.0/24") {
		t.Errorf("v4 drop set missing ASN-blocked CIDR:\n%s", joined)
	}
	if !strings.Contains(joined, "2001:db8::/32") {
		t.Errorf("v6 drop set missing ASN-blocked CIDR:\n%s", joined)
	}
	// Allowed ASN ranges join the allow set (and its accept rule exists).
	if !strings.Contains(joined, "nft add rule inet irongrid geo_input ip saddr @geo_allow_v4 accept") ||
		!strings.Contains(joined, "91.0.0.0/8") {
		t.Errorf("allow set missing ASN-allowed CIDR:\n%s", joined)
	}
}

// TestApplyASNRulesOnly verifies ASN rules alone (no countries) keep the
// feature alive: the drop sets are populated from the ASN file even when
// every country is absent, so the earlier "no cached country CIDRs" error
// must not fire.
func TestApplyASNRulesOnly(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "asn-blocked.txt"), []byte("10.0.0.0/24\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	f := &fakeRunner{available: map[string]bool{"nft": true}}
	m := NewWithRunner(f)
	if _, err := m.Apply([]string{"RU"}, nil, nil, dir); err != nil {
		t.Fatalf("Apply with only ASN data must not fail: %v", err)
	}
	joined := strings.Join(f.cmds, "\n")
	if !strings.Contains(joined, "10.0.0.0/24") {
		t.Errorf("drop set missing ASN-blocked CIDR:\n%s", joined)
	}
}

func TestApplyNft(t *testing.T) {
	dir := t.TempDir()
	writeCountry(t, dir, "RU", "ipv4", "# Country: Russia\n5.45.192.0/24\n93.0.0.0/8\n")
	writeCountry(t, dir, "RU", "ipv6", "2001:db8::/32\n")
	writeCountry(t, dir, "CN", "ipv4", "1.0.1.0/24\n")

	f := &fakeRunner{available: map[string]bool{"nft": true}}
	m := NewWithRunner(f)

	backend, err := m.Apply([]string{"RU", "cn"}, []string{"203.0.113.9", "10.0.0.0/8"},
		[]string{"198.51.100.7", "2001:db8:1::/48"}, dir)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if backend != "nft" {
		t.Fatalf("backend = %q, want nft", backend)
	}

	// Sanity: the essential pieces are present in the issued commands.
	joined := strings.Join(f.cmds, "\n")
	for _, want := range []string{
		"nft add table inet irongrid",
		"nft add chain inet irongrid geo_input { type filter hook input priority 0; policy accept; }",
		"nft add set inet irongrid geo_v4 { type ipv4_addr; flags interval; auto-merge; }",
		"nft add rule inet irongrid geo_input ct state established,related accept",
		"nft add rule inet irongrid geo_input ip saddr @geo_allow_v4 accept",
		"nft add rule inet irongrid geo_input ip saddr @geo_v4 drop",
		"nft add rule inet irongrid geo_input ip6 saddr @geo_v6 drop",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing command %q\nissued:\n%s", want, joined)
		}
	}
	// Both countries' CIDRs land in the v4 set (lowercase input normalised).
	if !strings.Contains(joined, "5.45.192.0/24, 93.0.0.0/8, 1.0.1.0/24") {
		t.Errorf("geo_v4 elements missing all countries' CIDRs:\n%s", joined)
	}
	// Allowlist entries are classified and installed.
	if !strings.Contains(joined, "203.0.113.9, 10.0.0.0/8") {
		t.Errorf("geo_allow_v4 elements missing:\n%s", joined)
	}
	// Explicit block IPs are merged into the same drop sets as the country
	// CIDRs.
	if !strings.Contains(joined, "198.51.100.7") {
		t.Errorf("blocked client IP missing from the drop set:\n%s", joined)
	}
	if !strings.Contains(joined, "2001:db8:1::/48") {
		t.Errorf("blocked client v6 CIDR missing from the drop set:\n%s", joined)
	}
	// Ordering: the country DROPs must be added BEFORE the
	// established/related ACCEPT — otherwise a pre-existing conntrack flow
	// exempts blocked clients forever (each REFUSED reply refreshes the
	// timer, so the drop never fires). This ordering regression would let a
	// previously-active blocked country keep reaching the DNS server.
	idxDrop := strings.Index(joined, "nft add rule inet irongrid geo_input ip saddr @geo_v4 drop")
	idxEst := strings.Index(joined, "nft add rule inet irongrid geo_input ct state established,related accept")
	if idxDrop < 0 || idxEst < 0 || idxDrop > idxEst {
		t.Errorf("geo drop rule (%d) must precede established/related accept (%d):\n%s", idxDrop, idxEst, joined)
	}

	// Second Apply must be idempotent in shape (flush + rebuild, no error).
	before := len(f.cmds)
	if _, err := m.Apply([]string{"RU"}, nil, nil, dir); err != nil {
		t.Fatalf("second Apply: %v", err)
	}
	if len(f.cmds) == before {
		t.Error("second Apply issued no commands")
	}
}

func TestApplyNftIPBlocksOnly(t *testing.T) {
	// Explicit block IPs alone (no countries, no country data) must still
	// build the sets and the drop rules — so AddIP can extend them later.
	f := &fakeRunner{available: map[string]bool{"nft": true}}
	m := NewWithRunner(f)
	if _, err := m.Apply(nil, nil, []string{"198.51.100.7"}, t.TempDir()); err != nil {
		t.Fatalf("Apply with only ipBlocks: %v", err)
	}
	joined := strings.Join(f.cmds, "\n")
	for _, want := range []string{
		"nft add rule inet irongrid geo_input ip saddr @geo_v4 drop",
		"nft add rule inet irongrid geo_input ip6 saddr @geo_v6 drop",
		"198.51.100.7",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing command %q\nissued:\n%s", want, joined)
		}
	}
}

func TestAddIPNft(t *testing.T) {
	f := &fakeRunner{available: map[string]bool{"nft": true}}
	m := NewWithRunner(f)
	if _, err := m.Apply([]string{"RU"}, nil, nil, t.TempDir()); err == nil {
		t.Fatal("Apply without data should fail before AddIP")
	}
	// Seed a valid apply, then AddIP must emit one element-add per family.
	if _, err := m.Apply(nil, nil, nil, t.TempDir()); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if err := m.AddIP("198.51.100.7"); err != nil {
		t.Fatalf("AddIP v4: %v", err)
	}
	if err := m.AddIP("2001:db8::9"); err != nil {
		t.Fatalf("AddIP v6: %v", err)
	}
	if got := f.cmds[len(f.cmds)-2]; got != "nft add element inet irongrid geo_v4 { 198.51.100.7 }" {
		t.Errorf("v4 add = %q", got)
	}
	if got := f.cmds[len(f.cmds)-1]; got != "nft add element inet irongrid geo_v6 { 2001:db8::9 }" {
		t.Errorf("v6 add = %q", got)
	}
	if err := m.AddIP("not-an-ip"); err == nil {
		t.Error("AddIP with a non-IP should fail")
	}
}

func TestAddIPRemoveIPIptables(t *testing.T) {
	f := &fakeRunner{available: map[string]bool{"ipset": true, "iptables": true, "ip6tables": true}}
	m := NewWithRunner(f)
	if _, err := m.Apply(nil, nil, nil, t.TempDir()); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if err := m.AddIP("198.51.100.7"); err != nil {
		t.Fatalf("AddIP: %v", err)
	}
	if got := f.last(); got != "ipset add irongrid_geo_v4 198.51.100.7 -exist" {
		t.Errorf("AddIP command = %q", got)
	}
	if err := m.RemoveIP("198.51.100.7"); err != nil {
		t.Fatalf("RemoveIP: %v", err)
	}
	if got := f.last(); got != "ipset del irongrid_geo_v4 198.51.100.7 -exist" {
		t.Errorf("RemoveIP command = %q", got)
	}
}

func TestApplyNftNoData(t *testing.T) {
	f := &fakeRunner{available: map[string]bool{"nft": true}}
	m := NewWithRunner(f)
	if _, err := m.Apply([]string{"XX"}, nil, nil, t.TempDir()); err == nil {
		t.Fatal("Apply with no cached data should fail")
	}
}

func TestApplyIptables(t *testing.T) {
	dir := t.TempDir()
	writeCountry(t, dir, "RU", "ipv4", "93.0.0.0/8\n")

	f := &fakeRunner{available: map[string]bool{"ipset": true, "iptables": true, "ip6tables": true}}
	m := NewWithRunner(f)
	backend, err := m.Apply([]string{"RU"}, []string{"198.51.100.7"}, nil, dir)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if backend != "iptables" {
		t.Fatalf("backend = %q, want iptables", backend)
	}
	joined := strings.Join(f.cmds, "\n")
	for _, want := range []string{
		"ipset create irongrid_geo_v4 hash:net family inet hashsize 4096 maxelem 131072 -exist",
		"ipset restore -exist <<< add irongrid_geo_v4 93.0.0.0/8",
		"iptables -N irongrid-geo",
		"iptables -A irongrid-geo -m set --match-set irongrid_geo_allow_v4 src -j ACCEPT",
		"iptables -A irongrid-geo -m set --match-set irongrid_geo_v4 src -j DROP",
		"iptables -A irongrid-geo -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT",
		"iptables -C INPUT -j irongrid-geo",
		"ip6tables -C INPUT -j irongrid-geo",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing command %q\nissued:\n%s", want, joined)
		}
	}
	// Ordering: country DROP before the established/related ACCEPT (see
	// TestApplyNft's ordering check for why). The conntrack accept is
	// appended after the drop rules, not inserted at position 1.
	idxDrop := strings.Index(joined, "iptables -A irongrid-geo -m set --match-set irongrid_geo_v4 src -j DROP")
	idxEst := strings.Index(joined, "iptables -A irongrid-geo -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT")
	if idxDrop < 0 || idxEst < 0 || idxDrop > idxEst {
		t.Errorf("iptables drop rule (%d) must precede established accept (%d):\n%s", idxDrop, idxEst, joined)
	}
}

func TestNoBackend(t *testing.T) {
	f := &fakeRunner{available: map[string]bool{}}
	m := NewWithRunner(f)
	if _, err := m.Apply([]string{"RU"}, nil, nil, t.TempDir()); err == nil || !strings.Contains(err.Error(), "no supported firewall backend") {
		t.Fatalf("err = %v, want no-backend error", err)
	}
}

func TestClearNft(t *testing.T) {
	f := &fakeRunner{available: map[string]bool{"nft": true}}
	m := NewWithRunner(f)
	if err := m.Clear(); err != nil {
		t.Fatalf("Clear: %v", err)
	}
	if got := f.last(); got != "nft delete table inet irongrid" {
		t.Fatalf("last command = %q", got)
	}
}

func TestClearIptables(t *testing.T) {
	f := &fakeRunner{available: map[string]bool{"ipset": true, "iptables": true, "ip6tables": true}}
	m := NewWithRunner(f)
	if err := m.Clear(); err != nil {
		t.Fatalf("Clear: %v", err)
	}
	joined := strings.Join(f.cmds, "\n")
	for _, want := range []string{
		"iptables -D INPUT -j irongrid-geo",
		"iptables -X irongrid-geo",
		"ipset destroy irongrid_geo_v4",
		"ipset destroy irongrid_geo_v6",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing clear command %q", want)
		}
	}
}

func TestParseCIDRs(t *testing.T) {
	got := parseCIDRs("# header\n93.0.0.0/8  ; trailing comment\n\n1.2.3.0/24 # inline\n2001:db8::/32\n")
	want := []string{"93.0.0.0/8", "1.2.3.0/24", "2001:db8::/32"}
	if len(got) != len(want) {
		t.Fatalf("parsed %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("parsed %v, want %v", got, want)
		}
	}
}

func TestClassifyIPs(t *testing.T) {
	v4, v6 := classifyIPs([]string{"198.51.100.7", "10.0.0.0/8", "2001:db8::1", "2400::/12", "not-an-ip"})
	if len(v4) != 2 || v4[0] != "198.51.100.7" || v4[1] != "10.0.0.0/8" {
		t.Fatalf("v4 = %v", v4)
	}
	if len(v6) != 2 || v6[0] != "2001:db8::1" || v6[1] != "2400::/12" {
		t.Fatalf("v6 = %v", v6)
	}
}

func TestStatusNft(t *testing.T) {
	f := &fakeRunner{available: map[string]bool{"nft": true}, failWhen: "nft list table"}
	m := NewWithRunner(f)
	// `nft list table` fails → nothing installed → inactive.
	if b, active := m.Status(); b != "nft" || active {
		t.Fatalf("Status = (%q, %v), want (nft, false)", b, active)
	}
	// With the table present (list succeeds) → active.
	f.failWhen = ""
	if b, active := m.Status(); b != "nft" || !active {
		t.Fatalf("Status = (%q, %v), want (nft, true)", b, active)
	}
}
