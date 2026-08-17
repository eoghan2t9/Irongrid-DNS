package dnsserver

import (
	"net"
	"testing"

	"github.com/eoghan2t9/Irongrid-DNS/internal/filter"
	"github.com/eoghan2t9/Irongrid-DNS/internal/geoip"
)

func TestClientRouterCIDRAndBareIP(t *testing.T) {
	kids := &ClientPolicy{GroupID: "kids", Engine: filter.NewEngine()}
	iot := &ClientPolicy{GroupID: "iot", Engine: filter.NewEngine()}

	cr := NewClientRouter()
	cr.SetPolicies([]GroupCIDRs{
		{CIDRs: []string{"192.168.1.50"}, Policy: kids}, // bare IP, exact host
		{CIDRs: []string{"10.0.5.0/24"}, Policy: iot},   // subnet
	}, nil)

	if p := cr.Resolve("192.168.1.50"); p == nil || p.GroupID != "kids" {
		t.Fatalf("expected the bare-IP entry to match kids, got %v", p)
	}
	if p := cr.Resolve("192.168.1.51"); p != nil {
		t.Fatalf("a bare IP entry must not match a neighboring address, got %v", p)
	}
	if p := cr.Resolve("10.0.5.77"); p == nil || p.GroupID != "iot" {
		t.Fatalf("expected the /24 entry to match iot, got %v", p)
	}
	if p := cr.Resolve("10.0.6.1"); p != nil {
		t.Fatalf("address outside the /24 must not match, got %v", p)
	}
	if p := cr.Resolve("8.8.8.8"); p != nil {
		t.Fatalf("an unmatched client should resolve to nil (fall back to global policy), got %v", p)
	}
}

func TestClientRouterFirstMatchWins(t *testing.T) {
	first := &ClientPolicy{GroupID: "first", Engine: filter.NewEngine()}
	second := &ClientPolicy{GroupID: "second", Engine: filter.NewEngine()}

	cr := NewClientRouter()
	cr.SetPolicies([]GroupCIDRs{
		{CIDRs: []string{"10.0.0.0/8"}, Policy: first},
		{CIDRs: []string{"10.0.0.0/16"}, Policy: second}, // overlaps but listed second
	}, nil)

	if p := cr.Resolve("10.0.1.1"); p == nil || p.GroupID != "first" {
		t.Fatalf("the first listed matching group should win, got %v", p)
	}
}

func TestClientRouterSetPoliciesReplacesTable(t *testing.T) {
	a := &ClientPolicy{GroupID: "a", Engine: filter.NewEngine()}
	cr := NewClientRouter()
	cr.SetPolicies([]GroupCIDRs{{CIDRs: []string{"192.168.0.0/16"}, Policy: a}}, nil)
	if p := cr.Resolve("192.168.1.1"); p == nil {
		t.Fatal("expected a match before replacing the table")
	}
	cr.SetPolicies(nil, nil)
	if p := cr.Resolve("192.168.1.1"); p != nil {
		t.Fatal("SetPolicies(nil) should clear the routing table entirely")
	}
}

// TestClientRouterCacheInvalidatedOnSetPolicies verifies the per-IP result
// cache is cleared whenever the routing table is replaced: a policy change
// for the same client must take effect on the very next query, not be served
// from the cached pre-reload result.
func TestClientRouterCacheInvalidatedOnSetPolicies(t *testing.T) {
	a := &ClientPolicy{GroupID: "a", Engine: filter.NewEngine()}
	b := &ClientPolicy{GroupID: "b", Engine: filter.NewEngine()}
	cr := NewClientRouter()
	cr.SetPolicies([]GroupCIDRs{{CIDRs: []string{"192.168.0.0/16"}, Policy: a}}, nil)

	if p := cr.Resolve("192.168.1.1"); p == nil || p.GroupID != "a" {
		t.Fatalf("expected policy a, got %v", p)
	}
	if p := cr.Resolve("10.0.0.9"); p != nil {
		t.Fatalf("unmatched client should be cached as nil, got %v", p)
	}

	// Reconfigure: the same CIDR now maps to b, and 10.0.0.0/8 is added.
	cr.SetPolicies([]GroupCIDRs{
		{CIDRs: []string{"192.168.0.0/16"}, Policy: b},
		{CIDRs: []string{"10.0.0.0/8"}, Policy: b},
	}, nil)

	if p := cr.Resolve("192.168.1.1"); p == nil || p.GroupID != "b" {
		t.Fatalf("cached policy a was served after SetPolicies, got %v", p)
	}
	// The previously cached nil must also be invalidated.
	if p := cr.Resolve("10.0.0.9"); p == nil || p.GroupID != "b" {
		t.Fatalf("cached nil was served after SetPolicies, got %v", p)
	}
}

func TestClientRouterInvalidClientIP(t *testing.T) {
	a := &ClientPolicy{GroupID: "a", Engine: filter.NewEngine()}
	cr := NewClientRouter()
	cr.SetPolicies([]GroupCIDRs{{CIDRs: []string{"0.0.0.0/0"}, Policy: a}}, nil) // matches every real IP
	if p := cr.Resolve("not-an-ip"); p != nil {
		t.Fatalf("an unparseable client string must resolve to nil even against a catch-all group, got %v", p)
	}
}

func TestClientRouterEntryWithNoPolicyIsDropped(t *testing.T) {
	cr := NewClientRouter()
	cr.SetPolicies([]GroupCIDRs{{CIDRs: []string{"0.0.0.0/0"}}}, nil) // Policy is nil
	if p := cr.Resolve("1.2.3.4"); p != nil {
		t.Fatalf("an entry with no Policy must be dropped by SetPolicies, got %v", p)
	}
}

// TestClientRouterASNMatch verifies groups can match clients by the ASN of
// their source IP: a client whose ISP is in the group's ASN list resolves to
// that group, CIDR matching still works alongside, and a group without ASNs
// never consults the table.
func TestClientRouterASNMatch(t *testing.T) {
	asnTbl, _, err := geoip.LoadASNTables(
		[]byte("1.2.3.0\t1.2.3.255\t15169\tUS\tGOOGLE\n"+
			"104.16.0.0\t104.31.255.255\t13335\tUS\tCLOUDFLARE\n"),
		nil, map[uint32]bool{15169: true, 13335: true}, map[uint32]bool{})
	if err != nil {
		t.Fatalf("LoadASNTables: %v", err)
	}
	cloud := &ClientPolicy{GroupID: "cloud", Engine: filter.NewEngine()}
	kids := &ClientPolicy{GroupID: "kids", Engine: filter.NewEngine()}

	cr := NewClientRouter()
	cr.SetPolicies([]GroupCIDRs{
		{ASNs: []uint32{13335}, Policy: cloud},
		{CIDRs: []string{"10.0.0.0/8"}, Policy: kids},
	}, asnTbl)

	// 104.16.0.1 is AS13335 — matched by ASN even though no CIDR covers it.
	if p := cr.Resolve("104.16.0.1"); p == nil || p.GroupID != "cloud" {
		t.Fatalf("ASN-matched client should resolve to cloud, got %v", p)
	}
	// 1.2.3.4 is AS15169 — not in any group's ASN list, no CIDR matches.
	if p := cr.Resolve("1.2.3.4"); p != nil {
		t.Fatalf("ASN not in any group must not match, got %v", p)
	}
	// CIDR matching still works alongside ASN matching.
	if p := cr.Resolve("10.0.0.9"); p == nil || p.GroupID != "kids" {
		t.Fatalf("CIDR match should still work, got %v", p)
	}
}

// TestClientRouterASNWithoutTable verifies ASN matching is inert when no
// table is installed — the config-less default must not panic or match.
func TestClientRouterASNWithoutTable(t *testing.T) {
	cloud := &ClientPolicy{GroupID: "cloud", Engine: filter.NewEngine()}
	cr := NewClientRouter()
	cr.SetPolicies([]GroupCIDRs{{ASNs: []uint32{13335}, Policy: cloud}}, nil)
	if p := cr.Resolve("104.16.0.1"); p != nil {
		t.Fatalf("no table installed: ASN matching must not fire, got %v", p)
	}
}

// TestASNTableLookup verifies Lookup returns the owning ASN, not just a
// membership boolean — the client router needs the number to pick a group.
func TestASNTableLookup(t *testing.T) {
	tbl, _, err := geoip.LoadASNTables(
		[]byte("1.2.3.0\t1.2.3.255\t15169\tUS\tGOOGLE\n"+
			"10.0.0.0\t10.0.0.255\t3257\tUS\tGTT\n"),
		nil, map[uint32]bool{15169: true, 3257: true}, map[uint32]bool{})
	if err != nil {
		t.Fatalf("LoadASNTables: %v", err)
	}
	if asn, ok := tbl.Lookup(net.ParseIP("1.2.3.4")); !ok || asn != 15169 {
		t.Errorf("Lookup(1.2.3.4) = %d,%v want 15169,true", asn, ok)
	}
	if asn, ok := tbl.Lookup(net.ParseIP("10.0.0.9")); !ok || asn != 3257 {
		t.Errorf("Lookup(10.0.0.9) = %d,%v want 3257,true", asn, ok)
	}
	if asn, ok := tbl.Lookup(net.ParseIP("8.8.8.8")); ok {
		t.Errorf("Lookup(8.8.8.8) = %d,%v want no match", asn, ok)
	}
	if !tbl.Contains(net.ParseIP("1.2.3.4")) {
		t.Error("Contains must stay consistent with Lookup")
	}
}
