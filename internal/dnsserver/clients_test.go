package dnsserver

import (
	"testing"

	"github.com/eoghan2t9/Irongrid-DNS/internal/filter"
)

func TestClientRouterCIDRAndBareIP(t *testing.T) {
	kids := &ClientPolicy{GroupID: "kids", Engine: filter.NewEngine()}
	iot := &ClientPolicy{GroupID: "iot", Engine: filter.NewEngine()}

	cr := NewClientRouter()
	cr.SetPolicies([]GroupCIDRs{
		{CIDRs: []string{"192.168.1.50"}, Policy: kids}, // bare IP, exact host
		{CIDRs: []string{"10.0.5.0/24"}, Policy: iot},   // subnet
	})

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
	})

	if p := cr.Resolve("10.0.1.1"); p == nil || p.GroupID != "first" {
		t.Fatalf("the first listed matching group should win, got %v", p)
	}
}

func TestClientRouterSetPoliciesReplacesTable(t *testing.T) {
	a := &ClientPolicy{GroupID: "a", Engine: filter.NewEngine()}
	cr := NewClientRouter()
	cr.SetPolicies([]GroupCIDRs{{CIDRs: []string{"192.168.0.0/16"}, Policy: a}})
	if p := cr.Resolve("192.168.1.1"); p == nil {
		t.Fatal("expected a match before replacing the table")
	}
	cr.SetPolicies(nil)
	if p := cr.Resolve("192.168.1.1"); p != nil {
		t.Fatal("SetPolicies(nil) should clear the routing table entirely")
	}
}

func TestClientRouterInvalidClientIP(t *testing.T) {
	a := &ClientPolicy{GroupID: "a", Engine: filter.NewEngine()}
	cr := NewClientRouter()
	cr.SetPolicies([]GroupCIDRs{{CIDRs: []string{"0.0.0.0/0"}, Policy: a}}) // matches every real IP
	if p := cr.Resolve("not-an-ip"); p != nil {
		t.Fatalf("an unparseable client string must resolve to nil even against a catch-all group, got %v", p)
	}
}

func TestClientRouterEntryWithNoPolicyIsDropped(t *testing.T) {
	cr := NewClientRouter()
	cr.SetPolicies([]GroupCIDRs{{CIDRs: []string{"0.0.0.0/0"}}}) // Policy is nil
	if p := cr.Resolve("1.2.3.4"); p != nil {
		t.Fatalf("an entry with no Policy must be dropped by SetPolicies, got %v", p)
	}
}
