package dnsserver

import "testing"

func TestBuildACLEmptyAllowsEverything(t *testing.T) {
	acl, err := BuildACL(nil)
	if err != nil {
		t.Fatalf("BuildACL(nil): %v", err)
	}
	if acl != nil {
		t.Fatalf("BuildACL(nil) = %v, want nil (allow everyone)", acl)
	}
	if !acl.Allowed("203.0.113.5") {
		t.Fatal("nil ACL must allow every client")
	}
}

func TestBuildACLInvalidEntry(t *testing.T) {
	if _, err := BuildACL([]string{"not-an-ip"}); err == nil {
		t.Fatal("expected an error for an invalid allow_from entry")
	}
}

func TestACLAllowedMatchesBareIPAndCIDR(t *testing.T) {
	acl, err := BuildACL([]string{"192.168.1.10", "10.0.0.0/8", " 2001:db8::1/128 "})
	if err != nil {
		t.Fatalf("BuildACL: %v", err)
	}
	tests := []struct {
		ip   string
		want bool
	}{
		{"192.168.1.10", true},  // exact bare-IP match
		{"192.168.1.11", false}, // adjacent IP, not allowed
		{"10.1.2.3", true},      // inside CIDR
		{"11.0.0.1", false},     // outside CIDR
		{"2001:db8::1", true},   // IPv6 bare host route
		{"2001:db8::2", false},
		{"not-an-ip", false}, // unparseable client IP: refused, not allowed
	}
	for _, tt := range tests {
		if got := acl.Allowed(tt.ip); got != tt.want {
			t.Errorf("Allowed(%q) = %v, want %v", tt.ip, got, tt.want)
		}
	}
}
