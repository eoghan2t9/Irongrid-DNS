package dnsserver

import (
	"fmt"
	"net"
	"strings"
)

// ACL is an allow-list of client networks permitted to query this server.
// A nil ACL (the zero value returned by BuildACL for an empty spec list)
// means "allow everyone" — this feature is opt-in and backward compatible:
// an unconfigured server.allow_from behaves exactly as before.
type ACL struct {
	nets []*net.IPNet
}

// BuildACL parses server.allow_from entries (bare IPs or CIDRs) into an ACL.
// A bare IP is treated as a host route (/32 for IPv4, /128 for IPv6).
// Returns (nil, nil) for an empty spec list, meaning "allow every client".
func BuildACL(specs []string) (*ACL, error) {
	acl := &ACL{}
	for _, raw := range specs {
		spec := strings.TrimSpace(raw)
		if spec == "" {
			continue
		}
		if !strings.Contains(spec, "/") {
			ip := net.ParseIP(spec)
			if ip == nil {
				return nil, fmt.Errorf("invalid allow_from entry %q: not an IP or CIDR", raw)
			}
			bits := 32
			if ip.To4() == nil {
				bits = 128
			}
			spec = fmt.Sprintf("%s/%d", spec, bits)
		}
		_, ipnet, err := net.ParseCIDR(spec)
		if err != nil {
			return nil, fmt.Errorf("invalid allow_from entry %q: %w", raw, err)
		}
		acl.nets = append(acl.nets, ipnet)
	}
	if len(acl.nets) == 0 {
		return nil, nil
	}
	return acl, nil
}

// Allowed reports whether clientIP (a bare IP string, no port) may query
// this server. A nil ACL allows everyone; an unparseable clientIP is
// refused rather than silently allowed.
func (a *ACL) Allowed(clientIP string) bool {
	if a == nil || len(a.nets) == 0 {
		return true
	}
	ip := net.ParseIP(clientIP)
	if ip == nil {
		return false
	}
	for _, n := range a.nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}
