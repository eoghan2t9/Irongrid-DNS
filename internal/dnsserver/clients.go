package dnsserver

import (
	"net"
	"sync"

	"github.com/eoghan2t9/Irongrid-DNS/internal/filter"
	"github.com/eoghan2t9/Irongrid-DNS/internal/upstream"
)

// ClientPolicy is the resolved policy for clients matching one group: its
// own compiled filter Engine and (if configured) its own upstream set.
type ClientPolicy struct {
	GroupID   string
	GroupName string
	Engine    *filter.Engine
	// Upstreams overrides the global forwarders for this group; nil means
	// "use the global upstreams".
	Upstreams []*upstream.Upstream
}

// GroupCIDRs pairs a policy with the raw CIDR/IP strings that route to it.
type GroupCIDRs struct {
	CIDRs  []string
	Policy *ClientPolicy
}

type clientEntry struct {
	nets   []*net.IPNet
	policy *ClientPolicy
}

// ClientRouter resolves a client IP to the first matching group's policy —
// groups are evaluated in the order SetPolicies received them. Safe for
// concurrent use; SetPolicies fully replaces the routing table so config
// reloads are atomic from a reader's perspective.
type ClientRouter struct {
	mu      sync.RWMutex
	entries []clientEntry
}

// NewClientRouter returns a router with no groups (Resolve always misses).
func NewClientRouter() *ClientRouter { return &ClientRouter{} }

// SetPolicies replaces the routing table.
func (cr *ClientRouter) SetPolicies(groups []GroupCIDRs) {
	entries := make([]clientEntry, 0, len(groups))
	for _, g := range groups {
		if g.Policy == nil {
			continue
		}
		var nets []*net.IPNet
		for _, c := range g.CIDRs {
			if _, ipnet, err := net.ParseCIDR(c); err == nil {
				nets = append(nets, ipnet)
				continue
			}
			// A bare IP (no /prefix) matches that single host exactly.
			if ip := net.ParseIP(c); ip != nil {
				bits := 32
				if ip.To4() == nil {
					bits = 128
				}
				nets = append(nets, &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)})
			}
		}
		if len(nets) == 0 {
			continue
		}
		entries = append(entries, clientEntry{nets: nets, policy: g.Policy})
	}
	cr.mu.Lock()
	cr.entries = entries
	cr.mu.Unlock()
}

// Resolve returns the policy for the first group whose CIDRs contain client,
// or nil when no group matches (callers fall back to the global policy).
func (cr *ClientRouter) Resolve(client string) *ClientPolicy {
	ip := net.ParseIP(client)
	if ip == nil {
		return nil
	}
	cr.mu.RLock()
	defer cr.mu.RUnlock()
	for _, e := range cr.entries {
		for _, n := range e.nets {
			if n.Contains(ip) {
				return e.policy
			}
		}
	}
	return nil
}
