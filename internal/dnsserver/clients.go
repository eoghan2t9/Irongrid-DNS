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

// maxPolicyCache bounds the per-IP resolution cache. When full it resets —
// the table is cheap to rebuild and a reset only costs a few lookups.
const maxPolicyCache = 4096

// ClientRouter resolves a client IP to the first matching group's policy —
// groups are evaluated in the order SetPolicies received them. Safe for
// concurrent use; SetPolicies fully replaces the routing table so config
// reloads are atomic from a reader's perspective.
//
// Resolve is on the DNS hot path (every query), so results are cached per
// client IP: the first query from a client does the ParseIP + CIDR scan,
// subsequent ones are a map lookup. SetPolicies clears the cache since the
// routing table changed.
type ClientRouter struct {
	mu      sync.RWMutex
	entries []clientEntry
	// cache maps client IP string -> resolved policy. A nil value is a
	// cached "no group matches" so repeat lookups for unmatched clients
	// skip the scan too.
	cache map[string]*ClientPolicy
}

// NewClientRouter returns a router with no groups (Resolve always misses).
func NewClientRouter() *ClientRouter {
	return &ClientRouter{cache: map[string]*ClientPolicy{}}
}

// SetPolicies replaces the routing table and clears the per-IP cache.
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
	cr.cache = map[string]*ClientPolicy{}
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
	if p, ok := cr.cache[client]; ok {
		cr.mu.RUnlock()
		return p
	}
	cr.mu.RUnlock()

	cr.mu.Lock()
	defer cr.mu.Unlock()
	if p, ok := cr.cache[client]; ok { // double-checked: another goroutine filled it
		return p
	}
	var p *ClientPolicy
	for _, e := range cr.entries {
		for _, n := range e.nets {
			if n.Contains(ip) {
				p = e.policy
				break
			}
		}
		if p != nil {
			break
		}
	}
	if len(cr.cache) >= maxPolicyCache {
		cr.cache = map[string]*ClientPolicy{}
	}
	cr.cache[client] = p
	return p
}
