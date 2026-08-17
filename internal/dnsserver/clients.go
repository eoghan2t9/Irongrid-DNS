package dnsserver

import (
	"net"
	"sync"
	"sync/atomic"

	"github.com/eoghan2t9/Irongrid-DNS/internal/filter"
	"github.com/eoghan2t9/Irongrid-DNS/internal/geoip"
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

// GroupCIDRs pairs a policy with the raw CIDR/IP strings and the parsed
// ASN numbers that route clients to it.
type GroupCIDRs struct {
	CIDRs  []string
	ASNs   []uint32
	Policy *ClientPolicy
}

type clientEntry struct {
	nets   []*net.IPNet
	asns   map[uint32]bool // non-empty only when the group matches by ASN
	policy *ClientPolicy
}

// clientEntries is one immutable router snapshot: the groups in evaluation
// order plus the IP→ASN table backing ASN matching (nil when no group
// matches by ASN, so the common case pays no lookup at all).
type clientEntries struct {
	groups   []clientEntry
	asnTable *geoip.ASNTable
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
// subsequent ones are a cache lookup. Both entries and cache are lock-free
// on the read side — entries is an atomic-swapped snapshot (published whole
// by SetPolicies, exactly the shape internal/dnsserver's h.settings uses for
// the same reason: reads dominate hot-path traffic by orders of magnitude
// over reloads) and cache is a sync.Map, which is specifically optimized for
// this access pattern (a key written once, read many times, by many
// goroutines) rather than a map behind a mutex that every query would
// contend on.
type ClientRouter struct {
	entries atomic.Pointer[clientEntries]
	// cache maps client IP string -> resolved policy. A stored (*ClientPolicy)(nil)
	// is a cached "no group matches" so repeat lookups for unmatched clients
	// skip the scan too; Load's ok return still distinguishes that from "not
	// cached yet".
	cache     sync.Map
	cacheSize atomic.Int64
}

// NewClientRouter returns a router with no groups (Resolve always misses).
func NewClientRouter() *ClientRouter {
	cr := &ClientRouter{}
	empty := clientEntries{}
	cr.entries.Store(&empty)
	return cr
}

// SetPolicies replaces the routing table (and the ASN lookup table backing
// it) and clears the per-IP cache. asnTable may be nil — ASN matching is
// then skipped entirely, so routers for configs without group ASNs pay no
// lookup on the hot path.
func (cr *ClientRouter) SetPolicies(groups []GroupCIDRs, asnTable *geoip.ASNTable) {
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
		var asns map[uint32]bool
		if len(g.ASNs) > 0 {
			asns = make(map[uint32]bool, len(g.ASNs))
			for _, a := range g.ASNs {
				asns[a] = true
			}
		}
		if len(nets) == 0 && len(asns) == 0 {
			continue
		}
		entries = append(entries, clientEntry{nets: nets, asns: asns, policy: g.Policy})
	}
	cr.entries.Store(&clientEntries{groups: entries, asnTable: asnTable})
	cr.cache.Clear()
	cr.cacheSize.Store(0)
}

// Resolve returns the policy for the first group whose CIDRs contain client
// or whose ASN list owns the client's ISP, or nil when no group matches
// (callers fall back to the global policy). On the DNS hot path, so the
// cache is checked before ParseIP: a cached hit (the common case — every
// query from an established client) skips the parse and the scans entirely,
// and takes no lock at all.
func (cr *ClientRouter) Resolve(client string) *ClientPolicy {
	if v, ok := cr.cache.Load(client); ok {
		p, _ := v.(*ClientPolicy)
		return p
	}

	ip := net.ParseIP(client)
	if ip == nil {
		return nil
	}
	// A concurrent miss on the same brand-new client may redo this scan more
	// than once — cheap and deterministic (same input, same result), so the
	// duplicate work is a better trade than a lock every cache hit would pay
	// forever.
	entries := cr.entries.Load()
	var p *ClientPolicy
	for _, e := range entries.groups {
		if len(e.nets) > 0 {
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
		// ASN matching runs only for groups that ask for it (and only when a
		// table is installed), so the common no-ASN config stays allocation-
		// and lookup-free.
		if p == nil && len(e.asns) > 0 && entries.asnTable != nil {
			if asn, ok := entries.asnTable.Lookup(ip); ok && e.asns[asn] {
				p = e.policy
			}
		}
		if p != nil {
			break
		}
	}
	if cr.cacheSize.Add(1) > maxPolicyCache {
		cr.cache.Clear()
		cr.cacheSize.Store(0)
	}
	cr.cache.Store(client, p)
	return p
}

// ASNOf returns the ASN the router's table attributes to client, if any.
// The table is only installed when at least one group matches by ASN (nil
// otherwise), so for a config without group ASNs this never resolves — the
// DoH ASN response header falls back to the geo blocker's tables instead.
func (cr *ClientRouter) ASNOf(client string) (uint32, bool) {
	ip := net.ParseIP(client)
	if ip == nil {
		return 0, false
	}
	return cr.ASNOfIP(ip)
}

// ASNOfIP is the no-parse form of ASNOf for callers that already hold the
// parsed IP — the handler's ClientASN parses once and shares the net.IP
// between this lookup and the geo blocker's, so the hot path doesn't pay
// two ParseIP calls per client.
func (cr *ClientRouter) ASNOfIP(ip net.IP) (uint32, bool) {
	entries := cr.entries.Load()
	if entries.asnTable == nil {
		return 0, false
	}
	return entries.asnTable.Lookup(ip)
}
