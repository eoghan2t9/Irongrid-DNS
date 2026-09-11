package vpn

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ProfileSpec is the config form of one WireGuard tunnel — the vpn package's
// own type so it never has to import internal/config; main.go converts
// config.VPNProfile into this, the same split dnsserver.RouteSpec uses for
// upstream_routes.
type ProfileSpec struct {
	ID       string
	Provider string // "nordvpn" | "pia"
	Region   string
}

// RouteSpec is the config form of one domain-to-profile route.
type RouteSpec struct {
	Profile string
	Domains []string
	// Proxy mirrors config.VPNRoute.Proxy — see that doc comment and
	// VPNProxyConfig. Checked by ProxyAnswer, used by the Relay.
	Proxy bool
}

// Credentials holds every provider's account credentials. Only the fields
// for providers actually referenced by a profile need to be set.
type Credentials struct {
	NordVPNToken string
	PIAUsername  string
	PIAPassword  string
}

type activeProfile struct {
	id       string
	provider string
	region   string
	names    profileNames
	peer     PeerConfig
	upSince  time.Time
}

type route struct {
	profile string
	domains []string
	proxy   bool
}

// snapshot is the atomically-swapped state Observe reads on the DNS hot
// path — never mutated in place, always replaced whole by Reconcile.
type snapshot struct {
	routes []route
	names  map[string]profileNames // profile id -> identifiers, only for currently-connected profiles
}

type workItem struct {
	names profileNames
	ips   []net.IP
	ttl   time.Duration
}

// Manager owns every active WireGuard tunnel and the shared nftables
// marking table, and reacts to DNS answers observed by the caller
// (internal/dnsserver's Handler) to keep routed destinations current.
//
// Observe is safe to call from the DNS hot path: it does one atomic load, a
// route match, and a non-blocking channel send — never a syscall, never a
// lock. Reconcile (config load/reload) and the background worker (draining
// the channel into nft) are the only paths that shell out.
type Manager struct {
	runner Runner

	mu     sync.Mutex
	active map[string]*activeProfile // profile id -> state; guarded by mu

	snap atomic.Pointer[snapshot]

	// publicIP is the address ProxyAnswer hands out for a Proxy-enabled
	// route's domains — set via SetPublicIP, read atomically since it can
	// be looked up from the DNS hot path.
	publicIP atomic.Pointer[net.IP]

	work    chan workItem
	workers sync.WaitGroup
	closed  chan struct{}
}

// NewManager starts a Manager with its background routing-update workers
// running. Call Close when done.
func NewManager() *Manager {
	m := &Manager{
		runner: execRunner{},
		active: make(map[string]*activeProfile),
		work:   make(chan workItem, 2048),
		closed: make(chan struct{}),
	}
	m.snap.Store(&snapshot{})
	const workerCount = 2
	m.workers.Add(workerCount)
	for range workerCount {
		go m.worker()
	}
	return m
}

func (m *Manager) worker() {
	defer m.workers.Done()
	for {
		select {
		case item := <-m.work:
			for _, ip := range item.ips {
				if err := addDestination(m.runner, item.names, ip, item.ttl); err != nil {
					slog.Warn("vpn: routing update failed", "error", err)
				}
			}
		case <-m.closed:
			return
		}
	}
}

// Observe reacts to one DNS answer written to a client. name is the
// (lowercased, no trailing dot) query name; ips are every A/AAAA address in
// the response; ttl is the answer's TTL (used to time out the routing
// entry, clamped to a sane range in addDestination). It must never block —
// see the Manager doc comment.
func (m *Manager) Observe(a Answer) {
	if len(a.IPs) == 0 {
		return
	}
	snap := m.snap.Load()
	if snap == nil || len(snap.routes) == 0 {
		return
	}
	rt := matchRoute(snap.routes, a.Name)
	if rt == nil {
		return
	}
	names, ok := snap.names[rt.profile]
	if !ok {
		return // route's profile is defined but not currently connected
	}
	select {
	case m.work <- workItem{names: names, ips: a.IPs, ttl: a.TTL}:
	default:
		// Never block the DNS response path. A dropped update just means
		// this particular answer's IPs start routing through the tunnel a
		// beat later, once a subsequent query for the same domain succeeds.
	}
}

// matchRoute returns the most specific route whose domain matches name —
// exactly or as any ancestor — or nil. Mirrors dnsserver's routeMatch for
// upstream_routes.
func matchRoute(routes []route, name string) *route {
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	var best *route
	bestLen := -1
	for i := range routes {
		for _, dom := range routes[i].domains {
			if name == dom || strings.HasSuffix(name, "."+dom) {
				if len(dom) > bestLen {
					best = &routes[i]
					bestLen = len(dom)
				}
			}
		}
	}
	return best
}

// Reconcile brings the running tunnels in line with the desired profiles
// and routes: profiles that were removed or changed provider/region are
// torn down, new ones are connected, unchanged ones are left alone (so a
// config save that touches an unrelated setting never forces every tunnel
// to reconnect). Safe to call repeatedly (boot, every config reload).
func (m *Manager) Reconcile(ctx context.Context, profiles []ProfileSpec, routes []RouteSpec, creds Credentials) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	desired := make(map[string]ProfileSpec, len(profiles))
	for _, p := range profiles {
		desired[p.ID] = p
	}

	for id, ap := range m.active {
		p, ok := desired[id]
		if ok && p.Provider == ap.provider && p.Region == ap.region {
			continue
		}
		m.teardown(ap)
		delete(m.active, id)
	}

	var errs []string
	for _, p := range profiles {
		if _, ok := m.active[p.ID]; ok {
			continue
		}
		ap, err := m.bringUp(ctx, p, creds)
		if err != nil {
			slog.Error("vpn: profile failed to connect", "profile", p.ID, "provider", p.Provider, "region", p.Region, "error", err)
			errs = append(errs, fmt.Sprintf("%s: %v", p.ID, err))
			continue
		}
		m.active[p.ID] = ap
	}

	var names []profileNames
	nameByID := make(map[string]profileNames, len(m.active))
	for id, ap := range m.active {
		names = append(names, ap.names)
		nameByID[id] = ap.names
	}
	if len(names) > 0 {
		if err := rebuildMarkingTable(m.runner, names); err != nil {
			errs = append(errs, err.Error())
		}
	} else {
		_ = clearMarkingTable(m.runner) // best-effort; fine if it was never created
	}

	compiled := make([]route, 0, len(routes))
	for _, rt := range routes {
		compiled = append(compiled, route{profile: rt.Profile, domains: rt.Domains, proxy: rt.Proxy})
	}
	m.snap.Store(&snapshot{routes: compiled, names: nameByID})

	if len(errs) > 0 {
		return fmt.Errorf("vpn: %d profile(s) failed: %s", len(errs), strings.Join(errs, "; "))
	}
	return nil
}

func (m *Manager) bringUp(ctx context.Context, p ProfileSpec, creds Credentials) (*activeProfile, error) {
	provider, err := providerFactory(p.Provider, creds)
	if err != nil {
		return nil, err
	}
	peer, err := provider.Connect(ctx, p.Region)
	if err != nil {
		return nil, fmt.Errorf("connecting via %s: %w", p.Provider, err)
	}
	names := namesFor(p.ID)
	if err := wireguardUp(m.runner, names.iface, peer); err != nil {
		return nil, err
	}
	if err := profileRouteUp(m.runner, names); err != nil {
		_ = wireguardDown(m.runner, names.iface)
		return nil, err
	}
	return &activeProfile{
		id: p.ID, provider: p.Provider, region: p.Region,
		names: names, peer: peer, upSince: time.Now(),
	}, nil
}

func (m *Manager) teardown(ap *activeProfile) {
	profileRouteDown(m.runner, ap.names)
	if err := wireguardDown(m.runner, ap.names.iface); err != nil {
		slog.Warn("vpn: tearing down interface", "profile", ap.id, "iface", ap.names.iface, "error", err)
	}
}

// providerFactory constructs a Provider for a profile's configured
// vendor. A package-level variable (rather than a plain function) so
// tests can substitute a stub and avoid any real network access.
var providerFactory = func(kind string, creds Credentials) (Provider, error) {
	switch kind {
	case "nordvpn":
		return &NordVPN{Token: creds.NordVPNToken}, nil
	case "pia":
		return &PIA{Username: creds.PIAUsername, Password: creds.PIAPassword}, nil
	default:
		return nil, fmt.Errorf("unsupported provider %q", kind)
	}
}

// Close tears down every active tunnel, clears the shared nftables table
// and stops the background workers. The Manager must not be used after
// Close returns.
func (m *Manager) Close() {
	close(m.closed)
	m.workers.Wait()
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, ap := range m.active {
		m.teardown(ap)
	}
	m.active = make(map[string]*activeProfile)
	_ = clearMarkingTable(m.runner)
	m.snap.Store(&snapshot{})
}

// ProfileStatus is one connected tunnel's state, for the REST API/dashboard.
type ProfileStatus struct {
	ID       string    `json:"id"`
	Provider string    `json:"provider"`
	Region   string    `json:"region"`
	Iface    string    `json:"iface"`
	Endpoint string    `json:"endpoint"`
	UpSince  time.Time `json:"up_since"`
}

// SetPublicIP sets the address ProxyAnswer hands out for Proxy-enabled
// routes. Safe to call anytime, including concurrently with ProxyAnswer.
func (m *Manager) SetPublicIP(ip net.IP) {
	m.publicIP.Store(&ip)
}

// ProxyAnswer is the DNS hot-path hook for the Smart-DNS-style relay (see
// config.VPNProxyConfig): called with the query name for every lookup, it
// returns this server's own public IP — for the caller to answer with
// directly, instead of resolving the real address — when name matches a
// Proxy-enabled route whose profile is currently connected. It does one
// atomic load and a route match, exactly like Observe, so it is safe to
// call on every query even when the feature is unused (the common case
// simply finds no proxy routes and returns immediately).
func (m *Manager) ProxyAnswer(name string) (net.IP, bool) {
	snap := m.snap.Load()
	if snap == nil || len(snap.routes) == 0 {
		return nil, false
	}
	rt := matchRoute(snap.routes, name)
	if rt == nil || !rt.proxy {
		return nil, false
	}
	if _, ok := snap.names[rt.profile]; !ok {
		return nil, false // profile defined but not currently connected
	}
	ipPtr := m.publicIP.Load()
	if ipPtr == nil || *ipPtr == nil {
		return nil, false // proxy enabled but no public IP configured/detected yet
	}
	return *ipPtr, true
}

// MatchProxyRoute is the Relay's counterpart to ProxyAnswer: given a
// hostname sniffed from a live connection (TLS SNI or an HTTP Host
// header), it returns the id of the currently-connected profile whose
// Proxy-enabled route matches, or ok=false if nothing matches — including
// when the matching route exists but its profile isn't connected right
// now, so the Relay never routes through a dead tunnel.
func (m *Manager) MatchProxyRoute(hostname string) (profileID string, ok bool) {
	snap := m.snap.Load()
	if snap == nil || len(snap.routes) == 0 {
		return "", false
	}
	rt := matchRoute(snap.routes, hostname)
	if rt == nil || !rt.proxy {
		return "", false
	}
	if _, connected := snap.names[rt.profile]; !connected {
		return "", false
	}
	return rt.profile, true
}

// EnsureRouted adds ip to profileID's nftables destination set so outbound
// connections this process makes to it — including the Relay's outbound
// dial for a proxied connection — get policy-routed through that profile's
// WireGuard tunnel, exactly like an IP observed from a DNS answer. Unlike
// Observe, this is synchronous: the caller (the Relay, before dialing out)
// needs the routing rule to exist before the first packet goes out, not
// merely queued for eventual application.
func (m *Manager) EnsureRouted(profileID string, ip net.IP, ttl time.Duration) error {
	m.mu.Lock()
	ap, ok := m.active[profileID]
	m.mu.Unlock()
	if !ok {
		return fmt.Errorf("vpn: profile %q is not currently connected", profileID)
	}
	return addDestination(m.runner, ap.names, ip, ttl)
}

// Status returns a snapshot of every currently-connected profile, sorted by
// ID for a stable API response.
func (m *Manager) Status() []ProfileStatus {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]ProfileStatus, 0, len(m.active))
	for _, ap := range m.active {
		out = append(out, ProfileStatus{
			ID:       ap.id,
			Provider: ap.provider,
			Region:   ap.region,
			Iface:    ap.names.iface,
			Endpoint: ap.peer.Endpoint,
			UpSince:  ap.upSince,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}
