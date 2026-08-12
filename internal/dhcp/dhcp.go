// Package dhcp implements a stateful DHCPv4 (RFC 2131) and DHCPv6 (RFC 8415)
// server for the LAN this host's DNS server runs on. It hands out addresses
// from a config-driven pool, honours static reservations, persists leases so
// assignments survive restarts, and registers client hostnames so the DNS
// handler can resolve <hostname>.<domain> locally. It is off by default and
// deliberately simple: no relays (giaddr replies excepted), no prefix
// delegation, no relay-agent options — a home/office LAN server, like the
// DNS server it rides alongside.
package dhcp

import (
	"encoding/hex"
	"encoding/json"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/insomniacslk/dhcp/dhcpv4/server4"
	"github.com/insomniacslk/dhcp/dhcpv6"
	"github.com/insomniacslk/dhcp/dhcpv6/server6"
	"github.com/insomniacslk/dhcp/iana"
)

const (
	// defaultLeaseTime is used when the config leaves lease_time at 0.
	defaultLeaseTime = 24 * time.Hour
	// offeredHold is how long an address stays reserved for a client after
	// an OFFER, awaiting its REQUEST.
	offeredHold = 90 * time.Second
	// declinedHold is how long a DECLINEd address is withheld from the pool.
	declinedHold = 30 * time.Minute
	// minLeaseTime floors the lease a client can request (RFC 2131 §4.4.5
	// suggests rejecting sub-minute leases).
	minLeaseTime = 60 * time.Second
	// v6Preferred is the preferred lifetime advertised on IA_NA addresses
	// (0.5 * valid).
	v6PreferredFraction = 2
	// persistInterval debounces lease writes to disk.
	persistInterval = 2 * time.Second
)

// StaticLease is a fixed reservation: MAC keys DHCPv4, DUID keys DHCPv6.
type StaticLease struct {
	MAC      string
	DUID     string
	IP       net.IP
	Hostname string
}

// Config is the runtime DHCP configuration. It is built from
// config.DHCPConfig via ConfigFrom in the API/main wiring (the package keeps
// its own copy so it never imports config, matching the filter package's
// pattern).
type Config struct {
	// Enabled mirrors config.DHCPConfig.Enabled: whether the operator wants
	// the server running at all. It gates Start/Enabled so a subnet left in
	// the config after disabling DHCP never binds the listeners.
	Enabled              bool
	Interface            string
	Subnet               *net.IPNet
	RangeStart, RangeEnd net.IP
	Gateway              net.IP
	DNS                  []net.IP
	LeaseTime            time.Duration
	Domain               string
	Static               []StaticLease
	IPv6                 bool
	IPv6Prefix           *net.IPNet
	IPv6Start, IPv6End   net.IP
	// ServerIPv4/ServerIPv6 are this host's addresses inside the served
	// networks: the default gateway/DNS/lease-server options and the anchor
	// for the server DUID. ServerMAC is used to derive the DUID. Discovered
	// by ConfigFrom (via HostAddresses) rather than set from the YAML.
	ServerIPv4, ServerIPv6 net.IP
	ServerMAC              net.HardwareAddr
}

// ConfigFrom maps a config.DHCPConfig-equivalent field set into the runtime
// Config. The caller supplies this host's own addresses via addrs (may be
// zero-valued when unknown — the handlers then fall back to the configured
// gateway/DNS values). Sharing one constructor between main's boot/reload
// path and the API's live-apply path keeps the two configs identical, so a
// dashboard save never silently drops fields (e.g. the server identifier).
func ConfigFrom(
	enabled bool,
	iface, subnet, rangeStart, rangeEnd, gateway string,
	dns []string,
	leaseTime time.Duration,
	domain string,
	static []StaticLease,
	ipv6 bool,
	ipv6Prefix, ipv6Start, ipv6End string,
	addrs HostAddresses,
) Config {
	cfg := Config{
		Enabled:    enabled,
		Interface:  iface,
		Gateway:    net.ParseIP(gateway),
		LeaseTime:  leaseTime,
		Domain:     domain,
		IPv6:       ipv6,
		ServerIPv4: addrs.IPv4,
		ServerIPv6: addrs.IPv6,
		ServerMAC:  addrs.MAC,
	}
	if _, ipnet, err := net.ParseCIDR(subnet); err == nil {
		cfg.Subnet = ipnet
	}
	cfg.RangeStart = net.ParseIP(rangeStart)
	cfg.RangeEnd = net.ParseIP(rangeEnd)
	for _, d := range dns {
		cfg.DNS = append(cfg.DNS, net.ParseIP(d))
	}
	if _, ipnet6, err := net.ParseCIDR(ipv6Prefix); err == nil {
		cfg.IPv6Prefix = ipnet6
	}
	cfg.IPv6Start = net.ParseIP(ipv6Start)
	cfg.IPv6End = net.ParseIP(ipv6End)
	cfg.Static = static
	return cfg
}

// HostAddresses are this host's own addresses inside the served networks,
// used as the default gateway/DNS options and to derive the server DUID.
type HostAddresses struct {
	IPv4, IPv6 net.IP
	MAC        net.HardwareAddr
}

// Lease is one address assignment.
type Lease struct {
	Key      string    `json:"key"` // "v4:<mac>" or "v6:<duid-hex>"
	MAC      string    `json:"mac,omitempty"`
	DUID     string    `json:"duid,omitempty"`
	IP       string    `json:"ip"`
	Hostname string    `json:"hostname,omitempty"`
	Expires  time.Time `json:"expires"` // zero time = static reservation
	Static   bool      `json:"static,omitempty"`
}

// leaseKey is the per-client identity used for both address families.
type leaseKey string

func v4Key(mac net.HardwareAddr) leaseKey { return leaseKey("v4:" + strings.ToLower(mac.String())) }
func v6Key(duidHex string) leaseKey       { return leaseKey("v6:" + duidHex) }

// reservation pins one address: either an in-flight OFFER owned by a client
// key, or a declined address held away from everyone (key == "").
type reservation struct {
	key   leaseKey
	until time.Time
}

// Server is the DHCP server. It is safe for concurrent use: the packet
// handlers, the API and the persistence loop all read/write under mu.
type Server struct {
	mu         sync.RWMutex
	cfg        Config
	leases     map[leaseKey]*Lease
	byIP       map[string]*Lease
	hosts      map[string]net.IP // lowercased hostname -> address
	reserved   map[string]reservation
	cursor4    uint32
	cursor6    uint32
	serverDUID dhcpv6.DUID
	v4srv      *server4.Server
	v6srv      *server6.Server
	persistDir string
	dirty      bool
	stopCh     chan struct{}
	stopped    bool
}

// New creates a DHCP server whose leases persist under dir.
func New(dir string) *Server {
	return &Server{
		leases:     map[leaseKey]*Lease{},
		byIP:       map[string]*Lease{},
		hosts:      map[string]net.IP{},
		reserved:   map[string]reservation{},
		persistDir: dir,
		stopCh:     make(chan struct{}),
	}
}

// SetConfig replaces the runtime configuration. Pools, static reservations,
// options and the domain are read per packet under the lock, so a live
// change applies immediately; only the listener bind (interface/enabled)
// needs RestartListeners.
func (s *Server) SetConfig(cfg Config) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cfg = cfg
	s.leaseTimeLocked()
	if s.serverDUID == nil {
		s.serverDUID = makeServerDUID(cfg.ServerMAC)
	}
	s.loadLocked()
	s.rebuildHostsLocked()
}

// leaseTime returns the effective lease duration.
func (s *Server) leaseTimeLocked() time.Duration {
	if s.cfg.LeaseTime > 0 {
		return s.cfg.LeaseTime
	}
	return defaultLeaseTime
}

// makeServerDUID derives a stable server DUID from the host's MAC (a
// DUID-LL, RFC 8415 §11.3): the same MAC yields the same DUID across
// restarts, so clients' cached server identities keep matching.
func makeServerDUID(mac net.HardwareAddr) dhcpv6.DUID {
	ll := &dhcpv6.DUIDLL{HWType: iana.HWTypeEthernet}
	if mac != nil {
		ll.LinkLayerAddr = mac
	} else {
		// No MAC to anchor on (shouldn't happen on a real LAN box): a
		// deterministic opaque DUID from the time of first start, stable
		// for the process life.
		ll.LinkLayerAddr = net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, byte(time.Now().Unix() & 0xff)}
	}
	return ll
}

// Start binds the listeners for the configured protocols (DHCPv4 always when
// the config has a subnet; DHCPv6 when cfg.IPv6). It is a no-op when the
// server is already running, and re-binds cleanly after a Stop (the reload
// path disables and re-enables DHCP without dropping the lease table).
func (s *Server) Start() error {
	s.mu.Lock()
	// A disabled server must never bind, even if a subnet is still in the
	// config — the operator's enable flag is authoritative.
	if !s.cfg.Enabled || !(s.cfg.Subnet != nil || (s.cfg.IPv6 && s.cfg.IPv6Prefix != nil)) {
		s.mu.Unlock()
		return nil
	}
	if s.v4srv != nil || s.v6srv != nil {
		s.mu.Unlock()
		return nil
	}
	cfg := s.cfg
	duid := s.serverDUID
	s.stopped = false
	s.stopCh = make(chan struct{})
	s.mu.Unlock()

	go s.persistLoop()

	if cfg.Subnet != nil {
		v4srv, err := server4.NewServer(cfg.Interface, &net.UDPAddr{Port: 67}, s.handleV4)
		if err != nil {
			log.Printf("[dhcp] v4 listen on %q:67 failed: %v", cfg.Interface, err)
			return err
		}
		s.mu.Lock()
		s.v4srv = v4srv
		s.mu.Unlock()
		go func() {
			if err := v4srv.Serve(); err != nil {
				log.Printf("[dhcp] v4 server stopped: %v", err)
			}
		}()
		log.Printf("[dhcp] DHCPv4 on %q:67 serving %s (pool %s-%s)", cfg.Interface, cfg.Subnet, cfg.RangeStart, cfg.RangeEnd)
	}

	if cfg.IPv6 && cfg.IPv6Prefix != nil {
		v6srv, err := server6.NewServer(cfg.Interface, &net.UDPAddr{Port: 547}, s.handleV6)
		if err != nil {
			log.Printf("[dhcp] v6 listen on %q:547 failed: %v", cfg.Interface, err)
			return err
		}
		s.mu.Lock()
		s.v6srv = v6srv
		s.mu.Unlock()
		go func() {
			if err := v6srv.Serve(); err != nil {
				log.Printf("[dhcp] v6 server stopped: %v", err)
			}
		}()
		_ = duid
		log.Printf("[dhcp] DHCPv6 on %q:547 serving %s (pool %s-%s, DUID %s)", cfg.Interface, cfg.IPv6Prefix, cfg.IPv6Start, cfg.IPv6End, duid.String())
	}
	return nil
}

// RestartListeners stops and rebinds the packet listeners, applying a change
// to the interface or to which protocols are enabled without dropping leases
// (they live in memory + on disk).
func (s *Server) RestartListeners() error {
	s.Stop()
	return s.Start()
}

// Stop closes the packet listeners and flushes leases to disk. Idempotent;
// Start can be called again afterwards (a fresh stopCh is created there).
func (s *Server) Stop() {
	s.mu.Lock()
	v4srv, v6srv := s.v4srv, s.v6srv
	s.v4srv, s.v6srv = nil, nil
	if !s.stopped {
		close(s.stopCh)
	}
	s.stopped = true
	s.mu.Unlock()
	if v4srv != nil {
		_ = v4srv.Close()
	}
	if v6srv != nil {
		_ = v6srv.Close()
	}
	s.persistNow()
}

// Enabled reports whether the server is configured to run: the operator's
// enable flag AND at least one protocol with a network to serve. A subnet
// left in the config after disabling DHCP does not bind the listeners.
func (s *Server) Enabled() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.cfg.Enabled && (s.cfg.Subnet != nil || (s.cfg.IPv6 && s.cfg.IPv6Prefix != nil))
}

// Interface returns the NIC the listeners bind ("" = all interfaces).
func (s *Server) Interface() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.cfg.Interface
}

// Config returns a copy of the current runtime config — used by the API's
// live-apply path to carry the boot-discovered host addresses forward.
func (s *Server) Config() Config {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.cfg
}

// ---------------------------------------------------------------------------
// Persistence

// persistLoop debounces lease writes: a burst of renewals (every device on
// the LAN booting at once) collapses to one file write per interval.
func (s *Server) persistLoop() {
	t := time.NewTicker(persistInterval)
	defer t.Stop()
	for {
		select {
		case <-s.stopCh:
			return
		case <-t.C:
			s.persistNow()
		}
	}
}

// persistNow writes the current lease table to disk when it changed.
func (s *Server) persistNow() {
	s.mu.Lock()
	if !s.dirty {
		s.mu.Unlock()
		return
	}
	s.dirty = false
	leases := make([]Lease, 0, len(s.leases))
	for _, l := range s.leases {
		leases = append(leases, *l)
	}
	s.mu.Unlock()

	if err := os.MkdirAll(s.persistDir, 0o755); err != nil {
		log.Printf("[dhcp] lease persist mkdir: %v", err)
		return
	}
	data, err := json.Marshal(leases)
	if err != nil {
		log.Printf("[dhcp] lease persist encode: %v", err)
		return
	}
	tmp := filepath.Join(s.persistDir, "leases.json.tmp")
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		log.Printf("[dhcp] lease persist write: %v", err)
		return
	}
	if err := os.Rename(tmp, filepath.Join(s.persistDir, "leases.json")); err != nil {
		log.Printf("[dhcp] lease persist rename: %v", err)
	}
}

// loadLocked re-reads persisted leases (called under mu by SetConfig), keeps
// only unexpired dynamic ones plus all statics that are still configured.
func (s *Server) loadLocked() {
	data, err := os.ReadFile(filepath.Join(s.persistDir, "leases.json"))
	if err != nil {
		return // first boot or missing file
	}
	var saved []Lease
	if err := json.Unmarshal(data, &saved); err != nil {
		log.Printf("[dhcp] lease load: %v", err)
		return
	}
	now := time.Now()
	for _, l := range saved {
		if l.Static {
			// A static lease persists only while its reservation still
			// exists in the config.
			if s.staticForLocked(l.Key, l.IP) {
				s.leases[leaseKey(l.Key)] = &l
				s.byIP[l.IP] = &l
			}
			continue
		}
		if l.Expires.After(now) {
			s.leases[leaseKey(l.Key)] = &l
			s.byIP[l.IP] = &l
		}
	}
	log.Printf("[dhcp] loaded %d lease(s) from disk", len(s.leases))
}

// staticForLocked reports whether a persisted static lease still matches a
// configured reservation (same client key and address).
func (s *Server) staticForLocked(key string, ip string) bool {
	for _, st := range s.cfg.Static {
		if st.MAC != "" && v4Key(net.HardwareAddr(mustMAC(st.MAC))) == leaseKey(key) && st.IP.String() == ip {
			return true
		}
		if st.DUID != "" && v6Key(st.DUID) == leaseKey(key) && st.IP.String() == ip {
			return true
		}
	}
	return false
}

func mustMAC(s string) net.HardwareAddr {
	m, err := net.ParseMAC(s)
	if err != nil {
		return nil
	}
	return m
}

// markDirty schedules the next persistence write.
func (s *Server) markDirtyLocked() { s.dirty = true }

// ---------------------------------------------------------------------------
// Hostname resolution for the DNS handler

// LookupHost resolves a DHCP-registered hostname to its address(es). It
// matches both the bare hostname and <hostname>.<domain> (case-insensitive),
// returning the IPv4 and/or IPv6 lease. ok=false when the name is unknown.
func (s *Server) LookupHost(name string) (ips []net.IP, ok bool) {
	name = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
	if name == "" {
		return nil, false
	}
	// Peel the configured domain suffix: printer.lan -> printer.
	domain := strings.ToLower(strings.TrimSuffix(s.domain(), "."))
	if domain != "" && strings.HasSuffix(name, "."+domain) {
		name = strings.TrimSuffix(name, "."+domain)
	}
	s.mu.RLock()
	ip, found := s.hosts[name]
	s.mu.RUnlock()
	if !found {
		return nil, false
	}
	return []net.IP{ip}, true
}

func (s *Server) domain() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.cfg.Domain
}

// rebuildHostsLocked regenerates the hostname index from current leases and
// static reservations (called under mu on config/lease changes).
func (s *Server) rebuildHostsLocked() {
	s.hosts = map[string]net.IP{}
	for _, st := range s.cfg.Static {
		if st.Hostname == "" {
			continue
		}
		s.hosts[strings.ToLower(st.Hostname)] = st.IP
	}
	for _, l := range s.leases {
		if l.Hostname == "" {
			continue
		}
		if ip := net.ParseIP(l.IP); ip != nil {
			s.hosts[strings.ToLower(l.Hostname)] = ip
		}
	}
}

// ---------------------------------------------------------------------------
// API snapshot

// LeaseView is the JSON shape for the dashboard's DHCP page.
type LeaseView struct {
	IP       string `json:"ip"`
	MAC      string `json:"mac,omitempty"`
	DUID     string `json:"duid,omitempty"`
	Hostname string `json:"hostname,omitempty"`
	Expires  string `json:"expires,omitempty"` // RFC 3339; empty = static
	Static   bool   `json:"static"`
}

// Leases returns the current assignments for the API.
func (s *Server) Leases() []LeaseView {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]LeaseView, 0, len(s.leases))
	for _, l := range s.leases {
		v := LeaseView{IP: l.IP, MAC: l.MAC, DUID: l.DUID, Hostname: l.Hostname, Static: l.Static}
		if !l.Static {
			v.Expires = l.Expires.Format(time.RFC3339)
		}
		out = append(out, v)
	}
	return out
}

// duidHex is the hex encoding of a client DUID, used as a lease key.
func duidHex(d dhcpv6.DUID) string {
	if d == nil {
		return ""
	}
	return hex.EncodeToString(d.ToBytes())
}
