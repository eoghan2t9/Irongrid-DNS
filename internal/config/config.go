// Package config defines the YAML configuration schema for Irongrid DNS
// and handles loading, defaulting and persisting it.
package config

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
	"gopkg.in/yaml.v3"
)

// Config is the root configuration document.
type Config struct {
	Server ServerConfig `yaml:"server"`
	// Upstreams is the forwarder list. When more than one is configured,
	// UpstreamMode decides how they are queried for each resolution:
	// "race" (default) queries them all concurrently and returns the fastest
	// successful answer; "sequential" tries them in list order, failing over
	// to the next only when the previous errors or answers SERVFAIL.
	Upstreams []string `yaml:"upstreams"`
	// UpstreamMode is the multi-upstream resolution strategy ("race" or
	// "sequential"); empty defaults to "race". It is global — client groups
	// that override the upstream list use the same strategy.
	UpstreamMode string `yaml:"upstream_mode"`
	// UpstreamRoutes is conditional (split-horizon) forwarding: queries for
	// a domain subtree are sent to that route's own upstream set instead of
	// the global forwarders (or a client group's upstream override). A route
	// matches its domain and every subdomain under it; the longest matching
	// domain wins when several routes overlap. The cache is shared, which is
	// safe because routes partition the name space — one question can only
	// ever match one route.
	UpstreamRoutes []UpstreamRoute `yaml:"upstream_routes"`
	Cache          CacheConfig     `yaml:"cache"`
	TLS            TLSConfig       `yaml:"tls"`
	Filter         FilterConfig    `yaml:"filter"`
	Log            LogConfig       `yaml:"log"`
	Web            WebConfig       `yaml:"web"`
	Tunnel         TunnelConfig    `yaml:"tunnel"`
	Rewrites       []RewriteSpec   `yaml:"rewrites"`      // local DNS records (A/AAAA/CNAME)
	ClientGroups   []ClientGroup   `yaml:"client_groups"` // per-client blocking/upstream policy
	RateLimit      RateLimitConfig `yaml:"rate_limit"`
	GeoBlock       GeoBlockConfig  `yaml:"geo_block"`
	Abuse          AbuseConfig     `yaml:"abuse"`
	DNSSEC         DNSSECConfig    `yaml:"dnssec"`
	Warmer         WarmerConfig    `yaml:"warmer"`
	// Recursive tunes the recursive:// upstream transport (the iterative
	// resolver that walks referrals from the root servers itself).
	Recursive RecursiveConfig `yaml:"recursive"`
	DHCP      DHCPConfig      `yaml:"dhcp"`
}

// DHCPConfig controls the built-in DHCP server: stateful DHCPv4 (RFC 2131)
// and DHCPv6 (RFC 8415 IA_NA, plus stateless option serving to SLAAC
// clients). It is meant for a LAN deployment where this host is the network's
// DNS server — the addresses handed out and the options advertised are all
// config-driven, and off by default.
type DHCPConfig struct {
	Enabled bool `yaml:"enabled"`
	// Interface binds the server to one NIC (e.g. "eth0", "br0"); empty
	// listens on all interfaces. Binding a specific interface is
	// recommended when the host has several NICs so the server only
	// answers on the LAN.
	Interface string `yaml:"interface"`
	// Subnet is the IPv4 network served, e.g. "192.168.1.0/24".
	Subnet string `yaml:"subnet"`
	// RangeStart/RangeEnd bound the dynamic IPv4 pool handed to clients.
	RangeStart string `yaml:"range_start"`
	RangeEnd   string `yaml:"range_end"`
	// Gateway is the router option advertised to clients; empty defaults to
	// this server's own address on the subnet.
	Gateway string `yaml:"gateway"`
	// DNS are the DNS server options advertised to clients; empty defaults
	// to this server's own address (the whole point: Irongrid is the DNS).
	DNS []string `yaml:"dns"`
	// LeaseTime is how long a dynamic lease lasts; 0 uses the default (24h).
	LeaseTime time.Duration `yaml:"lease_time"`
	// Domain is the suffix appended to client hostnames for local DNS
	// resolution (e.g. "lan" makes a client "printer" resolvable as
	// printer.lan). Empty disables hostname resolution.
	Domain string `yaml:"domain"`
	// StaticLeases reserve fixed addresses per client (MAC for v4, DUID for
	// v6) that never expire, and their hostnames are always resolvable.
	StaticLeases []DHCPStaticLease `yaml:"static_leases"`
	// IPv6 enables the DHCPv6 server on the same interface: stateful IA_NA
	// assignment from IPv6Range within IPv6Prefix, plus stateless option
	// serving (DNS etc.) to SLAAC-only clients.
	IPv6 bool `yaml:"ipv6"`
	// IPv6Prefix is the network served, e.g. "fd00::/64" (ULA).
	IPv6Prefix     string `yaml:"ipv6_prefix"`
	IPv6RangeStart string `yaml:"ipv6_range_start"`
	IPv6RangeEnd   string `yaml:"ipv6_range_end"`
}

// DHCPStaticLease reserves a fixed address for one client and optionally
// pins its hostname. MAC is used by DHCPv4; DUID by DHCPv6.
type DHCPStaticLease struct {
	MAC      string `yaml:"mac"`
	DUID     string `yaml:"duid"`
	IP       string `yaml:"ip"`
	Hostname string `yaml:"hostname"`
}

// RecursiveConfig tunes the recursive:// upstream transport.
type RecursiveConfig struct {
	// ServerTimeout bounds one exchange with one nameserver during a
	// referral walk (each hop of root -> TLD -> authoritative). A dead or
	// unresponsive server is given up on after this so the walk can move on;
	// 0 uses the built-in default (3s). server.timeout_sec still bounds the
	// whole query — this only caps the per-server share of it.
	ServerTimeout time.Duration `yaml:"server_timeout"`
}

// WarmerConfig is the proactive cache warmer: a background loop that scans
// the query log for the domains queried within Lookback and pre-resolves
// them (A + AAAA) through the current upstreams into the cache, so a restart
// or cache flush doesn't leave the first query for each domain cold. A pass
// runs immediately at boot and then every Interval; each pass only refreshes
// entries that are missing, expired or inside their serve-stale window, so
// steady-state upstream traffic is low. Off by default because warming uses
// the upstreams even when nobody is asking.
type WarmerConfig struct {
	Enabled bool `yaml:"enabled"`
	// Interval between passes; 0 uses the default (15m).
	Interval time.Duration `yaml:"interval"`
	// Lookback is how far back into the query log a pass looks for active
	// domains; 0 uses the default (24h).
	Lookback time.Duration `yaml:"lookback"`
	// MaxDomains caps the number of domains warmed per pass (0 = every
	// domain in the lookback window, up to the query-log scan bound).
	MaxDomains int `yaml:"max_domains"`
	// Concurrency bounds how many upstream resolutions run in parallel per
	// pass; 0 uses the default (8).
	Concurrency int `yaml:"concurrency"`
}

// UpstreamRoute sends queries for Domain (and every subdomain under it) to
// a dedicated upstream set — split-horizon routing for networks whose
// internal names must not leak to public resolvers (e.g. "lan" -> a local
// AD or Pi-hole server). The upstream entries use the same syntax as the
// global upstreams list (udp://, tcp://, tls://, https://, quic://,
// recursive://).
type UpstreamRoute struct {
	Domain    string   `yaml:"domain"`    // exact domain, matches every subdomain under it
	Upstreams []string `yaml:"upstreams"` // dedicated forwarders for this subtree
}

// RewriteSpec is a local DNS record: a domain answered directly by Irongrid
// instead of being forwarded upstream. Domain may be an exact name or a
// "*.suffix" wildcard covering the whole subtree.
type RewriteSpec struct {
	Domain string `yaml:"domain"`
	Type   string `yaml:"type"` // "A", "AAAA" or "CNAME"
	Value  string `yaml:"value"`
	TTL    uint32 `yaml:"ttl"` // 0 = default (300s)
}

// ClientGroup applies a different blocking/upstream policy to clients whose
// source IP falls in one of CIDRs, or whose ISP's ASN is listed in ASNs.
// Groups are evaluated in list order; the first match wins. Clients matching
// no group use the global Filter/Upstreams.
type ClientGroup struct {
	ID      string   `yaml:"id"`
	Name    string   `yaml:"name"`
	Enabled bool     `yaml:"enabled"`
	CIDRs   []string `yaml:"cidrs"` // e.g. "192.168.1.50/32", "10.0.5.0/24"
	// ASNs matches clients by ISP instead of (or in addition to) CIDR — e.g.
	// "AS13335" to pin every Cloudflare-egressed client to this group. Uses
	// the same ip2asn dataset as geo_block (iptoasn.com by default), fetched
	// and cached the same way.
	ASNs []string `yaml:"asns"`
	// Blocklists selects a subset of filter.blocklists by ID. Empty means
	// "every enabled global blocklist" (same as the default policy).
	Blocklists []string `yaml:"blocklists"`
	Whitelist  []string `yaml:"whitelist"` // additional to the global whitelist
	Blacklist  []string `yaml:"blacklist"` // additional to the global blacklist
	// Upstreams overrides the global forwarders for this group. Empty uses
	// the global Upstreams list.
	Upstreams []string `yaml:"upstreams"`
}

// RateLimitConfig throttles queries per source IP to protect against abuse
// (e.g. a compromised LAN device, or a misconfigured public listener being
// used for DNS amplification).
type RateLimitConfig struct {
	Enabled bool `yaml:"enabled"`
	QPS     int  `yaml:"qps"`   // sustained queries/sec allowed per client IP
	Burst   int  `yaml:"burst"` // short-burst allowance above qps
	// AutoBlock adds a fail2ban-style layer on top of the token bucket: a
	// client that trips the limit BlockAfter times (within BlockFor of each
	// other) has every query dropped (UDP) or refused (TCP/DoT/DoH/DoQ)
	// until the BlockFor cooldown elapses, instead of merely being throttled
	// back to the allowed rate.
	AutoBlock  bool          `yaml:"auto_block"`
	BlockAfter int           `yaml:"block_after"` // violations required to trigger; default 3
	BlockFor   time.Duration `yaml:"block_for"`   // cooldown; default 10m
	// NXGuard throttles random-subdomain ("water torture") floods: it counts
	// NXDOMAIN responses served per client prefix (IPv4 /24, IPv6 /64) and
	// refuses every query from a prefix that produces Threshold NXDOMAINs
	// within Window for BlockFor. Unlike the per-IP token bucket above, a
	// flood spread over many sources or churned IPv6 privacy addresses can't
	// dodge it. Off by default; independent of rate_limit.enabled.
	NXGuard NXGuardConfig `yaml:"nxdomain_guard"`
}

// NXGuardConfig tunes the NXDOMAIN flood guard (rate_limit.nxdomain_guard).
type NXGuardConfig struct {
	Enabled bool `yaml:"enabled"`
	// Threshold is how many NXDOMAIN responses a prefix may produce within
	// Window before it is refused; default 30.
	Threshold int `yaml:"threshold"`
	// Window is how long a burst may accumulate toward Threshold; default
	// 30s.
	Window time.Duration `yaml:"window"`
	// BlockFor is how long a tripped prefix is refused; default 10m.
	BlockFor time.Duration `yaml:"block_for"`
}

// GeoBlockConfig blocks queries by the country of the client's source IP.
// Country-to-CIDR data is fetched from ipverse/rir-ip (or a base_url
// override) as per-country prefix lists, exactly like blocklists: one
// "<CC>/ipv4_agg.txt" and one "<CC>/ipv6_agg.txt" per enabled country,
// cached under the data dir and refreshed on demand.
type GeoBlockConfig struct {
	Enabled bool `yaml:"enabled"`
	// Countries are ISO 3166-1 alpha-2 codes (uppercase), e.g. RU, CN, KP.
	Countries []string `yaml:"countries"`
	// Allowlist is a set of client IPs/CIDRs that are never blocked — not by
	// country geo-blocking, not by the explicit IP block list, and not by
	// honeypot auto-blocks (a honeypot query from an allowlisted client is
	// refused but never auto-blocks or firewall-drops the source). Put the
	// operator's own servers here so whitelisting is absolute.
	Allowlist []string `yaml:"allowlist"`
	// IPs is a set of client IPs/CIDRs that are always blocked, regardless
	// of country — the "block this specific client/netblock" list (e.g.
	// known proxy-exit ranges). Entries are refused by the DNS handler like
	// blocked countries and installed into the host firewall's drop sets.
	IPs []string `yaml:"ips"`
	// Honeypots are trap domains that are never answered: any client that
	// queries one is auto-added to the blocked-IP set (persisted across
	// restarts and pushed into the host firewall so its connections are
	// dropped at the packet level, not just refused at the DNS layer). A
	// trap matches the domain AND every subdomain under it (e.g.
	// "exponea.com" also traps "x.exponea.com") — DDoS floods randomise the
	// first label, and the trap must catch those. Honeypot traffic is not
	// written to the query log. Requires geo_block.enabled to take effect.
	Honeypots []string `yaml:"honeypots"`
	// TrustUDP opt-in: when true, a honeypot hit over plain UDP auto-blocks
	// its source address too. Off by default — a UDP source can be spoofed,
	// so enabling this lets a spoofing attacker permanently block an
	// innocent victim with a single packet. Only turn it on for a trusted
	// network where client addresses are genuine.
	TrustUDP bool `yaml:"trust_udp"`
	// HoneypotUDPBlock, when > 0, is the bounded middle ground for UDP
	// honeypot hits: the source is auto-blocked via the rate limiter for
	// this window (dropped at the DNS layer, expiring automatically,
	// unblockable on the dashboard) instead of earning the permanent
	// banner/firewall block trust_udp grants. A spoofed packet can then
	// only block a victim for the window, never forever. Requires
	// rate_limit.enabled (the block runs on the rate limiter); 0 disables.
	HoneypotUDPBlock time.Duration `yaml:"honeypot_udp_block"`
	// BaseURL overrides where per-country CIDR lists are fetched from; the
	// lowercase country code and file are appended as
	// "<cc>/ipv4-aggregated.txt" and "<cc>/ipv6-aggregated.txt" (the
	// ipverse/rir-ip layout). file:// paths are supported for local datasets.
	BaseURL string `yaml:"base_url"`
	// AllowASNs are ISPs — by ASN, e.g. "AS13335" or "13335" — whose clients
	// are never blocked: not by country geo-blocking, not by the explicit IP
	// list, and not by honeypot auto-blocks (the same guarantee as the CIDR
	// allowlist, but for a whole ISP). Client IPs are mapped to ASNs with
	// the free ip2asn dataset (iptoasn.com by default), fetched and cached
	// like the country lists — no per-query network calls.
	AllowASNs []string `yaml:"allow_asns"`
	// BlockASNs are ISPs whose clients are always blocked, like IPs but
	// covering the whole ISP's ranges (DNS REFUSED plus a host-firewall
	// drop).
	BlockASNs []string `yaml:"block_asns"`
	// ASNBaseURL overrides where the ip2asn dataset is fetched from; the
	// filenames ip2asn-v4.tsv.gz / ip2asn-v6.tsv.gz are appended. file://
	// paths are supported for local datasets. Like base_url it is read at
	// boot, so a change requires a restart.
	ASNBaseURL string `yaml:"asn_base_url"`
	// AutoUpdate re-fetches the enabled countries' data every AutoUpdate
	// (the ipverse/rir-ip aggregates change roughly weekly). 0 disables
	// automatic refreshes (data is then only refreshed on save/manual
	// refresh); the default is 168h (weekly).
	AutoUpdate time.Duration `yaml:"auto_update"`
}

// AbuseConfig configures the free threat-intel integrations used to report
// the attacker IPs Irongrid blocks (one-click report from the dashboard, plus
// IP -> ASN/owner lookups for routing reports to the right hosting provider).
type AbuseConfig struct {
	// AbuseIPDBKey is the API key for api.abuseipdb.com (free tier: 1,000
	// checks/reports per day, one report per IP per 15 minutes). Empty
	// disables one-click reporting; the export and ASN lookup need no key.
	AbuseIPDBKey string `yaml:"abuseipdb_key"`
}

// DNSSECConfig enables DNSSEC enforcement. Irongrid is a forwarding
// resolver — like Pi-hole, AdGuard Home and dnsmasq, it does not build its
// own root-of-trust chain validator. Instead, enabling this sets the DO bit
// on upstream queries and requires the AD (Authenticated Data) bit in the
// response, trusting that the encrypted upstream (DoT/DoH/DoQ to e.g.
// Cloudflare, Google or Quad9) has already validated the signature chain.
// Plain UDP/TCP upstreams can have the AD bit stripped or forged in transit,
// so this option is only meaningful with an encrypted upstream.
type DNSSECConfig struct {
	Enabled bool `yaml:"enabled"`
	// RequireAD, when true, treats an answer without the AD bit as bogus and
	// returns SERVFAIL instead of passing it through unauthenticated.
	RequireAD bool `yaml:"require_ad"`
}

// ServerConfig controls every network listener.
type ServerConfig struct {
	ListenUDP string `yaml:"listen_udp"` // plain DNS over UDP, "" disables
	ListenTCP string `yaml:"listen_tcp"` // plain DNS over TCP, "" disables
	ListenDoT string `yaml:"listen_dot"` // DNS over TLS, "" disables
	ListenDoH string `yaml:"listen_doh"` // DNS over HTTPS, "" disables
	// ListenDoH3 is the UDP address for DNS over HTTP/3 (RFC 9114/8484
	// over QUIC, "h3" ALPN), typically "0.0.0.0:443" next to the TCP DoH
	// listener. "" disables. DoH3 binds UDP, so it can coexist with the
	// dashboard/DoH on TCP 443; it must not share an address with the DoQ
	// listener (different ALPNs on one UDP port cannot be negotiated).
	ListenDoH3 string `yaml:"listen_doh3"`
	ListenDoQ  string `yaml:"listen_doq"` // DNS over QUIC, "" disables
	DoHPath    string `yaml:"doh_path"`   // HTTP path served for DoH (RFC 8484)
	WebListen  string `yaml:"web_listen"` // management web UI + REST API
	WebTLS     bool   `yaml:"web_tls"`    // serve the web UI + API over HTTPS (uses the TLS cert)
	// WebRedirect serves a plain-HTTP listener on WebRedirectPort that 301s
	// to https://<host>/ — a convenience when web_tls is enabled.
	WebRedirect     bool `yaml:"web_redirect"`
	WebRedirectPort int  `yaml:"web_redirect_port"` // default 80
	TimeoutSec      int  `yaml:"timeout_sec"`       // per-query timeout
	// UDPSockets is how many SO_REUSEPORT sockets the plain UDP and DoQ
	// listeners bind so the kernel spreads incoming datagrams across
	// per-socket receive queues (each drained by its own read goroutine).
	// 0 = auto (one per CPU, capped); 1 = a single plain socket (strictly
	// exclusive binding — the pre-reuseport behaviour); N = exactly N
	// sockets (capped at 64).
	UDPSockets int `yaml:"udp_sockets"`
	// UDPWorkers is how many handler workers each plain-UDP socket's read
	// loop dispatches to. The workers replace miekg/dns's
	// goroutine-per-datagram model, so a flood costs zero goroutine
	// creation and bounded memory. 0 = auto (4 × CPU per socket, floor 16,
	// capped 256); N = exactly N workers per socket (capped at 512).
	UDPWorkers int `yaml:"udp_workers"`
	// Padding pads responses on the encrypted transports (DoT/DoH/DoH3/DoQ)
	// to fixed 128-byte block boundaries (RFC 7830), so an observer of the
	// encrypted stream cannot infer which domain was queried from the
	// message length. Off by default; plain UDP/TCP are never padded.
	Padding bool `yaml:"padding"`
	// Cookies enables server DNS cookies (RFC 7873) on UDP and TCP: a
	// client that sends a COOKIE option gets its 8-byte client cookie
	// echoed with an HMAC server cookie bound to its IP, and a query
	// carrying a stale/forged server cookie is answered BADCOOKIE instead
	// of being processed — blunting off-path spoofing and cache pollution.
	Cookies bool `yaml:"cookies"`
	// DebugPprof exposes Go's net/http/pprof endpoints under /debug/pprof/,
	// gated behind the same session/Basic auth as the REST API. Off by
	// default: even authenticated, a heap profile can dump memory contents
	// and a CPU/trace profile ties up real cycles for its duration — opt in
	// only while actively chasing a performance problem.
	DebugPprof bool `yaml:"debug_pprof"`
	// MaxTCPConnsPerIP caps how many concurrent connections one client IP
	// may hold on the plain-TCP and DoT listeners (0 = unlimited, the
	// default). It stops connection floods and slowloris-style attacks from
	// exhausting file descriptors and goroutines — the rate limiter only
	// sees clients that actually send queries, so a flood of half-open
	// connections needs a connection counter instead. Connections past the
	// cap are closed at accept without a reply.
	MaxTCPConnsPerIP int `yaml:"max_tcp_conns_per_ip"`
	// MaxHTTPConnsPerIP caps how many concurrent connections one client IP
	// may hold on the DoH listener (and the shared dashboard+DoH HTTPS
	// listener when they share a port); 0 = unlimited, the default. Same
	// rationale as max_tcp_conns_per_ip for the HTTP transports.
	MaxHTTPConnsPerIP int `yaml:"max_http_conns_per_ip"`
	// TrustedProxies lists reverse proxies (IPs or CIDRs) in front of the
	// DoH endpoint whose X-Forwarded-For header is honored, in addition to
	// loopback/private peers (a local nginx/Caddy or the baked-in
	// cloudflared tunnel, both always trusted). Without this, a DoH
	// listener fronted by a public reverse proxy sees only the proxy's own
	// address, so geo/ASN blocking, rate limiting and per-client policy
	// apply to the proxy instead of the end client. The direct peer must
	// itself be trusted before XFF is read at all — entries only widen the
	// set of peers allowed to stamp it, they never bypass that gate.
	TrustedProxies []string `yaml:"trusted_proxies"`
	// XFFHopLimit is how many trusted proxy hops the X-Forwarded-For chain
	// may contain: the client IP is the hop_limit-th entry from the right,
	// so 1 (the default, and what 0 selects) uses the rightmost entry —
	// the address the trusted peer itself saw, which cannot be spoofed —
	// and N skips that many trusted hops to reach the real client. Set it
	// to the number of proxies in front of the direct peer (e.g. 2 for
	// client → CDN → nginx → Irongrid).
	XFFHopLimit int `yaml:"xff_hop_limit"`
	// DoHASNHeader, when enabled, adds an X-Irongrid-Client-ASN header to
	// DoH responses (RFC 8484 GET and POST, on the DoH/DoH3/shared
	// listeners) carrying the ASN the server attributes to the client's IP
	// — handy for verifying which ISP a client resolves as without digging
	// through the query log. The header is only added when the client's ISP
	// matches one of the configured ASN lists (geo_block allow/block ASNs
	// or a client group's asns); clients the server has no ASN data on get
	// no header.
	DoHASNHeader bool `yaml:"doh_asn_header"`
}

// CacheConfig points at the Dragonfly instance that is the authoritative
// response cache. Irongrid DNS will not start if it cannot reach it.
type CacheConfig struct {
	Addr        string        `yaml:"addr"`         // host:port of Dragonfly
	Password    string        `yaml:"password"`     // optional auth
	DB          int           `yaml:"db"`           // logical db index
	TTL         time.Duration `yaml:"ttl"`          // positive answer cache TTL
	NegativeTTL time.Duration `yaml:"negative_ttl"` // cached NXDOMAIN/SERVFAIL TTL
	// L1Entries is the per-shard entry capacity of the in-process L1 cache
	// layered in front of Dragonfly. -1 disables the L1 layer entirely;
	// 0 (the default) auto-sizes it from the detected memory ceiling (see
	// cache.AutoPerShard) so a small Pi and a big server get proportionally
	// sized caches; N is an explicit per-shard entry cap.
	L1Entries int `yaml:"l1_entries"`
	// ServeStale (RFC 8767) keeps an L1 entry answerable for this long past
	// its expiry, so a query whose upstream resolution fails (outage,
	// timeout, all upstreams in cooldown) is answered from the last known
	// good data instead of SERVFAIL. The stale answer's TTLs are floored at
	// 1 so no client caches it. 0 disables serve-stale.
	ServeStale time.Duration `yaml:"serve_stale"`
	// Prefetch refreshes hot entries in the background shortly before they
	// expire, so the next query finds a warm answer instead of paying an
	// upstream round trip.
	Prefetch bool `yaml:"prefetch"`
	// LookupTimeout bounds the L2 (Dragonfly) cache read on the DNS hot
	// path: if the cache can't answer within this budget the query proceeds
	// straight to the upstream instead of stalling behind a slow cache tier.
	// 0 uses the built-in default (150ms).
	LookupTimeout time.Duration `yaml:"lookup_timeout"`
	// FailureTTL is how long a resolution failure — an upstream that never
	// answered (timeout, dial error, circuit-breaker cooldown) with no
	// serve-stale entry to fall back on — is negatively cached as SERVFAIL,
	// so retries during an outage don't re-pay the full per-query timeout
	// every time. 0 uses NegativeTTL. The default is a short 5s window (not
	// 0) so a recovered upstream becomes visible within seconds instead of
	// being shadowed by a minute of cached SERVFAIL; the short window bounds
	// how long a transient failure can shadow a recovery.
	FailureTTL time.Duration `yaml:"failure_ttl"`
}

// TLSConfig controls certificates used by DoT, DoH and DoQ (and the web UI
// when server.web_tls is enabled).
type TLSConfig struct {
	CertFile           string     `yaml:"cert_file"`            // PEM cert chain
	KeyFile            string     `yaml:"key_file"`             // PEM private key
	GenerateSelfSigned bool       `yaml:"generate_self_signed"` // create a self-signed cert if none given
	SelfSignedHosts    []string   `yaml:"self_signed_hosts"`    // SANs for the generated cert
	CertDir            string     `yaml:"cert_dir"`             // where generated certs are stored
	ACME               ACMEConfig `yaml:"acme"`                 // Let's Encrypt auto-issuance
}

// ACMEConfig enables automatic certificate issuance from Let's Encrypt using
// the HTTP-01 challenge (needs the domains to answer on port 80) or, when
// tls.acme.dns01.provider is set, the DNS-01 challenge (needs DNS API access
// but no inbound port).
type ACMEConfig struct {
	Enabled         bool        `yaml:"enabled"`
	Email           string      `yaml:"email"`             // account contact (required)
	Domains         []string    `yaml:"domains"`           // public hostnames to cover
	Staging         bool        `yaml:"staging"`           // use Let's Encrypt staging CA (untrusted, for testing)
	HTTP01Port      int         `yaml:"http01_port"`       // port for the HTTP-01 challenge, default 80
	RenewBeforeDays int         `yaml:"renew_before_days"` // renew when fewer days remain, default 30
	DNS01           DNS01Config `yaml:"dns01"`             // optional: issue via DNS TXT records instead of HTTP-01
}

// DNS01Config configures DNS-01 challenge issuance through a DNS provider API.
// Supported providers: cloudflare, digitalocean, hetzner, godaddy, route53.
type DNS01Config struct {
	Provider           string `yaml:"provider"`              // "" = HTTP-01 challenge
	PropagationWait    int    `yaml:"propagation_wait_sec"`  // seconds to wait for TXT propagation, default 60
	CloudflareToken    string `yaml:"cloudflare_token"`      // Cloudflare API token (Zone:DNS:Edit)
	DigitalOceanToken  string `yaml:"digitalocean_token"`    // DigitalOcean personal access token (DNS:edit)
	HetznerToken       string `yaml:"hetzner_token"`         // Hetzner DNS API token
	GoDaddyKey         string `yaml:"godaddy_key"`           // GoDaddy API key
	GoDaddySecret      string `yaml:"godaddy_secret"`        // GoDaddy API secret
	AWSAccessKeyID     string `yaml:"aws_access_key_id"`     // AWS access key (Route53)
	AWSSecretAccessKey string `yaml:"aws_secret_access_key"` // AWS secret key (Route53)
}

// FilterConfig configures blocking behaviour and lists.
type FilterConfig struct {
	// BlockResponse is what blocked queries receive:
	// "nxdomain", "refused", or an IPv4/IPv6 address ("0.0.0.0" / "::").
	BlockResponse string          `yaml:"block_response"`
	BlockTTL      uint32          `yaml:"block_ttl"`
	Blocklists    []BlocklistSpec `yaml:"blocklists"`
	Whitelist     []string        `yaml:"whitelist"` // always-allowed domains & IPs (override blocklists)
	Blacklist     []string        `yaml:"blacklist"` // manual deny entries, same syntax as lists
	// AutoUpdate is the single refresh interval applied to every enabled
	// blocklist (0 disables auto-refresh entirely). Replaces what used to be
	// a per-list setting — one global cadence is simpler to reason about
	// than tracking a different schedule per list.
	AutoUpdate time.Duration `yaml:"auto_update"`
	// CNAMECloakingProtection checks every CNAME hop in an upstream answer
	// against the blocklist/whitelist rules, not just the originally queried
	// name — closing the gap trackers exploit by hiding a blocklisted domain
	// behind a first-party-looking CNAME. Off by default: a CNAME chain that
	// passes through a shared CDN (Cloudfront, Fastly, Akamai, ...) could in
	// principle collide with an overly broad blocklist entry, so this is an
	// explicit opt-in rather than a silent behavior change on upgrade.
	CNAMECloakingProtection bool `yaml:"cname_cloaking_protection"`
}

// BlocklistSpec describes a remote or local blocklist source.
type BlocklistSpec struct {
	ID          string    `yaml:"id"`      // unique identifier shown in the UI
	Name        string    `yaml:"name"`    // friendly name
	URL         string    `yaml:"url"`     // remote URL, or local file path (file://)
	Enabled     bool      `yaml:"enabled"` // fetched and applied when true
	LastUpdated time.Time `yaml:"-"`       // runtime state, not persisted here
}

// LogConfig controls the query log. The log lives in Dragonfly (Redis stream
// "irongrid:log") — QueryLogFile is kept only for backward compatibility
// with older configs and is ignored.
type LogConfig struct {
	QueryLogFile  string `yaml:"query_log_file"`
	RetentionDays int    `yaml:"retention_days"`
	Verbose       bool   `yaml:"verbose"`
	// BatchSize is how many entries the async query-log writer commits per
	// pipelined stream flush. 0 uses the built-in default (256).
	BatchSize int `yaml:"batch_size"`
}

// WebConfig controls the management interface auth.
type WebConfig struct {
	Username string `yaml:"username"`
	// Password is stored as a bcrypt hash. Plaintext values found in the file
	// are hashed automatically on load.
	Password string `yaml:"password"`
	// SessionSecret is used to sign API session cookies. Generated if empty.
	SessionSecret string `yaml:"session_secret"`
}

// TunnelConfig controls the baked-in cloudflared tunnel.
type TunnelConfig struct {
	Enabled        bool   `yaml:"enabled"`
	Token          string `yaml:"token"`            // named tunnel token (remote-managed)
	ConfigFile     string `yaml:"config_file"`      // cloudflared YAML config, if used
	QuickTunnel    bool   `yaml:"quick_tunnel"`     // unauth trycloudflare.com quick tunnel
	QuickTunnelURL string `yaml:"quick_tunnel_url"` // origin URL exposed by quick tunnel
	Hostname       string `yaml:"hostname"`         // e.g. dns.example.com
}

// Default returns the built-in default configuration.
func Default() *Config {
	return &Config{
		Server: ServerConfig{
			ListenUDP:  "0.0.0.0:53",
			ListenTCP:  "0.0.0.0:53",
			ListenDoT:  "0.0.0.0:853",
			ListenDoH:  "0.0.0.0:443",
			ListenDoQ:  "0.0.0.0:853",
			DoHPath:    "/dns-query",
			WebListen:  "0.0.0.0:8080",
			TimeoutSec: 5,
		},
		Upstreams: []string{
			"udp://1.1.1.1:53",
			"udp://8.8.8.8:53",
		},
		UpstreamMode: "race",
		Cache: CacheConfig{
			Addr:          "localhost:6379",
			DB:            0,
			TTL:           6 * time.Hour,
			NegativeTTL:   60 * time.Second,
			L1Entries:     0, // 0 = auto-size the L1 cache from available RAM
			ServeStale:    5 * time.Minute,
			Prefetch:      true,
			LookupTimeout: 150 * time.Millisecond,
			// Failure cache is deliberately much shorter than negative_ttl:
			// a cached SERVFAIL must not keep a recovered upstream invisible
			// for a full minute. 5s means retries re-probe upstream about as
			// often as the circuit breaker's own cooldown cycle.
			FailureTTL: 5 * time.Second,
		},
		TLS: TLSConfig{
			GenerateSelfSigned: true,
			SelfSignedHosts:    []string{"localhost", "dns.example.com"},
			CertDir:            "data/certs",
		},
		Filter: FilterConfig{
			BlockResponse:           "nxdomain",
			BlockTTL:                600,
			Whitelist:               []string{},
			Blacklist:               []string{},
			AutoUpdate:              24 * time.Hour,
			CNAMECloakingProtection: false,
		},
		Log: LogConfig{
			QueryLogFile:  "data/querylog.db",
			RetentionDays: 30,
			Verbose:       true,
			BatchSize:     256,
		},
		Web: WebConfig{
			Username: "admin",
		},
		Tunnel: TunnelConfig{
			QuickTunnelURL: "http://localhost:8080",
		},
		RateLimit: RateLimitConfig{
			Enabled:    false,
			QPS:        20,
			Burst:      40,
			AutoBlock:  false,
			BlockAfter: 3,
			BlockFor:   10 * time.Minute,
			// NXDOMAIN flood guard: off by default, with sane values ready to
			// flip on (30 NXDOMAIN responses per prefix within 30s -> 10m
			// refusal).
			NXGuard: NXGuardConfig{
				Enabled:   false,
				Threshold: 30,
				Window:    30 * time.Second,
				BlockFor:  10 * time.Minute,
			},
		},
		GeoBlock: GeoBlockConfig{
			AutoUpdate: 168 * time.Hour,
		},
		Abuse: AbuseConfig{},
		DNSSEC: DNSSECConfig{
			Enabled:   false,
			RequireAD: true,
		},
		Warmer: WarmerConfig{
			Enabled:     false,
			Interval:    15 * time.Minute,
			Lookback:    24 * time.Hour,
			MaxDomains:  5000,
			Concurrency: 8,
		},
		DHCP: DHCPConfig{
			LeaseTime: 24 * time.Hour,
			Domain:    "lan",
		},
	}
}

// Load reads the config file at path, applies defaults for missing values and
// returns the result.
func Load(path string) (*Config, error) {
	cfg := Default()
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			// No config yet: persist defaults so the user can edit them.
			if err := cfg.Save(path); err != nil {
				return nil, fmt.Errorf("create default config: %w", err)
			}
			return cfg, nil
		}
		return nil, fmt.Errorf("read config %s: %w", path, err)
	}
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parse config %s: %w", path, err)
	}
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	// Generate the session secret on first load so signed login cookies work.
	// Persisting it is best-effort: on a read-only config mount (e.g. Docker
	// with :ro) the write fails, so the secret stays in memory and sessions
	// simply reset on restart — never abort startup over it.
	if cfg.Web.SessionSecret == "" {
		if sec, err := randomHex(32); err != nil {
			return nil, fmt.Errorf("generate session secret: %w", err)
		} else {
			cfg.Web.SessionSecret = sec
			if err := cfg.Save(path); err != nil {
				fmt.Fprintf(os.Stderr, "warning: could not persist session secret (%v); sessions will reset on restart\n", err)
			}
		}
	}
	return cfg, nil
}

// randomHex returns n random bytes hex-encoded.
func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// NewSessionSecret returns a fresh random secret for signing login session
// cookies. Use it when the web password changes to rotate the signing key and
// thereby invalidate every previously issued session cookie at once.
func NewSessionSecret() (string, error) {
	return randomHex(32)
}

// Validate checks the configuration for required fields. It is used by the
// config loader and by the API when the frontend submits edited settings.
func (c *Config) Validate() error {
	return c.validate()
}

func (c *Config) validate() error {
	if len(c.Upstreams) == 0 {
		return fmt.Errorf("at least one upstream DNS server is required")
	}
	// Empty upstream_mode defaults to race; anything else must be one of the
	// two supported strategies. Keep the accepted values in sync with the
	// dnsserver package's UpstreamModeRace / UpstreamModeSequential
	// constants — config cannot import dnsserver (dnsserver imports config).
	switch c.UpstreamMode {
	case "":
		c.UpstreamMode = "race"
	case "race", "sequential":
	default:
		return fmt.Errorf("upstream_mode: unsupported mode %q (supported: race, sequential)", c.UpstreamMode)
	}
	// Conditional routes: normalize the domain (lowercase, no trailing dot)
	// and require at least one non-empty upstream per route.
	for i, rt := range c.UpstreamRoutes {
		dom := normalizeDomain(rt.Domain)
		if dom == "" {
			return fmt.Errorf("upstream_routes[%d]: a valid domain is required", i)
		}
		c.UpstreamRoutes[i].Domain = dom
		if len(rt.Upstreams) == 0 {
			return fmt.Errorf("upstream_routes[%d] (%s): at least one upstream is required", i, dom)
		}
		if slices.Contains(rt.Upstreams, "") {
			return fmt.Errorf("upstream_routes[%d] (%s): empty upstream entry", i, dom)
		}
	}
	if c.Cache.Addr == "" {
		return fmt.Errorf("cache.addr is required (Dragonfly endpoint)")
	}
	if c.Cache.L1Entries < -1 {
		return fmt.Errorf("cache.l1_entries must be >= -1 (-1 disables the in-process cache, 0 auto-sizes it from available RAM, N is an exact per-shard cap)")
	}
	if c.Cache.ServeStale < 0 {
		return fmt.Errorf("cache.serve_stale must be >= 0 (0 disables serve-stale)")
	}
	if c.Cache.LookupTimeout < 0 {
		return fmt.Errorf("cache.lookup_timeout must be >= 0 (0 uses the built-in default)")
	}
	if c.Cache.FailureTTL < 0 {
		return fmt.Errorf("cache.failure_ttl must be >= 0 (0 uses cache.negative_ttl)")
	}
	if c.Recursive.ServerTimeout < 0 {
		return fmt.Errorf("recursive.server_timeout must be >= 0 (0 uses the built-in default)")
	}
	if c.Log.BatchSize < 0 {
		return fmt.Errorf("log.batch_size must be >= 0 (0 uses the default)")
	}
	if c.Warmer.Interval < 0 {
		return fmt.Errorf("warmer.interval must be >= 0 (0 uses the default)")
	}
	if c.Warmer.Lookback < 0 {
		return fmt.Errorf("warmer.lookback must be >= 0 (0 uses the default)")
	}
	if c.Warmer.MaxDomains < 0 {
		return fmt.Errorf("warmer.max_domains must be >= 0 (0 = every domain in the lookback window)")
	}
	if c.Warmer.Concurrency < 0 {
		return fmt.Errorf("warmer.concurrency must be >= 0 (0 uses the default)")
	}
	if c.DHCP.Enabled {
		_, ipnet, err := net.ParseCIDR(c.DHCP.Subnet)
		if err != nil {
			return fmt.Errorf("dhcp.subnet %q is not a valid CIDR", c.DHCP.Subnet)
		}
		if c.DHCP.RangeStart == "" || c.DHCP.RangeEnd == "" {
			return fmt.Errorf("dhcp.range_start and dhcp.range_end are required when DHCP is enabled")
		}
		start, end := net.ParseIP(c.DHCP.RangeStart), net.ParseIP(c.DHCP.RangeEnd)
		if start == nil || end == nil || start.To4() == nil || end.To4() == nil {
			return fmt.Errorf("dhcp.range_start/range_end must be IPv4 addresses")
		}
		if !ipnet.Contains(start) || !ipnet.Contains(end) {
			return fmt.Errorf("dhcp range %s-%s must lie inside dhcp.subnet %s", c.DHCP.RangeStart, c.DHCP.RangeEnd, c.DHCP.Subnet)
		}
		if bytes.Compare(start.To4(), end.To4()) > 0 {
			return fmt.Errorf("dhcp.range_start %s is after dhcp.range_end %s", c.DHCP.RangeStart, c.DHCP.RangeEnd)
		}
		if c.DHCP.Gateway != "" {
			g := net.ParseIP(c.DHCP.Gateway)
			if g == nil || g.To4() == nil || !ipnet.Contains(g) {
				return fmt.Errorf("dhcp.gateway %q is not an IPv4 address inside dhcp.subnet", c.DHCP.Gateway)
			}
		}
		for _, d := range c.DHCP.DNS {
			if net.ParseIP(d) == nil {
				return fmt.Errorf("dhcp.dns entry %q is not a valid IP", d)
			}
		}
		if c.DHCP.LeaseTime < 0 {
			return fmt.Errorf("dhcp.lease_time must be >= 0 (0 uses the default)")
		}
		if c.DHCP.Domain != "" && !validHostname(c.DHCP.Domain) {
			return fmt.Errorf("dhcp.domain %q is not a valid hostname", c.DHCP.Domain)
		}
		for i, sl := range c.DHCP.StaticLeases {
			if sl.MAC == "" && sl.DUID == "" {
				return fmt.Errorf("dhcp.static_leases[%d]: mac or duid is required", i)
			}
			if sl.MAC != "" && !validMAC(sl.MAC) {
				return fmt.Errorf("dhcp.static_leases[%d]: mac %q is not a valid MAC address", i, sl.MAC)
			}
			ip := net.ParseIP(sl.IP)
			if ip == nil {
				return fmt.Errorf("dhcp.static_leases[%d]: ip %q is not a valid address", i, sl.IP)
			}
			if ip.To4() != nil && !ipnet.Contains(ip) {
				return fmt.Errorf("dhcp.static_leases[%d]: ip %s must lie inside dhcp.subnet %s", i, sl.IP, c.DHCP.Subnet)
			}
			if sl.Hostname != "" && !validHostname(sl.Hostname) {
				return fmt.Errorf("dhcp.static_leases[%d]: hostname %q is not valid", i, sl.Hostname)
			}
		}
		if c.DHCP.IPv6 {
			_, ipnet6, err := net.ParseCIDR(c.DHCP.IPv6Prefix)
			if err != nil {
				return fmt.Errorf("dhcp.ipv6_prefix %q is not a valid CIDR", c.DHCP.IPv6Prefix)
			}
			s6, e6 := net.ParseIP(c.DHCP.IPv6RangeStart), net.ParseIP(c.DHCP.IPv6RangeEnd)
			if s6 == nil || e6 == nil || s6.To4() != nil || e6.To4() != nil {
				return fmt.Errorf("dhcp.ipv6_range_start/ipv6_range_end must be IPv6 addresses")
			}
			if !ipnet6.Contains(s6) || !ipnet6.Contains(e6) {
				return fmt.Errorf("dhcp ipv6 range %s-%s must lie inside dhcp.ipv6_prefix %s", c.DHCP.IPv6RangeStart, c.DHCP.IPv6RangeEnd, c.DHCP.IPv6Prefix)
			}
			if bytes.Compare(s6, e6) > 0 {
				return fmt.Errorf("dhcp.ipv6_range_start %s is after dhcp.ipv6_range_end %s", c.DHCP.IPv6RangeStart, c.DHCP.IPv6RangeEnd)
			}
			for i, sl := range c.DHCP.StaticLeases {
				ip := net.ParseIP(sl.IP)
				if ip != nil && ip.To4() == nil && !ipnet6.Contains(ip) {
					return fmt.Errorf("dhcp.static_leases[%d]: ipv6 address %s must lie inside dhcp.ipv6_prefix %s", i, sl.IP, c.DHCP.IPv6Prefix)
				}
			}
		}
	}
	if c.Server.ListenUDP == "" && c.Server.ListenTCP == "" &&
		c.Server.ListenDoT == "" && c.Server.ListenDoH == "" && c.Server.ListenDoQ == "" {
		return fmt.Errorf("at least one DNS listener must be enabled")
	}
	if c.Server.TimeoutSec < 1 {
		return fmt.Errorf("server.timeout_sec must be >= 1")
	}
	if c.Server.UDPSockets < 0 {
		return fmt.Errorf("server.udp_sockets must be >= 0 (0 = auto, 1 = single exclusive socket)")
	}
	if c.Server.UDPWorkers < 0 {
		return fmt.Errorf("server.udp_workers must be >= 0 (0 = auto, N = workers per UDP socket)")
	}
	if c.Server.MaxTCPConnsPerIP < 0 {
		return fmt.Errorf("server.max_tcp_conns_per_ip must be >= 0 (0 = unlimited)")
	}
	if c.Server.MaxHTTPConnsPerIP < 0 {
		return fmt.Errorf("server.max_http_conns_per_ip must be >= 0 (0 = unlimited)")
	}
	for i, e := range c.Server.TrustedProxies {
		e = strings.TrimSpace(e)
		if e == "" {
			return fmt.Errorf("server.trusted_proxies[%d]: empty entry", i)
		}
		if net.ParseIP(e) == nil {
			if _, _, err := net.ParseCIDR(e); err != nil {
				return fmt.Errorf("server.trusted_proxies[%d] %q: not a valid IP or CIDR", i, e)
			}
		}
	}
	if c.Server.XFFHopLimit < 0 {
		return fmt.Errorf("server.xff_hop_limit must be >= 0 (0 = trust the direct peer only)")
	}
	if c.Server.XFFHopLimit == 0 {
		c.Server.XFFHopLimit = 1
	}
	// DoH3 and DoQ are both QUIC over UDP on the address they bind. Two
	// QUIC listeners on one UDP address would each accept the other's
	// connections and fail the ALPN negotiation — an operator mistake that
	// must be caught at config time, not as a live bind failure.
	if c.Server.ListenDoH3 != "" && c.Server.ListenDoQ != "" &&
		sameUDPAddr(c.Server.ListenDoH3, c.Server.ListenDoQ) {
		return fmt.Errorf("server.listen_doh3 %s and listen_doq %s share one UDP address — DoH3 (ALPN h3) and DoQ (ALPN doq) cannot negotiate different ALPNs on the same port", c.Server.ListenDoH3, c.Server.ListenDoQ)
	}
	if c.Log.RetentionDays < 1 {
		return fmt.Errorf("log.retention_days must be >= 1")
	}
	if c.TLS.ACME.Enabled {
		if c.TLS.ACME.Email == "" {
			return fmt.Errorf("tls.acme.email is required when ACME is enabled")
		}
		if len(c.TLS.ACME.Domains) == 0 {
			return fmt.Errorf("tls.acme.domains requires at least one domain when ACME is enabled")
		}
		if c.TLS.ACME.HTTP01Port == 0 {
			c.TLS.ACME.HTTP01Port = 80
		}
		if c.TLS.ACME.RenewBeforeDays <= 0 {
			c.TLS.ACME.RenewBeforeDays = 30
		}
		dns01 := &c.TLS.ACME.DNS01
		switch dns01.Provider {
		case "":
			// HTTP-01; nothing extra required.
		case "cloudflare":
			if dns01.CloudflareToken == "" {
				return fmt.Errorf("tls.acme.dns01.cloudflare_token is required when using the cloudflare provider")
			}
		case "digitalocean":
			if dns01.DigitalOceanToken == "" {
				return fmt.Errorf("tls.acme.dns01.digitalocean_token is required when using the digitalocean provider")
			}
		case "hetzner":
			if dns01.HetznerToken == "" {
				return fmt.Errorf("tls.acme.dns01.hetzner_token is required when using the hetzner provider")
			}
		case "godaddy":
			if dns01.GoDaddyKey == "" || dns01.GoDaddySecret == "" {
				return fmt.Errorf("tls.acme.dns01.godaddy_key and godaddy_secret are required when using the godaddy provider")
			}
		case "route53":
			if dns01.AWSAccessKeyID == "" || dns01.AWSSecretAccessKey == "" {
				return fmt.Errorf("tls.acme.dns01.aws_access_key_id and aws_secret_access_key are required when using the route53 provider")
			}
		default:
			return fmt.Errorf("tls.acme.dns01.provider: unsupported provider %q (supported: cloudflare, digitalocean, hetzner, godaddy, route53)", dns01.Provider)
		}
		if dns01.PropagationWait == 0 {
			dns01.PropagationWait = 60
		}
	}
	if c.Server.WebRedirect && !c.Server.WebTLS {
		return fmt.Errorf("server.web_redirect requires server.web_tls to be enabled")
	}
	if c.Server.WebRedirect && c.Server.WebRedirectPort == 0 {
		c.Server.WebRedirectPort = 80
	}
	if c.Server.WebRedirect && c.Server.WebRedirectPort == webPort(c.Server.WebListen) {
		return fmt.Errorf("server.web_redirect_port %d collides with the HTTPS web server port", c.Server.WebRedirectPort)
	}
	// When the dashboard shares the DoH port, it must serve HTTPS so the
	// merged listener can carry /dns-query (RFC 8484 requires TLS), and the
	// DoH path must be a valid non-root path for the shared mux.
	if c.Server.ListenDoH != "" && c.Server.WebListen != "" &&
		webPort(c.Server.ListenDoH) == webPort(c.Server.WebListen) {
		if !c.Server.WebTLS {
			return fmt.Errorf("server.web_listen %s shares port with listen_doh %s — enable server.web_tls to serve the dashboard and DoH on one HTTPS port", c.Server.WebListen, c.Server.ListenDoH)
		}
		if c.Server.DoHPath == "" {
			return fmt.Errorf("server.doh_path is required when web_listen shares the DoH port")
		}
	}
	if c.Web.Username == "" {
		return fmt.Errorf("web.username is required")
	}
	for i, rw := range c.Rewrites {
		if rw.Domain == "" {
			return fmt.Errorf("rewrites[%d]: domain is required", i)
		}
		switch strings.ToUpper(rw.Type) {
		case "A", "AAAA", "CNAME":
		default:
			return fmt.Errorf("rewrites[%d]: type must be A, AAAA or CNAME, got %q", i, rw.Type)
		}
		if rw.Value == "" {
			return fmt.Errorf("rewrites[%d]: value is required", i)
		}
	}
	seenGroup := map[string]bool{}
	for i, g := range c.ClientGroups {
		if g.ID == "" {
			return fmt.Errorf("client_groups[%d]: id is required", i)
		}
		if seenGroup[g.ID] {
			return fmt.Errorf("client_groups[%d]: duplicate id %q", i, g.ID)
		}
		seenGroup[g.ID] = true
		if len(g.CIDRs) == 0 && len(g.ASNs) == 0 {
			return fmt.Errorf("client_groups[%d] (%s): at least one CIDR or ASN is required", i, g.ID)
		}
		for _, cidr := range g.CIDRs {
			if _, _, err := net.ParseCIDR(cidr); err != nil {
				if net.ParseIP(cidr) == nil {
					return fmt.Errorf("client_groups[%d] (%s): invalid CIDR/IP %q", i, g.ID, cidr)
				}
			}
		}
		for j, a := range g.ASNs {
			asn, err := parseASN(a)
			if err != nil {
				return fmt.Errorf("client_groups[%d] (%s): asns[%d]: %w", i, g.ID, j, err)
			}
			c.ClientGroups[i].ASNs[j] = asn
		}
		if slices.Contains(g.Upstreams, "") {
			return fmt.Errorf("client_groups[%d] (%s): empty upstream entry", i, g.ID)
		}
	}
	// auto_block is a layer on top of the token bucket — without the limiter
	// there are no rejections to count, so it would silently never fire.
	if c.RateLimit.AutoBlock && !c.RateLimit.Enabled {
		return fmt.Errorf("rate_limit.auto_block requires rate_limit.enabled")
	}
	if c.RateLimit.Enabled {
		if c.RateLimit.QPS < 1 {
			return fmt.Errorf("rate_limit.qps must be >= 1 when rate_limit is enabled")
		}
		if c.RateLimit.Burst < c.RateLimit.QPS {
			return fmt.Errorf("rate_limit.burst must be >= rate_limit.qps")
		}
		if c.RateLimit.AutoBlock {
			if c.RateLimit.BlockAfter < 1 {
				return fmt.Errorf("rate_limit.block_after must be >= 1 when auto_block is enabled")
			}
			if c.RateLimit.BlockFor <= 0 {
				return fmt.Errorf("rate_limit.block_for must be positive when auto_block is enabled")
			}
		}
	}
	if c.RateLimit.NXGuard.Enabled {
		if c.RateLimit.NXGuard.Threshold < 1 {
			return fmt.Errorf("rate_limit.nxdomain_guard.threshold must be >= 1 when enabled")
		}
		if c.RateLimit.NXGuard.Window <= 0 {
			return fmt.Errorf("rate_limit.nxdomain_guard.window must be positive when enabled")
		}
		if c.RateLimit.NXGuard.BlockFor <= 0 {
			return fmt.Errorf("rate_limit.nxdomain_guard.block_for must be positive when enabled")
		}
	}
	for i, cc := range c.GeoBlock.Countries {
		cc = strings.ToUpper(strings.TrimSpace(cc))
		if len(cc) != 2 || cc[0] < 'A' || cc[0] > 'Z' || cc[1] < 'A' || cc[1] > 'Z' {
			return fmt.Errorf("geo_block.countries[%d]: %q is not an ISO 3166-1 alpha-2 country code (e.g. RU, CN)", i, cc)
		}
		c.GeoBlock.Countries[i] = cc
	}
	for i, e := range c.GeoBlock.Allowlist {
		if _, _, err := net.ParseCIDR(e); err != nil {
			if net.ParseIP(e) == nil {
				return fmt.Errorf("geo_block.allowlist[%d]: %q is not an IP or CIDR", i, e)
			}
		}
	}
	for i, e := range c.GeoBlock.AllowASNs {
		a, err := parseASN(e)
		if err != nil {
			return fmt.Errorf("geo_block.allow_asns[%d]: %w", i, err)
		}
		c.GeoBlock.AllowASNs[i] = a
	}
	for i, e := range c.GeoBlock.BlockASNs {
		a, err := parseASN(e)
		if err != nil {
			return fmt.Errorf("geo_block.block_asns[%d]: %w", i, err)
		}
		c.GeoBlock.BlockASNs[i] = a
	}
	if u := c.GeoBlock.ASNBaseURL; u != "" && !strings.HasPrefix(u, "http://") && !strings.HasPrefix(u, "https://") && !strings.HasPrefix(u, "file://") {
		return fmt.Errorf("geo_block.asn_base_url must start with http://, https:// or file://")
	}
	for i, e := range c.GeoBlock.IPs {
		if _, _, err := net.ParseCIDR(e); err != nil {
			if net.ParseIP(e) == nil {
				return fmt.Errorf("geo_block.ips[%d]: %q is not an IP or CIDR", i, e)
			}
		}
	}
	for i, d := range c.GeoBlock.Honeypots {
		d = normalizeDomain(d)
		if d == "" {
			return fmt.Errorf("geo_block.honeypots[%d]: %q is not a valid domain", i, c.GeoBlock.Honeypots[i])
		}
		c.GeoBlock.Honeypots[i] = d
	}
	if u := c.GeoBlock.BaseURL; u != "" && !strings.HasPrefix(u, "http://") && !strings.HasPrefix(u, "https://") && !strings.HasPrefix(u, "file://") {
		return fmt.Errorf("geo_block.base_url must start with http://, https:// or file://")
	}
	if c.GeoBlock.AutoUpdate < 0 {
		return fmt.Errorf("geo_block.auto_update must be >= 0 (0 disables automatic refreshes)")
	}
	if c.GeoBlock.HoneypotUDPBlock < 0 {
		return fmt.Errorf("geo_block.honeypot_udp_block must be >= 0 (0 disables the bounded UDP honeypot block)")
	}
	// The bounded UDP block runs on the rate limiter — without it there is
	// nowhere to park the temporary block, so the knob would silently never
	// fire (mirrors the rate_limit.auto_block coupling above).
	if c.GeoBlock.HoneypotUDPBlock > 0 && !c.RateLimit.Enabled {
		return fmt.Errorf("geo_block.honeypot_udp_block requires rate_limit.enabled (the bounded UDP honeypot block runs on the rate limiter)")
	}
	return nil
}

// parseASN normalizes an ASN config entry ("AS13335" or "13335") to the
// canonical "AS<number>" form, validating the 32-bit ASN space
// (1..4294967295). Rules mirror geoip.ParseASN, which converts the
// canonical form to the number at refresh time.
func parseASN(s string) (string, error) {
	s = strings.ToUpper(strings.TrimSpace(s))
	s = strings.TrimPrefix(s, "AS")
	if s == "" {
		return "", fmt.Errorf("empty ASN (use e.g. AS13335)")
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return "", fmt.Errorf("%q is not a valid ASN (use e.g. AS13335)", s)
		}
	}
	n, err := strconv.ParseUint(s, 10, 32)
	if err != nil || n == 0 {
		return "", fmt.Errorf("%q is not a valid ASN (use e.g. AS13335)", s)
	}
	return "AS" + strconv.FormatUint(n, 10), nil
}

// validMAC reports whether s parses as a colon-separated MAC address.
func validMAC(s string) bool {
	_, err := net.ParseMAC(strings.ToLower(s))
	return err == nil
}

// validHostname reports whether s is a plausible single-label hostname
// (letters, digits, hyphens — no dots, no spaces).
func validHostname(s string) bool {
	if s == "" || len(s) > 63 {
		return false
	}
	for _, r := range s {
		if (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9') && r != '-' {
			return false
		}
	}
	return true
}

// normalizeDomain lowercases, trims and strips a trailing dot from a domain
// for the honeypot list, returning "" for entries that are clearly invalid
// (empty or containing whitespace).
func normalizeDomain(d string) string {
	d = strings.ToLower(strings.TrimSpace(d))
	d = strings.TrimSuffix(d, ".")
	if d == "" || strings.ContainsAny(d, " \t") {
		return ""
	}
	return d
}

// sameUDPAddr reports whether two listen addresses would bind the same UDP
// endpoint: the same port, with hosts that are equal or both wildcard
// ("", "0.0.0.0", "::", "*").
func sameUDPAddr(a, b string) bool {
	ah, ap, errA := net.SplitHostPort(a)
	bh, bp, errB := net.SplitHostPort(b)
	if errA != nil || errB != nil {
		return false
	}
	if ap != bp {
		return false
	}
	wild := func(h string) bool {
		return h == "" || h == "0.0.0.0" || h == "::" || h == "*"
	}
	return ah == bh || (wild(ah) && wild(bh))
}

// webPort returns the port of a host:port listen address (0 when absent).
func webPort(addr string) int {
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		return 0
	}
	n, _ := strconv.Atoi(port)
	return n
}

// Save writes the config to path, creating parent directories. Plaintext web
// passwords are bcrypt-hashed before persisting.
func (c *Config) Save(path string) error {
	if c.Web.Password != "" && !isBcrypt(c.Web.Password) {
		if hash, err := bcrypt.GenerateFromPassword([]byte(c.Web.Password), bcrypt.DefaultCost); err == nil {
			c.Web.Password = string(hash)
		}
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	data, err := yaml.Marshal(c)
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}

func isBcrypt(s string) bool {
	return strings.HasPrefix(s, "$2a$") || strings.HasPrefix(s, "$2b$") || strings.HasPrefix(s, "$2y$")
}
