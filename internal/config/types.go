package config

import "time"

// Configuration schema: every YAML-backed struct.

// Config is the root configuration document.
type Config struct {
	Server ServerConfig `yaml:"server"`
	// Upstreams is the forwarder list. When more than one is configured,
	// UpstreamMode decides how they are queried for each resolution:
	// "race" (default) queries them all concurrently and returns the fastest
	// successful answer; "sequential" tries them in list order, failing over
	// to the next only when the previous errors or answers SERVFAIL;
	// "roundrobin" load-balances, sending each resolution to the next
	// upstream in turn (failing over to the following ones on error/SERVFAIL).
	Upstreams []string `yaml:"upstreams"`
	// UpstreamMode is the multi-upstream resolution strategy ("race",
	// "sequential" or "roundrobin"); empty defaults to "race". It is global —
	// client groups that override the upstream list use the same strategy.
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
	// Logging controls the application's own log stream (startup, errors,
	// reloads — everything through slog). Distinct from Log above, which
	// controls the DNS query log.
	Logging      LoggingConfig `yaml:"logging"`
	Web          WebConfig     `yaml:"web"`
	Tunnel       TunnelConfig  `yaml:"tunnel"`
	Rewrites     []RewriteSpec `yaml:"rewrites"`      // local DNS records (A/AAAA/CNAME)
	ClientGroups []ClientGroup `yaml:"client_groups"` // per-client blocking/upstream policy
	// VPN configures domain-based split-tunnel routing: the resolved answers
	// for selected domains are routed out through a dedicated WireGuard
	// tunnel to a NordVPN or PIA server instead of the host's normal default
	// route (e.g. sending only bbc.co.uk through a UK server so iPlayer
	// works while traveling, with everything else unaffected).
	VPN       VPNConfig       `yaml:"vpn"`
	RateLimit RateLimitConfig `yaml:"rate_limit"`
	GeoBlock  GeoBlockConfig  `yaml:"geo_block"`
	Abuse     AbuseConfig     `yaml:"abuse"`
	DNSSEC    DNSSECConfig    `yaml:"dnssec"`
	Warmer    WarmerConfig    `yaml:"warmer"`
	// Recursive tunes the recursive:// upstream transport (the iterative
	// resolver that walks referrals from the root servers itself).
	Recursive RecursiveConfig `yaml:"recursive"`
	DHCP      DHCPConfig      `yaml:"dhcp"`
	// UpstreamHealth tunes proactive upstream health probing: a canary
	// query sent to every upstream on a fixed interval, independent of
	// live client traffic, so the circuit breaker can catch a degrading
	// upstream before a real client query hits it.
	UpstreamHealth UpstreamHealthConfig `yaml:"upstream_health"`
}

// UpstreamHealthConfig controls proactive upstream health probing
// (upstream_health.enabled). Off by default: an upgrade must never start
// sending a running deployment's upstreams extra background traffic
// without an explicit opt-in.
type UpstreamHealthConfig struct {
	Enabled bool `yaml:"enabled"`
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

// VPNConfig is domain-based split-tunnel VPN routing. Selected domains'
// resolved answers are routed through a dedicated WireGuard tunnel to a
// NordVPN or PIA server instead of the host's normal default route, while
// every other domain is unaffected. Requires root/CAP_NET_ADMIN (creates
// WireGuard interfaces and policy-routing rules) plus the `ip`, `wg` and
// `nft` binaries; Linux only.
type VPNConfig struct {
	Enabled   bool         `yaml:"enabled"`
	Providers VPNProviders `yaml:"providers"`
	// Profiles are individual WireGuard tunnels to a specific provider
	// region/server. Multiple routes can share one profile.
	Profiles []VPNProfile `yaml:"profiles"`
	// Routes sends a set of domains (and their subdomains) through one
	// profile's tunnel. Matching is the same exact-or-subdomain,
	// longest-match rule as upstream_routes.
	Routes []VPNRoute `yaml:"routes"`
	// Proxy is the SNI/Host-based relay that makes Proxy-enabled routes work
	// for clients whose IP traffic never passes through this host — see
	// VPNProxyConfig.
	Proxy VPNProxyConfig `yaml:"proxy"`
}

// VPNProxyConfig is a relay that makes domain-based VPN routing work for ANY
// client that merely uses this server for DNS — not only clients whose IP
// traffic already passes through this host (the plain vpn.routes case,
// which only works if this box is your gateway/router). For a route with
// Proxy: true, DNS answers for its domains point at this server's own
// public IP instead of the real one; a TCP listener on Listen (typically
// ":443") and, optionally, ListenHTTP (":80") then relay each connection
// through the matching profile's WireGuard tunnel to the real destination —
// identified via the TLS SNI (HTTPS) or Host header (plain HTTP), the same
// technique commercial "Smart DNS" unblocking services use, without any
// app or VPN client on the end device. A connection whose SNI/Host doesn't
// match a Proxy-enabled route's domain is forwarded unchanged to Fallback
// (typically wherever the dashboard/DoH already listens) — the relay never
// forwards anywhere else, so it cannot be abused as an open proxy for
// arbitrary destinations.
type VPNProxyConfig struct {
	Enabled bool `yaml:"enabled"`
	// Listen is the TLS/SNI relay address (typically ":443", since that's
	// where a normal HTTPS client actually connects). "" defaults to ":443".
	Listen string `yaml:"listen"`
	// ListenHTTP is the plain-HTTP (Host header) relay address, typically
	// ":80". "" disables the HTTP relay (HTTPS-only sites still work).
	ListenHTTP string `yaml:"listen_http"`
	// Fallback is where a connection whose SNI/Host doesn't match any
	// Proxy-enabled route is forwarded — normally the dashboard/DoH
	// listener. "" defaults to server.web_listen. When Listen shares a port
	// with server.web_listen (the common case, ":443"), Fallback MUST point
	// at a different address (e.g. a loopback port) or the two listeners
	// would conflict — see the example config.
	Fallback string `yaml:"fallback"`
	// PublicIP is the address returned for a Proxy-enabled route's domains.
	// "" auto-detects this host's outbound-facing address.
	PublicIP string `yaml:"public_ip"`
}

// VPNProviders holds account credentials for the supported VPN vendors.
// Only the providers actually referenced by a profile need to be filled in.
type VPNProviders struct {
	NordVPN NordVPNCreds `yaml:"nordvpn"`
	PIA     PIACreds     `yaml:"pia"`
}

// NordVPNCreds authenticates against NordVPN's account API to fetch the
// account's NordLynx (WireGuard) private key. Generate a token at
// nordvpn.com -> Account -> "Set up NordVPN manually" — the same token
// `nordvpn login --token` uses.
type NordVPNCreds struct {
	Token string `yaml:"token"`
}

// PIACreds authenticates against PIA's published WireGuard connection API
// (github.com/pia-foss/manual-connections) using a regular PIA account
// login, not a separate token.
type PIACreds struct {
	Username string `yaml:"username"`
	Password string `yaml:"password"`
}

// VPNProfile is one WireGuard tunnel to a specific provider region/server.
type VPNProfile struct {
	ID       string `yaml:"id"`
	Provider string `yaml:"provider"` // "nordvpn" or "pia"
	// Region is provider-specific: a NordVPN country code (e.g. "gb") or a
	// PIA region id (e.g. "uk_london" — see PIA's region list).
	Region string `yaml:"region"`
}

// VPNRoute sends every listed domain's resolved answers through Profile's
// tunnel instead of the host's default route.
type VPNRoute struct {
	Profile string   `yaml:"profile"`
	Domains []string `yaml:"domains"`
	// Proxy additionally makes this route's domains work for clients whose
	// IP traffic never passes through this host — see VPNProxyConfig. Off
	// by default: it changes what DNS answer these domains get (this
	// server's own IP instead of the real one), which only makes sense
	// when vpn.proxy.enabled is also true.
	Proxy bool `yaml:"proxy"`
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
	// RepeatQuery throttles a client that resolves the *same* domain over
	// and over at a rapid pace — the signature of this resolver being used
	// to flood/DDoS that domain (or its authoritative infrastructure)
	// rather than normal browsing, which moves between many names. Off by
	// default; independent of rate_limit.enabled.
	RepeatQuery RepeatQueryConfig `yaml:"repeat_query_guard"`
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

// RepeatQueryConfig tunes the repeat-query flood guard
// (rate_limit.repeat_query_guard): a client that queries the same domain
// Threshold times within Window is treated as flooding that domain and its
// source is blocked, the same fail-closed cooldown NXGuard uses but keyed
// on the exact client IP and tripped by the query itself, not its response.
type RepeatQueryConfig struct {
	Enabled bool `yaml:"enabled"`
	// Threshold is how many queries for the same domain a client may send
	// within Window before it is treated as a flood; default 50.
	Threshold int `yaml:"threshold"`
	// Window is how long a same-domain streak may accumulate toward
	// Threshold; default 10s.
	Window time.Duration `yaml:"window"`
	// BlockFor is how long a tripped client is refused, for a client whose
	// source is trusted — a real handshake (TCP/DoT/DoH/DoQ) or the
	// server.geo_block.trust_udp opt-in; default 10m.
	BlockFor time.Duration `yaml:"block_for"`
	// UDPBlockFor bounds the block applied to a plain-UDP source instead:
	// a query's source IP is trivially spoofable over UDP, so an untrusted
	// plain-UDP source only ever earns this bounded window (mirroring
	// geo_block.honeypot_udp_block) rather than the full BlockFor. Zero
	// disables blocking untrusted UDP sources entirely — they are still
	// counted, just never blocked. Default 0 (disabled).
	UDPBlockFor time.Duration `yaml:"udp_block_for"`
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
	// ValidateLocally turns on real local DNSSEC chain-of-trust validation
	// (RRSIG/DNSKEY/DS verification up to a trust anchor fetched from
	// IANA) instead of only trusting the upstream's AD bit — catches a
	// compromised or lying upstream that a plain require_ad check can't.
	// Opportunistic: a zone with no RRSIG (most of the internet — unsigned)
	// falls through to the require_ad behavior unchanged, and a validation
	// that can't complete for an infrastructure reason (a DNSKEY/DS lookup
	// failing) fails open the same way, rather than blocking resolution
	// over a transient hiccup unrelated to answer integrity. Off by
	// default: an upgrade must never start enforcing stricter validation
	// on a running deployment without an explicit opt-in — and it adds
	// extra DNSKEY/DS lookups (cached per zone) that only matter once
	// enabled.
	ValidateLocally bool `yaml:"validate_locally"`
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
	// DiscoveryHost is the hostname advertised to clients through Discovery
	// of Designated Resolvers (RFC 9462): a query for _dns.resolver.arpa is
	// answered with SVCB records pointing at this name for each enabled
	// encrypted listener, so devices can upgrade from plain DNS on their own.
	// It must be a name the TLS certificate covers. Empty = the first
	// acme.domains entry when ACME is enabled, otherwise nothing is advertised.
	DiscoveryHost string `yaml:"discovery_host"`
	WebListen     string `yaml:"web_listen"` // management web UI + REST API
	WebTLS        bool   `yaml:"web_tls"`    // serve the web UI + API over HTTPS (uses the TLS cert)
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
	// AllowFrom is a query allow-list: bare IPs or CIDRs permitted to query
	// this server on any listener. Empty (the default) allows every
	// client, unchanged from prior behavior — this is opt-in hardening for
	// a server reachable beyond a trusted LAN.
	AllowFrom []string `yaml:"allow_from"`
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

// LoggingConfig controls the application's own log stream (everything
// logged through slog: startup, config errors, reloads, listener failures).
// Not to be confused with LogConfig, which controls the DNS query log.
type LoggingConfig struct {
	// Level is the minimum severity logged: "debug", "info" (the default,
	// used for an empty value), "warn", or "error".
	Level string `yaml:"level"`
	// JSON switches the log format from human-readable text (default) to
	// structured JSON — useful for log aggregators (Loki, journald's JSON
	// export, etc.) that parse each line as a record.
	JSON bool `yaml:"json"`
}

// WebConfig controls the management interface auth.
type WebConfig struct {
	Username string `yaml:"username"`
	// Password is stored as a bcrypt hash. Plaintext values found in the file
	// are hashed automatically on load.
	Password string `yaml:"password"`
	// SessionSecret is used to sign API session cookies. Generated if empty.
	SessionSecret string `yaml:"session_secret"`
	// Tokens are named bearer-token credentials for the REST API, additive
	// to the primary username/password above — a way to hand a specific
	// integration or household member its own individually revocable
	// credential (optionally read-only) instead of sharing the main login.
	// Sent as "Authorization: Bearer <token>". Empty by default.
	Tokens []APIToken `yaml:"tokens"`
	// Users are the dashboard/API login accounts (replaces the single
	// Username/Password pair above as the live auth source — see Load's
	// migration, which turns an existing Username/Password into the sole
	// admin Users entry on first load after upgrade). Username/Password
	// stay in this struct only as that migration input.
	Users []WebUser `yaml:"users"`
}

// WebUser is one dashboard/API login account. Role gates write access:
// "admin" can do everything including managing other users; "viewer" is
// restricted to GET/HEAD requests, exactly like a read-only APIToken.
type WebUser struct {
	// ID is a stable identifier independent of Username, so renaming a
	// user's login name is an edit, not a delete-and-recreate (which would
	// otherwise wrongly demand a new password on every rename).
	ID       string `yaml:"id"`
	Username string `yaml:"username"`
	// Password is a bcrypt hash. A plaintext value found here is hashed
	// automatically on the next Config.Save, like WebConfig.Password.
	Password string `yaml:"password"`
	// Role is "admin" or "viewer".
	Role string `yaml:"role"`
}

// APIToken is one bearer-token credential for the REST API (see
// WebConfig.Tokens).
type APIToken struct {
	// Name is a human label (e.g. "home-assistant") shown in the dashboard
	// and logs — tokens are never logged, only their name.
	Name string `yaml:"name"`
	// Token is a SHA-256 hex hash (64 lowercase hex chars) of the bearer
	// token. A value found here that isn't already such a hash is treated
	// as plaintext and hashed automatically on the next Config.Save, like
	// WebConfig.Password.
	Token string `yaml:"token"`
	// ReadOnly restricts this token to GET/HEAD requests; a write request
	// (POST/PUT/PATCH/DELETE) bearing a read-only token is refused.
	ReadOnly bool `yaml:"read_only"`
}

// TunnelConfig controls the baked-in cloudflared tunnel.
type TunnelConfig struct {
	Enabled        bool   `yaml:"enabled"`
	Token          string `yaml:"token"`            // named tunnel token (remote-managed)
	ConfigFile     string `yaml:"config_file"`      // cloudflared YAML config, if used
	QuickTunnel    bool   `yaml:"quick_tunnel"`     // unauth trycloudflare.com quick tunnel
	QuickTunnelURL string `yaml:"quick_tunnel_url"` // origin URL exposed by quick tunnel
	Hostname       string `yaml:"hostname"`         // e.g. dns.example.com
	// CloudflareAPIToken is a scoped Cloudflare API token (Account: Cloudflare
	// Tunnel: Edit, Zone: DNS: Edit, Zone: Zone: Read) that lets the dashboard
	// manage the tunnel's public hostnames and their DNS records. It is not
	// part of the dashboard's settings payload and is never sent back to it.
	CloudflareAPIToken string `yaml:"cloudflare_api_token"`
	// CloudflareAccountID is the account the API token manages; empty means
	// derive it from the tunnel token.
	CloudflareAccountID string `yaml:"cloudflare_account_id"`
}
