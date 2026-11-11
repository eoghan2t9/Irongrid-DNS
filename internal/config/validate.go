package config

import (
	"bytes"
	"fmt"
	"net"
	"slices"
	"strconv"
	"strings"

	"github.com/eoghan2t9/Irongrid-DNS/internal/geoip"
)

// Config validation and the field-level helpers it uses.

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
	case "race", "sequential", "roundrobin":
	default:
		return fmt.Errorf("upstream_mode: unsupported mode %q (supported: race, sequential, roundrobin)", c.UpstreamMode)
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
	if err := c.validateVPN(); err != nil {
		return err
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
	switch strings.ToLower(strings.TrimSpace(c.Logging.Level)) {
	case "", "debug", "info", "warn", "warning", "error":
	default:
		return fmt.Errorf("logging.level must be one of debug, info, warn, error (got %q)", c.Logging.Level)
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
	seenUserID := map[string]bool{}
	seenUsername := map[string]bool{}
	admins := 0
	for i, u := range c.Web.Users {
		if u.ID == "" {
			return fmt.Errorf("web.users[%d]: id is required", i)
		}
		if seenUserID[u.ID] {
			return fmt.Errorf("web.users[%d]: duplicate id %q", i, u.ID)
		}
		seenUserID[u.ID] = true
		if u.Username == "" {
			return fmt.Errorf("web.users[%d] (%s): username is required", i, u.ID)
		}
		if seenUsername[u.Username] {
			return fmt.Errorf("web.users[%d]: duplicate username %q", i, u.Username)
		}
		seenUsername[u.Username] = true
		switch u.Role {
		case "admin":
			admins++
		case "viewer":
		default:
			return fmt.Errorf("web.users[%d] (%s): role must be admin or viewer, got %q", i, u.Username, u.Role)
		}
	}
	if len(c.Web.Users) > 0 && admins == 0 {
		return fmt.Errorf("web.users: at least one admin is required")
	}
	if len(c.Web.Users) == 0 && c.Web.Username == "" {
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
	if c.RateLimit.RepeatQuery.Enabled {
		if c.RateLimit.RepeatQuery.Threshold < 2 {
			return fmt.Errorf("rate_limit.repeat_query_guard.threshold must be >= 2 when enabled")
		}
		if c.RateLimit.RepeatQuery.Window <= 0 {
			return fmt.Errorf("rate_limit.repeat_query_guard.window must be positive when enabled")
		}
		if c.RateLimit.RepeatQuery.BlockFor <= 0 {
			return fmt.Errorf("rate_limit.repeat_query_guard.block_for must be positive when enabled")
		}
		if c.RateLimit.RepeatQuery.UDPBlockFor < 0 {
			return fmt.Errorf("rate_limit.repeat_query_guard.udp_block_for must not be negative")
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

// validateVPN normalizes and checks the vpn config: profile IDs must be
// unique and reference a supported provider, and every route must name an
// existing profile and at least one domain. Route domains are lowercased
// and de-dotted in place, matching normalizeDomain's use elsewhere.
func (c *Config) validateVPN() error {
	v := &c.VPN
	if !v.Enabled && len(v.Profiles) == 0 && len(v.Routes) == 0 {
		return nil
	}
	profileIDs := make(map[string]bool, len(v.Profiles))
	for i, p := range v.Profiles {
		if p.ID == "" {
			return fmt.Errorf("vpn.profiles[%d]: id is required", i)
		}
		if profileIDs[p.ID] {
			return fmt.Errorf("vpn.profiles[%d]: duplicate profile id %q", i, p.ID)
		}
		profileIDs[p.ID] = true
		switch p.Provider {
		case "nordvpn", "pia":
		default:
			return fmt.Errorf("vpn.profiles[%d] (%s): unsupported provider %q (supported: nordvpn, pia)", i, p.ID, p.Provider)
		}
		if p.Region == "" {
			return fmt.Errorf("vpn.profiles[%d] (%s): region is required", i, p.ID)
		}
	}
	for i, rt := range v.Routes {
		if rt.Profile == "" {
			return fmt.Errorf("vpn.routes[%d]: profile is required", i)
		}
		if !profileIDs[rt.Profile] {
			return fmt.Errorf("vpn.routes[%d]: profile %q is not defined in vpn.profiles", i, rt.Profile)
		}
		if len(rt.Domains) == 0 {
			return fmt.Errorf("vpn.routes[%d] (%s): at least one domain is required", i, rt.Profile)
		}
		for j, d := range rt.Domains {
			dom := normalizeDomain(d)
			if dom == "" {
				return fmt.Errorf("vpn.routes[%d] (%s): domain[%d] is invalid", i, rt.Profile, j)
			}
			v.Routes[i].Domains[j] = dom
		}
	}
	if v.Enabled {
		usesNord, usesPIA := false, false
		for _, p := range v.Profiles {
			if p.Provider == "nordvpn" {
				usesNord = true
			}
			if p.Provider == "pia" {
				usesPIA = true
			}
		}
		if usesNord && v.Providers.NordVPN.Token == "" {
			return fmt.Errorf("vpn: a profile uses provider \"nordvpn\" but vpn.providers.nordvpn.token is empty")
		}
		if usesPIA && (v.Providers.PIA.Username == "" || v.Providers.PIA.Password == "") {
			return fmt.Errorf("vpn: a profile uses provider \"pia\" but vpn.providers.pia.username/password are empty")
		}
	}
	return nil
}

// parseASN normalizes an ASN config entry ("AS13335" or "13335") to the
// canonical "AS<number>" form, validating the 32-bit ASN space
// (1..4294967295). Delegates to geoip.ParseASN for the actual parsing.
func parseASN(s string) (string, error) {
	n, ok := geoip.ParseASN(s)
	if !ok {
		return "", fmt.Errorf("%q is not a valid ASN (use e.g. AS13335)", strings.TrimSpace(s))
	}
	return "AS" + strconv.FormatUint(uint64(n), 10), nil
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
