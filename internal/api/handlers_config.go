package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"reflect"
	"strings"
	"time"

	"github.com/eoghan2t9/Irongrid-DNS/internal/config"
	"github.com/eoghan2t9/Irongrid-DNS/internal/dnsserver"
	"github.com/eoghan2t9/Irongrid-DNS/internal/recursive"
	"github.com/eoghan2t9/Irongrid-DNS/internal/upstream"
)

// ---- config & diagnostics ----

// configPayload is the JSON shape used to read and write configuration from
// the web UI. Durations are human strings ("6h") and the web password is a
// plaintext field that is empty unless the user wants to change it.
type configPayload struct {
	Server         serverPayload          `json:"server"`
	Upstreams      []string               `json:"upstreams"`
	UpstreamMode   string                 `json:"upstream_mode"` // "race" | "sequential"
	UpstreamRoutes []upstreamRoutePayload `json:"upstream_routes"`
	Cache          cachePayload           `json:"cache"`
	TLS            tlsPayload             `json:"tls"`
	Filter         filterPayload          `json:"filter"`
	Log            logPayload             `json:"log"`
	Web            webPayload             `json:"web"`
	Tunnel         tunnelPayload          `json:"tunnel"`
	Rewrites       []rewritePayload       `json:"rewrites"`
	ClientGroups   []clientGroupPayload   `json:"client_groups"`
	RateLimit      rateLimitPayload       `json:"rate_limit"`
	GeoBlock       geoBlockPayload        `json:"geo_block"`
	Abuse          abusePayload           `json:"abuse"`
	DNSSEC         dnssecPayload          `json:"dnssec"`
	Warmer         warmerPayload          `json:"warmer"`
	Recursive      recursivePayload       `json:"recursive"`
	DHCP           dhcpPayload            `json:"dhcp"`
}

// dhcpPayload is the JSON shape for the built-in DHCP server settings.
// LeaseTime is a human duration string; empty means the default (24h).
type dhcpPayload struct {
	Enabled        bool                `json:"enabled"`
	Interface      string              `json:"interface"`
	Subnet         string              `json:"subnet"`
	RangeStart     string              `json:"range_start"`
	RangeEnd       string              `json:"range_end"`
	Gateway        string              `json:"gateway"`
	DNS            []string            `json:"dns"`
	LeaseTime      string              `json:"lease_time"`
	Domain         string              `json:"domain"`
	StaticLeases   []dhcpStaticPayload `json:"static_leases"`
	IPv6           bool                `json:"ipv6"`
	IPv6Prefix     string              `json:"ipv6_prefix"`
	IPv6RangeStart string              `json:"ipv6_range_start"`
	IPv6RangeEnd   string              `json:"ipv6_range_end"`
}

type dhcpStaticPayload struct {
	MAC      string `json:"mac"`
	DUID     string `json:"duid"`
	IP       string `json:"ip"`
	Hostname string `json:"hostname"`
}

// upstreamRoutePayload is the JSON shape for one conditional (split-horizon)
// route: a domain subtree and the dedicated upstreams that answer it.
type upstreamRoutePayload struct {
	Domain    string   `json:"domain"`
	Upstreams []string `json:"upstreams"`
}

// recursivePayload is the JSON shape for the recursive:// upstream tuning
// (see config.RecursiveConfig). Durations are human strings; empty means the
// built-in default.
type recursivePayload struct {
	ServerTimeout string `json:"server_timeout"`
}

// warmerPayload is the JSON shape for the proactive cache warmer settings.
// Durations are human strings ("15m"); empty means the built-in default.
type warmerPayload struct {
	Enabled     bool   `json:"enabled"`
	Interval    string `json:"interval"`
	Lookback    string `json:"lookback"`
	MaxDomains  int    `json:"max_domains"`
	Concurrency int    `json:"concurrency"`
}

type rewritePayload struct {
	Domain string `json:"domain"`
	Type   string `json:"type"`
	Value  string `json:"value"`
	TTL    uint32 `json:"ttl"`
}

type clientGroupPayload struct {
	ID         string   `json:"id"`
	Name       string   `json:"name"`
	Enabled    bool     `json:"enabled"`
	CIDRs      []string `json:"cidrs"`
	ASNs       []string `json:"asns"`
	Blocklists []string `json:"blocklists"`
	Whitelist  []string `json:"whitelist"`
	Blacklist  []string `json:"blacklist"`
	Upstreams  []string `json:"upstreams"`
}

type rateLimitPayload struct {
	Enabled    bool           `json:"enabled"`
	QPS        int            `json:"qps"`
	Burst      int            `json:"burst"`
	AutoBlock  bool           `json:"auto_block"`
	BlockAfter int            `json:"block_after"`
	BlockFor   string         `json:"block_for"` // duration string
	NXGuard    nxGuardPayload `json:"nxdomain_guard"`
}

// nxGuardPayload is the NXDOMAIN flood guard block of the rate-limit
// settings (rate_limit.nxdomain_guard). Durations are human strings.
type nxGuardPayload struct {
	Enabled   bool   `json:"enabled"`
	Threshold int    `json:"threshold"`
	Window    string `json:"window"`    // duration string
	BlockFor  string `json:"block_for"` // duration string
}

type geoBlockPayload struct {
	Enabled    bool     `json:"enabled"`
	Countries  []string `json:"countries"`
	Allowlist  []string `json:"allowlist"`
	IPs        []string `json:"ips"`       // always-blocked client IPs/CIDRs
	Honeypots  []string `json:"honeypots"` // trap domains: querying clients get blocked
	AllowASNs  []string `json:"allow_asns"`
	BlockASNs  []string `json:"block_asns"`
	BaseURL    string   `json:"base_url"`
	ASNBaseURL string   `json:"asn_base_url"`
	AutoUpdate string   `json:"auto_update"` // duration string, "" = never
	// TrustUDP lets plain-UDP honeypot hits auto-block their source too.
	// Off by default — spoofed UDP could otherwise be used to block
	// innocent victims.
	TrustUDP bool `json:"trust_udp"`
	// HoneypotUDPBlock is the bounded UDP-honeypot block window (duration
	// string, "" = off): the source of a plain-UDP honeypot hit is blocked
	// via the rate limiter for this long instead of earning the permanent
	// banner/firewall block trust_udp grants.
	HoneypotUDPBlock string `json:"honeypot_udp_block"`
}

// abusePayload holds the AbuseIPDB API key used for one-click reporting of
// blocked attacker IPs from the dashboard.
type abusePayload struct {
	AbuseIPDBKey string `json:"abuseipdb_key"`
}

type dnssecPayload struct {
	Enabled   bool `json:"enabled"`
	RequireAD bool `json:"require_ad"`
}

type serverPayload struct {
	ListenUDP       string `json:"listen_udp"`
	ListenTCP       string `json:"listen_tcp"`
	ListenDoT       string `json:"listen_dot"`
	ListenDoH       string `json:"listen_doh"`
	ListenDoH3      string `json:"listen_doh3"`
	ListenDoQ       string `json:"listen_doq"`
	DoHPath         string `json:"doh_path"`
	WebListen       string `json:"web_listen"`
	WebTLS          bool   `json:"web_tls"`
	WebRedirect     bool   `json:"web_redirect"`
	WebRedirectPort int    `json:"web_redirect_port"`
	TimeoutSec      int    `json:"timeout_sec"`
	// UDPSockets is how many SO_REUSEPORT sockets the plain UDP listener
	// binds: 0 = auto (one per CPU, capped), 1 = a single exclusive socket,
	// N = exactly N.
	UDPSockets int `json:"udp_sockets"`
	// UDPWorkers is how many handler workers each plain-UDP socket's read
	// loop dispatches to: 0 = auto (4 x CPU, floor 16, capped 256), N =
	// exactly N per socket (capped at 512).
	UDPWorkers int  `json:"udp_workers"`
	Padding    bool `json:"padding"`
	Cookies    bool `json:"cookies"`
	DebugPprof bool `json:"debug_pprof"`
	// MaxTCPConnsPerIP caps concurrent connections per client IP on the
	// TCP/DoT listeners (0 = unlimited).
	MaxTCPConnsPerIP int `json:"max_tcp_conns_per_ip"`
	// MaxHTTPConnsPerIP caps concurrent connections per client IP on the
	// DoH/shared-HTTP listener (0 = unlimited).
	MaxHTTPConnsPerIP int `json:"max_http_conns_per_ip"`
	// TrustedProxies lists reverse proxies (IPs or CIDRs) whose
	// X-Forwarded-For header the DoH endpoint honors, in addition to
	// loopback/private peers.
	TrustedProxies []string `json:"trusted_proxies"`
	// XFFHopLimit is how many trusted proxy hops the X-Forwarded-For chain
	// may contain (0 = the default, 1).
	XFFHopLimit int `json:"xff_hop_limit"`
	// DoHASNHeader adds X-Irongrid-Client-ASN to DoH responses when on.
	DoHASNHeader bool `json:"doh_asn_header"`
}

type cachePayload struct {
	Addr          string `json:"addr"`
	Password      string `json:"password"`
	DB            int    `json:"db"`
	TTL           string `json:"ttl"`
	NegativeTTL   string `json:"negative_ttl"`
	L1Entries     int    `json:"l1_entries"`
	ServeStale    string `json:"serve_stale"`
	Prefetch      bool   `json:"prefetch"`
	LookupTimeout string `json:"lookup_timeout"` // cache-read budget on the hot path; "" = default 150ms
	// FailureTTL is how long a resolution failure is negatively cached as
	// SERVFAIL; "" = use negative_ttl.
	FailureTTL string `json:"failure_ttl"`
}

type tlsPayload struct {
	CertFile           string      `json:"cert_file"`
	KeyFile            string      `json:"key_file"`
	GenerateSelfSigned bool        `json:"generate_self_signed"`
	SelfSignedHosts    []string    `json:"self_signed_hosts"`
	CertDir            string      `json:"cert_dir"`
	ACME               acmePayload `json:"acme"`
}

type acmePayload struct {
	Enabled         bool         `json:"enabled"`
	Email           string       `json:"email"`
	Domains         []string     `json:"domains"`
	Staging         bool         `json:"staging"`
	HTTP01Port      int          `json:"http01_port"`
	RenewBeforeDays int          `json:"renew_before_days"`
	DNS01           dns01Payload `json:"dns01"`
}

type dns01Payload struct {
	Provider           string `json:"provider"`
	PropagationWait    int    `json:"propagation_wait_sec"`
	CloudflareToken    string `json:"cloudflare_token"`
	DigitalOceanToken  string `json:"digitalocean_token"`
	HetznerToken       string `json:"hetzner_token"`
	GoDaddyKey         string `json:"godaddy_key"`
	GoDaddySecret      string `json:"godaddy_secret"`
	AWSAccessKeyID     string `json:"aws_access_key_id"`
	AWSSecretAccessKey string `json:"aws_secret_access_key"`
}

type filterPayload struct {
	BlockResponse string             `json:"block_response"`
	BlockTTL      uint32             `json:"block_ttl"`
	Blocklists    []blocklistPayload `json:"blocklists"`
	Whitelist     []string           `json:"whitelist"`
	Blacklist     []string           `json:"blacklist"`
	// AutoUpdate is the single refresh interval applied to every enabled
	// blocklist (duration string, "" = never) — replaces what used to be a
	// per-list setting.
	AutoUpdate string `json:"auto_update"`
	// CNAMECloakingProtection checks every CNAME hop in an answer against
	// the blocklist/whitelist rules, not just the queried name.
	CNAMECloakingProtection bool `json:"cname_cloaking_protection"`
}

type blocklistPayload struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	URL     string `json:"url"`
	Enabled bool   `json:"enabled"`
}

type logPayload struct {
	QueryLogFile  string `json:"query_log_file"`
	RetentionDays int    `json:"retention_days"`
	Verbose       bool   `json:"verbose"`
	BatchSize     int    `json:"batch_size"`
}

type webPayload struct {
	Username string `json:"username"`
	Password string `json:"password"` // plaintext; empty keeps the existing hash
}

type tunnelPayload struct {
	Enabled        bool   `json:"enabled"`
	Token          string `json:"token"`
	ConfigFile     string `json:"config_file"`
	QuickTunnel    bool   `json:"quick_tunnel"`
	QuickTunnelURL string `json:"quick_tunnel_url"`
	Hostname       string `json:"hostname"`
}

// durationOrEmpty renders d as a duration string, or "" for zero (matching
// the "" = never/disabled convention the frontend's duration fields use).
func durationOrEmpty(d time.Duration) string {
	if d <= 0 {
		return ""
	}
	// Whole-hour durations render as "24h", not Go's default "24h0m0s" —
	// the frontend's auto-update dropdown matches by exact string against
	// its hour-based presets ("6h"/"24h"/"168h"), so the verbose form would
	// never match any of them and the select would silently fall back to
	// its first option ("Never") even though the value saved correctly.
	if d%time.Hour == 0 {
		return fmt.Sprintf("%dh", int64(d/time.Hour))
	}
	return d.String()
}

// payloadFromConfig maps the internal config into the JSON shape.
func payloadFromConfig(c *config.Config) configPayload {
	p := configPayload{
		Server: serverPayload{
			ListenUDP:         c.Server.ListenUDP,
			ListenTCP:         c.Server.ListenTCP,
			ListenDoT:         c.Server.ListenDoT,
			ListenDoH:         c.Server.ListenDoH,
			ListenDoH3:        c.Server.ListenDoH3,
			ListenDoQ:         c.Server.ListenDoQ,
			DoHPath:           c.Server.DoHPath,
			WebListen:         c.Server.WebListen,
			WebTLS:            c.Server.WebTLS,
			WebRedirect:       c.Server.WebRedirect,
			WebRedirectPort:   c.Server.WebRedirectPort,
			TimeoutSec:        c.Server.TimeoutSec,
			UDPSockets:        c.Server.UDPSockets,
			UDPWorkers:        c.Server.UDPWorkers,
			Padding:           c.Server.Padding,
			Cookies:           c.Server.Cookies,
			DebugPprof:        c.Server.DebugPprof,
			MaxTCPConnsPerIP:  c.Server.MaxTCPConnsPerIP,
			MaxHTTPConnsPerIP: c.Server.MaxHTTPConnsPerIP,
			TrustedProxies:    c.Server.TrustedProxies,
			XFFHopLimit:       c.Server.XFFHopLimit,
			DoHASNHeader:      c.Server.DoHASNHeader,
		},
		Upstreams:    c.Upstreams,
		UpstreamMode: c.UpstreamMode,
		UpstreamRoutes: func() []upstreamRoutePayload {
			routes := make([]upstreamRoutePayload, 0, len(c.UpstreamRoutes))
			for _, rt := range c.UpstreamRoutes {
				routes = append(routes, upstreamRoutePayload{Domain: rt.Domain, Upstreams: rt.Upstreams})
			}
			return routes
		}(),
		Cache: cachePayload{
			Addr:          c.Cache.Addr,
			Password:      c.Cache.Password,
			DB:            c.Cache.DB,
			TTL:           c.Cache.TTL.String(),
			NegativeTTL:   c.Cache.NegativeTTL.String(),
			L1Entries:     c.Cache.L1Entries,
			ServeStale:    durationOrEmpty(c.Cache.ServeStale),
			Prefetch:      c.Cache.Prefetch,
			LookupTimeout: durationOrEmpty(c.Cache.LookupTimeout),
			FailureTTL:    durationOrEmpty(c.Cache.FailureTTL),
		},
		Warmer: warmerPayload{
			Enabled:     c.Warmer.Enabled,
			Interval:    durationOrEmpty(c.Warmer.Interval),
			Lookback:    durationOrEmpty(c.Warmer.Lookback),
			MaxDomains:  c.Warmer.MaxDomains,
			Concurrency: c.Warmer.Concurrency,
		},
		TLS: tlsPayload{
			CertFile:           c.TLS.CertFile,
			KeyFile:            c.TLS.KeyFile,
			GenerateSelfSigned: c.TLS.GenerateSelfSigned,
			SelfSignedHosts:    c.TLS.SelfSignedHosts,
			CertDir:            c.TLS.CertDir,
			ACME: acmePayload{
				Enabled:         c.TLS.ACME.Enabled,
				Email:           c.TLS.ACME.Email,
				Domains:         c.TLS.ACME.Domains,
				Staging:         c.TLS.ACME.Staging,
				HTTP01Port:      c.TLS.ACME.HTTP01Port,
				RenewBeforeDays: c.TLS.ACME.RenewBeforeDays,
				DNS01: dns01Payload{
					Provider:           c.TLS.ACME.DNS01.Provider,
					PropagationWait:    c.TLS.ACME.DNS01.PropagationWait,
					CloudflareToken:    c.TLS.ACME.DNS01.CloudflareToken,
					DigitalOceanToken:  c.TLS.ACME.DNS01.DigitalOceanToken,
					HetznerToken:       c.TLS.ACME.DNS01.HetznerToken,
					GoDaddyKey:         c.TLS.ACME.DNS01.GoDaddyKey,
					GoDaddySecret:      c.TLS.ACME.DNS01.GoDaddySecret,
					AWSAccessKeyID:     c.TLS.ACME.DNS01.AWSAccessKeyID,
					AWSSecretAccessKey: c.TLS.ACME.DNS01.AWSSecretAccessKey,
				},
			},
		},
		Filter: filterPayload{
			BlockResponse:           c.Filter.BlockResponse,
			BlockTTL:                c.Filter.BlockTTL,
			Blocklists:              make([]blocklistPayload, 0, len(c.Filter.Blocklists)),
			Whitelist:               c.Filter.Whitelist,
			Blacklist:               c.Filter.Blacklist,
			AutoUpdate:              durationOrEmpty(c.Filter.AutoUpdate),
			CNAMECloakingProtection: c.Filter.CNAMECloakingProtection,
		},
		Log: logPayload{
			QueryLogFile:  c.Log.QueryLogFile,
			RetentionDays: c.Log.RetentionDays,
			Verbose:       c.Log.Verbose,
			BatchSize:     c.Log.BatchSize,
		},
		Web: webPayload{Username: c.Web.Username},
		Tunnel: tunnelPayload{
			Enabled:        c.Tunnel.Enabled,
			Token:          c.Tunnel.Token,
			ConfigFile:     c.Tunnel.ConfigFile,
			QuickTunnel:    c.Tunnel.QuickTunnel,
			QuickTunnelURL: c.Tunnel.QuickTunnelURL,
			Hostname:       c.Tunnel.Hostname,
		},
	}
	for _, bl := range c.Filter.Blocklists {
		p.Filter.Blocklists = append(p.Filter.Blocklists, blocklistPayload{
			ID: bl.ID, Name: bl.Name, URL: bl.URL, Enabled: bl.Enabled,
		})
	}
	p.Rewrites = make([]rewritePayload, 0, len(c.Rewrites))
	for _, rw := range c.Rewrites {
		p.Rewrites = append(p.Rewrites, rewritePayload{Domain: rw.Domain, Type: rw.Type, Value: rw.Value, TTL: rw.TTL})
	}
	p.ClientGroups = make([]clientGroupPayload, 0, len(c.ClientGroups))
	for _, g := range c.ClientGroups {
		p.ClientGroups = append(p.ClientGroups, clientGroupPayload{
			ID: g.ID, Name: g.Name, Enabled: g.Enabled, CIDRs: g.CIDRs, ASNs: g.ASNs,
			Blocklists: g.Blocklists, Whitelist: g.Whitelist, Blacklist: g.Blacklist, Upstreams: g.Upstreams,
		})
	}
	p.RateLimit = rateLimitPayload{
		Enabled:    c.RateLimit.Enabled,
		QPS:        c.RateLimit.QPS,
		Burst:      c.RateLimit.Burst,
		AutoBlock:  c.RateLimit.AutoBlock,
		BlockAfter: c.RateLimit.BlockAfter,
		BlockFor:   durationOrEmpty(c.RateLimit.BlockFor),
		NXGuard: nxGuardPayload{
			Enabled:   c.RateLimit.NXGuard.Enabled,
			Threshold: c.RateLimit.NXGuard.Threshold,
			Window:    durationOrEmpty(c.RateLimit.NXGuard.Window),
			BlockFor:  durationOrEmpty(c.RateLimit.NXGuard.BlockFor),
		},
	}
	p.GeoBlock = geoBlockPayload{
		Enabled:          c.GeoBlock.Enabled,
		Countries:        c.GeoBlock.Countries,
		Allowlist:        c.GeoBlock.Allowlist,
		IPs:              c.GeoBlock.IPs,
		Honeypots:        c.GeoBlock.Honeypots,
		AllowASNs:        c.GeoBlock.AllowASNs,
		BlockASNs:        c.GeoBlock.BlockASNs,
		BaseURL:          c.GeoBlock.BaseURL,
		ASNBaseURL:       c.GeoBlock.ASNBaseURL,
		AutoUpdate:       durationOrEmpty(c.GeoBlock.AutoUpdate),
		TrustUDP:         c.GeoBlock.TrustUDP,
		HoneypotUDPBlock: durationOrEmpty(c.GeoBlock.HoneypotUDPBlock),
	}
	p.Abuse = abusePayload{AbuseIPDBKey: c.Abuse.AbuseIPDBKey}
	p.DNSSEC = dnssecPayload{Enabled: c.DNSSEC.Enabled, RequireAD: c.DNSSEC.RequireAD}
	p.Recursive = recursivePayload{ServerTimeout: durationOrEmpty(c.Recursive.ServerTimeout)}
	p.DHCP = dhcpPayload{
		Enabled:        c.DHCP.Enabled,
		Interface:      c.DHCP.Interface,
		Subnet:         c.DHCP.Subnet,
		RangeStart:     c.DHCP.RangeStart,
		RangeEnd:       c.DHCP.RangeEnd,
		Gateway:        c.DHCP.Gateway,
		DNS:            c.DHCP.DNS,
		LeaseTime:      durationOrEmpty(c.DHCP.LeaseTime),
		Domain:         c.DHCP.Domain,
		StaticLeases:   make([]dhcpStaticPayload, 0, len(c.DHCP.StaticLeases)),
		IPv6:           c.DHCP.IPv6,
		IPv6Prefix:     c.DHCP.IPv6Prefix,
		IPv6RangeStart: c.DHCP.IPv6RangeStart,
		IPv6RangeEnd:   c.DHCP.IPv6RangeEnd,
	}
	for _, sl := range c.DHCP.StaticLeases {
		p.DHCP.StaticLeases = append(p.DHCP.StaticLeases, dhcpStaticPayload{
			MAC: sl.MAC, DUID: sl.DUID, IP: sl.IP, Hostname: sl.Hostname,
		})
	}
	return p
}

// applyPayload validates a submitted config, live-applies the hot parts and
// persists it to disk. It returns the list of sections that need a restart.
func (h *Handler) applyPayload(p configPayload) ([]string, error) {
	parseDur := func(s string) (time.Duration, error) {
		if strings.TrimSpace(s) == "" {
			return 0, nil
		}
		d, err := time.ParseDuration(s)
		if err != nil {
			return 0, err
		}
		return d, nil
	}

	ttl, err := parseDur(p.Cache.TTL)
	if err != nil {
		return nil, fmt.Errorf("cache.ttl: %w", err)
	}
	negTTL, err := parseDur(p.Cache.NegativeTTL)
	if err != nil {
		return nil, fmt.Errorf("cache.negative_ttl: %w", err)
	}
	serveStale, err := parseDur(p.Cache.ServeStale)
	if err != nil {
		return nil, fmt.Errorf("cache.serve_stale: %w", err)
	}
	lookupTimeout, err := parseDur(p.Cache.LookupTimeout)
	if err != nil {
		return nil, fmt.Errorf("cache.lookup_timeout: %w", err)
	}
	failureTTL, err := parseDur(p.Cache.FailureTTL)
	if err != nil {
		return nil, fmt.Errorf("cache.failure_ttl: %w", err)
	}
	recursiveTimeout, err := parseDur(p.Recursive.ServerTimeout)
	if err != nil {
		return nil, fmt.Errorf("recursive.server_timeout: %w", err)
	}
	blocklistAutoUpdate, err := parseDur(p.Filter.AutoUpdate)
	if err != nil {
		return nil, fmt.Errorf("filter.auto_update: %w", err)
	}
	blockFor, err := parseDur(p.RateLimit.BlockFor)
	if err != nil {
		return nil, fmt.Errorf("rate_limit.block_for: %w", err)
	}
	nxWindow, err := parseDur(p.RateLimit.NXGuard.Window)
	if err != nil {
		return nil, fmt.Errorf("rate_limit.nxdomain_guard.window: %w", err)
	}
	nxBlockFor, err := parseDur(p.RateLimit.NXGuard.BlockFor)
	if err != nil {
		return nil, fmt.Errorf("rate_limit.nxdomain_guard.block_for: %w", err)
	}
	geoAutoUpdate, err := parseDur(p.GeoBlock.AutoUpdate)
	if err != nil {
		return nil, fmt.Errorf("geo_block.auto_update: %w", err)
	}
	geoUDPBlock, err := parseDur(p.GeoBlock.HoneypotUDPBlock)
	if err != nil {
		return nil, fmt.Errorf("geo_block.honeypot_udp_block: %w", err)
	}
	leaseTime, err := parseDur(p.DHCP.LeaseTime)
	if err != nil {
		return nil, fmt.Errorf("dhcp.lease_time: %w", err)
	}
	warmerInterval, err := parseDur(p.Warmer.Interval)
	if err != nil {
		return nil, fmt.Errorf("warmer.interval: %w", err)
	}
	warmerLookback, err := parseDur(p.Warmer.Lookback)
	if err != nil {
		return nil, fmt.Errorf("warmer.lookback: %w", err)
	}
	// Friendly defaults when auto-block is switched on without explicit
	// values: 3 violations then a 10-minute cooldown.
	if p.RateLimit.AutoBlock {
		if blockFor <= 0 {
			blockFor = 10 * time.Minute
		}
		if p.RateLimit.BlockAfter < 1 {
			p.RateLimit.BlockAfter = 3
		}
	}

	cfg := &config.Config{
		Server: config.ServerConfig{
			ListenUDP:         p.Server.ListenUDP,
			ListenTCP:         p.Server.ListenTCP,
			ListenDoT:         p.Server.ListenDoT,
			ListenDoH:         p.Server.ListenDoH,
			ListenDoH3:        p.Server.ListenDoH3,
			ListenDoQ:         p.Server.ListenDoQ,
			DoHPath:           p.Server.DoHPath,
			WebListen:         p.Server.WebListen,
			WebTLS:            p.Server.WebTLS,
			WebRedirect:       p.Server.WebRedirect,
			WebRedirectPort:   p.Server.WebRedirectPort,
			TimeoutSec:        p.Server.TimeoutSec,
			UDPSockets:        p.Server.UDPSockets,
			UDPWorkers:        p.Server.UDPWorkers,
			Padding:           p.Server.Padding,
			Cookies:           p.Server.Cookies,
			DebugPprof:        p.Server.DebugPprof,
			MaxTCPConnsPerIP:  p.Server.MaxTCPConnsPerIP,
			MaxHTTPConnsPerIP: p.Server.MaxHTTPConnsPerIP,
			TrustedProxies:    p.Server.TrustedProxies,
			XFFHopLimit:       p.Server.XFFHopLimit,
			DoHASNHeader:      p.Server.DoHASNHeader,
		},
		Upstreams:    p.Upstreams,
		UpstreamMode: p.UpstreamMode,
		UpstreamRoutes: func() []config.UpstreamRoute {
			routes := make([]config.UpstreamRoute, 0, len(p.UpstreamRoutes))
			for _, rt := range p.UpstreamRoutes {
				routes = append(routes, config.UpstreamRoute{Domain: rt.Domain, Upstreams: rt.Upstreams})
			}
			return routes
		}(),
		Cache: config.CacheConfig{
			Addr:          p.Cache.Addr,
			Password:      p.Cache.Password,
			DB:            p.Cache.DB,
			TTL:           ttl,
			NegativeTTL:   negTTL,
			L1Entries:     p.Cache.L1Entries,
			ServeStale:    serveStale,
			Prefetch:      p.Cache.Prefetch,
			LookupTimeout: lookupTimeout,
			FailureTTL:    failureTTL,
		},
		TLS: config.TLSConfig{
			CertFile:           p.TLS.CertFile,
			KeyFile:            p.TLS.KeyFile,
			GenerateSelfSigned: p.TLS.GenerateSelfSigned,
			SelfSignedHosts:    p.TLS.SelfSignedHosts,
			CertDir:            p.TLS.CertDir,
			ACME: config.ACMEConfig{
				Enabled:         p.TLS.ACME.Enabled,
				Email:           p.TLS.ACME.Email,
				Domains:         p.TLS.ACME.Domains,
				Staging:         p.TLS.ACME.Staging,
				HTTP01Port:      p.TLS.ACME.HTTP01Port,
				RenewBeforeDays: p.TLS.ACME.RenewBeforeDays,
				DNS01: config.DNS01Config{
					Provider:           p.TLS.ACME.DNS01.Provider,
					PropagationWait:    p.TLS.ACME.DNS01.PropagationWait,
					CloudflareToken:    p.TLS.ACME.DNS01.CloudflareToken,
					DigitalOceanToken:  p.TLS.ACME.DNS01.DigitalOceanToken,
					HetznerToken:       p.TLS.ACME.DNS01.HetznerToken,
					GoDaddyKey:         p.TLS.ACME.DNS01.GoDaddyKey,
					GoDaddySecret:      p.TLS.ACME.DNS01.GoDaddySecret,
					AWSAccessKeyID:     p.TLS.ACME.DNS01.AWSAccessKeyID,
					AWSSecretAccessKey: p.TLS.ACME.DNS01.AWSSecretAccessKey,
				},
			},
		},
		Filter: config.FilterConfig{
			BlockResponse:           p.Filter.BlockResponse,
			BlockTTL:                p.Filter.BlockTTL,
			Blocklists:              make([]config.BlocklistSpec, 0, len(p.Filter.Blocklists)),
			Whitelist:               p.Filter.Whitelist,
			Blacklist:               p.Filter.Blacklist,
			AutoUpdate:              blocklistAutoUpdate,
			CNAMECloakingProtection: p.Filter.CNAMECloakingProtection,
		},
		Log: config.LogConfig{
			QueryLogFile:  p.Log.QueryLogFile,
			RetentionDays: p.Log.RetentionDays,
			Verbose:       p.Log.Verbose,
			BatchSize:     p.Log.BatchSize,
		},
		Web: config.WebConfig{
			Username: p.Web.Username,
			Password: p.Web.Password,
		},
		Tunnel: config.TunnelConfig{
			Enabled:        p.Tunnel.Enabled,
			Token:          p.Tunnel.Token,
			ConfigFile:     p.Tunnel.ConfigFile,
			QuickTunnel:    p.Tunnel.QuickTunnel,
			QuickTunnelURL: p.Tunnel.QuickTunnelURL,
			Hostname:       p.Tunnel.Hostname,
		},
		RateLimit: config.RateLimitConfig{
			Enabled:    p.RateLimit.Enabled,
			QPS:        p.RateLimit.QPS,
			Burst:      p.RateLimit.Burst,
			AutoBlock:  p.RateLimit.AutoBlock,
			BlockAfter: p.RateLimit.BlockAfter,
			BlockFor:   blockFor,
			NXGuard: config.NXGuardConfig{
				Enabled:   p.RateLimit.NXGuard.Enabled,
				Threshold: p.RateLimit.NXGuard.Threshold,
				Window:    nxWindow,
				BlockFor:  nxBlockFor,
			},
		},
		GeoBlock: config.GeoBlockConfig{
			Enabled:          p.GeoBlock.Enabled,
			Countries:        p.GeoBlock.Countries,
			Allowlist:        p.GeoBlock.Allowlist,
			IPs:              p.GeoBlock.IPs,
			Honeypots:        p.GeoBlock.Honeypots,
			AllowASNs:        p.GeoBlock.AllowASNs,
			BlockASNs:        p.GeoBlock.BlockASNs,
			BaseURL:          p.GeoBlock.BaseURL,
			ASNBaseURL:       p.GeoBlock.ASNBaseURL,
			AutoUpdate:       geoAutoUpdate,
			TrustUDP:         p.GeoBlock.TrustUDP,
			HoneypotUDPBlock: geoUDPBlock,
		},
		Abuse: config.AbuseConfig{
			AbuseIPDBKey: p.Abuse.AbuseIPDBKey,
		},
		DNSSEC: config.DNSSECConfig{
			Enabled:   p.DNSSEC.Enabled,
			RequireAD: p.DNSSEC.RequireAD,
		},
		Warmer: config.WarmerConfig{
			Enabled:     p.Warmer.Enabled,
			Interval:    warmerInterval,
			Lookback:    warmerLookback,
			MaxDomains:  p.Warmer.MaxDomains,
			Concurrency: p.Warmer.Concurrency,
		},
		Recursive: config.RecursiveConfig{ServerTimeout: recursiveTimeout},
		DHCP: config.DHCPConfig{
			Enabled:        p.DHCP.Enabled,
			Interface:      p.DHCP.Interface,
			Subnet:         p.DHCP.Subnet,
			RangeStart:     p.DHCP.RangeStart,
			RangeEnd:       p.DHCP.RangeEnd,
			Gateway:        p.DHCP.Gateway,
			DNS:            p.DHCP.DNS,
			LeaseTime:      leaseTime,
			Domain:         p.DHCP.Domain,
			StaticLeases:   make([]config.DHCPStaticLease, 0, len(p.DHCP.StaticLeases)),
			IPv6:           p.DHCP.IPv6,
			IPv6Prefix:     p.DHCP.IPv6Prefix,
			IPv6RangeStart: p.DHCP.IPv6RangeStart,
			IPv6RangeEnd:   p.DHCP.IPv6RangeEnd,
		},
	}
	for _, rw := range p.Rewrites {
		cfg.Rewrites = append(cfg.Rewrites, config.RewriteSpec{Domain: rw.Domain, Type: rw.Type, Value: rw.Value, TTL: rw.TTL})
	}
	for _, g := range p.ClientGroups {
		cfg.ClientGroups = append(cfg.ClientGroups, config.ClientGroup{
			ID: g.ID, Name: g.Name, Enabled: g.Enabled, CIDRs: g.CIDRs, ASNs: g.ASNs,
			Blocklists: g.Blocklists, Whitelist: g.Whitelist, Blacklist: g.Blacklist, Upstreams: g.Upstreams,
		})
	}
	for _, bl := range p.Filter.Blocklists {
		cfg.Filter.Blocklists = append(cfg.Filter.Blocklists, config.BlocklistSpec{
			ID: bl.ID, Name: bl.Name, URL: bl.URL, Enabled: bl.Enabled,
		})
	}
	for _, sl := range p.DHCP.StaticLeases {
		cfg.DHCP.StaticLeases = append(cfg.DHCP.StaticLeases, config.DHCPStaticLease{
			MAC: sl.MAC, DUID: sl.DUID, IP: sl.IP, Hostname: sl.Hostname,
		})
	}

	// Keep the existing password hash unless a new plaintext password was
	// provided (it is bcrypt-hashed by Config.Save). Changing the password
	// rotates the session secret so every previously issued session cookie —
	// including the one authorizing this very request — becomes invalid at
	// once (session rotation on password change).
	if cfg.Web.Password == "" {
		cfg.Web.Password = h.Cfg.Web.Password
		cfg.Web.SessionSecret = h.Cfg.Web.SessionSecret
	} else {
		sec, err := sessionSecretFor(cfg.Web.Password, h.Cfg.Web.SessionSecret)
		if err != nil {
			return nil, fmt.Errorf("rotate session secret: %w", err)
		}
		cfg.Web.SessionSecret = sec
	}

	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	// Parse conditional routes before any live-apply: a bad route spec (e.g.
	// an unsupported upstream scheme, which Validate doesn't catch) fails the
	// save with nothing touched. SetUpstreamRoutes takes the compiled routes,
	// so the live-apply below can no longer fail.
	parsedRoutes, err := dnsserver.ParseRoutes(routeSpecs(cfg.UpstreamRoutes))
	if err != nil {
		return nil, err
	}

	h.cfgMu.Lock()
	defer h.cfgMu.Unlock()

	// Diff against the running config to report restart-required sections.
	restart := []string{}
	if !reflect.DeepEqual(h.Cfg.Server, cfg.Server) {
		restart = append(restart, "server (listeners)")
	}
	// cache.failure_ttl is live-applied below (SetFailureTTL), so exclude it
	// from the restart comparison — changing just it shouldn't prompt a full
	// cache reload.
	cacheNoFailure := func(c config.CacheConfig) config.CacheConfig {
		c.FailureTTL = 0
		return c
	}
	if !reflect.DeepEqual(cacheNoFailure(h.Cfg.Cache), cacheNoFailure(cfg.Cache)) {
		restart = append(restart, "cache")
	}
	if !reflect.DeepEqual(h.Cfg.TLS, cfg.TLS) {
		restart = append(restart, "tls")
	}
	if !reflect.DeepEqual(h.Cfg.Log, cfg.Log) {
		restart = append(restart, "log")
	}
	if !reflect.DeepEqual(h.Cfg.Tunnel, cfg.Tunnel) {
		restart = append(restart, "tunnel")
	}
	// DHCP is live-applied below (SetConfig + listener restart when the
	// interface/enable state changed), so a pure pool-option tweak doesn't
	// prompt a restart — but a bind change (interface, enabling/disabling)
	// is reported like the other listener-bound sections.
	if h.DHCP != nil && !reflect.DeepEqual(dhcpBindConfig(h.Cfg.DHCP), dhcpBindConfig(cfg.DHCP)) {
		restart = append(restart, "dhcp (listeners)")
	}

	// Live-apply the hot sections.
	if !reflect.DeepEqual(h.Cfg.Upstreams, cfg.Upstreams) {
		ups := make([]*upstream.Upstream, 0, len(cfg.Upstreams))
		for _, spec := range cfg.Upstreams {
			up, err := upstream.Parse(spec)
			if err != nil {
				return nil, fmt.Errorf("upstream %q: %w", spec, err)
			}
			ups = append(ups, up)
		}
		h.DNS.SetUpstreams(ups)
		h.Upstreams = ups
	}
	// Conditional routes are a pure hot-swap like the upstreams list itself
	// (per-query selection, no listener rebind), so a change applies live
	// without a restart note. The specs were already parsed up front, so
	// this cannot fail.
	if !reflect.DeepEqual(h.Cfg.UpstreamRoutes, cfg.UpstreamRoutes) {
		h.DNS.SetUpstreamRoutes(parsedRoutes)
	}
	// The resolution strategy is a cheap, side-effect-free hot-swap, applied
	// unconditionally like the other live policy knobs.
	h.DNS.SetUpstreamMode(cfg.UpstreamMode)
	h.DNS.SetBlockPolicy(cfg.Filter.BlockResponse, cfg.Filter.BlockTTL)
	h.DNS.SetTimeout(time.Duration(cfg.Server.TimeoutSec) * time.Second)
	h.DNS.SetFailureTTL(cfg.Cache.FailureTTL)
	// recursive.server_timeout is a package-level default read at query time
	// by every recursive:// resolver (existing, reloaded and per-client-group).
	recursive.SetDefaultServerTimeout(cfg.Recursive.ServerTimeout)
	h.Cache.SetLookupTimeout(cfg.Cache.LookupTimeout)
	h.Cfg.Filter.Whitelist = cfg.Filter.Whitelist
	h.Cfg.Filter.Blacklist = cfg.Filter.Blacklist
	h.applyUserLists()
	h.Cfg.Filter.Blocklists = cfg.Filter.Blocklists
	h.Cfg.Filter.AutoUpdate = cfg.Filter.AutoUpdate
	h.applyLists()
	// Rewrites, client groups, rate limiting and DNSSEC are all cheap,
	// side-effect-free hot-swaps — unlike Server/Cache/TLS there's no
	// listener rebind risk, so just reapply them unconditionally rather than
	// diffing first.
	h.DNS.SetRewriter(dnsserver.BuildRewriter(cfg.Rewrites))
	h.DNS.SetClientRouter(dnsserver.BuildClientRouter(cfg, h.Lists, h.GroupASN.Load()))
	h.DNS.SetRateLimiter(dnsserver.BuildRateLimiter(cfg.RateLimit))
	h.DNS.SetDNSSEC(cfg.DNSSEC.Enabled, cfg.DNSSEC.RequireAD)
	h.DNS.SetCNAMECloakingProtection(cfg.Filter.CNAMECloakingProtection)
	// The cache warmer is hot-swappable (a plain settings change, no
	// listener rebind), so it is live-applied without marking a restart.
	if h.Warmer != nil {
		h.Warmer.SetConfig(cfg.Warmer)
	}
	// DHCP options (pool, gateway, DNS, lease time, domain, statics) apply
	// immediately — the handlers read them per packet under the server's own
	// lock. Only the bind itself (interface, enable state) needs a listener
	// restart, which main's Reload performs.
	if h.DHCP != nil {
		h.DHCP.SetConfig(h.dhcpRuntimeConfig(cfg.DHCP))
	}

	oldSecret := h.Cfg.Web.SessionSecret
	*h.Cfg = *cfg
	if err := h.SaveConfig(); err != nil {
		// A failed save must not leave a rotated session secret live in
		// memory while the file still holds the old one — sessions signed
		// with the new secret would silently die on the next restart.
		// Revert just the secret; the rest of the in-memory apply keeps the
		// established (pre-existing) semantics.
		h.Cfg.Web.SessionSecret = oldSecret
		return nil, err
	}
	// Geo-blocking changes are hot-swapped (no listener rebind needed). The
	// rebuild runs asynchronously so a country-data download can never stall
	// the config save or hold cfgMu.
	if h.RebuildGeo != nil {
		_ = h.RebuildGeo(cfg.GeoBlock)
	}
	// Client-group ASN matching needs the IP→ASN dataset pruned to the new
	// group lists; the refresh and router rebuild run asynchronously for the
	// same reason (and the router built above with the previous table is
	// replaced the moment the fresh one lands).
	if h.RebuildClientGroups != nil {
		_ = h.RebuildClientGroups(cfg)
	}
	return restart, nil
}

func (h *Handler) getConfig(w http.ResponseWriter) {
	h.cfgMu.Lock()
	defer h.cfgMu.Unlock()
	writeJSON(w, http.StatusOK, payloadFromConfig(h.Cfg))
}

func (h *Handler) putConfig(w http.ResponseWriter, r *http.Request) {
	var p configPayload
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad body: " + err.Error()})
		return
	}
	restart, err := h.applyPayload(p)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":               true,
		"restart_required": restart,
	})
}

func (h *Handler) reloadConfig(w http.ResponseWriter) {
	if h.Reload == nil {
		writeJSON(w, http.StatusNotImplemented, map[string]string{"error": "reload not supported in this build"})
		return
	}
	// Hold cfgMu: Reload reads the in-memory config which putConfig mutates
	// under the same mutex.
	h.cfgMu.Lock()
	err := h.Reload()
	h.cfgMu.Unlock()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	// Sections the in-process reload does not handle still need a restart.
	remaining := []string{}
	if h.Cfg.Tunnel.Enabled || h.Cfg.Tunnel.Token != "" || h.Cfg.Tunnel.QuickTunnel {
		remaining = append(remaining, "tunnel")
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":                     true,
		"reloaded":               true,
		"still_requires_restart": remaining,
	})
}
