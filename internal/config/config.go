// Package config defines the YAML configuration schema for Irongrid DNS
// and handles loading, defaulting and persisting it.
package config

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
	"gopkg.in/yaml.v3"
)

// Config is the root configuration document.
type Config struct {
	Server       ServerConfig    `yaml:"server"`
	Upstreams    []string        `yaml:"upstreams"`
	Cache        CacheConfig     `yaml:"cache"`
	TLS          TLSConfig       `yaml:"tls"`
	Filter       FilterConfig    `yaml:"filter"`
	Log          LogConfig       `yaml:"log"`
	Web          WebConfig       `yaml:"web"`
	Tunnel       TunnelConfig    `yaml:"tunnel"`
	Rewrites     []RewriteSpec   `yaml:"rewrites"`      // local DNS records (A/AAAA/CNAME)
	ClientGroups []ClientGroup   `yaml:"client_groups"` // per-client blocking/upstream policy
	RateLimit    RateLimitConfig `yaml:"rate_limit"`
	GeoBlock     GeoBlockConfig  `yaml:"geo_block"`
	DNSSEC       DNSSECConfig    `yaml:"dnssec"`
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
// source IP falls in one of CIDRs. Groups are evaluated in list order; the
// first match wins. Clients matching no group use the global Filter/Upstreams.
type ClientGroup struct {
	ID      string   `yaml:"id"`
	Name    string   `yaml:"name"`
	Enabled bool     `yaml:"enabled"`
	CIDRs   []string `yaml:"cidrs"` // e.g. "192.168.1.50/32", "10.0.5.0/24"
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
	// Allowlist is a set of client IPs/CIDRs that are never geo-blocked.
	Allowlist []string `yaml:"allowlist"`
	// BaseURL overrides where per-country CIDR lists are fetched from; the
	// country code and file are appended as "<CC>/ipv4_agg.txt" and
	// "<CC>/ipv6_agg.txt". file:// paths are supported for local datasets.
	BaseURL string `yaml:"base_url"`
	// AutoUpdate re-fetches the enabled countries' data every AutoUpdate
	// (the ipverse/rir-ip aggregates change roughly weekly). 0 disables
	// automatic refreshes (data is then only refreshed on save/manual
	// refresh); the default is 168h (weekly).
	AutoUpdate time.Duration `yaml:"auto_update"`
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
	ListenDoQ string `yaml:"listen_doq"` // DNS over QUIC, "" disables
	DoHPath   string `yaml:"doh_path"`   // HTTP path served for DoH (RFC 8484)
	WebListen string `yaml:"web_listen"` // management web UI + REST API
	WebTLS    bool   `yaml:"web_tls"`    // serve the web UI + API over HTTPS (uses the TLS cert)
	// WebRedirect serves a plain-HTTP listener on WebRedirectPort that 301s
	// to https://<host>/ — a convenience when web_tls is enabled.
	WebRedirect     bool `yaml:"web_redirect"`
	WebRedirectPort int  `yaml:"web_redirect_port"` // default 80
	TimeoutSec      int  `yaml:"timeout_sec"`       // per-query timeout
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
	// layered in front of Dragonfly. 0 disables the L1 entirely.
	L1Entries int `yaml:"l1_entries"`
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
}

// BlocklistSpec describes a remote or local blocklist source.
type BlocklistSpec struct {
	ID          string    `yaml:"id"`      // unique identifier shown in the UI
	Name        string    `yaml:"name"`    // friendly name
	URL         string    `yaml:"url"`     // remote URL, or local file path (file://)
	Enabled     bool      `yaml:"enabled"` // fetched and applied when true
	LastUpdated time.Time `yaml:"-"`       // runtime state, not persisted here
}

// LogConfig controls the query log.
type LogConfig struct {
	QueryLogFile  string `yaml:"query_log_file"`
	RetentionDays int    `yaml:"retention_days"`
	Verbose       bool   `yaml:"verbose"`
	// BatchSize is how many entries the async query-log writer commits per
	// transaction. 0 uses the built-in default (256).
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
		Cache: CacheConfig{
			Addr:        "localhost:6379",
			DB:          0,
			TTL:         6 * time.Hour,
			NegativeTTL: 60 * time.Second,
			L1Entries:   512,
		},
		TLS: TLSConfig{
			GenerateSelfSigned: true,
			SelfSignedHosts:    []string{"localhost", "dns.example.com"},
			CertDir:            "data/certs",
		},
		Filter: FilterConfig{
			BlockResponse: "nxdomain",
			BlockTTL:      600,
			Whitelist:     []string{},
			Blacklist:     []string{},
			AutoUpdate:    24 * time.Hour,
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
		},
		GeoBlock: GeoBlockConfig{
			AutoUpdate: 168 * time.Hour,
		},
		DNSSEC: DNSSECConfig{
			Enabled:   false,
			RequireAD: true,
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
	if c.Cache.Addr == "" {
		return fmt.Errorf("cache.addr is required (Dragonfly endpoint)")
	}
	if c.Cache.L1Entries < 0 {
		return fmt.Errorf("cache.l1_entries must be >= 0 (0 disables the in-memory cache)")
	}
	if c.Log.BatchSize < 0 {
		return fmt.Errorf("log.batch_size must be >= 0 (0 uses the default)")
	}
	if c.Server.ListenUDP == "" && c.Server.ListenTCP == "" &&
		c.Server.ListenDoT == "" && c.Server.ListenDoH == "" && c.Server.ListenDoQ == "" {
		return fmt.Errorf("at least one DNS listener must be enabled")
	}
	if c.Server.TimeoutSec < 1 {
		return fmt.Errorf("server.timeout_sec must be >= 1")
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
		if len(g.CIDRs) == 0 {
			return fmt.Errorf("client_groups[%d] (%s): at least one CIDR is required", i, g.ID)
		}
		for _, cidr := range g.CIDRs {
			if _, _, err := net.ParseCIDR(cidr); err != nil {
				if net.ParseIP(cidr) == nil {
					return fmt.Errorf("client_groups[%d] (%s): invalid CIDR/IP %q", i, g.ID, cidr)
				}
			}
		}
		for _, spec := range g.Upstreams {
			if spec == "" {
				return fmt.Errorf("client_groups[%d] (%s): empty upstream entry", i, g.ID)
			}
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
	if u := c.GeoBlock.BaseURL; u != "" && !strings.HasPrefix(u, "http://") && !strings.HasPrefix(u, "https://") && !strings.HasPrefix(u, "file://") {
		return fmt.Errorf("geo_block.base_url must start with http://, https:// or file://")
	}
	if c.GeoBlock.AutoUpdate < 0 {
		return fmt.Errorf("geo_block.auto_update must be >= 0 (0 disables automatic refreshes)")
	}
	return nil
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
