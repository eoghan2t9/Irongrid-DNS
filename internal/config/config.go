// Package config defines the YAML configuration schema for Irongrid DNS
// and handles loading, defaulting and persisting it.
package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
	"gopkg.in/yaml.v3"
)

// Config is the root configuration document.
type Config struct {
	Server    ServerConfig    `yaml:"server"`
	Upstreams []string        `yaml:"upstreams"`
	Cache     CacheConfig     `yaml:"cache"`
	TLS       TLSConfig       `yaml:"tls"`
	Filter    FilterConfig    `yaml:"filter"`
	Log       LogConfig       `yaml:"log"`
	Web       WebConfig       `yaml:"web"`
	Tunnel    TunnelConfig    `yaml:"tunnel"`
}

// ServerConfig controls every network listener.
type ServerConfig struct {
	ListenUDP  string `yaml:"listen_udp"`  // plain DNS over UDP, "" disables
	ListenTCP  string `yaml:"listen_tcp"`  // plain DNS over TCP, "" disables
	ListenDoT  string `yaml:"listen_dot"`  // DNS over TLS, "" disables
	ListenDoH  string `yaml:"listen_doh"`  // DNS over HTTPS, "" disables
	ListenDoQ  string `yaml:"listen_doq"`  // DNS over QUIC, "" disables
	DoHPath    string `yaml:"doh_path"`    // HTTP path served for DoH (RFC 8484)
	WebListen  string `yaml:"web_listen"`  // management web UI + REST API
	TimeoutSec int    `yaml:"timeout_sec"` // per-query timeout
}

// CacheConfig points at the Dragonfly instance that is the authoritative
// response cache. Irongrid DNS will not start if it cannot reach it.
type CacheConfig struct {
	Addr        string        `yaml:"addr"`          // host:port of Dragonfly
	Password    string        `yaml:"password"`      // optional auth
	DB          int           `yaml:"db"`            // logical db index
	TTL         time.Duration `yaml:"ttl"`           // positive answer cache TTL
	NegativeTTL time.Duration `yaml:"negative_ttl"`  // cached NXDOMAIN/SERVFAIL TTL
}

// TLSConfig controls certificates used by DoT, DoH and DoQ.
type TLSConfig struct {
	CertFile          string   `yaml:"cert_file"`            // PEM cert chain
	KeyFile           string   `yaml:"key_file"`             // PEM private key
	GenerateSelfSigned bool    `yaml:"generate_self_signed"` // create a self-signed cert if none given
	SelfSignedHosts   []string `yaml:"self_signed_hosts"`    // SANs for the generated cert
	CertDir           string   `yaml:"cert_dir"`             // where generated certs are stored
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
}

// BlocklistSpec describes a remote or local blocklist source.
type BlocklistSpec struct {
	ID         string        `yaml:"id"`          // unique identifier shown in the UI
	Name       string        `yaml:"name"`        // friendly name
	URL        string        `yaml:"url"`         // remote URL, or local file path (file://)
	Enabled    bool          `yaml:"enabled"`     // fetched and applied when true
	AutoUpdate time.Duration `yaml:"auto_update"` // refresh interval, 0 = never
	LastUpdated time.Time    `yaml:"-"`           // runtime state, not persisted here
}

// LogConfig controls the query log.
type LogConfig struct {
	QueryLogFile  string `yaml:"query_log_file"`
	RetentionDays int    `yaml:"retention_days"`
	Verbose       bool   `yaml:"verbose"`
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
	Enabled       bool   `yaml:"enabled"`
	Token         string `yaml:"token"`   // named tunnel token (remote-managed)
	ConfigFile    string `yaml:"config_file"` // cloudflared YAML config, if used
	QuickTunnel   bool   `yaml:"quick_tunnel"` // unauth trycloudflare.com quick tunnel
	QuickTunnelURL string `yaml:"quick_tunnel_url"` // origin URL exposed by quick tunnel
	Hostname      string `yaml:"hostname"` // e.g. dns.example.com
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
		},
		Log: LogConfig{
			QueryLogFile:  "data/querylog.db",
			RetentionDays: 30,
			Verbose:       true,
		},
		Web: WebConfig{
			Username: "admin",
		},
		Tunnel: TunnelConfig{
			QuickTunnelURL: "http://localhost:8080",
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
	return cfg, nil
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
	if c.Web.Username == "" {
		return fmt.Errorf("web.username is required")
	}
	return nil
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
