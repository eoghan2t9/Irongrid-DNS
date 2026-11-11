// Package config defines the YAML configuration schema for Irongrid DNS
// and handles loading, defaulting and persisting it.
package config

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/goccy/go-yaml"
	"golang.org/x/crypto/bcrypt"
)

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
			// Repeat-query flood guard: off by default, with sane values
			// ready to flip on (50 queries for the same domain within 10s
			// -> 10m refusal for a trusted source; untrusted plain-UDP
			// sources are counted but never blocked until udp_block_for is
			// set).
			RepeatQuery: RepeatQueryConfig{
				Enabled:     false,
				Threshold:   50,
				Window:      10 * time.Second,
				BlockFor:    10 * time.Minute,
				UDPBlockFor: 0,
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
	// Migrate a pre-multi-user config's single admin login into Users on
	// first load after upgrade: the existing account becomes the sole
	// admin, unchanged, with no action needed. Only fires once — once
	// Users is non-empty (whether from this migration or from real
	// multi-user config), it's the live auth source and this is a no-op.
	if len(cfg.Web.Users) == 0 && cfg.Web.Username != "" && cfg.Web.Password != "" {
		id, err := randomHex(8)
		if err != nil {
			return nil, fmt.Errorf("generate web user id: %w", err)
		}
		cfg.Web.Users = []WebUser{{ID: id, Username: cfg.Web.Username, Password: cfg.Web.Password, Role: "admin"}}
		if err := cfg.Save(path); err != nil {
			fmt.Fprintf(os.Stderr, "warning: could not persist migrated web user (%v); will re-migrate on next load\n", err)
		}
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

// NewWebUserID returns a fresh random identifier for a new WebUser.
func NewWebUserID() (string, error) {
	return randomHex(8)
}

// Save writes the config to path, creating parent directories. Plaintext web
// passwords and API tokens are hashed before persisting.
func (c *Config) Save(path string) error {
	if c.Web.Password != "" && !isBcrypt(c.Web.Password) {
		// A bcrypt failure must abort the save, not fall through to writing
		// the plaintext password to disk — silently ignoring err == nil
		// used to do exactly that.
		hash, err := bcrypt.GenerateFromPassword([]byte(c.Web.Password), bcrypt.DefaultCost)
		if err != nil {
			return fmt.Errorf("hash web password: %w", err)
		}
		c.Web.Password = string(hash)
	}
	for i, t := range c.Web.Tokens {
		if t.Token != "" && !isSHA256Hex(t.Token) {
			sum := sha256.Sum256([]byte(t.Token))
			c.Web.Tokens[i].Token = hex.EncodeToString(sum[:])
		}
	}
	for i, u := range c.Web.Users {
		if u.Password != "" && !isBcrypt(u.Password) {
			hash, err := bcrypt.GenerateFromPassword([]byte(u.Password), bcrypt.DefaultCost)
			if err != nil {
				return fmt.Errorf("hash web user %q password: %w", u.Username, err)
			}
			c.Web.Users[i].Password = string(hash)
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

// isSHA256Hex reports whether s looks like a SHA-256 hex digest (64
// lowercase hex characters) — the stored form of an APIToken.Token.
func isSHA256Hex(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, r := range s {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f')) {
			return false
		}
	}
	return true
}
