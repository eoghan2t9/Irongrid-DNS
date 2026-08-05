package config

import (
	"strings"
	"testing"
)

// TestPerfTunablesDefaults verifies the performance tunables ship with sane
// defaults: the L1 cache on (512 entries/shard) and a 256-entry log batch.
func TestPerfTunablesDefaults(t *testing.T) {
	c := Default()
	if c.Cache.L1Entries != 512 {
		t.Errorf("cache.l1_entries = %d, want default 512", c.Cache.L1Entries)
	}
	if c.Log.BatchSize != 256 {
		t.Errorf("log.batch_size = %d, want default 256", c.Log.BatchSize)
	}
}

// TestPerfTunablesValidation verifies negative values are rejected.
func TestPerfTunablesValidation(t *testing.T) {
	c := validBase()
	c.Cache.L1Entries = -1
	if err := c.Validate(); err == nil {
		t.Error("negative cache.l1_entries accepted")
	}
	c = validBase()
	c.Log.BatchSize = -1
	if err := c.Validate(); err == nil {
		t.Error("negative log.batch_size accepted")
	}
}

func validBase() *Config {
	return &Config{
		Server: ServerConfig{
			ListenUDP:  "0.0.0.0:53",
			WebListen:  "0.0.0.0:8080",
			TimeoutSec: 5,
		},
		Cache:     CacheConfig{Addr: "localhost:6379", TTL: 6 * 3600e9, NegativeTTL: 60e9},
		Upstreams: []string{"udp://1.1.1.1:53"},
		Log:       LogConfig{RetentionDays: 30},
		Web:       WebConfig{Username: "admin"},
	}
}

func TestValidateWebRedirect(t *testing.T) {
	c := validBase()
	c.Server.WebTLS = true
	c.Server.WebRedirect = true
	if err := c.Validate(); err != nil {
		t.Fatalf("valid web_redirect rejected: %v", err)
	}
	if c.Server.WebRedirectPort != 80 {
		t.Errorf("web_redirect_port = %d, want default 80", c.Server.WebRedirectPort)
	}
}

func TestValidateWebRedirectRequiresWebTLS(t *testing.T) {
	c := validBase()
	c.Server.WebRedirect = true // web_tls stays false
	err := c.Validate()
	if err == nil || !strings.Contains(err.Error(), "web_redirect requires") {
		t.Fatalf("err = %v, want web_redirect-requires-web_tls", err)
	}
}

func TestValidateWebSharesDoHPort(t *testing.T) {
	c := validBase()
	c.Server.WebListen = "0.0.0.0:443"
	c.Server.ListenDoH = "0.0.0.0:443"
	c.Server.DoHPath = "/dns-query"
	c.Server.WebTLS = true
	if err := c.Validate(); err != nil {
		t.Fatalf("dashboard sharing the DoH port with web_tls rejected: %v", err)
	}
}

func TestValidateWebSharesDoHRequiresWebTLS(t *testing.T) {
	c := validBase()
	c.Server.WebListen = "0.0.0.0:443"
	c.Server.ListenDoH = "0.0.0.0:443"
	c.Server.DoHPath = "/dns-query"
	c.Server.WebTLS = false // DoH needs TLS on the merged listener
	err := c.Validate()
	if err == nil || !strings.Contains(err.Error(), "web_tls") {
		t.Fatalf("err = %v, want web_tls-required error when sharing the DoH port", err)
	}
}

func TestValidateWebSharesDoHRequiresDoHPath(t *testing.T) {
	c := validBase()
	c.Server.WebListen = "0.0.0.0:443"
	c.Server.ListenDoH = "0.0.0.0:443"
	c.Server.DoHPath = "" // shared mux needs a non-empty path
	c.Server.WebTLS = true
	err := c.Validate()
	if err == nil || !strings.Contains(err.Error(), "doh_path") {
		t.Fatalf("err = %v, want doh_path-required error when sharing the DoH port", err)
	}
}

func TestValidateWebRedirectPortCollision(t *testing.T) {
	c := validBase()
	c.Server.WebTLS = true
	c.Server.WebRedirect = true
	c.Server.WebRedirectPort = 8080 // same as WebListen port
	err := c.Validate()
	if err == nil || !strings.Contains(err.Error(), "collides") {
		t.Fatalf("err = %v, want port collision error", err)
	}
}

func TestValidateDNS01Cloudflare(t *testing.T) {
	c := validBase()
	c.TLS.ACME = ACMEConfig{
		Enabled: true,
		Email:   "a@example.com",
		Domains: []string{"dns.example.com"},
		DNS01:   DNS01Config{Provider: "cloudflare", CloudflareToken: "tok"},
	}
	if err := c.Validate(); err != nil {
		t.Fatalf("valid cloudflare dns01 rejected: %v", err)
	}
	if c.TLS.ACME.DNS01.PropagationWait != 60 {
		t.Errorf("propagation_wait_sec = %d, want default 60", c.TLS.ACME.DNS01.PropagationWait)
	}
}

func TestValidateDNS01CloudflareRequiresToken(t *testing.T) {
	c := validBase()
	c.TLS.ACME = ACMEConfig{
		Enabled: true,
		Email:   "a@example.com",
		Domains: []string{"dns.example.com"},
		DNS01:   DNS01Config{Provider: "cloudflare"},
	}
	err := c.Validate()
	if err == nil || !strings.Contains(err.Error(), "cloudflare_token") {
		t.Fatalf("err = %v, want cloudflare_token error", err)
	}
}

func TestValidateDNS01UnsupportedProvider(t *testing.T) {
	c := validBase()
	c.TLS.ACME = ACMEConfig{
		Enabled: true,
		Email:   "a@example.com",
		Domains: []string{"dns.example.com"},
		DNS01:   DNS01Config{Provider: "route-unknown"},
	}
	err := c.Validate()
	if err == nil || !strings.Contains(err.Error(), "unsupported provider") {
		t.Fatalf("err = %v, want unsupported-provider error", err)
	}
}

func TestValidateDNS01SupportedProviders(t *testing.T) {
	cases := []struct {
		provider string
		dns01    DNS01Config
	}{
		{"digitalocean", DNS01Config{Provider: "digitalocean", DigitalOceanToken: "t"}},
		{"hetzner", DNS01Config{Provider: "hetzner", HetznerToken: "t"}},
		{"godaddy", DNS01Config{Provider: "godaddy", GoDaddyKey: "k", GoDaddySecret: "s"}},
		{"route53", DNS01Config{Provider: "route53", AWSAccessKeyID: "a", AWSSecretAccessKey: "s"}},
	}
	for _, tc := range cases {
		c := validBase()
		c.TLS.ACME = ACMEConfig{
			Enabled: true,
			Email:   "a@example.com",
			Domains: []string{"dns.example.com"},
			DNS01:   tc.dns01,
		}
		if err := c.Validate(); err != nil {
			t.Errorf("%s: %v", tc.provider, err)
		}
	}
}
