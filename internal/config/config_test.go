package config

import (
	"strings"
	"testing"
)

func validBase() *Config {
	return &Config{
		Server: ServerConfig{
			ListenUDP: "0.0.0.0:53",
			WebListen: "0.0.0.0:8080",
			TimeoutSec: 5,
		},
		Cache: CacheConfig{Addr: "localhost:6379", TTL: 6 * 3600e9, NegativeTTL: 60e9},
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
		DNS01:   DNS01Config{Provider: "route53"},
	}
	err := c.Validate()
	if err == nil || !strings.Contains(err.Error(), "unsupported provider") {
		t.Fatalf("err = %v, want unsupported-provider error", err)
	}
}
