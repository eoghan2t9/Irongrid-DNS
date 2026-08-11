package config

import (
	"strings"
	"testing"
	"time"
)

// TestValidateUpstreamMode verifies the resolution strategy accepts race and
// sequential, defaults an empty value to race, and rejects anything else.
func TestValidateUpstreamMode(t *testing.T) {
	c := validBase()
	c.UpstreamMode = ""
	if err := c.Validate(); err != nil {
		t.Fatalf("empty upstream_mode: %v", err)
	}
	if c.UpstreamMode != "race" {
		t.Fatalf("empty upstream_mode defaulted to %q, want race", c.UpstreamMode)
	}
	c.UpstreamMode = "sequential"
	if err := c.Validate(); err != nil {
		t.Fatalf("sequential upstream_mode: %v", err)
	}
	if c.UpstreamMode != "sequential" {
		t.Fatalf("sequential upstream_mode was rewritten to %q", c.UpstreamMode)
	}
	c.UpstreamMode = "parallel"
	if err := c.Validate(); err == nil {
		t.Fatal("unsupported upstream_mode accepted")
	}
}

// TestPerfTunablesDefaults verifies the performance tunables ship with sane
// defaults: the L1 cache on (512 entries/shard) and a 256-entry log batch.
func TestPerfTunablesDefaults(t *testing.T) {
	c := Default()
	if c.Cache.L1Entries != 4096 {
		t.Errorf("cache.l1_entries = %d, want default 4096", c.Cache.L1Entries)
	}
	if c.Log.BatchSize != 256 {
		t.Errorf("log.batch_size = %d, want default 256", c.Log.BatchSize)
	}
	if c.Cache.ServeStale != 5*time.Minute {
		t.Errorf("cache.serve_stale = %v, want default 5m", c.Cache.ServeStale)
	}
	if !c.Cache.Prefetch {
		t.Error("cache.prefetch should default to true")
	}
	// Latency-knob defaults: failure caching defaults to a short 5s window
	// (shorter than negative_ttl so a recovery is visible quickly, not
	// shadowed by a minute of cached SERVFAIL) and the recursive resolver
	// uses its built-in per-server timeout.
	if c.Cache.FailureTTL != 5*time.Second {
		t.Errorf("cache.failure_ttl = %v, want default 5s", c.Cache.FailureTTL)
	}
	if c.Recursive.ServerTimeout != 0 {
		t.Errorf("recursive.server_timeout = %v, want 0 (built-in default)", c.Recursive.ServerTimeout)
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
	c.Cache.ServeStale = -time.Minute
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "serve_stale") {
		t.Errorf("err = %v, want negative cache.serve_stale rejected", err)
	}
	c = validBase()
	c.Log.BatchSize = -1
	if err := c.Validate(); err == nil {
		t.Error("negative log.batch_size accepted")
	}
	c = validBase()
	c.Cache.FailureTTL = -time.Minute
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "failure_ttl") {
		t.Errorf("err = %v, want negative cache.failure_ttl rejected", err)
	}
	c = validBase()
	c.Recursive.ServerTimeout = -time.Second
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "server_timeout") {
		t.Errorf("err = %v, want negative recursive.server_timeout rejected", err)
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

func TestValidateRateLimitAutoBlock(t *testing.T) {
	c := validBase()
	c.RateLimit = RateLimitConfig{Enabled: true, QPS: 10, Burst: 20, AutoBlock: true, BlockAfter: 3, BlockFor: 10 * time.Minute}
	if err := c.Validate(); err != nil {
		t.Fatalf("valid auto_block config rejected: %v", err)
	}
	c.RateLimit.BlockAfter = 0
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "block_after") {
		t.Fatalf("err = %v, want block_after error", err)
	}
	c = validBase()
	c.RateLimit = RateLimitConfig{Enabled: true, QPS: 10, Burst: 20, AutoBlock: true, BlockAfter: 3, BlockFor: 0}
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "block_for") {
		t.Fatalf("err = %v, want block_for error", err)
	}
	// auto_block is a layer on the token bucket: without rate limiting there
	// are no rejections to count, so the config must say so explicitly.
	c = validBase()
	c.RateLimit = RateLimitConfig{AutoBlock: true, BlockAfter: 3, BlockFor: 10 * time.Minute} // Enabled stays false
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "auto_block") {
		t.Fatalf("err = %v, want auto_block-requires-enabled error", err)
	}
}

func TestValidateGeoBlock(t *testing.T) {
	c := validBase()
	c.GeoBlock = GeoBlockConfig{
		Enabled:   true,
		Countries: []string{"ru", "CN"},
		Allowlist: []string{"192.168.1.0/24", "10.0.0.5"},
	}
	if err := c.Validate(); err != nil {
		t.Fatalf("valid geo_block rejected: %v", err)
	}
	if c.GeoBlock.Countries[0] != "RU" {
		t.Errorf("country normalized to %q, want RU", c.GeoBlock.Countries[0])
	}

	c.GeoBlock.Countries = []string{"Russia"}
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "alpha-2") {
		t.Fatalf("err = %v, want alpha-2 error", err)
	}

	c = validBase()
	c.GeoBlock = GeoBlockConfig{Enabled: true, Countries: []string{"RU"}, Allowlist: []string{"not-an-ip"}}
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "allowlist") {
		t.Fatalf("err = %v, want allowlist error", err)
	}

	c = validBase()
	c.GeoBlock = GeoBlockConfig{Enabled: true, Countries: []string{"RU"}, BaseURL: "ftp://example.com/geo"}
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "base_url") {
		t.Fatalf("err = %v, want base_url error", err)
	}

	c = validBase()
	c.GeoBlock = GeoBlockConfig{Enabled: true, Countries: []string{"RU"}, AutoUpdate: -time.Hour}
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "auto_update") {
		t.Fatalf("err = %v, want auto_update error", err)
	}
}

func TestValidateGeoBlockIPsAndHoneypots(t *testing.T) {
	c := validBase()
	c.GeoBlock = GeoBlockConfig{
		Enabled:   true,
		Countries: []string{"RU"},
		IPs:       []string{"38.11.106.3", "203.0.113.0/24", "2001:db8::/32"},
		Honeypots: []string{"Trap.Example.com.", "trap2.example.com"},
	}
	if err := c.Validate(); err != nil {
		t.Fatalf("valid ips/honeypots rejected: %v", err)
	}
	if c.GeoBlock.Honeypots[0] != "trap.example.com" {
		t.Errorf("honeypot normalized to %q, want trap.example.com", c.GeoBlock.Honeypots[0])
	}

	c = validBase()
	c.GeoBlock = GeoBlockConfig{Enabled: true, Countries: []string{"RU"}, IPs: []string{"not-an-ip"}}
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "geo_block.ips") {
		t.Fatalf("err = %v, want geo_block.ips error", err)
	}

	c = validBase()
	c.GeoBlock = GeoBlockConfig{Enabled: true, Countries: []string{"RU"}, Honeypots: []string{"has space.com"}}
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "honeypots") {
		t.Fatalf("err = %v, want honeypots error", err)
	}
}

func TestGeoAutoUpdateDefault(t *testing.T) {
	if d := Default().GeoBlock.AutoUpdate; d != 168*time.Hour {
		t.Errorf("geo_block.auto_update default = %v, want 168h (weekly)", d)
	}
}

// TestWarmerDefaults verifies the cache warmer ships off with sane tunables:
// off by default (warming generates upstream traffic), a 15m interval over a
// 24h lookback, capped at 5000 domains per pass with 8-way concurrency.
func TestWarmerDefaults(t *testing.T) {
	c := Default()
	if c.Warmer.Enabled {
		t.Error("warmer.enabled should default to false (off = no upstream traffic)")
	}
	if c.Warmer.Interval != 15*time.Minute {
		t.Errorf("warmer.interval = %v, want default 15m", c.Warmer.Interval)
	}
	if c.Warmer.Lookback != 24*time.Hour {
		t.Errorf("warmer.lookback = %v, want default 24h", c.Warmer.Lookback)
	}
	if c.Warmer.MaxDomains != 5000 {
		t.Errorf("warmer.max_domains = %d, want default 5000", c.Warmer.MaxDomains)
	}
	if c.Warmer.Concurrency != 8 {
		t.Errorf("warmer.concurrency = %d, want default 8", c.Warmer.Concurrency)
	}
}

// TestWarmerValidation verifies negative warmer values are rejected.
func TestWarmerValidation(t *testing.T) {
	c := validBase()
	c.Warmer = WarmerConfig{Interval: -time.Minute}
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "warmer.interval") {
		t.Errorf("err = %v, want negative warmer.interval rejected", err)
	}
	c = validBase()
	c.Warmer = WarmerConfig{Lookback: -time.Hour}
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "warmer.lookback") {
		t.Errorf("err = %v, want negative warmer.lookback rejected", err)
	}
	c = validBase()
	c.Warmer = WarmerConfig{MaxDomains: -1}
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "warmer.max_domains") {
		t.Errorf("err = %v, want negative warmer.max_domains rejected", err)
	}
	c = validBase()
	c.Warmer = WarmerConfig{Concurrency: -1}
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "warmer.concurrency") {
		t.Errorf("err = %v, want negative warmer.concurrency rejected", err)
	}
}

// TestWarmerValid verifies a fully-configured warmer is accepted.
func TestWarmerValid(t *testing.T) {
	c := validBase()
	c.Warmer = WarmerConfig{Enabled: true, Interval: 5 * time.Minute, Lookback: time.Hour, MaxDomains: 100, Concurrency: 4}
	if err := c.Validate(); err != nil {
		t.Fatalf("valid warmer config rejected: %v", err)
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
