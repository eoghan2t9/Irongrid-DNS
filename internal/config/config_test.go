package config

import (
	"strings"
	"testing"
	"time"
)

// TestValidateUpstreamMode verifies the resolution strategy accepts race and
// sequential, defaults an empty value to race, and rejects anything else.
func TestValidateUpstreamMode(t *testing.T) {
	t.Parallel()
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
	t.Parallel()
	c := Default()
	if c.Cache.L1Entries != 0 {
		t.Errorf("cache.l1_entries = %d, want default 0 (auto-size from available RAM)", c.Cache.L1Entries)
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
	t.Parallel()
	c := validBase()
	c.Cache.L1Entries = -2
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "l1_entries") {
		t.Errorf("err = %v, want out-of-range cache.l1_entries rejected", err)
	}
	// -1 (disable) and 0 (auto) are both valid.
	for _, v := range []int{-1, 0} {
		c = validBase()
		c.Cache.L1Entries = v
		if err := c.Validate(); err != nil {
			t.Errorf("cache.l1_entries = %d rejected: %v", v, err)
		}
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

func TestUDPSocketsValidation(t *testing.T) {
	t.Parallel()
	c := validBase()
	c.Server.UDPSockets = -1
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "udp_sockets") {
		t.Errorf("err = %v, want negative server.udp_sockets rejected", err)
	}
	c = validBase()
	c.Server.UDPSockets = 8 // explicit multi-socket binding is fine
	if err := c.Validate(); err != nil {
		t.Errorf("valid server.udp_sockets rejected: %v", err)
	}
}

func TestUDPWorkersValidation(t *testing.T) {
	t.Parallel()
	c := validBase()
	c.Server.UDPWorkers = -1
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "udp_workers") {
		t.Errorf("err = %v, want negative server.udp_workers rejected", err)
	}
	c = validBase()
	c.Server.UDPWorkers = 64 // explicit worker count is fine
	if err := c.Validate(); err != nil {
		t.Errorf("valid server.udp_workers rejected: %v", err)
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
	t.Parallel()
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
	t.Parallel()
	c := validBase()
	c.Server.WebRedirect = true // web_tls stays false
	err := c.Validate()
	if err == nil || !strings.Contains(err.Error(), "web_redirect requires") {
		t.Fatalf("err = %v, want web_redirect-requires-web_tls", err)
	}
}

func TestValidateWebSharesDoHPort(t *testing.T) {
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
	c := validBase()
	c.Server.WebTLS = true
	c.Server.WebRedirect = true
	c.Server.WebRedirectPort = 8080 // same as WebListen port
	err := c.Validate()
	if err == nil || !strings.Contains(err.Error(), "collides") {
		t.Fatalf("err = %v, want port collision error", err)
	}
}

func TestValidateTrustedProxies(t *testing.T) {
	t.Parallel()
	c := validBase()
	c.Server.TrustedProxies = []string{"203.0.113.7", "198.51.100.0/24", " 2001:db8::1 "}
	if err := c.Validate(); err != nil {
		t.Fatalf("valid trusted_proxies rejected: %v", err)
	}
	c.Server.TrustedProxies = []string{"203.0.113.7", "not-an-ip-or-cidr"}
	err := c.Validate()
	if err == nil || !strings.Contains(err.Error(), "trusted_proxies[1]") {
		t.Fatalf("err = %v, want trusted_proxies[1] invalid-entry error", err)
	}
	c.Server.TrustedProxies = []string{" "}
	err = c.Validate()
	if err == nil || !strings.Contains(err.Error(), "empty entry") {
		t.Fatalf("err = %v, want empty trusted_proxies entry error", err)
	}
}

func TestValidateXFFHopLimit(t *testing.T) {
	t.Parallel()
	c := validBase()
	c.Server.XFFHopLimit = 0 // 0 selects the default
	if err := c.Validate(); err != nil {
		t.Fatalf("xff_hop_limit 0 rejected: %v", err)
	}
	if c.Server.XFFHopLimit != 1 {
		t.Errorf("xff_hop_limit = %d after validation, want normalized 1", c.Server.XFFHopLimit)
	}
	c.Server.XFFHopLimit = -1
	err := c.Validate()
	if err == nil || !strings.Contains(err.Error(), "xff_hop_limit") {
		t.Fatalf("err = %v, want negative xff_hop_limit error", err)
	}
}

func TestValidateDNS01Cloudflare(t *testing.T) {
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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

func TestValidateNXGuard(t *testing.T) {
	t.Parallel()
	c := validBase()
	c.RateLimit = RateLimitConfig{
		Enabled: false, // the NXDOMAIN guard is independent of the token bucket
		NXGuard: NXGuardConfig{Enabled: true, Threshold: 30, Window: 30 * time.Second, BlockFor: 10 * time.Minute},
	}
	if err := c.Validate(); err != nil {
		t.Fatalf("valid nxdomain_guard config rejected: %v", err)
	}
	c.RateLimit.NXGuard.Threshold = 0
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "threshold") {
		t.Fatalf("err = %v, want nxdomain_guard.threshold error", err)
	}
	c = validBase()
	c.RateLimit.NXGuard = NXGuardConfig{Enabled: true, Threshold: 10, Window: 0, BlockFor: time.Minute}
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "window") {
		t.Fatalf("err = %v, want nxdomain_guard.window error", err)
	}
	c = validBase()
	c.RateLimit.NXGuard = NXGuardConfig{Enabled: true, Threshold: 10, Window: time.Minute, BlockFor: 0}
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "block_for") {
		t.Fatalf("err = %v, want nxdomain_guard.block_for error", err)
	}
	// Disabled guard with zeroed values must pass (the defaults are applied
	// at construction, not validation).
	c = validBase()
	c.RateLimit.NXGuard = NXGuardConfig{}
	if err := c.Validate(); err != nil {
		t.Fatalf("disabled nxdomain_guard rejected: %v", err)
	}
}

func TestValidateConnCaps(t *testing.T) {
	t.Parallel()
	c := validBase()
	c.Server.MaxTCPConnsPerIP = 32
	c.Server.MaxHTTPConnsPerIP = 64
	if err := c.Validate(); err != nil {
		t.Fatalf("valid conn caps rejected: %v", err)
	}
	c.Server.MaxTCPConnsPerIP = -1
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "max_tcp_conns_per_ip") {
		t.Fatalf("err = %v, want max_tcp_conns_per_ip error", err)
	}
	c = validBase()
	c.Server.MaxHTTPConnsPerIP = -1
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "max_http_conns_per_ip") {
		t.Fatalf("err = %v, want max_http_conns_per_ip error", err)
	}
}

func TestValidateGeoBlock(t *testing.T) {
	t.Parallel()
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

func TestValidateGeoBlockASNs(t *testing.T) {
	t.Parallel()
	c := validBase()
	c.GeoBlock = GeoBlockConfig{
		Enabled:    true,
		AllowASNs:  []string{"as13335", "4134", " AS4294967295 "},
		BlockASNs:  []string{"AS3257"},
		ASNBaseURL: "https://example.com/data",
	}
	if err := c.Validate(); err != nil {
		t.Fatalf("valid ASN geo_block rejected: %v", err)
	}
	if c.GeoBlock.AllowASNs[0] != "AS13335" || c.GeoBlock.AllowASNs[1] != "AS4134" || c.GeoBlock.AllowASNs[2] != "AS4294967295" {
		t.Errorf("allow_asns not normalized: %v", c.GeoBlock.AllowASNs)
	}
	if c.GeoBlock.BlockASNs[0] != "AS3257" {
		t.Errorf("block_asns not normalized: %v", c.GeoBlock.BlockASNs)
	}

	c = validBase()
	c.GeoBlock = GeoBlockConfig{Enabled: true, AllowASNs: []string{"AS13X35"}}
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "geo_block.allow_asns") {
		t.Fatalf("err = %v, want geo_block.allow_asns error", err)
	}

	c = validBase()
	c.GeoBlock = GeoBlockConfig{Enabled: true, BlockASNs: []string{"AS0"}}
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "geo_block.block_asns") {
		t.Fatalf("err = %v, want geo_block.block_asns error", err)
	}

	c = validBase()
	c.GeoBlock = GeoBlockConfig{Enabled: true, ASNBaseURL: "ftp://example.com/data"}
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "asn_base_url") {
		t.Fatalf("err = %v, want asn_base_url error", err)
	}
}

func TestValidateClientGroupASNs(t *testing.T) {
	t.Parallel()
	// A group may match purely by ASN (no CIDRs at all).
	c := validBase()
	c.ClientGroups = []ClientGroup{
		{ID: "cloud", Name: "Cloud egress", Enabled: true, ASNs: []string{"as13335", "AS15169"}},
	}
	if err := c.Validate(); err != nil {
		t.Fatalf("ASN-only group rejected: %v", err)
	}
	if c.ClientGroups[0].ASNs[0] != "AS13335" || c.ClientGroups[0].ASNs[1] != "AS15169" {
		t.Errorf("group ASNs not normalized: %v", c.ClientGroups[0].ASNs)
	}
	// Mixed CIDR + ASN matching is fine too.
	c = validBase()
	c.ClientGroups = []ClientGroup{
		{ID: "kids", Enabled: true, CIDRs: []string{"10.0.0.0/8"}, ASNs: []string{"AS3257"}},
	}
	if err := c.Validate(); err != nil {
		t.Fatalf("CIDR+ASN group rejected: %v", err)
	}
	// A bad ASN is rejected by name.
	c = validBase()
	c.ClientGroups = []ClientGroup{{ID: "x", Enabled: true, ASNs: []string{"AS13X"}}}
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "asns[0]") {
		t.Fatalf("err = %v, want asns[0] error", err)
	}
	// Neither CIDRs nor ASNs is still an error.
	c = validBase()
	c.ClientGroups = []ClientGroup{{ID: "x", Enabled: true}}
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "CIDR or ASN") {
		t.Fatalf("err = %v, want CIDR-or-ASN error", err)
	}
}

func TestValidateGeoBlockIPsAndHoneypots(t *testing.T) {
	t.Parallel()
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

func TestValidateGeoBlockHoneypotUDPBlock(t *testing.T) {
	t.Parallel()
	c := validBase()
	c.GeoBlock = GeoBlockConfig{Enabled: true, Countries: []string{"RU"}, HoneypotUDPBlock: 10 * time.Minute}
	c.RateLimit = RateLimitConfig{Enabled: true, QPS: 10, Burst: 20}
	if err := c.Validate(); err != nil {
		t.Fatalf("valid honeypot_udp_block config rejected: %v", err)
	}

	// The bounded UDP block runs on the rate limiter — without it the knob
	// would silently never fire.
	c = validBase()
	c.GeoBlock = GeoBlockConfig{Enabled: true, Countries: []string{"RU"}, HoneypotUDPBlock: 10 * time.Minute}
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "rate_limit.enabled") {
		t.Fatalf("err = %v, want honeypot_udp_block-requires-rate-limit error", err)
	}

	c = validBase()
	c.GeoBlock = GeoBlockConfig{Enabled: true, Countries: []string{"RU"}, HoneypotUDPBlock: -time.Minute}
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "honeypot_udp_block") {
		t.Fatalf("err = %v, want honeypot_udp_block >= 0 error", err)
	}
}

func TestGeoAutoUpdateDefault(t *testing.T) {
	t.Parallel()
	if d := Default().GeoBlock.AutoUpdate; d != 168*time.Hour {
		t.Errorf("geo_block.auto_update default = %v, want 168h (weekly)", d)
	}
}

// TestWarmerDefaults verifies the cache warmer ships off with sane tunables:
// off by default (warming generates upstream traffic), a 15m interval over a
// 24h lookback, capped at 5000 domains per pass with 8-way concurrency.
func TestWarmerDefaults(t *testing.T) {
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
	c := validBase()
	c.Warmer = WarmerConfig{Enabled: true, Interval: 5 * time.Minute, Lookback: time.Hour, MaxDomains: 100, Concurrency: 4}
	if err := c.Validate(); err != nil {
		t.Fatalf("valid warmer config rejected: %v", err)
	}
}

func TestValidateDNS01SupportedProviders(t *testing.T) {
	t.Parallel()
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

// dhcpBase returns a valid DHCP-enabled config for validation tests.
func dhcpBase() *Config {
	c := validBase()
	c.DHCP = DHCPConfig{
		Enabled:    true,
		Subnet:     "192.168.1.0/24",
		RangeStart: "192.168.1.100",
		RangeEnd:   "192.168.1.200",
		Gateway:    "192.168.1.1",
		DNS:        []string{"192.168.1.1"},
		LeaseTime:  24 * time.Hour,
		Domain:     "lan",
	}
	return c
}

func TestValidateDHCPValid(t *testing.T) {
	t.Parallel()
	if err := dhcpBase().Validate(); err != nil {
		t.Fatalf("valid DHCP config rejected: %v", err)
	}
}

func TestValidateDHCPRequiresRange(t *testing.T) {
	t.Parallel()
	c := dhcpBase()
	c.DHCP.RangeStart = ""
	if err := c.Validate(); err == nil {
		t.Fatal("missing range_start accepted")
	}
}

func TestValidateDHCPBadSubnet(t *testing.T) {
	t.Parallel()
	c := dhcpBase()
	c.DHCP.Subnet = "not-a-cidr"
	if err := c.Validate(); err == nil {
		t.Fatal("invalid subnet accepted")
	}
}

func TestValidateDHCPRangeOutsideSubnet(t *testing.T) {
	t.Parallel()
	c := dhcpBase()
	c.DHCP.RangeEnd = "10.9.9.9"
	if err := c.Validate(); err == nil {
		t.Fatal("range outside subnet accepted")
	}
}

func TestValidateDHCPReversedRange(t *testing.T) {
	t.Parallel()
	c := dhcpBase()
	c.DHCP.RangeStart = "192.168.1.200"
	c.DHCP.RangeEnd = "192.168.1.100"
	if err := c.Validate(); err == nil {
		t.Fatal("reversed range accepted")
	}
}

func TestValidateDHCPBadGateway(t *testing.T) {
	t.Parallel()
	c := dhcpBase()
	c.DHCP.Gateway = "203.0.113.1" // outside the subnet
	if err := c.Validate(); err == nil {
		t.Fatal("gateway outside subnet accepted")
	}
}

func TestValidateDHCPBadDNS(t *testing.T) {
	t.Parallel()
	c := dhcpBase()
	c.DHCP.DNS = []string{"not-an-ip"}
	if err := c.Validate(); err == nil {
		t.Fatal("invalid DNS entry accepted")
	}
}

func TestValidateDHCPBadDomain(t *testing.T) {
	t.Parallel()
	c := dhcpBase()
	c.DHCP.Domain = "bad domain!"
	if err := c.Validate(); err == nil {
		t.Fatal("invalid domain accepted")
	}
}

func TestValidateDHCPStaticLease(t *testing.T) {
	t.Parallel()
	// Valid static reservation passes.
	c := dhcpBase()
	c.DHCP.StaticLeases = []DHCPStaticLease{{MAC: "aa:bb:cc:dd:ee:ff", IP: "192.168.1.50", Hostname: "printer"}}
	if err := c.Validate(); err != nil {
		t.Fatalf("valid static lease rejected: %v", err)
	}
	// Static lease with no MAC/DUID rejected.
	c = dhcpBase()
	c.DHCP.StaticLeases = []DHCPStaticLease{{IP: "192.168.1.50"}}
	if err := c.Validate(); err == nil {
		t.Fatal("static lease without mac/duid accepted")
	}
	// Static lease IP outside subnet rejected.
	c = dhcpBase()
	c.DHCP.StaticLeases = []DHCPStaticLease{{MAC: "aa:bb:cc:dd:ee:ff", IP: "10.9.9.9"}}
	if err := c.Validate(); err == nil {
		t.Fatal("static lease IP outside subnet accepted")
	}
}

func TestValidateDHCPv6(t *testing.T) {
	t.Parallel()
	// Valid v6 config passes.
	c := dhcpBase()
	c.DHCP.IPv6 = true
	c.DHCP.IPv6Prefix = "fd00::/64"
	c.DHCP.IPv6RangeStart = "fd00::100"
	c.DHCP.IPv6RangeEnd = "fd00::200"
	if err := c.Validate(); err != nil {
		t.Fatalf("valid DHCPv6 config rejected: %v", err)
	}
	// v6 range outside prefix rejected.
	c = dhcpBase()
	c.DHCP.IPv6 = true
	c.DHCP.IPv6Prefix = "fd00::/64"
	c.DHCP.IPv6RangeStart = "2001:db8::1"
	c.DHCP.IPv6RangeEnd = "2001:db8::2"
	if err := c.Validate(); err == nil {
		t.Fatal("v6 range outside prefix accepted")
	}
}

// ---- upstream routes (conditional / split-horizon forwarding) ----

func TestValidateUpstreamRoutes(t *testing.T) {
	t.Parallel()
	c := validBase()
	c.UpstreamRoutes = []UpstreamRoute{
		{Domain: "lan", Upstreams: []string{"udp://192.168.1.1:53"}},
		{Domain: "corp.example.com.", Upstreams: []string{"tls://10.0.0.2:853", "https://dns.corp.example.com/dns-query"}},
	}
	if err := c.Validate(); err != nil {
		t.Fatalf("valid routes rejected: %v", err)
	}
	// Domains are normalized: the trailing dot is stripped.
	if c.UpstreamRoutes[1].Domain != "corp.example.com" {
		t.Fatalf("route domain not normalized: %q", c.UpstreamRoutes[1].Domain)
	}
}

func TestValidateUpstreamRoutesRequireUpstreams(t *testing.T) {
	t.Parallel()
	c := validBase()
	c.UpstreamRoutes = []UpstreamRoute{{Domain: "lan"}}
	if err := c.Validate(); err == nil {
		t.Fatal("route without upstreams accepted")
	}
}

func TestValidateUpstreamRoutesRejectEmptyEntry(t *testing.T) {
	t.Parallel()
	c := validBase()
	c.UpstreamRoutes = []UpstreamRoute{{Domain: "lan", Upstreams: []string{"udp://192.168.1.1:53", ""}}}
	if err := c.Validate(); err == nil {
		t.Fatal("route with an empty upstream accepted")
	}
}

func TestValidateUpstreamRoutesRejectBadDomain(t *testing.T) {
	t.Parallel()
	c := validBase()
	c.UpstreamRoutes = []UpstreamRoute{{Domain: "bad domain!", Upstreams: []string{"udp://192.168.1.1:53"}}}
	if err := c.Validate(); err == nil {
		t.Fatal("route with an invalid domain accepted")
	}
}
