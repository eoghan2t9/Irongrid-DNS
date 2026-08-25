package acme

import "testing"

func TestNewDNSProvider(t *testing.T) {
	t.Parallel()
	if p, err := NewDNSProvider("", DNSProviderConfig{}); err != nil || p != nil {
		t.Fatalf("empty provider = %v, %v; want nil,nil", p, err)
	}
	if _, err := NewDNSProvider("cloudflare", DNSProviderConfig{CloudflareToken: "tok"}); err != nil {
		t.Fatalf("cloudflare: %v", err)
	}
	if _, err := NewDNSProvider("cloudflare", DNSProviderConfig{}); err == nil {
		t.Fatal("cloudflare without token: expected error")
	}
	if _, err := NewDNSProvider("digitalocean", DNSProviderConfig{DigitalOceanToken: "tok"}); err != nil {
		t.Fatalf("digitalocean: %v", err)
	}
	if _, err := NewDNSProvider("digitalocean", DNSProviderConfig{}); err == nil {
		t.Fatal("digitalocean without token: expected error")
	}
	if _, err := NewDNSProvider("hetzner", DNSProviderConfig{HetznerToken: "tok"}); err != nil {
		t.Fatalf("hetzner: %v", err)
	}
	if _, err := NewDNSProvider("hetzner", DNSProviderConfig{}); err == nil {
		t.Fatal("hetzner without token: expected error")
	}
	if _, err := NewDNSProvider("godaddy", DNSProviderConfig{GoDaddyKey: "k", GoDaddySecret: "s"}); err != nil {
		t.Fatalf("godaddy: %v", err)
	}
	if _, err := NewDNSProvider("godaddy", DNSProviderConfig{GoDaddyKey: "k"}); err == nil {
		t.Fatal("godaddy without secret: expected error")
	}
	if _, err := NewDNSProvider("route53", DNSProviderConfig{AWSAccessKeyID: "a", AWSSecretAccessKey: "s"}); err != nil {
		t.Fatalf("route53: %v", err)
	}
	if _, err := NewDNSProvider("route53", DNSProviderConfig{AWSAccessKeyID: "a"}); err == nil {
		t.Fatal("route53 without secret key: expected error")
	}
	if _, err := NewDNSProvider("nonsense", DNSProviderConfig{}); err == nil {
		t.Fatal("nonsense: expected unsupported error")
	}
}
