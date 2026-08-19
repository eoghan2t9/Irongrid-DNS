// DNS-01 challenge providers. A provider creates and later removes the
// _acme-challenge.<domain> TXT record that proves control of the domain, so
// certificates can be issued without opening an inbound HTTP port.
//
// Every provider here delegates to go-acme/lego's providers/dns/* packages
// instead of a hand-rolled API client: lego's implementations handle zone
// discovery via real DNS lookups (not label-walking guesses), API edge cases,
// and are exercised across a much larger population of ACME clients than
// this project could maintain alone.
package acme

import (
	"fmt"
	"strings"

	"github.com/go-acme/lego/v4/providers/dns/cloudflare"
	"github.com/go-acme/lego/v4/providers/dns/digitalocean"
	"github.com/go-acme/lego/v4/providers/dns/godaddy"
	"github.com/go-acme/lego/v4/providers/dns/hetzner"
	"github.com/go-acme/lego/v4/providers/dns/route53"
)

// DNSProvider is implemented by DNS API integrations that can publish and
// remove the _acme-challenge TXT record for a domain. It is the same shape
// as lego's challenge.Provider, so every github.com/go-acme/lego/v4/providers/dns/*
// provider satisfies it without an adapter.
type DNSProvider interface {
	// Present creates the TXT record for domain from the challenge token and
	// key authorization.
	Present(domain, token, keyAuth string) error
	// CleanUp removes the TXT record created by Present.
	CleanUp(domain, token, keyAuth string) error
}

// DNSProviderConfig carries the credentials for every supported provider.
// Only the fields for the configured provider are required.
type DNSProviderConfig struct {
	CloudflareToken    string
	DigitalOceanToken  string
	HetznerToken       string
	GoDaddyKey         string
	GoDaddySecret      string
	AWSAccessKeyID     string
	AWSSecretAccessKey string
}

// SupportedProviders lists the DNS-01 providers this build can issue through.
func SupportedProviders() []string {
	return []string{"cloudflare", "digitalocean", "hetzner", "godaddy", "route53"}
}

// NewDNSProvider builds a provider by name. Unsupported names return an error
// so a bad config fails loudly at startup rather than at renewal time.
func NewDNSProvider(name string, cfg DNSProviderConfig) (DNSProvider, error) {
	switch name {
	case "":
		return nil, nil
	case "cloudflare":
		if cfg.CloudflareToken == "" {
			return nil, fmt.Errorf("acme: cloudflare provider requires cloudflare_token")
		}
		c := cloudflare.NewDefaultConfig()
		c.AuthToken = cfg.CloudflareToken
		return cloudflare.NewDNSProviderConfig(c)
	case "digitalocean":
		if cfg.DigitalOceanToken == "" {
			return nil, fmt.Errorf("acme: digitalocean provider requires digitalocean_token")
		}
		c := digitalocean.NewDefaultConfig()
		c.AuthToken = cfg.DigitalOceanToken
		return digitalocean.NewDNSProviderConfig(c)
	case "hetzner":
		if cfg.HetznerToken == "" {
			return nil, fmt.Errorf("acme: hetzner provider requires hetzner_token")
		}
		c := hetzner.NewDefaultConfig()
		c.APIToken = cfg.HetznerToken
		return hetzner.NewDNSProviderConfig(c)
	case "godaddy":
		if cfg.GoDaddyKey == "" || cfg.GoDaddySecret == "" {
			return nil, fmt.Errorf("acme: godaddy provider requires godaddy_key and godaddy_secret")
		}
		c := godaddy.NewDefaultConfig()
		c.APIKey = cfg.GoDaddyKey
		c.APISecret = cfg.GoDaddySecret
		return godaddy.NewDNSProviderConfig(c)
	case "route53":
		if cfg.AWSAccessKeyID == "" || cfg.AWSSecretAccessKey == "" {
			return nil, fmt.Errorf("acme: route53 provider requires aws_access_key_id and aws_secret_access_key")
		}
		c := route53.NewDefaultConfig()
		c.AccessKeyID = cfg.AWSAccessKeyID
		c.SecretAccessKey = cfg.AWSSecretAccessKey
		return route53.NewDNSProviderConfig(c)
	default:
		return nil, fmt.Errorf("acme: unsupported dns-01 provider %q (supported: %s)", name, strings.Join(SupportedProviders(), ", "))
	}
}
