// DNS-01 challenge providers. A provider creates and later removes the
// _acme-challenge.<domain> TXT record that proves control of the domain, so
// certificates can be issued without opening an inbound HTTP port.
package acme

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// DNSProvider is implemented by DNS API integrations. The value handed to
// Present is the base64url SHA-256 digest that must be placed in the
// _acme-challenge.<domain> TXT record.
type DNSProvider interface {
	// Present creates the TXT record for domain. It should return once the
	// record is live (Cloudflare API writes are immediately visible).
	Present(ctx context.Context, domain, value string) error
	// CleanUp removes the TXT record created by Present.
	CleanUp(ctx context.Context, domain, value string) error
}

// DNSProviderConfig carries the credentials for every supported provider.
// Only the fields for the configured provider are required.
type DNSProviderConfig struct {
	CloudflareToken   string
	DigitalOceanToken string
	HetznerToken      string
	GoDaddyKey        string
	GoDaddySecret     string
	AWSAccessKeyID    string
	AWSSecretAccessKey string
}

// SupportedProviders lists the DNS-01 providers this build can issue through.
func SupportedProviders() []string {
	return []string{"cloudflare", "digitalocean", "hetzner", "godaddy", "route53"}
}

// NewDNSProvider builds a provider by name. Unsupported names return an error
// so a bad config fails loudly at startup rather than at renewal time.
func NewDNSProvider(name string, cfg DNSProviderConfig, wait time.Duration) (DNSProvider, error) {
	switch name {
	case "":
		return nil, nil
	case "cloudflare":
		if cfg.CloudflareToken == "" {
			return nil, fmt.Errorf("acme: cloudflare provider requires cloudflare_token")
		}
		return &cloudflareProvider{token: cfg.CloudflareToken, wait: wait, hc: httpClient()}, nil
	case "digitalocean":
		if cfg.DigitalOceanToken == "" {
			return nil, fmt.Errorf("acme: digitalocean provider requires digitalocean_token")
		}
		return &digitalOceanProvider{token: cfg.DigitalOceanToken, wait: wait, hc: httpClient()}, nil
	case "hetzner":
		if cfg.HetznerToken == "" {
			return nil, fmt.Errorf("acme: hetzner provider requires hetzner_token")
		}
		return &hetznerProvider{token: cfg.HetznerToken, wait: wait, hc: httpClient()}, nil
	case "godaddy":
		if cfg.GoDaddyKey == "" || cfg.GoDaddySecret == "" {
			return nil, fmt.Errorf("acme: godaddy provider requires godaddy_key and godaddy_secret")
		}
		return &goDaddyProvider{key: cfg.GoDaddyKey, secret: cfg.GoDaddySecret, wait: wait, hc: httpClient()}, nil
	case "route53":
		if cfg.AWSAccessKeyID == "" || cfg.AWSSecretAccessKey == "" {
			return nil, fmt.Errorf("acme: route53 provider requires aws_access_key_id and aws_secret_access_key")
		}
		return &route53Provider{accessKey: cfg.AWSAccessKeyID, secretKey: cfg.AWSSecretAccessKey, wait: wait, hc: httpClient()}, nil
	default:
		return nil, fmt.Errorf("acme: unsupported dns-01 provider %q (supported: %s)", name, strings.Join(SupportedProviders(), ", "))
	}
}

// ---- Cloudflare ----

// cloudflareProvider manages TXT records through the Cloudflare API v4.
// Requires an API token with Zone:DNS:Edit permission for the zone.
type cloudflareProvider struct {
	token string
	wait  time.Duration // propagation wait applied after Present
	hc    *http.Client  // dedicated client so renewals can't hang on a stuck API call
}

// cfAPI is a var (not const) so tests can point the provider at a fake API.
var cfAPI = "https://api.cloudflare.com/client/v4"

type cfResponse struct {
	Success bool            `json:"success"`
	Errors  []cfAPIError    `json:"errors"`
	Result  json.RawMessage `json:"result"`
}

type cfAPIError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type cfZone struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type cfDNSRecord struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Type    string `json:"type"`
	Content string `json:"content"`
}

func (p *cloudflareProvider) do(ctx context.Context, method, path string, body any, out any) error {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, cfAPI+path, rd)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+p.token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := p.hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	var cr cfResponse
	if err := json.Unmarshal(raw, &cr); err != nil {
		return fmt.Errorf("cloudflare: bad API response (%d): %s", resp.StatusCode, truncate(string(raw), 200))
	}
	if !cr.Success {
		msg := "unknown error"
		if len(cr.Errors) > 0 {
			parts := make([]string, 0, len(cr.Errors))
			for _, e := range cr.Errors {
				parts = append(parts, e.Message)
			}
			msg = strings.Join(parts, "; ")
		}
		return fmt.Errorf("cloudflare: API error (%d): %s", resp.StatusCode, msg)
	}
	if out != nil && len(cr.Result) > 0 {
		return json.Unmarshal(cr.Result, out)
	}
	return nil
}

// findZone returns the zone that contains domain, walking up subdomain labels
// until a matching Cloudflare zone is found.
func (p *cloudflareProvider) findZone(ctx context.Context, domain string) (string, error) {
	labels := strings.Split(strings.ToLower(domain), ".")
	for i := 0; i < len(labels)-1; i++ {
		candidate := strings.Join(labels[i:], ".")
		var zones []cfZone
		// per_page=50: the API defaults to 20 zones/page, which would miss
		// the target zone for accounts with many zones.
		if err := p.do(ctx, http.MethodGet, "/zones?name="+candidate+"&status=active&per_page=50", nil, &zones); err != nil {
			return "", err
		}
		if len(zones) > 0 {
			return zones[0].ID, nil
		}
	}
	return "", fmt.Errorf("cloudflare: no active zone found for %s (is the domain in your account?)", domain)
}

func challengeRecordName(domain string) string {
	// Wildcard authz identifiers arrive as "example.com" with the wildcard
	// flag set; strip any "*.", then prefix the challenge label.
	d := strings.TrimPrefix(strings.ToLower(domain), "*.")
	return "_acme-challenge." + d
}

func (p *cloudflareProvider) Present(ctx context.Context, domain, value string) error {
	zoneID, err := p.findZone(ctx, domain)
	if err != nil {
		return err
	}
	name := challengeRecordName(domain)
	body := map[string]any{
		"type":    "TXT",
		"name":    name,
		"content": value,
		"ttl":     120,
	}
	var rec cfDNSRecord
	if err := p.do(ctx, http.MethodPost, "/zones/"+zoneID+"/dns_records", body, &rec); err != nil {
		return err
	}
	if rec.ID == "" {
		return fmt.Errorf("cloudflare: no record id returned for %s", name)
	}
	if p.wait > 0 {
		select {
		case <-time.After(p.wait):
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return nil
}

func (p *cloudflareProvider) CleanUp(ctx context.Context, domain, value string) error {
	zoneID, err := p.findZone(ctx, domain)
	if err != nil {
		return err
	}
	name := challengeRecordName(domain)
	var records []cfDNSRecord
	// List TXT records for the challenge name and delete the matching ones
	// (the API may paginate, but challenge records are tiny and fresh).
	if err := p.do(ctx, http.MethodGet, "/zones/"+zoneID+"/dns_records?type=TXT&name="+name, nil, &records); err != nil {
		return err
	}
	for _, r := range records {
		if r.Content != value {
			continue
		}
		if err := p.do(ctx, http.MethodDelete, "/zones/"+zoneID+"/dns_records/"+r.ID, nil, nil); err != nil {
			return err
		}
	}
	return nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
