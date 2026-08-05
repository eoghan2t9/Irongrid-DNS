// Additional DNS-01 providers: DigitalOcean, Hetzner, GoDaddy and AWS Route53.
// All use the standard library only — no external SDKs.
package acme

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// httpClient returns a client with a sane timeout so renewals can't hang.
func httpClient() *http.Client { return &http.Client{Timeout: 30 * time.Second} }

// zoneApex walks up the labels of domain and returns the first that matches,
// calling probe(name) which reports whether name is a zone the provider owns.
func zoneApex(domain string, probe func(string) (bool, error)) (string, error) {
	labels := strings.Split(strings.ToLower(strings.TrimPrefix(domain, "*.")), ".")
	for i := 0; i < len(labels)-1; i++ {
		candidate := strings.Join(labels[i:], ".")
		ok, err := probe(candidate)
		if err != nil {
			return "", err
		}
		if ok {
			return candidate, nil
		}
	}
	return "", fmt.Errorf("no zone found for %s (is the domain in your account?)", domain)
}

// ---- DigitalOcean ----

// digitalOceanProvider uses the DigitalOcean v2 domains API (bearer token).
type digitalOceanProvider struct {
	token string
	wait  time.Duration
	hc    *http.Client
}

var doAPI = "https://api.digitalocean.com/v2"

type doRecord struct {
	ID   int    `json:"id"`
	Name string `json:"name"`
	Data string `json:"data"`
	Type string `json:"type"`
}

func (p *digitalOceanProvider) request(ctx context.Context, method, path string, body any, out any) error {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, doAPI+path, rd)
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
	if resp.StatusCode >= 300 {
		raw, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("digitalocean: API error (%d): %s", resp.StatusCode, truncate(string(raw), 200))
	}
	if out != nil {
		return json.NewDecoder(resp.Body).Decode(out)
	}
	return nil
}

func (p *digitalOceanProvider) Present(ctx context.Context, domain, value string) error {
	zone, err := zoneApex(domain, func(name string) (bool, error) {
		var z struct {
			Domain map[string]any `json:"domain"`
		}
		err := p.request(ctx, http.MethodGet, "/domains/"+name, nil, &z)
		if err != nil {
			// 404 = not a zone in this account; any other error is fatal.
			if strings.Contains(err.Error(), "(404)") {
				return false, nil
			}
			return false, err
		}
		return z.Domain != nil, nil
	})
	if err != nil {
		return err
	}
	name := strings.TrimSuffix(strings.TrimPrefix(domain, "*."), "."+zone)
	if name == domain {
		name = "_acme-challenge"
	} else {
		name = "_acme-challenge." + name
	}
	var out struct {
		Record doRecord `json:"domain_record"`
	}
	if err := p.request(ctx, http.MethodPost, "/domains/"+zone+"/records", map[string]any{
		"type": "TXT", "name": name, "data": value, "ttl": 120,
	}, &out); err != nil {
		return err
	}
	return p.waitFor(ctx)
}

func (p *digitalOceanProvider) CleanUp(ctx context.Context, domain, value string) error {
	zone, err := zoneApex(domain, func(name string) (bool, error) {
		err := p.request(ctx, http.MethodGet, "/domains/"+name, nil, nil)
		if err != nil {
			if strings.Contains(err.Error(), "(404)") {
				return false, nil
			}
			return false, err
		}
		return true, nil
	})
	if err != nil {
		return err
	}
	var out struct {
		Records []doRecord `json:"domain_records"`
	}
	if err := p.request(ctx, http.MethodGet, "/domains/"+zone+"/records?type=TXT&per_page=200", nil, &out); err != nil {
		return err
	}
	for _, r := range out.Records {
		if r.Type == "TXT" && r.Data == value {
			if err := p.request(ctx, http.MethodDelete, fmt.Sprintf("/domains/%s/records/%d", zone, r.ID), nil, nil); err != nil {
				return err
			}
		}
	}
	return nil
}

func (p *digitalOceanProvider) waitFor(ctx context.Context) error {
	if p.wait <= 0 {
		return nil
	}
	select {
	case <-time.After(p.wait):
	case <-ctx.Done():
		return ctx.Err()
	}
	return nil
}

// ---- Hetzner ----

// hetznerProvider uses the Hetzner DNS API (Auth-API-Token header).
type hetznerProvider struct {
	token string
	wait  time.Duration
	hc    *http.Client
}

var hetznerAPI = "https://dns.hetzner.com/api/v1"

type hetznerRecord struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Value string `json:"value"`
	Type  string `json:"type"`
}

func (p *hetznerProvider) do(ctx context.Context, method, path string, body any, out any) error {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, hetznerAPI+path, rd)
	if err != nil {
		return err
	}
	req.Header.Set("Auth-API-Token", p.token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := p.hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		raw, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("hetzner: API error (%d): %s", resp.StatusCode, truncate(string(raw), 200))
	}
	if out != nil {
		return json.NewDecoder(resp.Body).Decode(out)
	}
	return nil
}

func (p *hetznerProvider) Present(ctx context.Context, domain, value string) error {
	zoneID, zoneName, err := p.findZone(ctx, domain)
	if err != nil {
		return err
	}
	// Hetzner wants the label only (zone name is separate).
	name := strings.TrimPrefix(strings.ToLower(domain), "*.")
	name = strings.TrimSuffix(name, "."+zoneName)
	if name != "" {
		name = "_acme-challenge." + name
	} else {
		name = "_acme-challenge"
	}
	var out struct {
		Record hetznerRecord `json:"record"`
	}
	if err := p.do(ctx, http.MethodPost, "/records", map[string]any{
		"zone_id": zoneID, "type": "TXT", "name": name, "value": value, "ttl": 120,
	}, &out); err != nil {
		return err
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

func (p *hetznerProvider) CleanUp(ctx context.Context, domain, value string) error {
	zoneID, _, err := p.findZone(ctx, domain)
	if err != nil {
		return err
	}
	var out struct {
		Records []hetznerRecord `json:"records"`
	}
	if err := p.do(ctx, http.MethodGet, "/records?zone_id="+zoneID+"&type=TXT", nil, &out); err != nil {
		return err
	}
	for _, r := range out.Records {
		if r.Value == value {
			if err := p.do(ctx, http.MethodDelete, "/records/"+r.ID, nil, nil); err != nil {
				return err
			}
		}
	}
	return nil
}

func (p *hetznerProvider) findZone(ctx context.Context, domain string) (id, name string, err error) {
	type zone struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}
	labels := strings.Split(strings.ToLower(strings.TrimPrefix(domain, "*")), ".")
	for i := 0; i < len(labels)-1; i++ {
		candidate := strings.Join(labels[i:], ".")
		var out struct {
			Zones []zone `json:"zones"`
		}
		if err := p.do(ctx, http.MethodGet, "/zones?search_name="+url.QueryEscape(candidate), nil, &out); err != nil {
			return "", "", err
		}
		for _, z := range out.Zones {
			if strings.EqualFold(z.Name, candidate) {
				return z.ID, z.Name, nil
			}
		}
	}
	return "", "", fmt.Errorf("hetzner: no zone found for %s", domain)
}

// ---- GoDaddy ----

// goDaddyProvider uses the GoDaddy domains API with the sso-key header.
type goDaddyProvider struct {
	key    string
	secret string
	wait   time.Duration
	hc     *http.Client
}

var godaddyAPI = "https://api.godaddy.com/v1"

func (p *goDaddyProvider) do(ctx context.Context, method, path string, body any, out any) error {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, godaddyAPI+path, rd)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "sso-key "+p.key+":"+p.secret)
	req.Header.Set("Content-Type", "application/json")
	resp, err := p.hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		raw, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("godaddy: API error (%d): %s", resp.StatusCode, truncate(string(raw), 200))
	}
	if out != nil {
		return json.NewDecoder(resp.Body).Decode(out)
	}
	return nil
}

func (p *goDaddyProvider) Present(ctx context.Context, domain, value string) error {
	zone, err := zoneApex(domain, func(name string) (bool, error) {
		var raw map[string]any
		err := p.do(ctx, http.MethodGet, "/domains/"+name, nil, &raw)
		if err != nil {
			if strings.Contains(err.Error(), "(404)") {
				return false, nil
			}
			return false, err
		}
		return true, nil
	})
	if err != nil {
		return err
	}
	// GoDaddy PUT replaces every record at the name.
	if err := p.do(ctx, http.MethodPut, "/domains/"+zone+"/records/TXT/_acme-challenge",
		[]map[string]any{{"data": value, "ttl": 600}}, nil); err != nil {
		return err
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

func (p *goDaddyProvider) CleanUp(ctx context.Context, domain, value string) error {
	zone, err := zoneApex(domain, func(name string) (bool, error) {
		var raw map[string]any
		err := p.do(ctx, http.MethodGet, "/domains/"+name, nil, &raw)
		if err != nil {
			if strings.Contains(err.Error(), "(404)") {
				return false, nil
			}
			return false, err
		}
		return true, nil
	})
	if err != nil {
		return err
	}
	return p.do(ctx, http.MethodDelete, "/domains/"+zone+"/records/TXT/_acme-challenge", nil, nil)
}

// ---- AWS Route53 ----

// route53Provider uses the Route53 ChangeResourceRecordSets API with SigV4
// signing implemented from scratch (stdlib only). Route53 is a global service,
// so the region is always us-east-1.
type route53Provider struct {
	accessKey string
	secretKey string
	wait      time.Duration
	hc        *http.Client
}

var route53API = "https://route53.amazonaws.com/2013-04-01"

const route53Service = "route53"
const route53Region = "us-east-1"

type route53ChangeRequest struct {
	XMLName    xml.Name `xml:"ChangeResourceRecordSetsRequest"`
	NS         string   `xml:"xmlns,attr"`
	ChangeBatch struct {
		Changes []struct {
			Action string `xml:"Action"`
			ResourceRecordSet struct {
				Name            string `xml:"Name"`
				Type            string `xml:"Type"`
				TTL             int    `xml:"TTL"`
				ResourceRecords []struct {
					Value string `xml:"Value"`
				} `xml:"ResourceRecords>ResourceRecord"`
			} `xml:"ResourceRecordSet"`
		} `xml:"Changes>Change"`
	} `xml:"ChangeBatch"`
}

func (p *route53Provider) sign(req *http.Request, body []byte, now time.Time) {
	amzDate := now.UTC().Format("20060102T150405Z")
	dateStamp := now.UTC().Format("20060102")

	payloadHash := sha256.Sum256(body)
	host := req.URL.Host
	canonicalHeaders := "host:" + host + "\nx-amz-date:" + amzDate + "\n"
	signedHeaders := "host;x-amz-date"

	canonicalRequest := strings.Join([]string{
		req.Method,
		req.URL.EscapedPath(),
		req.URL.RawQuery,
		canonicalHeaders,
		signedHeaders,
		hex.EncodeToString(payloadHash[:]),
	}, "\n")

	scope := dateStamp + "/" + route53Region + "/" + route53Service + "/aws4_request"
	crHash := sha256.Sum256([]byte(canonicalRequest))
	stringToSign := strings.Join([]string{
		"AWS4-HMAC-SHA256",
		amzDate,
		scope,
		hex.EncodeToString(crHash[:]),
	}, "\n")

	kDate := hmacSHA256([]byte("AWS4"+p.secretKey), dateStamp)
	kRegion := hmacSHA256(kDate, route53Region)
	kService := hmacSHA256(kRegion, route53Service)
	kSigning := hmacSHA256(kService, "aws4_request")
	signature := hex.EncodeToString(hmacSHA256(kSigning, stringToSign))

	req.Header.Set("X-Amz-Date", amzDate)
	req.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential="+p.accessKey+"/"+scope+
		", SignedHeaders="+signedHeaders+", Signature="+signature)
	req.Header.Set("X-Amz-Content-Sha256", hex.EncodeToString(payloadHash[:]))
}

func hmacSHA256(key []byte, data string) []byte {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(data))
	return h.Sum(nil)
}

func (p *route53Provider) do(ctx context.Context, method, path string, body []byte, out any) error {
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, route53API+path, rd)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/xml")
	}
	p.sign(req, body, time.Now())
	resp, err := p.hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		raw, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("route53: API error (%d): %s", resp.StatusCode, truncate(string(raw), 300))
	}
	if out != nil {
		return xml.NewDecoder(resp.Body).Decode(out)
	}
	return nil
}

// findZoneID resolves the hosted zone for domain, walking up labels until the
// API returns a matching zone. Returns the zone id without the /hostedzone/ prefix.
func (p *route53Provider) findZoneID(ctx context.Context, domain string) (string, error) {
	type hz struct {
		ID   string `xml:"Id"`
		Name string `xml:"Name"`
	}
	labels := strings.Split(strings.ToLower(strings.TrimPrefix(domain, "*")), ".")
	for i := 0; i < len(labels)-1; i++ {
		candidate := strings.Join(labels[i:], ".")
		var out struct {
			HostedZones []hz `xml:"HostedZones>HostedZone"`
		}
		q := url.QueryEscape(candidate + ".") // Route53 zone names carry a trailing dot
		if err := p.do(ctx, http.MethodGet, "/hostedzone?name="+q+"&maxitems=1", nil, &out); err != nil {
			return "", err
		}
		for _, z := range out.HostedZones {
			if strings.EqualFold(strings.TrimSuffix(z.Name, "."), candidate) {
				return strings.TrimPrefix(z.ID, "/hostedzone/"), nil
			}
		}
	}
	return "", fmt.Errorf("route53: no hosted zone found for %s", domain)
}

func (p *route53Provider) change(ctx context.Context, zoneID, domain, value, action string) error {
	fqdn := challengeRecordName(domain) + "."
	// Route53 TXT values must be quoted (double quotes inside the XML value).
	var req route53ChangeRequest
	req.NS = "https://route53.amazonaws.com/doc/2013-04-01/"
	req.ChangeBatch.Changes = make([]struct {
		Action string `xml:"Action"`
		ResourceRecordSet struct {
			Name            string `xml:"Name"`
			Type            string `xml:"Type"`
			TTL             int    `xml:"TTL"`
			ResourceRecords []struct {
				Value string `xml:"Value"`
			} `xml:"ResourceRecords>ResourceRecord"`
		} `xml:"ResourceRecordSet"`
	}, 1)
	req.ChangeBatch.Changes[0].Action = action
	req.ChangeBatch.Changes[0].ResourceRecordSet.Name = fqdn
	req.ChangeBatch.Changes[0].ResourceRecordSet.Type = "TXT"
	req.ChangeBatch.Changes[0].ResourceRecordSet.TTL = 300
	req.ChangeBatch.Changes[0].ResourceRecordSet.ResourceRecords = []struct {
		Value string `xml:"Value"`
	}{{Value: `"` + value + `"`}}

	body, err := xml.Marshal(req)
	if err != nil {
		return err
	}
	return p.do(ctx, http.MethodPost, "/hostedzone/"+zoneID+"/rrset", body, nil)
}

func (p *route53Provider) Present(ctx context.Context, domain, value string) error {
	zoneID, err := p.findZoneID(ctx, domain)
	if err != nil {
		return err
	}
	if err := p.change(ctx, zoneID, domain, value, "UPSERT"); err != nil {
		return err
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

func (p *route53Provider) CleanUp(ctx context.Context, domain, value string) error {
	zoneID, err := p.findZoneID(ctx, domain)
	if err != nil {
		return err
	}
	return p.change(ctx, zoneID, domain, value, "DELETE")
}
