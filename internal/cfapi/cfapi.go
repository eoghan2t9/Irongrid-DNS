// Package cfapi is a small client for the parts of the Cloudflare v4 API that
// manage a remotely-configured Cloudflare Tunnel: the tunnels themselves, the
// public-hostname (ingress) rules stored on Cloudflare, and the proxied CNAME
// records that point a hostname at a tunnel.
//
// It is deliberately narrow and defensive about what it writes: a tunnel's
// configuration is replaced wholesale by Cloudflare on every update, so the
// helpers here read the current document, change only the rule they were asked
// to, and write everything else back untouched (including fields this package
// does not know about).
package cfapi

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/eoghan2t9/Irongrid-DNS/internal/version"
)

// DefaultBaseURL is the Cloudflare v4 API root.
const DefaultBaseURL = "https://api.cloudflare.com/client/v4"

const (
	maxBody  = 4 << 20 // a response larger than this is not a Cloudflare answer
	maxPages = 40      // 40 x 50 results is far beyond any real account
)

// Client talks to the Cloudflare API with a scoped API token.
type Client struct {
	// Token is a Cloudflare API token (not the tunnel's run token).
	Token string
	// BaseURL overrides DefaultBaseURL (tests).
	BaseURL string
	// HTTP is used for requests; a client with a timeout is used when nil.
	HTTP *http.Client
}

var defaultHTTP = &http.Client{Timeout: 20 * time.Second}

// APIError is an error answer from Cloudflare (or a non-JSON failure).
type APIError struct {
	Status  int    // HTTP status
	Code    int    // first Cloudflare error code, 0 if none
	Message string // all Cloudflare error messages joined
}

func (e *APIError) Error() string {
	if e.Message == "" {
		return "cloudflare API returned HTTP " + strconv.Itoa(e.Status)
	}
	return "cloudflare: " + e.Message
}

// IsPermission reports whether err is Cloudflare refusing the token (bad token
// or missing permission), as opposed to a bad request or an outage.
func IsPermission(err error) bool {
	var ae *APIError
	return errors.As(err, &ae) && (ae.Status == http.StatusUnauthorized || ae.Status == http.StatusForbidden)
}

type envelope struct {
	Success bool `json:"success"`
	Errors  []struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"errors"`
	Result     json.RawMessage `json:"result"`
	ResultInfo struct {
		Page       int `json:"page"`
		TotalPages int `json:"total_pages"`
	} `json:"result_info"`
}

// do performs one API call and decodes result into out (when non-nil). It
// returns the response's page count for list endpoints.
func (c *Client) do(ctx context.Context, method, path string, q url.Values, body, out any) (totalPages int, err error) {
	base := c.BaseURL
	if base == "" {
		base = DefaultBaseURL
	}
	u := base + path
	if len(q) > 0 {
		u += "?" + q.Encode()
	}
	var rdr io.Reader
	if body != nil {
		b, merr := json.Marshal(body)
		if merr != nil {
			return 0, merr
		}
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, u, rdr)
	if err != nil {
		return 0, err
	}
	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "irongrid-dns/"+version.Version)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	hc := c.HTTP
	if hc == nil {
		hc = defaultHTTP
	}
	resp, err := hc.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return 0, err
	}
	var env envelope
	jsonErr := json.Unmarshal(raw, &env)
	if jsonErr != nil || !env.Success || resp.StatusCode >= 400 {
		ae := &APIError{Status: resp.StatusCode}
		var msgs []string
		for _, e := range env.Errors {
			if ae.Code == 0 {
				ae.Code = e.Code
			}
			msgs = append(msgs, e.Message)
		}
		ae.Message = strings.Join(msgs, "; ")
		return 0, ae
	}
	if out != nil && len(env.Result) > 0 && string(env.Result) != "null" {
		if err := json.Unmarshal(env.Result, out); err != nil {
			return 0, fmt.Errorf("decoding cloudflare %s: %w", path, err)
		}
	}
	return env.ResultInfo.TotalPages, nil
}

// getAll walks every page of a list endpoint.
func getAll[T any](ctx context.Context, c *Client, path string, q url.Values) ([]T, error) {
	var all []T
	if q == nil {
		q = url.Values{}
	}
	for page := 1; page <= maxPages; page++ {
		q.Set("page", strconv.Itoa(page))
		q.Set("per_page", "50")
		var items []T
		pages, err := c.do(ctx, http.MethodGet, path, q, nil, &items)
		if err != nil {
			return nil, err
		}
		all = append(all, items...)
		if page >= pages || len(items) == 0 {
			break
		}
	}
	return all, nil
}

// ParseTunnelToken extracts the account and tunnel IDs a cloudflared run token
// carries (it is base64-encoded JSON {"a": account, "t": tunnel, "s": secret}).
// The secret is deliberately not returned.
func ParseTunnelToken(token string) (accountID, tunnelID string, err error) {
	token = strings.TrimSpace(token)
	b, derr := base64.StdEncoding.DecodeString(token)
	if derr != nil {
		b, derr = base64.RawStdEncoding.DecodeString(token)
	}
	if derr != nil {
		return "", "", errors.New("not a cloudflared tunnel token")
	}
	var v struct {
		A string `json:"a"`
		T string `json:"t"`
	}
	if json.Unmarshal(b, &v) != nil || v.A == "" || v.T == "" {
		return "", "", errors.New("not a cloudflared tunnel token")
	}
	return v.A, v.T, nil
}

// ---- accounts & tunnels ----

// Account is a Cloudflare account the token can see.
type Account struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// Connection is one cloudflared connector link to Cloudflare's edge.
type Connection struct {
	ID       string `json:"id"`
	ColoName string `json:"colo_name"`
	OriginIP string `json:"origin_ip"`
	OpenedAt string `json:"opened_at"`
}

// Tunnel is a Cloudflare Tunnel.
type Tunnel struct {
	ID          string       `json:"id"`
	Name        string       `json:"name"`
	Status      string       `json:"status"` // inactive | degraded | healthy | down
	CreatedAt   string       `json:"created_at"`
	ConfigSrc   string       `json:"config_src"` // cloudflare (remote) | local
	Connections []Connection `json:"connections"`
}

// ListAccounts returns the accounts visible to the token.
func (c *Client) ListAccounts(ctx context.Context) ([]Account, error) {
	return getAll[Account](ctx, c, "/accounts", nil)
}

// ListTunnels returns the account's active (not deleted) tunnels.
func (c *Client) ListTunnels(ctx context.Context, account string) ([]Tunnel, error) {
	return getAll[Tunnel](ctx, c, "/accounts/"+url.PathEscape(account)+"/cfd_tunnel", url.Values{"is_deleted": {"false"}})
}

// GetTunnel returns one tunnel with its live connector connections.
func (c *Client) GetTunnel(ctx context.Context, account, id string) (*Tunnel, error) {
	var t Tunnel
	if _, err := c.do(ctx, http.MethodGet, tunnelPath(account, id), nil, nil, &t); err != nil {
		return nil, err
	}
	return &t, nil
}

// CreateTunnel creates a remotely-configured tunnel (its hostnames live on
// Cloudflare, which is what makes them manageable through the API).
func (c *Client) CreateTunnel(ctx context.Context, account, name string) (*Tunnel, error) {
	var t Tunnel
	body := map[string]string{"name": name, "config_src": "cloudflare"}
	if _, err := c.do(ctx, http.MethodPost, "/accounts/"+url.PathEscape(account)+"/cfd_tunnel", nil, body, &t); err != nil {
		return nil, err
	}
	return &t, nil
}

// DeleteTunnel deletes a tunnel. Cloudflare refuses while connectors are
// attached, and that refusal is passed through.
func (c *Client) DeleteTunnel(ctx context.Context, account, id string) error {
	_, err := c.do(ctx, http.MethodDelete, tunnelPath(account, id), nil, nil, nil)
	return err
}

// TunnelToken returns the token cloudflared runs a tunnel with.
func (c *Client) TunnelToken(ctx context.Context, account, id string) (string, error) {
	var tok string
	if _, err := c.do(ctx, http.MethodGet, tunnelPath(account, id)+"/token", nil, nil, &tok); err != nil {
		return "", err
	}
	return tok, nil
}

func tunnelPath(account, id string) string {
	return "/accounts/" + url.PathEscape(account) + "/cfd_tunnel/" + url.PathEscape(id)
}

// ---- hostname (ingress) configuration ----

// Rule is one ingress rule. It is kept as raw JSON fields so that anything
// Cloudflare returns that this package does not model (origin request
// settings, future fields) is written back unchanged.
type Rule map[string]json.RawMessage

func (r Rule) str(key string) string {
	var s string
	_ = json.Unmarshal(r[key], &s)
	return s
}

// Hostname is the rule's public hostname ("" for the catch-all rule).
func (r Rule) Hostname() string { return r.str("hostname") }

// Service is where matching traffic is sent (an origin URL or http_status:N).
func (r Rule) Service() string { return r.str("service") }

// Path is the optional path filter.
func (r Rule) Path() string { return r.str("path") }

// NoTLSVerify reports originRequest.noTLSVerify.
func (r Rule) NoTLSVerify() bool {
	var o struct {
		NoTLSVerify bool `json:"noTLSVerify"`
	}
	_ = json.Unmarshal(r["originRequest"], &o)
	return o.NoTLSVerify
}

// NewRule builds a hostname rule.
func NewRule(hostname, service, path string, noTLSVerify bool) Rule {
	r := Rule{}
	r["hostname"], _ = json.Marshal(hostname)
	r["service"], _ = json.Marshal(service)
	if path != "" {
		r["path"], _ = json.Marshal(path)
	}
	if noTLSVerify {
		r["originRequest"] = json.RawMessage(`{"noTLSVerify":true}`)
	}
	return r
}

// mergeOriginRequest returns old's originRequest with only noTLSVerify set to
// what rule asks for, so other origin settings (timeouts, HTTP host header,
// ...) configured elsewhere survive an edit made here.
func mergeOriginRequest(old, rule Rule) (json.RawMessage, bool) {
	m := map[string]json.RawMessage{}
	if raw, ok := old["originRequest"]; ok {
		_ = json.Unmarshal(raw, &m)
	}
	if rule.NoTLSVerify() {
		m["noTLSVerify"] = json.RawMessage("true")
	} else {
		delete(m, "noTLSVerify")
	}
	if len(m) == 0 {
		return nil, false
	}
	b, _ := json.Marshal(m)
	return b, true
}

// TunnelConfig is a tunnel's remotely-managed configuration.
type TunnelConfig struct {
	// Other holds every config key except ingress (originRequest defaults,
	// warp-routing, ...), preserved verbatim.
	Other map[string]json.RawMessage
	// Rules is the ingress list; the last rule is always the catch-all.
	Rules []Rule
}

// catchAllService answers anything no hostname rule matched.
const catchAllService = "http_status:404"

// GetConfig reads the tunnel's configuration (empty for a tunnel that has
// never had one).
func (c *Client) GetConfig(ctx context.Context, account, id string) (*TunnelConfig, error) {
	var res struct {
		Config map[string]json.RawMessage `json:"config"`
	}
	if _, err := c.do(ctx, http.MethodGet, tunnelPath(account, id)+"/configurations", nil, nil, &res); err != nil {
		return nil, err
	}
	cfg := &TunnelConfig{Other: map[string]json.RawMessage{}}
	for k, v := range res.Config {
		if k == "ingress" {
			if err := json.Unmarshal(v, &cfg.Rules); err != nil {
				return nil, fmt.Errorf("decoding tunnel ingress: %w", err)
			}
			continue
		}
		cfg.Other[k] = v
	}
	cfg.ensureCatchAll()
	return cfg, nil
}

// PutConfig writes the configuration back.
func (c *Client) PutConfig(ctx context.Context, account, id string, cfg *TunnelConfig) error {
	cfg.ensureCatchAll()
	doc := make(map[string]any, len(cfg.Other)+1)
	for k, v := range cfg.Other {
		doc[k] = v
	}
	doc["ingress"] = cfg.Rules
	_, err := c.do(ctx, http.MethodPut, tunnelPath(account, id)+"/configurations", nil, map[string]any{"config": doc}, nil)
	return err
}

// ensureCatchAll guarantees the rule list ends with exactly one catch-all
// (a rule with neither hostname nor path), which Cloudflare requires.
func (c *TunnelConfig) ensureCatchAll() {
	var named []Rule
	var catch Rule
	for _, r := range c.Rules {
		if r.Hostname() == "" && r.Path() == "" {
			catch = r // the last catch-all wins, as in cloudflared
			continue
		}
		named = append(named, r)
	}
	if catch == nil {
		catch = Rule{}
		catch["service"], _ = json.Marshal(catchAllService)
	}
	c.Rules = append(named, catch)
}

// Hostnames returns the hostname rules (everything but the catch-all).
func (c *TunnelConfig) Hostnames() []Rule {
	c.ensureCatchAll()
	return c.Rules[:len(c.Rules)-1]
}

// CatchAll returns the catch-all service.
func (c *TunnelConfig) CatchAll() string {
	c.ensureCatchAll()
	return c.Rules[len(c.Rules)-1].Service()
}

// Find returns the index of the hostname rule, or -1.
func (c *TunnelConfig) Find(hostname string) int {
	for i, r := range c.Hostnames() {
		if strings.EqualFold(r.Hostname(), hostname) {
			return i
		}
	}
	return -1
}

// Upsert adds the rule before the catch-all, or replaces the existing rule for
// the same hostname in place, keeping the fields of the old rule that this
// package does not manage (and its other originRequest settings). It reports
// whether it replaced an existing rule.
func (c *TunnelConfig) Upsert(rule Rule) bool {
	if i := c.Find(rule.Hostname()); i >= 0 {
		old := c.Rules[i]
		for k, v := range old {
			if _, set := rule[k]; !set && k != "path" && k != "originRequest" {
				rule[k] = v
			}
		}
		delete(rule, "originRequest")
		if raw, ok := mergeOriginRequest(old, rule); ok {
			rule["originRequest"] = raw
		}
		c.Rules[i] = rule
		return true
	}
	named := append([]Rule(nil), c.Hostnames()...)
	catch := c.Rules[len(c.Rules)-1]
	c.Rules = append(named, rule, catch)
	return false
}

// Remove deletes the hostname rule, reporting whether it existed.
func (c *TunnelConfig) Remove(hostname string) bool {
	i := c.Find(hostname)
	if i < 0 {
		return false
	}
	c.Rules = append(c.Rules[:i:i], c.Rules[i+1:]...)
	return true
}

// ---- zones & DNS ----

// Zone is a DNS zone the token can manage.
type Zone struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Status string `json:"status"`
}

// Record is a DNS record.
type Record struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Type    string `json:"type"`
	Content string `json:"content"`
	Proxied bool   `json:"proxied"`
	TTL     int    `json:"ttl"`
	// Data is the structured form of SVCB/HTTPS records ({priority, target,
	// value}); Content carries the same information as one string.
	Data map[string]any `json:"data,omitempty"`
}

// RecordInput describes a record to create or replace. SVCB and HTTPS records
// are described by Data ({priority, target, value}); every other type by
// Content.
type RecordInput struct {
	Type    string
	Name    string
	Content string
	TTL     int // 1 = automatic
	Proxied bool
	Data    map[string]any
}

func (in RecordInput) body() map[string]any {
	ttl := in.TTL
	if ttl == 0 {
		ttl = 1
	}
	b := map[string]any{"type": in.Type, "name": in.Name, "ttl": ttl, "proxied": in.Proxied}
	if in.Content != "" {
		b["content"] = in.Content
	}
	if in.Data != nil {
		b["data"] = in.Data
	}
	return b
}

// CreateRecord creates a DNS record of any supported type.
func (c *Client) CreateRecord(ctx context.Context, zoneID string, in RecordInput) (*Record, error) {
	var r Record
	if _, err := c.do(ctx, http.MethodPost, "/zones/"+url.PathEscape(zoneID)+"/dns_records", nil, in.body(), &r); err != nil {
		return nil, err
	}
	return &r, nil
}

// UpdateRecord replaces an existing DNS record.
func (c *Client) UpdateRecord(ctx context.Context, zoneID, recordID string, in RecordInput) (*Record, error) {
	var r Record
	path := "/zones/" + url.PathEscape(zoneID) + "/dns_records/" + url.PathEscape(recordID)
	if _, err := c.do(ctx, http.MethodPut, path, nil, in.body(), &r); err != nil {
		return nil, err
	}
	return &r, nil
}

// ListZones returns the zones visible to the token.
func (c *Client) ListZones(ctx context.Context) ([]Zone, error) {
	return getAll[Zone](ctx, c, "/zones", nil)
}

// TunnelTarget is the CNAME target that routes a hostname to a tunnel.
func TunnelTarget(tunnelID string) string { return tunnelID + ".cfargotunnel.com" }

// RecordsNamed returns every DNS record with exactly this name.
func (c *Client) RecordsNamed(ctx context.Context, zoneID, name string) ([]Record, error) {
	return getAll[Record](ctx, c, "/zones/"+url.PathEscape(zoneID)+"/dns_records", url.Values{"name": {name}})
}

// RecordsPointingAt returns the zone's CNAMEs that target the tunnel.
func (c *Client) RecordsPointingAt(ctx context.Context, zoneID, tunnelID string) ([]Record, error) {
	return getAll[Record](ctx, c, "/zones/"+url.PathEscape(zoneID)+"/dns_records",
		url.Values{"type": {"CNAME"}, "content": {TunnelTarget(tunnelID)}})
}

// CreateTunnelCNAME creates the proxied CNAME that routes name to the tunnel.
func (c *Client) CreateTunnelCNAME(ctx context.Context, zoneID, name, tunnelID string) (*Record, error) {
	var r Record
	body := map[string]any{"type": "CNAME", "name": name, "content": TunnelTarget(tunnelID), "proxied": true, "ttl": 1}
	if _, err := c.do(ctx, http.MethodPost, "/zones/"+url.PathEscape(zoneID)+"/dns_records", nil, body, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

// UpdateTunnelCNAME re-points an existing CNAME at the tunnel and proxies it.
func (c *Client) UpdateTunnelCNAME(ctx context.Context, zoneID, recordID, name, tunnelID string) (*Record, error) {
	var r Record
	body := map[string]any{"type": "CNAME", "name": name, "content": TunnelTarget(tunnelID), "proxied": true, "ttl": 1}
	path := "/zones/" + url.PathEscape(zoneID) + "/dns_records/" + url.PathEscape(recordID)
	if _, err := c.do(ctx, http.MethodPut, path, nil, body, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

// DeleteRecord deletes a DNS record.
func (c *Client) DeleteRecord(ctx context.Context, zoneID, recordID string) error {
	_, err := c.do(ctx, http.MethodDelete, "/zones/"+url.PathEscape(zoneID)+"/dns_records/"+url.PathEscape(recordID), nil, nil, nil)
	return err
}

// ZoneFor picks the zone a hostname belongs to: the one whose name is the
// longest suffix of the hostname (so sub.example.com prefers a delegated
// sub.example.com zone over example.com). It returns nil when none match.
func ZoneFor(zones []Zone, hostname string) *Zone {
	hostname = strings.TrimPrefix(strings.ToLower(hostname), "*.")
	var best *Zone
	for i := range zones {
		z := strings.ToLower(zones[i].Name)
		if hostname == z || strings.HasSuffix(hostname, "."+z) {
			if best == nil || len(z) > len(best.Name) {
				best = &zones[i]
			}
		}
	}
	return best
}
