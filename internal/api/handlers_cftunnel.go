package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/eoghan2t9/Irongrid-DNS/internal/cfapi"
	"github.com/eoghan2t9/Irongrid-DNS/internal/dnsplan"
)

// ---- Cloudflare tunnel management ----
//
// These endpoints manage the tunnel from the dashboard through the Cloudflare
// API: which tunnel is in use, its public hostnames (ingress rules stored on
// Cloudflare) and the proxied CNAME records that route each hostname to it.
// They need a scoped Cloudflare API token, kept in the config but never sent
// back to the browser. A failure from Cloudflare is reported as 502, not
// 401/403: the dashboard treats those as "your session expired".

// cfCtx is what the Cloudflare endpoints resolve from the config.
type cfCtx struct {
	client *cfapi.Client
	// dns is the client DNS-record calls go through: the tunnel API token
	// first and, when Cloudflare denies it, the ACME (certificate) token.
	dns *fallbackDNS
	// dnsFallback reports that a second token is available for DNS records.
	dnsFallback    bool
	hasToken       bool
	tunnelTokenSet bool
	account        string
	tunnelID       string
}

func (h *Handler) cfContext() cfCtx {
	h.cfgMu.Lock()
	t := h.Cfg.Tunnel
	acmeToken := h.Cfg.TLS.ACME.DNS01.CloudflareToken
	h.cfgMu.Unlock()
	c := cfCtx{account: t.CloudflareAccountID}
	if t.CloudflareAPIToken != "" {
		c.hasToken = true
		c.client = &cfapi.Client{Token: t.CloudflareAPIToken, BaseURL: h.CloudflareBaseURL}
		var alt *cfapi.Client
		// The certificate settings already hold a Cloudflare token with
		// Zone › DNS › Edit, so it can stand in for DNS records when the
		// tunnel token lacks that permission.
		if acmeToken != "" && acmeToken != t.CloudflareAPIToken {
			alt = &cfapi.Client{Token: acmeToken, BaseURL: h.CloudflareBaseURL}
		}
		c.dns = &fallbackDNS{primary: c.client, alt: alt}
		c.dnsFallback = alt != nil
	}
	if t.Token != "" {
		c.tunnelTokenSet = true
		// The tunnel token names the account and tunnel it belongs to, which is
		// more specific than any configured account.
		if a, id, err := cfapi.ParseTunnelToken(t.Token); err == nil {
			c.tunnelID = id
			c.account = a
		}
	}
	return c
}

// dnsClient is the set of Cloudflare calls DNS handling needs.
type dnsClient interface {
	ListZones(ctx context.Context) ([]cfapi.Zone, error)
	RecordsNamed(ctx context.Context, zoneID, name string) ([]cfapi.Record, error)
	RecordsPointingAt(ctx context.Context, zoneID, tunnelID string) ([]cfapi.Record, error)
	CreateTunnelCNAME(ctx context.Context, zoneID, name, tunnelID string) (*cfapi.Record, error)
	UpdateTunnelCNAME(ctx context.Context, zoneID, recordID, name, tunnelID string) (*cfapi.Record, error)
	CreateRecord(ctx context.Context, zoneID string, in cfapi.RecordInput) (*cfapi.Record, error)
	UpdateRecord(ctx context.Context, zoneID, recordID string, in cfapi.RecordInput) (*cfapi.Record, error)
	DeleteRecord(ctx context.Context, zoneID, recordID string) error
}

// fallbackDNS tries the primary token for every DNS call and, only when
// Cloudflare refuses it for lack of permission, the alternate token. The
// primary stays the one that is configured on the Tunnel page: the alternate
// is never used when the primary works, and its own failures are not shown in
// place of the primary's unless they are something other than a refusal.
type fallbackDNS struct {
	primary, alt *cfapi.Client
	used         atomic.Bool
}

func withAlt[T any](f *fallbackDNS, call func(*cfapi.Client) (T, error)) (T, error) {
	v, err := call(f.primary)
	if err == nil || f.alt == nil || !cfapi.IsPermission(err) {
		return v, err
	}
	v2, err2 := call(f.alt)
	switch {
	case err2 == nil:
		f.used.Store(true)
		return v2, nil
	case !cfapi.IsPermission(err2):
		return v2, err2 // a real failure, not just a refusal
	}
	return v, err
}

func (f *fallbackDNS) ListZones(ctx context.Context) ([]cfapi.Zone, error) {
	return withAlt(f, func(c *cfapi.Client) ([]cfapi.Zone, error) { return c.ListZones(ctx) })
}

func (f *fallbackDNS) RecordsNamed(ctx context.Context, zoneID, name string) ([]cfapi.Record, error) {
	return withAlt(f, func(c *cfapi.Client) ([]cfapi.Record, error) { return c.RecordsNamed(ctx, zoneID, name) })
}

func (f *fallbackDNS) RecordsPointingAt(ctx context.Context, zoneID, tunnelID string) ([]cfapi.Record, error) {
	return withAlt(f, func(c *cfapi.Client) ([]cfapi.Record, error) { return c.RecordsPointingAt(ctx, zoneID, tunnelID) })
}

func (f *fallbackDNS) CreateTunnelCNAME(ctx context.Context, zoneID, name, tunnelID string) (*cfapi.Record, error) {
	return withAlt(f, func(c *cfapi.Client) (*cfapi.Record, error) { return c.CreateTunnelCNAME(ctx, zoneID, name, tunnelID) })
}

func (f *fallbackDNS) UpdateTunnelCNAME(ctx context.Context, zoneID, recordID, name, tunnelID string) (*cfapi.Record, error) {
	return withAlt(f, func(c *cfapi.Client) (*cfapi.Record, error) {
		return c.UpdateTunnelCNAME(ctx, zoneID, recordID, name, tunnelID)
	})
}

func (f *fallbackDNS) CreateRecord(ctx context.Context, zoneID string, in cfapi.RecordInput) (*cfapi.Record, error) {
	return withAlt(f, func(c *cfapi.Client) (*cfapi.Record, error) { return c.CreateRecord(ctx, zoneID, in) })
}

func (f *fallbackDNS) UpdateRecord(ctx context.Context, zoneID, recordID string, in cfapi.RecordInput) (*cfapi.Record, error) {
	return withAlt(f, func(c *cfapi.Client) (*cfapi.Record, error) { return c.UpdateRecord(ctx, zoneID, recordID, in) })
}

func (f *fallbackDNS) DeleteRecord(ctx context.Context, zoneID, recordID string) error {
	_, err := withAlt(f, func(c *cfapi.Client) (struct{}, error) { return struct{}{}, c.DeleteRecord(ctx, zoneID, recordID) })
	return err
}

// dnsDenied turns Cloudflare's bare "Authentication error" into what is
// actually wrong: the token has no DNS permission on this particular zone.
func dnsDenied(zone string, err error) error {
	if cfapi.IsPermission(err) {
		return &zoneDeniedError{zone: zone, err: err}
	}
	return err
}

// zoneDeniedError is a permission refusal for one zone's DNS records. It still
// unwraps to the Cloudflare error, so IsPermission recognises it.
type zoneDeniedError struct {
	zone string
	err  error
}

func (e *zoneDeniedError) Error() string {
	return fmt.Sprintf("cloudflare denies the API token access to DNS records in %s — it needs Zone › DNS › Edit with that zone (or All zones) under Zone Resources", e.zone)
}

func (e *zoneDeniedError) Unwrap() error { return e.err }

// cfFail reports a Cloudflare error. 502 keeps it distinct from this
// dashboard's own 401 (session) handling.
func cfFail(w http.ResponseWriter, err error) {
	body := map[string]any{"error": err.Error(), "cloudflare": true}
	var zd *zoneDeniedError
	switch {
	case errors.As(err, &zd):
		body["permission"] = true // the message already names the zone and the fix
	case cfapi.IsPermission(err):
		body["permission"] = true
		body["error"] = "Cloudflare refused the request: the API token is invalid or is missing a permission " +
			"(Account › Cloudflare Tunnel: Edit, Zone › DNS: Edit, Zone › Zone: Read). " + err.Error()
	}
	writeJSON(w, http.StatusBadGateway, body)
}

func badRequest(w http.ResponseWriter, msg string, extra map[string]any) {
	body := map[string]any{"error": msg}
	maps.Copy(body, extra)
	writeJSON(w, http.StatusBadRequest, body)
}

// cfReady checks the prerequisites for an endpoint, answering 400 with a
// machine-readable "needs" when one is missing.
func cfReady(w http.ResponseWriter, c cfCtx, needTunnel bool) bool {
	switch {
	case !c.hasToken:
		badRequest(w, "Add a Cloudflare API token first.", map[string]any{"needs": "api_token"})
	case c.account == "":
		badRequest(w, "No Cloudflare account is selected for the API token.", map[string]any{"needs": "account"})
	case needTunnel && c.tunnelID == "":
		badRequest(w, "No named tunnel is selected. Pick or create one first.", map[string]any{"needs": "tunnel"})
	default:
		return true
	}
	return false
}

func decodeJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(v); err != nil {
		badRequest(w, "bad request body", nil)
		return false
	}
	return true
}

// cloudflareAPI routes /api/tunnel/cf/*.
func (h *Handler) cloudflareAPI(ctx context.Context, w http.ResponseWriter, r *http.Request, parts []string) {
	ctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	m := r.Method
	switch {
	case len(parts) == 1 && parts[0] == "status" && m == http.MethodGet:
		h.cfStatus(ctx, w)
	case len(parts) == 1 && parts[0] == "credentials" && m == http.MethodPut:
		h.cfSetCredentials(ctx, w, r)
	case len(parts) == 1 && parts[0] == "zones" && m == http.MethodGet:
		h.cfZones(ctx, w)
	case len(parts) == 1 && parts[0] == "tunnels" && m == http.MethodGet:
		h.cfListTunnels(ctx, w)
	case len(parts) == 1 && parts[0] == "tunnels" && m == http.MethodPost:
		h.cfCreateTunnel(ctx, w, r)
	case len(parts) == 2 && parts[0] == "tunnels" && parts[1] == "select" && m == http.MethodPost:
		h.cfSelectTunnel(ctx, w, r)
	case len(parts) == 2 && parts[0] == "tunnels" && m == http.MethodDelete:
		h.cfDeleteTunnel(ctx, w, parts[1])
	case len(parts) == 1 && parts[0] == "hostnames" && m == http.MethodGet:
		h.cfHostnames(ctx, w)
	case len(parts) == 1 && parts[0] == "hostnames" && (m == http.MethodPost || m == http.MethodPut):
		h.cfUpsertHostname(ctx, w, r, m == http.MethodPut)
	case len(parts) == 1 && parts[0] == "hostnames" && m == http.MethodDelete:
		h.cfDeleteHostname(ctx, w, r)
	case len(parts) == 1 && parts[0] == "dns-plan" && m == http.MethodGet:
		h.cfDNSPlan(ctx, w)
	case len(parts) == 2 && parts[0] == "dns-plan" && parts[1] == "apply" && m == http.MethodPost:
		h.cfDNSApply(ctx, w, r)
	case len(parts) == 1 && parts[0] == "dns-settings" && m == http.MethodPut:
		h.cfDNSSettings(ctx, w, r)
	case len(parts) == 2 && parts[0] == "hostnames" && parts[1] == "sync-dns" && m == http.MethodPost:
		h.cfSyncDNS(ctx, w, r)
	default:
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
	}
}

// ---- status & credentials ----

type cfConnView struct {
	Colo     string `json:"colo"`
	OriginIP string `json:"origin_ip"`
	OpenedAt string `json:"opened_at"`
}

type cfTunnelView struct {
	ID              string       `json:"id"`
	Name            string       `json:"name"`
	Status          string       `json:"status"`
	CreatedAt       string       `json:"created_at"`
	RemotelyManaged bool         `json:"remotely_managed"`
	Selected        bool         `json:"selected"`
	Connections     []cfConnView `json:"connections"`
}

func tunnelView(t cfapi.Tunnel, selected string) cfTunnelView {
	v := cfTunnelView{
		ID: t.ID, Name: t.Name, Status: t.Status, CreatedAt: t.CreatedAt,
		RemotelyManaged: t.ConfigSrc != "local", Selected: t.ID == selected,
		Connections: []cfConnView{},
	}
	for _, c := range t.Connections {
		v.Connections = append(v.Connections, cfConnView{Colo: c.ColoName, OriginIP: c.OriginIP, OpenedAt: c.OpenedAt})
	}
	return v
}

type originSuggestion struct {
	Label       string `json:"label"`
	Service     string `json:"service"`
	NoTLSVerify bool   `json:"no_tls_verify"`
	// OriginServerName, when set, is the name the origin's certificate is
	// valid for: the connector dials localhost but verifies the certificate
	// as this, so verification can stay on.
	OriginServerName string `json:"origin_server_name,omitempty"`
}

type cfStatusResp struct {
	APITokenSet      bool               `json:"api_token_set"`
	TunnelTokenSet   bool               `json:"tunnel_token_set"`
	AccountID        string             `json:"account_id"`
	TunnelID         string             `json:"tunnel_id"`
	Tunnel           *cfTunnelView      `json:"tunnel,omitempty"`
	SuggestedOrigins []originSuggestion `json:"suggested_origins"`
	// DNSFallback reports that the ACME (certificate) Cloudflare token can stand
	// in for DNS records when the tunnel token is refused.
	DNSFallback bool   `json:"dns_fallback,omitempty"`
	Error       string `json:"error,omitempty"`
	Permission  bool   `json:"permission,omitempty"`
}

// suggestedOrigins offers the local addresses a tunnel hostname most often
// points at: the dashboard (which shares its port with DoH when configured
// so) and a separate DoH listener.
func (h *Handler) suggestedOrigins() []originSuggestion {
	h.cfgMu.Lock()
	web, tls, doh := h.Cfg.Server.WebListen, h.Cfg.Server.WebTLS, h.Cfg.Server.ListenDoH
	// The certificate is issued for the discovery host or the ACME domain, not
	// for "localhost", which is what the connector dials.
	certName := dnsplan.Normalize(h.Cfg.Server.DiscoveryHost)
	for i := 0; certName == "" && i < len(h.Cfg.TLS.ACME.Domains); i++ {
		if d := dnsplan.Normalize(h.Cfg.TLS.ACME.Domains[i]); d != "" && !strings.HasPrefix(d, "*.") {
			certName = d
		}
	}
	h.cfgMu.Unlock()
	// tlsOrigin returns the certificate handling for a local HTTPS origin:
	// verify as the certificate's own name when it is known, and only skip
	// verification when it is not.
	tlsOrigin := func(s originSuggestion) originSuggestion {
		if certName != "" {
			s.OriginServerName = certName
		} else {
			s.NoTLSVerify = true
		}
		return s
	}
	port := func(addr string) string {
		_, p, err := net.SplitHostPort(addr)
		if err != nil {
			return ""
		}
		return p
	}
	out := []originSuggestion{}
	if p := port(web); p != "" {
		scheme := "http"
		if tls {
			scheme = "https"
		}
		label := "Irongrid dashboard"
		if doh != "" && port(doh) == p {
			label = "Irongrid dashboard + DoH (shared port)"
		}
		s := originSuggestion{Label: label, Service: scheme + "://localhost:" + p}
		if tls {
			// Loopback to a certificate issued for a public name cannot verify
			// as "localhost".
			s = tlsOrigin(s)
		}
		out = append(out, s)
	}
	if p := port(doh); p != "" && p != port(web) {
		out = append(out, tlsOrigin(originSuggestion{Label: "Irongrid DoH endpoint", Service: "https://localhost:" + p}))
	}
	return out
}

func (h *Handler) buildCFStatus(ctx context.Context) cfStatusResp {
	c := h.cfContext()
	resp := cfStatusResp{
		APITokenSet: c.hasToken, TunnelTokenSet: c.tunnelTokenSet,
		AccountID: c.account, TunnelID: c.tunnelID,
		SuggestedOrigins: h.suggestedOrigins(), DNSFallback: c.dnsFallback,
	}
	if c.hasToken && c.account != "" && c.tunnelID != "" {
		t, err := c.client.GetTunnel(ctx, c.account, c.tunnelID)
		if err != nil {
			resp.Error = err.Error()
			resp.Permission = cfapi.IsPermission(err)
		} else {
			v := tunnelView(*t, c.tunnelID)
			resp.Tunnel = &v
		}
	}
	return resp
}

func (h *Handler) cfStatus(ctx context.Context, w http.ResponseWriter) {
	writeJSON(w, http.StatusOK, h.buildCFStatus(ctx))
}

type cfCredentialsReq struct {
	APIToken  string `json:"api_token"`
	AccountID string `json:"account_id"`
}

// cfSetCredentials verifies a Cloudflare API token against the API before
// saving it, so a mistyped or under-privileged token is rejected up front. An
// empty token disconnects the account.
func (h *Handler) cfSetCredentials(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	var req cfCredentialsReq
	if !decodeJSON(w, r, &req) {
		return
	}
	token := strings.TrimSpace(req.APIToken)
	account := strings.TrimSpace(req.AccountID)
	if token != "" {
		client := &cfapi.Client{Token: token, BaseURL: h.CloudflareBaseURL}
		if account == "" {
			account = h.cfContext().account // from the tunnel token, when one is saved
		}
		if account == "" {
			accts, err := client.ListAccounts(ctx)
			if err != nil {
				cfFail(w, err)
				return
			}
			switch len(accts) {
			case 0:
				badRequest(w, "That token can't see any Cloudflare account.", nil)
				return
			case 1:
				account = accts[0].ID
			default:
				badRequest(w, "That token can see several accounts — choose which one to manage.",
					map[string]any{"needs": "account", "accounts": accts})
				return
			}
		}
		// The real test of the token: it must be able to read this account's tunnels.
		if _, err := client.ListTunnels(ctx, account); err != nil {
			cfFail(w, err)
			return
		}
	} else {
		account = ""
	}
	h.cfgMu.Lock()
	h.Cfg.Tunnel.CloudflareAPIToken = token
	h.Cfg.Tunnel.CloudflareAccountID = account
	err := h.SaveConfig()
	h.cfgMu.Unlock()
	h.cfCacheClear()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "credentials not saved: " + err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, h.buildCFStatus(ctx))
}

func (h *Handler) cfZones(ctx context.Context, w http.ResponseWriter) {
	c := h.cfContext()
	if !cfReady(w, c, false) {
		return
	}
	zones, err := c.dns.ListZones(ctx)
	if err != nil {
		cfFail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"zones": zones})
}

// ---- tunnels ----

func (h *Handler) cfListTunnels(ctx context.Context, w http.ResponseWriter) {
	c := h.cfContext()
	if !cfReady(w, c, false) {
		return
	}
	ts, err := c.client.ListTunnels(ctx, c.account)
	if err != nil {
		cfFail(w, err)
		return
	}
	out := make([]cfTunnelView, 0, len(ts))
	for _, t := range ts {
		out = append(out, tunnelView(t, c.tunnelID))
	}
	writeJSON(w, http.StatusOK, map[string]any{"tunnels": out, "selected": c.tunnelID})
}

var cfTunnelNameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9 _.\-]{0,62}$`)

// useTunnel points the dashboard at a tunnel: it fetches the tunnel's run
// token and saves it as the tunnel token. Refused while a tunnel is running,
// because the live process would keep serving the old one.
func (h *Handler) useTunnel(ctx context.Context, w http.ResponseWriter, c cfCtx, id string) bool {
	if h.Tunnel != nil && h.Tunnel.Status().Running {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "Stop the running tunnel before switching to a different one."})
		return false
	}
	tok, err := c.client.TunnelToken(ctx, c.account, id)
	if err != nil {
		cfFail(w, err)
		return false
	}
	h.cfgMu.Lock()
	h.Cfg.Tunnel.Token = tok
	h.Cfg.Tunnel.QuickTunnel = false
	h.Cfg.Tunnel.ConfigFile = ""
	err = h.SaveConfig()
	h.cfgMu.Unlock()
	h.cfCacheClear()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "tunnel not saved: " + err.Error()})
		return false
	}
	return true
}

type cfCreateTunnelReq struct {
	Name   string `json:"name"`
	Select bool   `json:"select"`
}

func (h *Handler) cfCreateTunnel(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	var req cfCreateTunnelReq
	if !decodeJSON(w, r, &req) {
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	if !cfTunnelNameRe.MatchString(req.Name) {
		badRequest(w, "Give the tunnel a name of letters, digits, spaces, '-', '_' or '.' (up to 63 characters).", nil)
		return
	}
	c := h.cfContext()
	if !cfReady(w, c, false) {
		return
	}
	if req.Select && h.Tunnel != nil && h.Tunnel.Status().Running {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "Stop the running tunnel before switching to a new one."})
		return
	}
	t, err := c.client.CreateTunnel(ctx, c.account, req.Name)
	if err != nil {
		cfFail(w, err)
		return
	}
	selected := c.tunnelID
	if req.Select {
		if !h.useTunnel(ctx, w, c, t.ID) {
			return // the tunnel exists on Cloudflare; the error says why it was not selected
		}
		selected = t.ID
	}
	writeJSON(w, http.StatusOK, map[string]any{"tunnel": tunnelView(*t, selected), "selected": req.Select})
}

func (h *Handler) cfSelectTunnel(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	var req struct {
		TunnelID string `json:"tunnel_id"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	if !cfIDRe.MatchString(req.TunnelID) {
		badRequest(w, "bad tunnel id", nil)
		return
	}
	c := h.cfContext()
	if !cfReady(w, c, false) {
		return
	}
	if !h.useTunnel(ctx, w, c, req.TunnelID) {
		return
	}
	writeJSON(w, http.StatusOK, h.buildCFStatus(ctx))
}

var cfIDRe = regexp.MustCompile(`^[A-Za-z0-9-]{1,64}$`)

func (h *Handler) cfDeleteTunnel(ctx context.Context, w http.ResponseWriter, id string) {
	if !cfIDRe.MatchString(id) {
		badRequest(w, "bad tunnel id", nil)
		return
	}
	c := h.cfContext()
	if !cfReady(w, c, false) {
		return
	}
	if id == c.tunnelID {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "This is the tunnel Irongrid is configured to run. Switch to another tunnel before deleting it."})
		return
	}
	if err := c.client.DeleteTunnel(ctx, c.account, id); err != nil {
		cfFail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"deleted": id})
}

// ---- hostnames ----

type dnsView struct {
	// State: ok | proxy_off | missing | conflict | no_zone | unknown
	State    string `json:"state"`
	Zone     string `json:"zone,omitempty"`
	ZoneID   string `json:"zone_id,omitempty"`
	RecordID string `json:"record_id,omitempty"`
	Detail   string `json:"detail,omitempty"`
}

type hostnameView struct {
	Hostname        string  `json:"hostname"`
	Path            string  `json:"path,omitempty"`
	Service         string  `json:"service"`
	NoTLSVerify     bool    `json:"no_tls_verify"`
	OriginServer    string  `json:"origin_server_name,omitempty"`
	DNS             dnsView `json:"dns"`
	OriginReachable *bool   `json:"origin_reachable"`
}

type cfHostnamesResp struct {
	TunnelID  string         `json:"tunnel_id"`
	Hostnames []hostnameView `json:"hostnames"`
	CatchAll  string         `json:"catch_all"`
	DNSError  string         `json:"dns_error,omitempty"`
	// DNSDeniedZones are zones whose DNS records Cloudflare will not let the
	// token read: the token can see them but has no DNS permission on them.
	DNSDeniedZones []string `json:"dns_denied_zones,omitempty"`
	// DNSViaACME is set when the ACME (certificate) token had to be used for
	// DNS records because the tunnel token was refused.
	DNSViaACME bool `json:"dns_via_acme,omitempty"`
}

// cfServicePorts lists the origin schemes a tunnel hostname can point at and
// their default ports ("" = a port is required).
var cfServicePorts = map[string]string{"http": "80", "https": "443", "tcp": "", "ssh": "22", "rdp": "3389", "smb": "445"}

func validCFService(s string) string {
	if s == "" || len(s) > 300 {
		return "Enter the origin, for example https://localhost:443"
	}
	if s == "hello_world" {
		return ""
	}
	if code, ok := strings.CutPrefix(s, "http_status:"); ok {
		if n, err := strconv.Atoi(code); err != nil || n < 100 || n > 599 {
			return "http_status needs a status code between 100 and 599"
		}
		return ""
	}
	u, err := url.Parse(s)
	if err != nil || u.Host == "" || u.Hostname() == "" {
		return "The origin must look like https://localhost:443 (scheme, host and optional port)"
	}
	def, ok := cfServicePorts[u.Scheme]
	if !ok {
		return "The origin scheme must be http, https, tcp, ssh, rdp or smb"
	}
	if u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
		return "The origin cannot include credentials, a path or a query"
	}
	if p := u.Port(); p != "" {
		if n, err := strconv.Atoi(p); err != nil || n < 1 || n > 65535 {
			return "The origin port must be between 1 and 65535"
		}
	} else if def == "" {
		return "A tcp origin needs a port, for example tcp://localhost:5432"
	}
	return ""
}

func normHost(s string) string { return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(s)), ".") }

func validCFHostname(h string) bool {
	h = strings.TrimPrefix(h, "*.")
	if h == "" || len(h) > 253 || !strings.Contains(h, ".") {
		return false
	}
	for l := range strings.SplitSeq(h, ".") {
		if l == "" || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
			return false
		}
		for i := 0; i < len(l); i++ {
			c := l[i]
			if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
				return false
			}
		}
	}
	return true
}

// originReachable reports whether a loopback origin accepts connections. It
// only ever dials loopback: for anything else Cloudflare's connector, not this
// host, is the one that reaches the origin, so there is nothing honest to say.
func originReachable(service string) *bool {
	u, err := url.Parse(service)
	if err != nil || u.Host == "" {
		return nil
	}
	def, ok := cfServicePorts[u.Scheme]
	if !ok {
		return nil
	}
	host := u.Hostname()
	if ip := net.ParseIP(host); host != "localhost" && (ip == nil || !ip.IsLoopback()) {
		return nil
	}
	port := u.Port()
	if port == "" {
		port = def
	}
	if port == "" {
		return nil
	}
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, port), 400*time.Millisecond)
	up := err == nil
	if up {
		_ = conn.Close()
	}
	return &up
}

// ensureDNS makes the hostname's DNS point at the tunnel: a proxied CNAME to
// <tunnel>.cfargotunnel.com. It never deletes anything, and it refuses to
// overwrite a record that is not a CNAME (or a CNAME to somewhere else unless
// overwrite is set), because that would take another service offline.
func ensureDNS(ctx context.Context, cl dnsClient, tunnelID, host string, zones []cfapi.Zone, overwrite bool) (dnsView, error) {
	z := cfapi.ZoneFor(zones, host)
	if z == nil {
		return dnsView{State: "no_zone", Detail: "no Cloudflare zone for this name is visible to the API token"}, nil
	}
	v := dnsView{Zone: z.Name, ZoneID: z.ID}
	recs, err := cl.RecordsNamed(ctx, z.ID, host)
	if err != nil {
		return v, dnsDenied(z.Name, err)
	}
	target := cfapi.TunnelTarget(tunnelID)
	var cname *cfapi.Record
	for i := range recs {
		if recs[i].Type != "CNAME" {
			v.State = "conflict"
			v.Detail = "a " + recs[i].Type + " record already exists for this name; remove it in Cloudflare first"
			return v, nil
		}
		cname = &recs[i]
	}
	switch {
	case cname == nil:
		rec, err := cl.CreateTunnelCNAME(ctx, z.ID, host, tunnelID)
		if err != nil {
			return v, dnsDenied(z.Name, err)
		}
		v.State, v.RecordID = "ok", rec.ID
	case strings.EqualFold(cname.Content, target) && cname.Proxied:
		v.State, v.RecordID = "ok", cname.ID
	case strings.EqualFold(cname.Content, target) || overwrite:
		rec, err := cl.UpdateTunnelCNAME(ctx, z.ID, cname.ID, host, tunnelID)
		if err != nil {
			return v, dnsDenied(z.Name, err)
		}
		v.State, v.RecordID = "ok", rec.ID
	default:
		v.State, v.RecordID = "conflict", cname.ID
		v.Detail = "already points at " + cname.Content + ", not this tunnel"
	}
	return v, nil
}

// dnsDiag carries what went wrong while checking DNS, separating "this token
// has no DNS permission on these zones" (fixable in Cloudflare) from other
// failures.
type dnsDiag struct {
	Err    string   // zones could not be listed, or a lookup failed for another reason
	Denied []string // zones whose DNS records Cloudflare will not let the token read
}

// dnsStates describes, without changing anything, where each hostname's DNS
// stands relative to the tunnel.
func dnsStates(ctx context.Context, cl dnsClient, tunnelID string, hosts []string) (map[string]dnsView, dnsDiag) {
	out := make(map[string]dnsView, len(hosts))
	var diag dnsDiag
	zones, err := cl.ListZones(ctx)
	if err != nil {
		for _, h := range hosts {
			out[h] = dnsView{State: "unknown", Detail: "the API token cannot read DNS zones"}
		}
		diag.Err = err.Error()
		return out, diag
	}
	pointing := map[string][]cfapi.Record{}
	loaded := map[string]bool{}
	denied := map[string]bool{}
	deny := func(zone string) {
		if !denied[zone] {
			denied[zone] = true
			diag.Denied = append(diag.Denied, zone)
		}
	}
	for _, host := range hosts {
		z := cfapi.ZoneFor(zones, host)
		if z == nil {
			out[host] = dnsView{State: "no_zone", Detail: "no Cloudflare zone for this name is visible to the API token"}
			continue
		}
		v := dnsView{Zone: z.Name, ZoneID: z.ID}
		if !loaded[z.ID] {
			loaded[z.ID] = true
			recs, err := cl.RecordsPointingAt(ctx, z.ID, tunnelID)
			switch {
			case cfapi.IsPermission(err):
				deny(z.Name)
			case err != nil && diag.Err == "":
				diag.Err = err.Error()
			}
			pointing[z.ID] = recs
		}
		if denied[z.Name] {
			v.State = "unknown"
			v.Detail = "Cloudflare denies the API token access to DNS records in " + z.Name
			out[host] = v
			continue
		}
		var hit *cfapi.Record
		for i := range pointing[z.ID] {
			if strings.EqualFold(pointing[z.ID][i].Name, host) {
				hit = &pointing[z.ID][i]
			}
		}
		switch {
		case hit != nil && hit.Proxied:
			v.State, v.RecordID = "ok", hit.ID
		case hit != nil:
			v.State, v.RecordID = "proxy_off", hit.ID
			v.Detail = "the CNAME is DNS-only; tunnels need it proxied (orange cloud)"
		default:
			others, err := cl.RecordsNamed(ctx, z.ID, host)
			switch {
			case cfapi.IsPermission(err):
				deny(z.Name)
				v.State = "unknown"
				v.Detail = "Cloudflare denies the API token access to DNS records in " + z.Name
			case err != nil:
				v.State, v.Detail = "unknown", err.Error()
			case len(others) == 0:
				v.State, v.Detail = "missing", "no DNS record routes this name to the tunnel"
			default:
				v.State = "conflict"
				v.Detail = "a " + others[0].Type + " record for this name points at " + others[0].Content + " instead"
				v.RecordID = others[0].ID
			}
		}
		out[host] = v
	}
	return out, diag
}

func (h *Handler) cfCacheGet(key string) *cfHostnamesResp {
	h.cfCacheMu.Lock()
	defer h.cfCacheMu.Unlock()
	if h.cfCacheVal != nil && h.cfCacheKey == key && time.Since(h.cfCacheAt) < 4*time.Second {
		return h.cfCacheVal
	}
	return nil
}

func (h *Handler) cfCachePut(key string, v *cfHostnamesResp) {
	h.cfCacheMu.Lock()
	h.cfCacheKey, h.cfCacheAt, h.cfCacheVal = key, time.Now(), v
	h.cfCacheMu.Unlock()
}

func (h *Handler) cfCacheClear() {
	h.cfCacheMu.Lock()
	h.cfCacheVal = nil
	h.cfCacheMu.Unlock()
}

func (h *Handler) cfHostnames(ctx context.Context, w http.ResponseWriter) {
	c := h.cfContext()
	if !cfReady(w, c, true) {
		return
	}
	if v := h.cfCacheGet(c.tunnelID); v != nil {
		writeJSON(w, http.StatusOK, v)
		return
	}
	cfg, err := c.client.GetConfig(ctx, c.account, c.tunnelID)
	if err != nil {
		cfFail(w, err)
		return
	}
	rules := cfg.Hostnames()
	hosts := make([]string, 0, len(rules))
	for _, r := range rules {
		hosts = append(hosts, normHost(r.Hostname()))
	}
	dns, diag := dnsStates(ctx, c.dns, c.tunnelID, hosts)
	resp := &cfHostnamesResp{
		TunnelID: c.tunnelID, Hostnames: make([]hostnameView, 0, len(rules)), CatchAll: cfg.CatchAll(),
		DNSError: diag.Err, DNSDeniedZones: diag.Denied, DNSViaACME: c.dns.used.Load(),
	}
	for i, r := range rules {
		resp.Hostnames = append(resp.Hostnames, hostnameView{
			Hostname: r.Hostname(), Path: r.Path(), Service: r.Service(), NoTLSVerify: r.NoTLSVerify(), OriginServer: r.OriginServerName(),
			DNS: dns[hosts[i]], OriginReachable: originReachable(r.Service()),
		})
	}
	h.cfCachePut(c.tunnelID, resp)
	writeJSON(w, http.StatusOK, resp)
}

type cfHostnameReq struct {
	Hostname    string `json:"hostname"`
	Service     string `json:"service"`
	Path        string `json:"path"`
	NoTLSVerify bool   `json:"no_tls_verify"`
	// OriginServerName verifies the origin's certificate as this name instead
	// of the one in the origin URL (e.g. localhost).
	OriginServerName string `json:"origin_server_name"`
	CreateDNS        *bool  `json:"create_dns"` // default true
	OverwriteDNS     bool   `json:"overwrite_dns"`
}

// cfEditable loads the tunnel and refuses ones whose hostnames live in a local
// config file, which the API cannot edit.
func (h *Handler) cfEditable(ctx context.Context, w http.ResponseWriter, c cfCtx) bool {
	t, err := c.client.GetTunnel(ctx, c.account, c.tunnelID)
	if err != nil {
		cfFail(w, err)
		return false
	}
	if t.ConfigSrc == "local" {
		badRequest(w, "This tunnel is configured by a local config file, so its hostnames can't be managed here. Use a remotely-managed tunnel.", nil)
		return false
	}
	return true
}

func (h *Handler) cfUpsertHostname(ctx context.Context, w http.ResponseWriter, r *http.Request, mustExist bool) {
	var req cfHostnameReq
	if !decodeJSON(w, r, &req) {
		return
	}
	req.Hostname = normHost(req.Hostname)
	req.Service = strings.TrimSpace(req.Service)
	req.Path = strings.TrimSpace(req.Path)
	if !validCFHostname(req.Hostname) {
		badRequest(w, "Enter a full hostname such as dns.example.com (a leading *. wildcard is allowed).", nil)
		return
	}
	if msg := validCFService(req.Service); msg != "" {
		badRequest(w, msg, nil)
		return
	}
	if len(req.Path) > 200 || strings.ContainsAny(req.Path, " \t\r\n") {
		badRequest(w, "The path filter can't contain spaces and must be under 200 characters.", nil)
		return
	}
	req.OriginServerName = normHost(req.OriginServerName)
	if req.OriginServerName != "" && (strings.HasPrefix(req.OriginServerName, "*.") || !validCFHostname(req.OriginServerName)) {
		badRequest(w, "The certificate name must be a full hostname such as dns.example.com (no wildcard).", nil)
		return
	}
	c := h.cfContext()
	if !cfReady(w, c, true) {
		return
	}
	h.cfMu.Lock()
	defer h.cfMu.Unlock()
	if !h.cfEditable(ctx, w, c) {
		return
	}
	cfg, err := c.client.GetConfig(ctx, c.account, c.tunnelID)
	if err != nil {
		cfFail(w, err)
		return
	}
	if mustExist && cfg.Find(req.Hostname) < 0 {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "That hostname is not on this tunnel."})
		return
	}
	replaced := cfg.Upsert(cfapi.NewRuleOrigin(req.Hostname, req.Service, req.Path, req.NoTLSVerify, req.OriginServerName))
	if err := c.client.PutConfig(ctx, c.account, c.tunnelID, cfg); err != nil {
		cfFail(w, err)
		return
	}
	h.cfCacheClear()

	resp := map[string]any{"saved": true, "replaced": replaced, "hostname": req.Hostname}
	if req.CreateDNS == nil || *req.CreateDNS {
		zones, err := c.dns.ListZones(ctx)
		var dns dnsView
		if err == nil {
			dns, err = ensureDNS(ctx, c.dns, c.tunnelID, req.Hostname, zones, req.OverwriteDNS)
		}
		if c.dns.used.Load() {
			resp["dns_via_acme"] = true
		}
		if err != nil {
			// The hostname is on the tunnel; only its DNS needs another try.
			resp["dns_error"] = err.Error()
		} else {
			resp["dns"] = dns
		}
		h.cfCacheClear()
	}
	writeJSON(w, http.StatusOK, resp)
}

func (h *Handler) cfDeleteHostname(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	host := normHost(r.URL.Query().Get("hostname"))
	if !validCFHostname(host) {
		badRequest(w, "bad hostname", nil)
		return
	}
	withDNS := r.URL.Query().Get("dns") == "1"
	c := h.cfContext()
	if !cfReady(w, c, true) {
		return
	}
	h.cfMu.Lock()
	defer h.cfMu.Unlock()
	if !h.cfEditable(ctx, w, c) {
		return
	}
	cfg, err := c.client.GetConfig(ctx, c.account, c.tunnelID)
	if err != nil {
		cfFail(w, err)
		return
	}
	if !cfg.Remove(host) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "That hostname is not on this tunnel."})
		return
	}
	if err := c.client.PutConfig(ctx, c.account, c.tunnelID, cfg); err != nil {
		cfFail(w, err)
		return
	}
	h.cfCacheClear()
	resp := map[string]any{"removed": true, "hostname": host, "dns_removed": 0}
	if withDNS {
		removed, err := removeTunnelDNS(ctx, c.dns, c.tunnelID, host)
		resp["dns_removed"] = removed
		if c.dns.used.Load() {
			resp["dns_via_acme"] = true
		}
		if err != nil {
			resp["dns_error"] = err.Error()
		}
		h.cfCacheClear()
	}
	writeJSON(w, http.StatusOK, resp)
}

// removeTunnelDNS deletes the CNAMEs for host that point at this tunnel. A
// record pointing anywhere else is somebody else's and is left alone.
func removeTunnelDNS(ctx context.Context, cl dnsClient, tunnelID, host string) (int, error) {
	zones, err := cl.ListZones(ctx)
	if err != nil {
		return 0, err
	}
	z := cfapi.ZoneFor(zones, host)
	if z == nil {
		return 0, nil
	}
	recs, err := cl.RecordsNamed(ctx, z.ID, host)
	if err != nil {
		return 0, dnsDenied(z.Name, err)
	}
	n := 0
	for _, rec := range recs {
		if rec.Type == "CNAME" && strings.EqualFold(rec.Content, cfapi.TunnelTarget(tunnelID)) {
			if err := cl.DeleteRecord(ctx, z.ID, rec.ID); err != nil {
				return n, dnsDenied(z.Name, err)
			}
			n++
		}
	}
	return n, nil
}

func (h *Handler) cfSyncDNS(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	var req struct {
		Hostname  string `json:"hostname"`
		Overwrite bool   `json:"overwrite"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	host := normHost(req.Hostname)
	if !validCFHostname(host) {
		badRequest(w, "bad hostname", nil)
		return
	}
	c := h.cfContext()
	if !cfReady(w, c, true) {
		return
	}
	cfg, err := c.client.GetConfig(ctx, c.account, c.tunnelID)
	if err != nil {
		cfFail(w, err)
		return
	}
	if cfg.Find(host) < 0 {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "That hostname is not on this tunnel."})
		return
	}
	zones, err := c.dns.ListZones(ctx)
	if err != nil {
		cfFail(w, err)
		return
	}
	dns, err := ensureDNS(ctx, c.dns, c.tunnelID, host, zones, req.Overwrite)
	if err != nil {
		cfFail(w, err)
		return
	}
	h.cfCacheClear()
	writeJSON(w, http.StatusOK, map[string]any{"hostname": host, "dns": dns, "dns_via_acme": c.dns.used.Load()})
}
