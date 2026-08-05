package api

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"

	"github.com/eoghan2t9/Irongrid-DNS/internal/acme"
	"github.com/eoghan2t9/Irongrid-DNS/internal/cache"
	"github.com/eoghan2t9/Irongrid-DNS/internal/catalog"
	"github.com/eoghan2t9/Irongrid-DNS/internal/cert"
	"github.com/eoghan2t9/Irongrid-DNS/internal/config"
	"github.com/eoghan2t9/Irongrid-DNS/internal/dnsserver"
	"github.com/eoghan2t9/Irongrid-DNS/internal/filter"
	"github.com/eoghan2t9/Irongrid-DNS/internal/querylog"
	"github.com/eoghan2t9/Irongrid-DNS/internal/tunnel"
	"github.com/eoghan2t9/Irongrid-DNS/internal/update"
	"github.com/eoghan2t9/Irongrid-DNS/internal/upstream"
	"github.com/eoghan2t9/Irongrid-DNS/internal/version"
)

// Handler implements the REST endpoints. It is created by main and injected
// into the router.
type Handler struct {
	cfgMu      sync.Mutex // guards Cfg mutations + SaveConfig
	Cfg        *config.Config
	ConfigPath string
	SaveConfig func() error
	// Reload rebinds listeners, cache, TLS and the web server from the
	// current in-memory config. Wired up by main; nil when unavailable.
	Reload func() error
	// ReloadTLS regenerates the TLS config and rebinds only the DNS listeners
	// (DoT/DoH/DoQ + plain). Used after the dashboard generates or uploads a
	// certificate, without touching the cache or upstreams.
	ReloadTLS func() error
	// ACME is the Let's Encrypt manager; nil when disabled.
	ACME interface {
		GetStatus() acme.Status
		ForceIssue(context.Context) error
		NeedsRenewal() bool
	}

	Engine    *filter.Engine
	Lists     *filter.ListManager
	Cache     *cache.Cache
	Log       *querylog.Log
	DNS       *dnsserver.Handler
	Tunnel    *tunnel.Manager
	Upstreams []*upstream.Upstream
	Catalog   *catalog.Catalog
	StartedAt time.Time
	Version   string
}

// HandleAPI dispatches /api/* requests.
func (h *Handler) HandleAPI(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/")
	path = strings.TrimSuffix(path, "/")
	parts := strings.Split(path, "/")

	ctx := r.Context()
	switch {
	case len(parts) == 1 && parts[0] == "status" && r.Method == http.MethodGet:
		h.getStatus(w)
	case len(parts) == 1 && parts[0] == "stats" && r.Method == http.MethodGet:
		h.getStats(ctx, w)
	case len(parts) == 1 && parts[0] == "log" && r.Method == http.MethodGet:
		h.getLog(ctx, w, r)
	case len(parts) == 1 && parts[0] == "log" && r.Method == http.MethodDelete:
		h.clearLog(ctx, w)
	case len(parts) == 1 && parts[0] == "lists" && r.Method == http.MethodGet:
		h.getLists(w)
	case len(parts) == 1 && parts[0] == "lists" && r.Method == http.MethodPost:
		h.addList(w, r)
	case len(parts) == 2 && parts[0] == "lists" && r.Method == http.MethodPut:
		h.updateList(w, r, parts[1])
	case len(parts) == 2 && parts[0] == "lists" && r.Method == http.MethodDelete:
		h.deleteList(w, parts[1])
	case len(parts) == 2 && parts[0] == "lists" && parts[1] == "refresh" && r.Method == http.MethodPost:
		h.refreshAllLists(ctx, w)
	case len(parts) == 3 && parts[0] == "lists" && parts[2] == "fetch" && r.Method == http.MethodPost:
		h.refreshList(ctx, w, parts[1])
	case len(parts) == 3 && parts[0] == "lists" && parts[2] == "content" && r.Method == http.MethodGet:
		h.getListContent(w, parts[1])
	case len(parts) == 2 && parts[0] == "lists" && parts[1] == "catalog" && r.Method == http.MethodGet:
		h.getCatalog(w)
	case len(parts) == 2 && parts[0] == "filter" && parts[1] == "whitelist" && r.Method == http.MethodGet:
		h.getFilterList(w, "whitelist")
	case len(parts) == 2 && parts[0] == "filter" && parts[1] == "whitelist" && r.Method == http.MethodPost:
		h.addFilterEntry(w, r, "whitelist")
	case len(parts) == 2 && parts[0] == "filter" && parts[1] == "blacklist" && r.Method == http.MethodGet:
		h.getFilterList(w, "blacklist")
	case len(parts) == 2 && parts[0] == "filter" && parts[1] == "blacklist" && r.Method == http.MethodPost:
		h.addFilterEntry(w, r, "blacklist")
	case len(parts) == 2 && parts[0] == "filter" && parts[1] == "delete" && r.Method == http.MethodPost:
		h.deleteFilterEntry(w, r)
	case len(parts) == 2 && parts[0] == "filter" && parts[1] == "check" && r.Method == http.MethodPost:
		h.checkFilter(w, r)
	case len(parts) == 2 && parts[0] == "cache" && parts[1] == "flush" && r.Method == http.MethodPost:
		h.flushCache(ctx, w)
	case len(parts) == 2 && parts[0] == "tunnel" && parts[1] == "status" && r.Method == http.MethodGet:
		h.tunnelStatus(w)
	case len(parts) == 2 && parts[0] == "tunnel" && parts[1] == "start" && r.Method == http.MethodPost:
		h.tunnelStart(w, r)
	case len(parts) == 2 && parts[0] == "tunnel" && parts[1] == "stop" && r.Method == http.MethodPost:
		h.tunnelStop(w)
	case len(parts) == 2 && parts[0] == "tunnel" && parts[1] == "log" && r.Method == http.MethodGet:
		h.tunnelLog(w)
	case len(parts) == 1 && parts[0] == "config" && r.Method == http.MethodGet:
		h.getConfig(w)
	case len(parts) == 1 && parts[0] == "config" && r.Method == http.MethodPut:
		h.putConfig(w, r)
	case len(parts) == 2 && parts[0] == "config" && parts[1] == "reload" && r.Method == http.MethodPost:
		h.reloadConfig(w)
	case len(parts) == 2 && parts[0] == "diag" && parts[1] == "dns" && r.Method == http.MethodGet:
		h.diagDNS(ctx, w, r)
	case len(parts) == 2 && parts[0] == "update" && parts[1] == "check" && r.Method == http.MethodGet:
		h.checkUpdate(ctx, w)
	case len(parts) == 1 && parts[0] == "tls" && r.Method == http.MethodGet:
		h.getTLS(w)
	case len(parts) == 2 && parts[0] == "tls" && parts[1] == "generate" && r.Method == http.MethodPost:
		h.generateTLS(w, r)
	case len(parts) == 2 && parts[0] == "tls" && parts[1] == "upload" && r.Method == http.MethodPost:
		h.uploadTLS(w, r)
	case len(parts) == 2 && parts[0] == "tls" && parts[1] == "cert" && r.Method == http.MethodGet:
		h.downloadCert(w)
	case len(parts) == 3 && parts[0] == "tls" && parts[1] == "acme" && parts[2] == "issue" && r.Method == http.MethodPost:
		h.issueACME(ctx, w)
	default:
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
	}
}

// ---- status & stats ----

func (h *Handler) getStatus(w http.ResponseWriter) {
	h.cfgMu.Lock()
	defer h.cfgMu.Unlock()
	listeners := map[string]bool{}
	for _, proto := range []string{"udp", "tcp", "dot", "doh", "doq"} {
		s := h.Cfg.Server
		listeners[proto] = (proto == "udp" && s.ListenUDP != "") ||
			(proto == "tcp" && s.ListenTCP != "") ||
			(proto == "dot" && s.ListenDoT != "") ||
			(proto == "doh" && s.ListenDoH != "") ||
			(proto == "doq" && s.ListenDoQ != "")
	}
	cacheOK := true
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if h.Cache != nil {
		if err := h.Cache.Ping(ctx); err != nil {
			cacheOK = false
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"version":     version.String(),
		"uptime_sec":  int(time.Since(h.StartedAt).Seconds()),
		"listeners":   listeners,
		"cache_ok":    cacheOK,
		"tunnel":      h.Tunnel.Status(),
	})
}

func (h *Handler) getStats(ctx context.Context, w http.ResponseWriter) {
	days := 1
	stats, err := h.Log.Stats(ctx, time.Now().Add(-time.Duration(days)*24*time.Hour))
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	proto := map[string]int64{}
	for k, v := range h.DNS.Stats.ByProtocol {
		proto[k] = v.Load()
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"query":  stats,
		"counters": map[string]int64{
			"total":   h.DNS.Stats.Total.Load(),
			"blocked": h.DNS.Stats.Blocked.Load(),
			"allowed": h.DNS.Stats.Allowed.Load(),
			"cached":  h.DNS.Stats.Cached.Load(),
			"errors":  h.DNS.Stats.Errors.Load(),
		},
		"protocol": proto,
		"filter":   h.Engine.Stats(),
	})
}

// ---- query log ----

func (h *Handler) getLog(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	limit, _ := strconv.Atoi(q.Get("limit"))
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	offset, _ := strconv.Atoi(q.Get("offset"))
	entries, err := h.Log.Query(ctx, limit, offset, q.Get("action"), q.Get("domain"), q.Get("qtype"))
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"entries": entries})
}

func (h *Handler) clearLog(ctx context.Context, w http.ResponseWriter) {
	// Truncate via SQLite; simplest robust approach is a destructive delete.
	if _, err := h.Log.Exec(ctx, "DELETE FROM queries"); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"ok": "cleared"})
}

// ---- blocklists ----

func (h *Handler) getLists(w http.ResponseWriter) {
	snapshot := h.Lists.Snapshot()
	sort.Slice(snapshot, func(i, j int) bool { return snapshot[i].Spec.ID < snapshot[j].Spec.ID })
	writeJSON(w, http.StatusOK, map[string]any{"lists": snapshot})
}

type listPayload struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	URL        string `json:"url"`
	Enabled    bool   `json:"enabled"`
	AutoUpdate int    `json:"auto_update_hours"`
}

func (h *Handler) addList(w http.ResponseWriter, r *http.Request) {
	h.cfgMu.Lock()
	defer h.cfgMu.Unlock()
	var p listPayload
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil || p.ID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "id, url required"})
		return
	}
	h.Cfg.Filter.Blocklists = append(h.Cfg.Filter.Blocklists, config.BlocklistSpec{
		ID:         p.ID,
		Name:       p.Name,
		URL:        p.URL,
		Enabled:    p.Enabled,
		AutoUpdate: time.Duration(p.AutoUpdate) * time.Hour,
	})
	h.applyLists()
	if err := h.SaveConfig(); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"ok": "added"})
}

func (h *Handler) updateList(w http.ResponseWriter, r *http.Request, id string) {
	h.cfgMu.Lock()
	defer h.cfgMu.Unlock()
	var p listPayload
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad body"})
		return
	}
	changed := false
	for i := range h.Cfg.Filter.Blocklists {
		if h.Cfg.Filter.Blocklists[i].ID == id {
			s := &h.Cfg.Filter.Blocklists[i]
			if p.Name != "" {
				s.Name = p.Name
			}
			if p.URL != "" {
				s.URL = p.URL
			}
			s.Enabled = p.Enabled
			s.AutoUpdate = time.Duration(p.AutoUpdate) * time.Hour
			changed = true
			break
		}
	}
	if !changed {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "list not found"})
		return
	}
	h.applyLists()
	if err := h.SaveConfig(); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"ok": "updated"})
}

func (h *Handler) deleteList(w http.ResponseWriter, id string) {
	h.cfgMu.Lock()
	defer h.cfgMu.Unlock()
	lists := h.Cfg.Filter.Blocklists[:0]
	found := false
	for _, s := range h.Cfg.Filter.Blocklists {
		if s.ID == id {
			found = true
			continue
		}
		lists = append(lists, s)
	}
	if !found {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "list not found"})
		return
	}
	h.Cfg.Filter.Blocklists = lists
	h.applyLists()
	_ = h.SaveConfig()
	writeJSON(w, http.StatusOK, map[string]string{"ok": "deleted"})
}

func (h *Handler) refreshAllLists(ctx context.Context, w http.ResponseWriter) {
	err := h.Lists.FetchAll(ctx)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	h.Lists.ReloadAll()
	writeJSON(w, http.StatusOK, map[string]string{"ok": "refreshed"})
}

func (h *Handler) refreshList(ctx context.Context, w http.ResponseWriter, id string) {
	if err := h.Lists.FetchOne(ctx, id); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	h.Lists.ReloadAll()
	writeJSON(w, http.StatusOK, map[string]string{"ok": "refreshed"})
}

func (h *Handler) getListContent(w http.ResponseWriter, id string) {
	content := h.Lists.GetContent(id)
	if content == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "no content cached"})
		return
	}
	w.Header().Set("Content-Type", "text/plain")
	w.Write(content)
}

// getCatalog serves the curated blocklist/whitelist presets.
func (h *Handler) getCatalog(w http.ResponseWriter) {
	if h.Catalog == nil {
		writeJSON(w, http.StatusOK, catalog.Default())
		return
	}
	writeJSON(w, http.StatusOK, h.Catalog)
}

// applyLists pushes config specs into the manager and reloads the engine.
func (h *Handler) applyLists() {
	specs := make([]filter.ListSpec, 0, len(h.Cfg.Filter.Blocklists))
	for _, s := range h.Cfg.Filter.Blocklists {
		specs = append(specs, filter.ListSpec{
			ID: s.ID, Name: s.Name, URL: s.URL,
			Enabled: s.Enabled, AutoUpdate: s.AutoUpdate,
		})
	}
	h.Lists.SetSpecs(specs)
	h.Lists.LoadCached()
	h.Lists.ReloadAll()
}

// ---- whitelist / blacklist ----

func (h *Handler) getFilterList(w http.ResponseWriter, which string) {
	var list []string
	if which == "whitelist" {
		list = h.Cfg.Filter.Whitelist
	} else {
		list = h.Cfg.Filter.Blacklist
	}
	writeJSON(w, http.StatusOK, map[string]any{which: list})
}

type filterEntryPayload struct {
	Entry string `json:"entry"`
}

func (h *Handler) addFilterEntry(w http.ResponseWriter, r *http.Request, which string) {
	h.cfgMu.Lock()
	defer h.cfgMu.Unlock()
	var p filterEntryPayload
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil || p.Entry == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "entry required"})
		return
	}
	entry := strings.ToLower(strings.TrimSpace(p.Entry))
	if which == "whitelist" {
		if !contains(h.Cfg.Filter.Whitelist, entry) {
			h.Cfg.Filter.Whitelist = append(h.Cfg.Filter.Whitelist, entry)
		}
	} else {
		if !contains(h.Cfg.Filter.Blacklist, entry) {
			h.Cfg.Filter.Blacklist = append(h.Cfg.Filter.Blacklist, entry)
		}
	}
	h.applyUserLists()
	_ = h.SaveConfig()
	writeJSON(w, http.StatusOK, map[string]string{"ok": "added"})
}

type filterDeletePayload struct {
	Entry string `json:"entry"`
	Kind  string `json:"kind"` // whitelist | blacklist
}

func (h *Handler) deleteFilterEntry(w http.ResponseWriter, r *http.Request) {
	h.cfgMu.Lock()
	defer h.cfgMu.Unlock()
	var p filterDeletePayload
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil || p.Entry == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "entry, kind required"})
		return
	}
	switch p.Kind {
	case "whitelist":
		h.Cfg.Filter.Whitelist = removeStr(h.Cfg.Filter.Whitelist, p.Entry)
	case "blacklist":
		h.Cfg.Filter.Blacklist = removeStr(h.Cfg.Filter.Blacklist, p.Entry)
	default:
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "kind must be whitelist or blacklist"})
		return
	}
	h.applyUserLists()
	_ = h.SaveConfig()
	writeJSON(w, http.StatusOK, map[string]string{"ok": "deleted"})
}

func (h *Handler) applyUserLists() {
	h.Engine.SetUserLists(h.Cfg.Filter.Blacklist, h.Cfg.Filter.Whitelist)
	h.Engine.Compile()
}

func (h *Handler) checkFilter(w http.ResponseWriter, r *http.Request) {
	var p filterEntryPayload
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil || p.Entry == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "entry required"})
		return
	}
	name := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(p.Entry), "."))
	if ip := net.ParseIP(name); ip != nil {
		blocked, reason := h.Engine.CheckIPs([]net.IP{ip})
		writeJSON(w, http.StatusOK, map[string]any{"domain": name, "blocked": blocked, "reason": reason})
		return
	}
	d := h.Engine.DecideDomain(name)
	writeJSON(w, http.StatusOK, map[string]any{
		"domain":  name,
		"blocked": d.Action == filter.Block,
		"reason":  d.Reason,
		"list":    d.ListName,
	})
}

// ---- cache ----

func (h *Handler) flushCache(ctx context.Context, w http.ResponseWriter) {
	n, err := h.Cache.FlushAll(ctx)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": "flushed", "deleted": n})
}

// ---- tunnel ----

type tunnelStartPayload struct {
	Mode       string `json:"mode"` // quick | token | config
	Token      string `json:"token"`
	ConfigFile string `json:"config_file"`
	Origin     string `json:"origin"`
	Hostname   string `json:"hostname"`
}

func (h *Handler) tunnelStatus(w http.ResponseWriter) {
	writeJSON(w, http.StatusOK, h.Tunnel.Status())
}

func (h *Handler) tunnelStart(w http.ResponseWriter, r *http.Request) {
	var p tunnelStartPayload
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad body"})
		return
	}
	mode := tunnel.Mode(p.Mode)
	if mode == "" {
		mode = tunnel.ModeQuick
	}
	if err := h.Tunnel.Start(mode, p.Token, p.ConfigFile, p.Origin, p.Hostname); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, h.Tunnel.Status())
}

func (h *Handler) tunnelStop(w http.ResponseWriter) {
	h.Tunnel.Stop()
	writeJSON(w, http.StatusOK, h.Tunnel.Status())
}

func (h *Handler) tunnelLog(w http.ResponseWriter) {
	writeJSON(w, http.StatusOK, map[string]any{"lines": h.Tunnel.TailLog(50)})
}

// ---- config & diagnostics ----

// configPayload is the JSON shape used to read and write configuration from
// the web UI. Durations are human strings ("6h") and the web password is a
// plaintext field that is empty unless the user wants to change it.
type configPayload struct {
	Server    serverPayload    `json:"server"`
	Upstreams []string         `json:"upstreams"`
	Cache     cachePayload     `json:"cache"`
	TLS       tlsPayload       `json:"tls"`
	Filter    filterPayload    `json:"filter"`
	Log       logPayload       `json:"log"`
	Web       webPayload       `json:"web"`
	Tunnel    tunnelPayload    `json:"tunnel"`
}

type serverPayload struct {
	ListenUDP       string `json:"listen_udp"`
	ListenTCP       string `json:"listen_tcp"`
	ListenDoT       string `json:"listen_dot"`
	ListenDoH       string `json:"listen_doh"`
	ListenDoQ       string `json:"listen_doq"`
	DoHPath         string `json:"doh_path"`
	WebListen       string `json:"web_listen"`
	WebTLS          bool   `json:"web_tls"`
	WebRedirect     bool   `json:"web_redirect"`
	WebRedirectPort int    `json:"web_redirect_port"`
	TimeoutSec      int    `json:"timeout_sec"`
}

type cachePayload struct {
	Addr        string `json:"addr"`
	Password    string `json:"password"`
	DB          int    `json:"db"`
	TTL         string `json:"ttl"`
	NegativeTTL string `json:"negative_ttl"`
}

type tlsPayload struct {
	CertFile           string      `json:"cert_file"`
	KeyFile            string      `json:"key_file"`
	GenerateSelfSigned bool        `json:"generate_self_signed"`
	SelfSignedHosts    []string    `json:"self_signed_hosts"`
	CertDir            string      `json:"cert_dir"`
	ACME               acmePayload `json:"acme"`
}

type acmePayload struct {
	Enabled         bool        `json:"enabled"`
	Email           string      `json:"email"`
	Domains         []string    `json:"domains"`
	Staging         bool        `json:"staging"`
	HTTP01Port      int         `json:"http01_port"`
	RenewBeforeDays int         `json:"renew_before_days"`
	DNS01           dns01Payload `json:"dns01"`
}

type dns01Payload struct {
	Provider           string `json:"provider"`
	PropagationWait    int    `json:"propagation_wait_sec"`
	CloudflareToken    string `json:"cloudflare_token"`
	DigitalOceanToken  string `json:"digitalocean_token"`
	HetznerToken       string `json:"hetzner_token"`
	GoDaddyKey         string `json:"godaddy_key"`
	GoDaddySecret      string `json:"godaddy_secret"`
	AWSAccessKeyID     string `json:"aws_access_key_id"`
	AWSSecretAccessKey string `json:"aws_secret_access_key"`
}

type filterPayload struct {
	BlockResponse string              `json:"block_response"`
	BlockTTL      uint32              `json:"block_ttl"`
	Blocklists    []blocklistPayload  `json:"blocklists"`
	Whitelist     []string            `json:"whitelist"`
	Blacklist     []string            `json:"blacklist"`
}

type blocklistPayload struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	URL        string `json:"url"`
	Enabled    bool   `json:"enabled"`
	AutoUpdate string `json:"auto_update"` // duration string, "" = never
}

type logPayload struct {
	QueryLogFile  string `json:"query_log_file"`
	RetentionDays int    `json:"retention_days"`
	Verbose       bool   `json:"verbose"`
}

type webPayload struct {
	Username string `json:"username"`
	Password string `json:"password"` // plaintext; empty keeps the existing hash
}

type tunnelPayload struct {
	Enabled        bool   `json:"enabled"`
	Token          string `json:"token"`
	ConfigFile     string `json:"config_file"`
	QuickTunnel    bool   `json:"quick_tunnel"`
	QuickTunnelURL string `json:"quick_tunnel_url"`
	Hostname       string `json:"hostname"`
}

// payloadFromConfig maps the internal config into the JSON shape.
func payloadFromConfig(c *config.Config) configPayload {
	p := configPayload{
		Server: serverPayload{
			ListenUDP:       c.Server.ListenUDP,
			ListenTCP:       c.Server.ListenTCP,
			ListenDoT:       c.Server.ListenDoT,
			ListenDoH:       c.Server.ListenDoH,
			ListenDoQ:       c.Server.ListenDoQ,
			DoHPath:         c.Server.DoHPath,
			WebListen:       c.Server.WebListen,
			WebTLS:          c.Server.WebTLS,
			WebRedirect:     c.Server.WebRedirect,
			WebRedirectPort: c.Server.WebRedirectPort,
			TimeoutSec:      c.Server.TimeoutSec,
		},
		Upstreams: c.Upstreams,
		Cache: cachePayload{
			Addr:        c.Cache.Addr,
			Password:    c.Cache.Password,
			DB:          c.Cache.DB,
			TTL:         c.Cache.TTL.String(),
			NegativeTTL: c.Cache.NegativeTTL.String(),
		},
		TLS: tlsPayload{
			CertFile:           c.TLS.CertFile,
			KeyFile:            c.TLS.KeyFile,
			GenerateSelfSigned: c.TLS.GenerateSelfSigned,
			SelfSignedHosts:    c.TLS.SelfSignedHosts,
			CertDir:            c.TLS.CertDir,
			ACME: acmePayload{
				Enabled:         c.TLS.ACME.Enabled,
				Email:           c.TLS.ACME.Email,
				Domains:         c.TLS.ACME.Domains,
				Staging:         c.TLS.ACME.Staging,
				HTTP01Port:      c.TLS.ACME.HTTP01Port,
				RenewBeforeDays: c.TLS.ACME.RenewBeforeDays,
				DNS01: dns01Payload{
					Provider:           c.TLS.ACME.DNS01.Provider,
					PropagationWait:    c.TLS.ACME.DNS01.PropagationWait,
					CloudflareToken:    c.TLS.ACME.DNS01.CloudflareToken,
					DigitalOceanToken:  c.TLS.ACME.DNS01.DigitalOceanToken,
					HetznerToken:       c.TLS.ACME.DNS01.HetznerToken,
					GoDaddyKey:         c.TLS.ACME.DNS01.GoDaddyKey,
					GoDaddySecret:      c.TLS.ACME.DNS01.GoDaddySecret,
					AWSAccessKeyID:     c.TLS.ACME.DNS01.AWSAccessKeyID,
					AWSSecretAccessKey: c.TLS.ACME.DNS01.AWSSecretAccessKey,
				},
			},
		},
		Filter: filterPayload{
			BlockResponse: c.Filter.BlockResponse,
			BlockTTL:      c.Filter.BlockTTL,
			Blocklists:    make([]blocklistPayload, 0, len(c.Filter.Blocklists)),
			Whitelist:     c.Filter.Whitelist,
			Blacklist:     c.Filter.Blacklist,
		},
		Log: logPayload{
			QueryLogFile:  c.Log.QueryLogFile,
			RetentionDays: c.Log.RetentionDays,
			Verbose:       c.Log.Verbose,
		},
		Web: webPayload{Username: c.Web.Username},
		Tunnel: tunnelPayload{
			Enabled:        c.Tunnel.Enabled,
			Token:          c.Tunnel.Token,
			ConfigFile:     c.Tunnel.ConfigFile,
			QuickTunnel:    c.Tunnel.QuickTunnel,
			QuickTunnelURL: c.Tunnel.QuickTunnelURL,
			Hostname:       c.Tunnel.Hostname,
		},
	}
	for _, bl := range c.Filter.Blocklists {
		auto := ""
		if bl.AutoUpdate > 0 {
			auto = bl.AutoUpdate.String()
		}
		p.Filter.Blocklists = append(p.Filter.Blocklists, blocklistPayload{
			ID: bl.ID, Name: bl.Name, URL: bl.URL, Enabled: bl.Enabled, AutoUpdate: auto,
		})
	}
	return p
}

// applyPayload validates a submitted config, live-applies the hot parts and
// persists it to disk. It returns the list of sections that need a restart.
func (h *Handler) applyPayload(p configPayload) ([]string, error) {
	parseDur := func(s string) (time.Duration, error) {
		if strings.TrimSpace(s) == "" {
			return 0, nil
		}
		d, err := time.ParseDuration(s)
		if err != nil {
			return 0, err
		}
		return d, nil
	}

	ttl, err := parseDur(p.Cache.TTL)
	if err != nil {
		return nil, fmt.Errorf("cache.ttl: %w", err)
	}
	negTTL, err := parseDur(p.Cache.NegativeTTL)
	if err != nil {
		return nil, fmt.Errorf("cache.negative_ttl: %w", err)
	}

	cfg := &config.Config{
		Server: config.ServerConfig{
			ListenUDP:       p.Server.ListenUDP,
			ListenTCP:       p.Server.ListenTCP,
			ListenDoT:       p.Server.ListenDoT,
			ListenDoH:       p.Server.ListenDoH,
			ListenDoQ:       p.Server.ListenDoQ,
			DoHPath:         p.Server.DoHPath,
			WebListen:       p.Server.WebListen,
			WebTLS:          p.Server.WebTLS,
			WebRedirect:     p.Server.WebRedirect,
			WebRedirectPort: p.Server.WebRedirectPort,
			TimeoutSec:      p.Server.TimeoutSec,
		},
		Upstreams: p.Upstreams,
		Cache: config.CacheConfig{
			Addr:        p.Cache.Addr,
			Password:    p.Cache.Password,
			DB:          p.Cache.DB,
			TTL:         ttl,
			NegativeTTL: negTTL,
		},
		TLS: config.TLSConfig{
			CertFile:           p.TLS.CertFile,
			KeyFile:            p.TLS.KeyFile,
			GenerateSelfSigned: p.TLS.GenerateSelfSigned,
			SelfSignedHosts:    p.TLS.SelfSignedHosts,
			CertDir:            p.TLS.CertDir,
			ACME: config.ACMEConfig{
				Enabled:         p.TLS.ACME.Enabled,
				Email:           p.TLS.ACME.Email,
				Domains:         p.TLS.ACME.Domains,
				Staging:         p.TLS.ACME.Staging,
				HTTP01Port:      p.TLS.ACME.HTTP01Port,
				RenewBeforeDays: p.TLS.ACME.RenewBeforeDays,
				DNS01: config.DNS01Config{
					Provider:           p.TLS.ACME.DNS01.Provider,
					PropagationWait:    p.TLS.ACME.DNS01.PropagationWait,
					CloudflareToken:    p.TLS.ACME.DNS01.CloudflareToken,
					DigitalOceanToken:  p.TLS.ACME.DNS01.DigitalOceanToken,
					HetznerToken:       p.TLS.ACME.DNS01.HetznerToken,
					GoDaddyKey:         p.TLS.ACME.DNS01.GoDaddyKey,
					GoDaddySecret:      p.TLS.ACME.DNS01.GoDaddySecret,
					AWSAccessKeyID:     p.TLS.ACME.DNS01.AWSAccessKeyID,
					AWSSecretAccessKey: p.TLS.ACME.DNS01.AWSSecretAccessKey,
				},
			},
		},
		Filter: config.FilterConfig{
			BlockResponse: p.Filter.BlockResponse,
			BlockTTL:      p.Filter.BlockTTL,
			Blocklists:    make([]config.BlocklistSpec, 0, len(p.Filter.Blocklists)),
			Whitelist:     p.Filter.Whitelist,
			Blacklist:     p.Filter.Blacklist,
		},
		Log: config.LogConfig{
			QueryLogFile:  p.Log.QueryLogFile,
			RetentionDays: p.Log.RetentionDays,
			Verbose:       p.Log.Verbose,
		},
		Web: config.WebConfig{
			Username: p.Web.Username,
			Password: p.Web.Password,
		},
		Tunnel: config.TunnelConfig{
			Enabled:        p.Tunnel.Enabled,
			Token:          p.Tunnel.Token,
			ConfigFile:     p.Tunnel.ConfigFile,
			QuickTunnel:    p.Tunnel.QuickTunnel,
			QuickTunnelURL: p.Tunnel.QuickTunnelURL,
			Hostname:       p.Tunnel.Hostname,
		},
	}
	for _, bl := range p.Filter.Blocklists {
		auto, err := parseDur(bl.AutoUpdate)
		if err != nil {
			return nil, fmt.Errorf("blocklist %s auto_update: %w", bl.ID, err)
		}
		cfg.Filter.Blocklists = append(cfg.Filter.Blocklists, config.BlocklistSpec{
			ID: bl.ID, Name: bl.Name, URL: bl.URL, Enabled: bl.Enabled, AutoUpdate: auto,
		})
	}

	// Keep the existing password hash/session secret unless a new plaintext
	// password was provided (it is bcrypt-hashed by Config.Save).
	if cfg.Web.Password == "" {
		cfg.Web.Password = h.Cfg.Web.Password
	}
	cfg.Web.SessionSecret = h.Cfg.Web.SessionSecret

	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	h.cfgMu.Lock()
	defer h.cfgMu.Unlock()

	// Diff against the running config to report restart-required sections.
	restart := []string{}
	if !reflect.DeepEqual(h.Cfg.Server, cfg.Server) {
		restart = append(restart, "server (listeners)")
	}
	if !reflect.DeepEqual(h.Cfg.Cache, cfg.Cache) {
		restart = append(restart, "cache")
	}
	if !reflect.DeepEqual(h.Cfg.TLS, cfg.TLS) {
		restart = append(restart, "tls")
	}
	if !reflect.DeepEqual(h.Cfg.Log, cfg.Log) {
		restart = append(restart, "log")
	}
	if !reflect.DeepEqual(h.Cfg.Tunnel, cfg.Tunnel) {
		restart = append(restart, "tunnel")
	}

	// Live-apply the hot sections.
	if !reflect.DeepEqual(h.Cfg.Upstreams, cfg.Upstreams) {
		ups := make([]*upstream.Upstream, 0, len(cfg.Upstreams))
		for _, spec := range cfg.Upstreams {
			up, err := upstream.Parse(spec)
			if err != nil {
				return nil, fmt.Errorf("upstream %q: %w", spec, err)
			}
			ups = append(ups, up)
		}
		h.DNS.SetUpstreams(ups)
		h.Upstreams = ups
	}
	h.DNS.SetBlockPolicy(cfg.Filter.BlockResponse, cfg.Filter.BlockTTL)
	h.DNS.SetTimeout(time.Duration(cfg.Server.TimeoutSec) * time.Second)
	h.Cfg.Filter.Whitelist = cfg.Filter.Whitelist
	h.Cfg.Filter.Blacklist = cfg.Filter.Blacklist
	h.applyUserLists()
	h.Cfg.Filter.Blocklists = cfg.Filter.Blocklists
	h.applyLists()

	*h.Cfg = *cfg
	if err := h.SaveConfig(); err != nil {
		return nil, err
	}
	return restart, nil
}

func (h *Handler) getConfig(w http.ResponseWriter) {
	h.cfgMu.Lock()
	defer h.cfgMu.Unlock()
	writeJSON(w, http.StatusOK, payloadFromConfig(h.Cfg))
}

func (h *Handler) putConfig(w http.ResponseWriter, r *http.Request) {
	var p configPayload
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad body: " + err.Error()})
		return
	}
	restart, err := h.applyPayload(p)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":               true,
		"restart_required": restart,
	})
}

func (h *Handler) reloadConfig(w http.ResponseWriter) {
	if h.Reload == nil {
		writeJSON(w, http.StatusNotImplemented, map[string]string{"error": "reload not supported in this build"})
		return
	}
	// Hold cfgMu: Reload reads the in-memory config which putConfig mutates
	// under the same mutex.
	h.cfgMu.Lock()
	err := h.Reload()
	h.cfgMu.Unlock()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	// Sections the in-process reload does not handle still need a restart.
	remaining := []string{}
	if h.Cfg.Tunnel.Enabled || h.Cfg.Tunnel.Token != "" || h.Cfg.Tunnel.QuickTunnel {
		remaining = append(remaining, "tunnel")
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":                true,
		"reloaded":          true,
		"still_requires_restart": remaining,
	})
}

// ---- TLS & certificates ----

// tlsStatus is the shape returned by GET /api/tls.
type tlsStatus struct {
	// Listeners that currently use the certificate.
	Listeners map[string]bool `json:"listeners"`
	// Config knobs the UI reflects.
	CertFile           string   `json:"cert_file"`
	KeyFile            string   `json:"key_file"`
	CertDir            string   `json:"cert_dir"`
	GenerateSelfSigned bool     `json:"generate_self_signed"`
	SelfSignedHosts    []string `json:"self_signed_hosts"`
	WebTLS             bool     `json:"web_tls"`
	// Info is nil when no certificate exists yet.
	Info *cert.Info `json:"info"`
	// ACME status; nil when disabled.
	ACME *acme.Status `json:"acme,omitempty"`
}

func (h *Handler) tlsStatus() tlsStatus {
	s := h.Cfg.Server
	info, _ := cert.Inspect(h.Cfg.TLS.CertDir, h.Cfg.TLS.CertFile, h.Cfg.TLS.KeyFile)
	if info != nil && !info.Present {
		info = nil
	}
	ts := tlsStatus{
		Listeners: map[string]bool{
			"dot": s.ListenDoT != "",
			"doh": s.ListenDoH != "",
			"doq": s.ListenDoQ != "",
		},
		CertFile:           h.Cfg.TLS.CertFile,
		KeyFile:            h.Cfg.TLS.KeyFile,
		CertDir:            h.Cfg.TLS.CertDir,
		GenerateSelfSigned: h.Cfg.TLS.GenerateSelfSigned,
		SelfSignedHosts:    h.Cfg.TLS.SelfSignedHosts,
		WebTLS:             h.Cfg.Server.WebTLS,
		Info:               info,
	}
	if h.ACME != nil {
		st := h.ACME.GetStatus()
		ts.ACME = &st
	}
	return ts
}

func (h *Handler) getTLS(w http.ResponseWriter) {
	h.cfgMu.Lock()
	defer h.cfgMu.Unlock()
	writeJSON(w, http.StatusOK, h.tlsStatus())
}

type tlsGeneratePayload struct {
	Hosts   []string `json:"hosts"`
	KeyType string   `json:"key_type"` // "ecdsa" (default) | "rsa"
	KeyBits int      `json:"key_bits"` // RSA size: 2048 or 4096
	Days    int      `json:"days"`     // validity; <=0 = default (825)
}

// generateTLS creates a fresh self-signed certificate, updates the config so
// it is used, and rebinds the listeners. Returns the new status.
func (h *Handler) generateTLS(w http.ResponseWriter, r *http.Request) {
	h.cfgMu.Lock()
	defer h.cfgMu.Unlock()
	var p tlsGeneratePayload
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad body"})
		return
	}
	hosts := make([]string, 0, len(p.Hosts))
	for _, s := range p.Hosts {
		if t := strings.TrimSpace(s); t != "" {
			hosts = append(hosts, t)
		}
	}
	if len(hosts) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "at least one host (DNS name or IP) is required"})
		return
	}
	keyType := strings.ToLower(p.KeyType)
	if keyType != "rsa" && keyType != "ecdsa" {
		keyType = "ecdsa"
	}

	info, err := cert.Generate(h.Cfg.TLS.CertDir, hosts, keyType, p.KeyBits, p.Days)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "generate certificate: " + err.Error()})
		return
	}

	// Point the config at the freshly generated pair and persist.
	h.Cfg.TLS.CertFile = ""
	h.Cfg.TLS.KeyFile = ""
	h.Cfg.TLS.GenerateSelfSigned = true
	h.Cfg.TLS.SelfSignedHosts = hosts
	if err := h.SaveConfig(); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "save config: " + err.Error()})
		return
	}
	applied, applyErr := h.applyTLSReload()
	st := h.tlsStatus()
	st.Info = info
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "applied": applied, "apply_error": applyErr, "status": st})
}

type tlsUploadPayload struct {
	CertPEM string `json:"cert_pem"`
	KeyPEM  string `json:"key_pem"`
}

// uploadTLS stores a CA-signed certificate + key, points the config at it and
// rebinds the listeners. The pair is validated before anything is written.
func (h *Handler) uploadTLS(w http.ResponseWriter, r *http.Request) {
	h.cfgMu.Lock()
	defer h.cfgMu.Unlock()
	var p tlsUploadPayload
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad body"})
		return
	}
	if strings.TrimSpace(p.CertPEM) == "" || strings.TrimSpace(p.KeyPEM) == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "certificate and private key are both required"})
		return
	}
	// Validate the pair (matches, parses, private key fits the cert) before
	// touching the config or any file.
	if _, err := tls.X509KeyPair([]byte(p.CertPEM), []byte(p.KeyPEM)); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid certificate/key pair: " + err.Error()})
		return
	}

	dir := h.Cfg.TLS.CertDir
	if dir == "" {
		dir = "data/certs"
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	certPath := filepath.Join(dir, "custom-cert.pem")
	keyPath := filepath.Join(dir, "custom-key.pem")
	if err := os.WriteFile(certPath, []byte(p.CertPEM), 0o644); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if err := os.WriteFile(keyPath, []byte(p.KeyPEM), 0o600); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	h.Cfg.TLS.CertFile = certPath
	h.Cfg.TLS.KeyFile = keyPath
	h.Cfg.TLS.GenerateSelfSigned = false
	if err := h.SaveConfig(); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "save config: " + err.Error()})
		return
	}
	applied, applyErr := h.applyTLSReload()
	writeJSON(w, http.StatusOK, map[string]any{
		"ok": true, "applied": applied, "apply_error": applyErr,
		"status": h.tlsStatus(),
	})
}

// issueACME triggers an immediate Let's Encrypt issuance/renewal.
func (h *Handler) issueACME(ctx context.Context, w http.ResponseWriter) {
	if h.ACME == nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "ACME is not enabled — set tls.acme in the config"})
		return
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	if err := h.ACME.ForceIssue(ctx); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	// New cert on disk: rebind listeners and the web server with it.
	h.cfgMu.Lock()
	applied, applyErr := h.applyTLSReload()
	h.cfgMu.Unlock()
	st := h.ACME.GetStatus()
	writeJSON(w, http.StatusOK, map[string]any{
		"ok": true, "applied": applied, "apply_error": applyErr,
		"status": h.tlsStatus(), "acme": st,
	})
}

// applyTLSReload rebinds the DNS listeners with the new certificate via the
// ReloadTLS hook (wired in main). Returns applied=false when the hook is nil.
func (h *Handler) applyTLSReload() (bool, string) {
	if h.ReloadTLS == nil {
		return false, ""
	}
	if err := h.ReloadTLS(); err != nil {
		return false, err.Error()
	}
	return true, ""
}

// downloadCert serves the currently active certificate so clients (e.g.
// Android Private DNS) can install it as a trusted root.
func (h *Handler) downloadCert(w http.ResponseWriter) {
	h.cfgMu.Lock()
	defer h.cfgMu.Unlock()
	info, err := cert.Inspect(h.Cfg.TLS.CertDir, h.Cfg.TLS.CertFile, h.Cfg.TLS.KeyFile)
	if err != nil || info == nil || !info.Present {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "no certificate available yet"})
		return
	}
	data, err := os.ReadFile(info.CertPath)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Header().Set("Content-Disposition", `attachment; filename="irongrid-cert.pem"`)
	w.Write(data)
}

// ---- updates ----

// checkUpdate queries GitHub Releases for a newer version. Failures (offline,
// rate limit, no releases yet) are folded into the payload as a non-empty
// "error" field so the UI can degrade quietly.
func (h *Handler) checkUpdate(ctx context.Context, w http.ResponseWriter) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	cur := h.Version
	if cur == "" {
		cur = version.Version
	}
	client := &update.Client{Repo: update.DefaultRepo, Current: cur}
	writeJSON(w, http.StatusOK, client.Check(ctx))
}

func (h *Handler) diagDNS(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	name := strings.TrimSuffix(r.URL.Query().Get("name"), ".")
	qtype := r.URL.Query().Get("type")
	if qtype == "" {
		qtype = "A"
	}
	t, ok := dns.StringToType[strings.ToUpper(qtype)]
	if !ok {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad qtype"})
		return
	}
	q := dns.Question{Name: dns.Fqdn(name), Qtype: t, Qclass: dns.ClassINET}
	msg := new(dns.Msg)
	msg.SetQuestion(q.Name, q.Qtype)
	cctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	h.cfgMu.Lock()
	ups := append([]*upstream.Upstream(nil), h.Upstreams...)
	h.cfgMu.Unlock()
	var lastErr error
	for _, up := range ups {
		resp, err := up.Query(cctx, msg)
		if err == nil {
			answers := make([]string, 0, len(resp.Answer))
			for _, rr := range resp.Answer {
				answers = append(answers, rr.String())
			}
			blockedByIP, reason := h.Engine.CheckIPs(extractIPs(resp))
			writeJSON(w, http.StatusOK, map[string]any{
				"domain": name, "type": qtype, "upstream": up.Name(),
				"rcode": resp.Rcode, "answers": answers,
				"blocked_by_ip": blockedByIP, "reason": reason,
			})
			return
		}
		lastErr = err
	}
	writeJSON(w, http.StatusInternalServerError, map[string]any{"error": lastErr.Error()})
}

func extractIPs(m *dns.Msg) []net.IP {
	var ips []net.IP
	if m == nil {
		return ips
	}
	for _, rr := range m.Answer {
		switch v := rr.(type) {
		case *dns.A:
			ips = append(ips, v.A)
		case *dns.AAAA:
			ips = append(ips, v.AAAA)
		}
	}
	return ips
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

func removeStr(list []string, s string) []string {
	out := list[:0]
	for _, v := range list {
		if v != s {
			out = append(out, v)
		}
	}
	return out
}

