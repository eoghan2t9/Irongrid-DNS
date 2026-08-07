package api

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
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
	"github.com/eoghan2t9/Irongrid-DNS/internal/firewall"
	"github.com/eoghan2t9/Irongrid-DNS/internal/geoip"
	"github.com/eoghan2t9/Irongrid-DNS/internal/querylog"
	"github.com/eoghan2t9/Irongrid-DNS/internal/recursive"
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
	// Hints is the authoritative root-hints manager for recursive://
	// upstreams; nil when no recursive upstream is configured.
	Hints     *recursive.HintsManager
	Catalog   *catalog.Catalog
	StartedAt time.Time
	Version   string

	// Geo is the country-data manager behind geo-blocking; nil when geo
	// blocking was never enabled. RebuildGeo (re)loads country data and
	// swaps the DNS handler's blocker; wired up by main, nil when
	// unavailable. Firewall is the host-firewall manager that mirrors the
	// blocked countries at the packet level (nftables/iptables); nil when
	// unavailable.
	Geo        *geoip.Manager
	Firewall   *firewall.Manager
	RebuildGeo func(cfg config.GeoBlockConfig) error

	// lastInstalledVersion is set after a successful in-place update and
	// cleared on restart (process exit). It guards against installing twice
	// before the restart, which would clobber the .prev rollback copy.
	lastInstalledVersion string
}

// ConfigMu exposes the mutex that guards Cfg mutations so the App's auth
// checks (authorize/issueSession/validSession) can snapshot config fields
// under the same lock applyPayload uses when it rotates the session secret.
func (h *Handler) ConfigMu() *sync.Mutex { return &h.cfgMu }

// HandleAPI dispatches /api/* requests.
func (h *Handler) HandleAPI(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/")
	path = strings.TrimSuffix(path, "/")
	parts := strings.Split(path, "/")

	ctx := r.Context()
	switch {
	case len(parts) == 1 && parts[0] == "status" && r.Method == http.MethodGet:
		h.getStatus(w)
	case len(parts) == 1 && parts[0] == "logout" && r.Method == http.MethodPost:
		h.logout(w)
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
	case len(parts) == 2 && parts[0] == "filter" && parts[1] == "site" && r.Method == http.MethodPost:
		h.siteCheck(ctx, w, r)
	case len(parts) == 2 && parts[0] == "tools" && parts[1] == "resolve" && r.Method == http.MethodPost:
		h.toolsResolve(ctx, w, r)
	case len(parts) == 2 && parts[0] == "tools" && parts[1] == "mail" && r.Method == http.MethodPost:
		h.toolsMail(ctx, w, r)
	case len(parts) == 2 && parts[0] == "tools" && parts[1] == "rbl" && r.Method == http.MethodPost:
		h.toolsRBL(ctx, w, r)
	case len(parts) == 2 && parts[0] == "tools" && parts[1] == "axfr" && r.Method == http.MethodPost:
		h.toolsAXFR(ctx, w, r)
	case len(parts) == 2 && parts[0] == "tools" && parts[1] == "subdomains" && r.Method == http.MethodPost:
		h.toolsSubdomains(ctx, w, r)
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
	case len(parts) == 2 && parts[0] == "update" && parts[1] == "changelog" && r.Method == http.MethodGet:
		h.updateChangelog(ctx, w)
	case len(parts) == 2 && parts[0] == "update" && parts[1] == "install" && r.Method == http.MethodPost:
		h.installUpdate(ctx, w)
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
	case len(parts) == 2 && parts[0] == "rate" && parts[1] == "blocked" && r.Method == http.MethodGet:
		h.rateBlocked(w)
	case len(parts) == 2 && parts[0] == "rate" && parts[1] == "unblock" && r.Method == http.MethodPost:
		h.rateUnblock(w, r)
	case len(parts) == 2 && parts[0] == "geo" && parts[1] == "status" && r.Method == http.MethodGet:
		h.geoStatus(w)
	case len(parts) == 2 && parts[0] == "geo" && parts[1] == "refresh" && r.Method == http.MethodPost:
		h.geoRefresh(w)
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
	// Root-hints status (only present when a recursive:// upstream is
	// configured and the HintsManager exists).
	rootHints := map[string]any{"enabled": false}
	if h.Hints != nil {
		st := h.Hints.Status()
		rootHints = map[string]any{
			"enabled":          true,
			"source":           st.Source,
			"verified":         st.Verified,
			"last_fetch":       st.LastFetch,
			"last_error":       st.LastError,
			"addresses":        st.Addresses,
			"refresh_interval": st.RefreshInterval,
			"key_fingerprint":  st.KeyFingerprint,
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"version":    version.String(),
		"uptime_sec": int(time.Since(h.StartedAt).Seconds()),
		"listeners":  listeners,
		"cache_ok":   cacheOK,
		"tunnel":     h.Tunnel.Status(),
		"root_hints": rootHints,
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
		"query": stats,
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
	ID      string `json:"id"`
	Name    string `json:"name"`
	URL     string `json:"url"`
	Enabled bool   `json:"enabled"`
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
		ID:      p.ID,
		Name:    p.Name,
		URL:     p.URL,
		Enabled: p.Enabled,
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
		specs = append(specs, filter.ListSpec{ID: s.ID, Name: s.Name, URL: s.URL, Enabled: s.Enabled})
	}
	h.Lists.SetSpecs(specs)
	h.Lists.SetAutoUpdate(h.Cfg.Filter.AutoUpdate)
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
	Server       serverPayload        `json:"server"`
	Upstreams    []string             `json:"upstreams"`
	Cache        cachePayload         `json:"cache"`
	TLS          tlsPayload           `json:"tls"`
	Filter       filterPayload        `json:"filter"`
	Log          logPayload           `json:"log"`
	Web          webPayload           `json:"web"`
	Tunnel       tunnelPayload        `json:"tunnel"`
	Rewrites     []rewritePayload     `json:"rewrites"`
	ClientGroups []clientGroupPayload `json:"client_groups"`
	RateLimit    rateLimitPayload     `json:"rate_limit"`
	GeoBlock     geoBlockPayload      `json:"geo_block"`
	DNSSEC       dnssecPayload        `json:"dnssec"`
}

type rewritePayload struct {
	Domain string `json:"domain"`
	Type   string `json:"type"`
	Value  string `json:"value"`
	TTL    uint32 `json:"ttl"`
}

type clientGroupPayload struct {
	ID         string   `json:"id"`
	Name       string   `json:"name"`
	Enabled    bool     `json:"enabled"`
	CIDRs      []string `json:"cidrs"`
	Blocklists []string `json:"blocklists"`
	Whitelist  []string `json:"whitelist"`
	Blacklist  []string `json:"blacklist"`
	Upstreams  []string `json:"upstreams"`
}

type rateLimitPayload struct {
	Enabled    bool   `json:"enabled"`
	QPS        int    `json:"qps"`
	Burst      int    `json:"burst"`
	AutoBlock  bool   `json:"auto_block"`
	BlockAfter int    `json:"block_after"`
	BlockFor   string `json:"block_for"` // duration string
}

type geoBlockPayload struct {
	Enabled    bool     `json:"enabled"`
	Countries  []string `json:"countries"`
	Allowlist  []string `json:"allowlist"`
	BaseURL    string   `json:"base_url"`
	AutoUpdate string   `json:"auto_update"` // duration string, "" = never
}

type dnssecPayload struct {
	Enabled   bool `json:"enabled"`
	RequireAD bool `json:"require_ad"`
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
	L1Entries   int    `json:"l1_entries"`
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
	Enabled         bool         `json:"enabled"`
	Email           string       `json:"email"`
	Domains         []string     `json:"domains"`
	Staging         bool         `json:"staging"`
	HTTP01Port      int          `json:"http01_port"`
	RenewBeforeDays int          `json:"renew_before_days"`
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
	BlockResponse string             `json:"block_response"`
	BlockTTL      uint32             `json:"block_ttl"`
	Blocklists    []blocklistPayload `json:"blocklists"`
	Whitelist     []string           `json:"whitelist"`
	Blacklist     []string           `json:"blacklist"`
	// AutoUpdate is the single refresh interval applied to every enabled
	// blocklist (duration string, "" = never) — replaces what used to be a
	// per-list setting.
	AutoUpdate string `json:"auto_update"`
}

type blocklistPayload struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	URL     string `json:"url"`
	Enabled bool   `json:"enabled"`
}

type logPayload struct {
	QueryLogFile  string `json:"query_log_file"`
	RetentionDays int    `json:"retention_days"`
	Verbose       bool   `json:"verbose"`
	BatchSize     int    `json:"batch_size"`
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

// durationOrEmpty renders d as a duration string, or "" for zero (matching
// the "" = never/disabled convention the frontend's duration fields use).
func durationOrEmpty(d time.Duration) string {
	if d <= 0 {
		return ""
	}
	// Whole-hour durations render as "24h", not Go's default "24h0m0s" —
	// the frontend's auto-update dropdown matches by exact string against
	// its hour-based presets ("6h"/"24h"/"168h"), so the verbose form would
	// never match any of them and the select would silently fall back to
	// its first option ("Never") even though the value saved correctly.
	if d%time.Hour == 0 {
		return fmt.Sprintf("%dh", int64(d/time.Hour))
	}
	return d.String()
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
			L1Entries:   c.Cache.L1Entries,
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
			AutoUpdate:    durationOrEmpty(c.Filter.AutoUpdate),
		},
		Log: logPayload{
			QueryLogFile:  c.Log.QueryLogFile,
			RetentionDays: c.Log.RetentionDays,
			Verbose:       c.Log.Verbose,
			BatchSize:     c.Log.BatchSize,
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
		p.Filter.Blocklists = append(p.Filter.Blocklists, blocklistPayload{
			ID: bl.ID, Name: bl.Name, URL: bl.URL, Enabled: bl.Enabled,
		})
	}
	p.Rewrites = make([]rewritePayload, 0, len(c.Rewrites))
	for _, rw := range c.Rewrites {
		p.Rewrites = append(p.Rewrites, rewritePayload{Domain: rw.Domain, Type: rw.Type, Value: rw.Value, TTL: rw.TTL})
	}
	p.ClientGroups = make([]clientGroupPayload, 0, len(c.ClientGroups))
	for _, g := range c.ClientGroups {
		p.ClientGroups = append(p.ClientGroups, clientGroupPayload{
			ID: g.ID, Name: g.Name, Enabled: g.Enabled, CIDRs: g.CIDRs,
			Blocklists: g.Blocklists, Whitelist: g.Whitelist, Blacklist: g.Blacklist, Upstreams: g.Upstreams,
		})
	}
	p.RateLimit = rateLimitPayload{
		Enabled:    c.RateLimit.Enabled,
		QPS:        c.RateLimit.QPS,
		Burst:      c.RateLimit.Burst,
		AutoBlock:  c.RateLimit.AutoBlock,
		BlockAfter: c.RateLimit.BlockAfter,
		BlockFor:   durationOrEmpty(c.RateLimit.BlockFor),
	}
	p.GeoBlock = geoBlockPayload{
		Enabled:    c.GeoBlock.Enabled,
		Countries:  c.GeoBlock.Countries,
		Allowlist:  c.GeoBlock.Allowlist,
		BaseURL:    c.GeoBlock.BaseURL,
		AutoUpdate: durationOrEmpty(c.GeoBlock.AutoUpdate),
	}
	p.DNSSEC = dnssecPayload{Enabled: c.DNSSEC.Enabled, RequireAD: c.DNSSEC.RequireAD}
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
	blocklistAutoUpdate, err := parseDur(p.Filter.AutoUpdate)
	if err != nil {
		return nil, fmt.Errorf("filter.auto_update: %w", err)
	}
	blockFor, err := parseDur(p.RateLimit.BlockFor)
	if err != nil {
		return nil, fmt.Errorf("rate_limit.block_for: %w", err)
	}
	geoAutoUpdate, err := parseDur(p.GeoBlock.AutoUpdate)
	if err != nil {
		return nil, fmt.Errorf("geo_block.auto_update: %w", err)
	}
	// Friendly defaults when auto-block is switched on without explicit
	// values: 3 violations then a 10-minute cooldown.
	if p.RateLimit.AutoBlock {
		if blockFor <= 0 {
			blockFor = 10 * time.Minute
		}
		if p.RateLimit.BlockAfter < 1 {
			p.RateLimit.BlockAfter = 3
		}
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
			L1Entries:   p.Cache.L1Entries,
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
			AutoUpdate:    blocklistAutoUpdate,
		},
		Log: config.LogConfig{
			QueryLogFile:  p.Log.QueryLogFile,
			RetentionDays: p.Log.RetentionDays,
			Verbose:       p.Log.Verbose,
			BatchSize:     p.Log.BatchSize,
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
		RateLimit: config.RateLimitConfig{
			Enabled:    p.RateLimit.Enabled,
			QPS:        p.RateLimit.QPS,
			Burst:      p.RateLimit.Burst,
			AutoBlock:  p.RateLimit.AutoBlock,
			BlockAfter: p.RateLimit.BlockAfter,
			BlockFor:   blockFor,
		},
		GeoBlock: config.GeoBlockConfig{
			Enabled:    p.GeoBlock.Enabled,
			Countries:  p.GeoBlock.Countries,
			Allowlist:  p.GeoBlock.Allowlist,
			BaseURL:    p.GeoBlock.BaseURL,
			AutoUpdate: geoAutoUpdate,
		},
		DNSSEC: config.DNSSECConfig{
			Enabled:   p.DNSSEC.Enabled,
			RequireAD: p.DNSSEC.RequireAD,
		},
	}
	for _, rw := range p.Rewrites {
		cfg.Rewrites = append(cfg.Rewrites, config.RewriteSpec{Domain: rw.Domain, Type: rw.Type, Value: rw.Value, TTL: rw.TTL})
	}
	for _, g := range p.ClientGroups {
		cfg.ClientGroups = append(cfg.ClientGroups, config.ClientGroup{
			ID: g.ID, Name: g.Name, Enabled: g.Enabled, CIDRs: g.CIDRs,
			Blocklists: g.Blocklists, Whitelist: g.Whitelist, Blacklist: g.Blacklist, Upstreams: g.Upstreams,
		})
	}
	for _, bl := range p.Filter.Blocklists {
		cfg.Filter.Blocklists = append(cfg.Filter.Blocklists, config.BlocklistSpec{
			ID: bl.ID, Name: bl.Name, URL: bl.URL, Enabled: bl.Enabled,
		})
	}

	// Keep the existing password hash unless a new plaintext password was
	// provided (it is bcrypt-hashed by Config.Save). Changing the password
	// rotates the session secret so every previously issued session cookie —
	// including the one authorizing this very request — becomes invalid at
	// once (session rotation on password change).
	if cfg.Web.Password == "" {
		cfg.Web.Password = h.Cfg.Web.Password
		cfg.Web.SessionSecret = h.Cfg.Web.SessionSecret
	} else {
		sec, err := sessionSecretFor(cfg.Web.Password, h.Cfg.Web.SessionSecret)
		if err != nil {
			return nil, fmt.Errorf("rotate session secret: %w", err)
		}
		cfg.Web.SessionSecret = sec
	}

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
	h.Cfg.Filter.AutoUpdate = cfg.Filter.AutoUpdate
	h.applyLists()
	// Rewrites, client groups, rate limiting and DNSSEC are all cheap,
	// side-effect-free hot-swaps — unlike Server/Cache/TLS there's no
	// listener rebind risk, so just reapply them unconditionally rather than
	// diffing first.
	h.DNS.SetRewriter(dnsserver.BuildRewriter(cfg.Rewrites))
	h.DNS.SetClientRouter(dnsserver.BuildClientRouter(cfg, h.Lists))
	h.DNS.SetRateLimiter(dnsserver.BuildRateLimiter(cfg.RateLimit))
	h.DNS.SetDNSSEC(cfg.DNSSEC.Enabled, cfg.DNSSEC.RequireAD)

	oldSecret := h.Cfg.Web.SessionSecret
	*h.Cfg = *cfg
	if err := h.SaveConfig(); err != nil {
		// A failed save must not leave a rotated session secret live in
		// memory while the file still holds the old one — sessions signed
		// with the new secret would silently die on the next restart.
		// Revert just the secret; the rest of the in-memory apply keeps the
		// established (pre-existing) semantics.
		h.Cfg.Web.SessionSecret = oldSecret
		return nil, err
	}
	// Geo-blocking changes are hot-swapped (no listener rebind needed). The
	// rebuild runs asynchronously so a country-data download can never stall
	// the config save or hold cfgMu.
	if h.RebuildGeo != nil {
		_ = h.RebuildGeo(cfg.GeoBlock)
	}
	return restart, nil
}

// ---- abuse protection: auto-blocked clients & geo blocking ----

// rateBlocked serves the currently auto-blocked clients for the dashboard.
func (h *Handler) rateBlocked(w http.ResponseWriter) {
	writeJSON(w, http.StatusOK, map[string]any{"blocked": h.DNS.BlockedClients()})
}

// rateUnblock lifts an auto-blocked client's cooldown early.
func (h *Handler) rateUnblock(w http.ResponseWriter, r *http.Request) {
	var p struct {
		IP string `json:"ip"`
	}
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil || p.IP == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "ip required"})
		return
	}
	h.DNS.UnblockClient(p.IP)
	writeJSON(w, http.StatusOK, map[string]string{"ok": "unblocked"})
}

// geoStatus serves the per-country geo data status, plus the auto-refresh
// cadence and when the next automatic refresh is due (zero/nil when disabled).
func (h *Handler) geoStatus(w http.ResponseWriter) {
	if h.Geo == nil {
		writeJSON(w, http.StatusOK, map[string]any{"enabled": false, "countries": []any{}})
		return
	}
	h.cfgMu.Lock()
	autoUpdate := h.Cfg.GeoBlock.AutoUpdate
	h.cfgMu.Unlock()
	last := h.Geo.LastRefresh()
	var next any
	if autoUpdate > 0 && !last.IsZero() {
		next = last.Add(autoUpdate)
	}
	// Firewall status: the packet-level mirror of geo blocking. Only shown
	// when main wired a firewall manager (always, in this build).
	fw := map[string]any{"available": false}
	if h.Firewall != nil {
		backend, active := h.Firewall.Status()
		fw = map[string]any{"available": true, "backend": backend, "active": active}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"enabled":      true,
		"countries":    h.Geo.Status(),
		"auto_update":  durationOrEmpty(autoUpdate),
		"last_refresh": last,
		"next_refresh": next,
		"firewall":     fw,
	})
}

// geoRefresh re-downloads the enabled countries' CIDR data and swaps the DNS
// handler's blocker when ready.
func (h *Handler) geoRefresh(w http.ResponseWriter) {
	if h.RebuildGeo == nil || h.Geo == nil {
		writeJSON(w, http.StatusNotImplemented, map[string]string{"error": "geo blocking not configured in this build"})
		return
	}
	h.cfgMu.Lock()
	geo := h.Cfg.GeoBlock
	h.cfgMu.Unlock()
	// Nothing to download when no countries are configured — say so instead
	// of answering "ok" for a no-op (the dashboard otherwise looks like it
	// worked while the blocker stays uninstalled).
	if geo.Enabled && len(geo.Countries) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "geo blocking is enabled but no countries are configured — add ISO 3166-1 alpha-2 codes (e.g. RU, CN) in Settings, save, then refresh"})
		return
	}
	if err := h.RebuildGeo(geo); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "refreshing": true})
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
		"ok":                     true,
		"reloaded":               true,
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
	// Same fix as installUpdate: the web server's 30s WriteTimeout is fixed
	// at connection-accept time, before this handler runs. DNS-01 issuance
	// waits propagation_wait_sec (60s by default) before even checking the
	// TXT record, so it already exceeds 30s out of the box — without this
	// the browser would see "Failed to fetch" on a run that's still
	// succeeding server-side.
	_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(6 * time.Minute))
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

// updateChangelog returns the recent stable releases for the in-app
// changelog page. Failures are folded into an error field (the page shows a
// quiet notice) rather than an HTTP error.
func (h *Handler) updateChangelog(ctx context.Context, w http.ResponseWriter) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	cur := h.Version
	if cur == "" {
		cur = version.Version
	}
	client := &update.Client{Repo: update.DefaultRepo, Current: cur}
	releases, err := client.List(ctx)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"current_version": cur,
			"error":           err.Error(),
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"current_version": cur,
		"releases":        releases,
	})
}

// installUpdateMu serialises in-place updates so two tabs can't race.
var installUpdateMu sync.Mutex

// installUpdate downloads the release asset for this platform, verifies it
// against SHA256SUMS.txt, atomically swaps the running binary and — when the
// service is systemd-managed — schedules a restart via a detached systemd-run
// transient unit, so the restart outlives this process and the HTTP response
// is guaranteed to flush first.
func (h *Handler) installUpdate(ctx context.Context, w http.ResponseWriter) {
	installUpdateMu.Lock()
	defer installUpdateMu.Unlock()

	// h.Version is the version the process started with. Once a swap has
	// happened it is stale, so refuse a second install until the restart —
	// this also preserves the .prev rollback copy from being overwritten.
	// lastInstalledVersion is a GitHub release tag ("v1.4.1"), already
	// v-prefixed — do not add a second one.
	if h.lastInstalledVersion != "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": fmt.Sprintf("%s was already installed and is pending a restart", h.lastInstalledVersion),
		})
		return
	}

	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()

	// The web server's http.Server has a 30s WriteTimeout (sane for every
	// other endpoint), fixed at connection-accept time before this handler
	// even starts. A download + checksum verify + binary swap can easily run
	// past that on a slow link, so the connection would get killed out from
	// under a perfectly successful install — the browser reports "Failed to
	// fetch" with no clue the server kept working. Push the deadline out
	// past the context timeout above so our own error responses win instead.
	// (SetWriteDeadline no-ops with http.ErrNotSupported if the underlying
	// writer doesn't support it — never possible here, but safe either way.)
	_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(6 * time.Minute))

	cur := h.Version
	if cur == "" {
		cur = version.Version
	}
	client := &update.Client{Repo: update.DefaultRepo, Current: cur}
	res, err := client.Install(ctx, "")
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	payload := map[string]any{
		"previous_version": res.PreviousVersion,
		"new_version":      res.NewVersion,
		"installed_to":     res.InstalledTo,
		"rollback_path":    res.InstalledTo + ".prev",
		"asset_name":       res.AssetName,
		"asset_size":       res.AssetSize,
	}

	// Only claim (and guard) a restart when it can actually happen: systemd
	// must be running, systemd-run on PATH, and the systemd-run invocation
	// itself (which just registers a timer unit and returns — the actual
	// restart still happens on its own detached unit after the 1s delay,
	// independent of this process) has to actually succeed. Run it
	// synchronously so a registration failure (e.g. a stale same-named unit
	// left over from a previous attempt) is caught here instead of only
	// logged from an unobserved goroutine — the previous fire-and-forget
	// version set lastInstalledVersion unconditionally, so a failed
	// registration permanently wedged every future install behind a
	// "pending restart" that would never happen. --collect auto-unloads the
	// transient unit on completion (success or failure) so a retry never
	// collides with a leftover unit from an earlier attempt. The swap
	// itself is safe to retry regardless — a repeated install simply
	// re-downloads and re-verifies.
	unit := update.UnitName()
	_, systemdRunOK := exec.LookPath("systemd-run")
	restartable := unit != "" && systemdRunOK == nil
	if restartable {
		if _, err := os.Stat("/run/systemd/system"); err != nil {
			restartable = false
		}
	}
	if restartable {
		cmd := exec.Command("systemd-run", "--unit=irongrid-update", "--collect", "--on-active=1", "systemctl", "restart", unit)
		if out, err := cmd.CombinedOutput(); err != nil {
			log.Printf("[update] schedule restart failed: %v: %s", err, out)
			payload["restarting"] = false
			payload["note"] = "Binary updated, but scheduling the restart failed. Restart Irongrid manually to run the new version."
		} else {
			h.lastInstalledVersion = res.NewVersion
			payload["restarting"] = true
			payload["unit"] = unit
		}
	} else {
		payload["restarting"] = false
		payload["note"] = "Binary updated. Restart Irongrid manually to run the new version."
	}
	writeJSON(w, http.StatusOK, payload)
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

// logout clears the signed session cookie in the browser. The cookie is
// stateless (HMAC-signed), so expiring it client-side is all the server
// needs to do — no server-side session store exists.
func (h *Handler) logout(w http.ResponseWriter) {
	h.cfgMu.Lock()
	secure := h.Cfg.Server.WebTLS
	h.cfgMu.Unlock()
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   secure,
		MaxAge:   -1,
		Expires:  time.Unix(1, 0),
	})
	writeJSON(w, http.StatusOK, map[string]string{"ok": "logged out"})
}

// sessionSecretFor returns the session secret to persist when applying a
// config: the existing secret unless a new plaintext password was supplied,
// in which case a fresh secret is generated so all previously issued session
// cookies stop validating (session rotation).
func sessionSecretFor(newPassword, currentSecret string) (string, error) {
	if newPassword == "" {
		return currentSecret, nil
	}
	return config.NewSessionSecret()
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
