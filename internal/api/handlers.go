package api

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"

	"github.com/eoghan2t9/Irongrid-DNS/internal/cache"
	"github.com/eoghan2t9/Irongrid-DNS/internal/config"
	"github.com/eoghan2t9/Irongrid-DNS/internal/dnsserver"
	"github.com/eoghan2t9/Irongrid-DNS/internal/filter"
	"github.com/eoghan2t9/Irongrid-DNS/internal/querylog"
	"github.com/eoghan2t9/Irongrid-DNS/internal/tunnel"
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

	Engine    *filter.Engine
	Lists     *filter.ListManager
	Cache     *cache.Cache
	Log       *querylog.Log
	DNS       *dnsserver.Handler
	Tunnel    *tunnel.Manager
	Upstreams []*upstream.Upstream
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
	case len(parts) == 2 && parts[0] == "diag" && parts[1] == "dns" && r.Method == http.MethodGet:
		h.diagDNS(ctx, w, r)
	default:
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
	}
}

// ---- status & stats ----

func (h *Handler) getStatus(w http.ResponseWriter) {
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

func (h *Handler) getConfig(w http.ResponseWriter) {
	// Never leak the password hash or session secret.
	c := *h.Cfg
	c.Web.Password = ""
	c.Web.SessionSecret = ""
	writeJSON(w, http.StatusOK, c)
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
	var lastErr error
	for _, up := range h.Upstreams {
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

