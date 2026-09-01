package api

import (
	"cmp"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"slices"
	"strings"

	"github.com/eoghan2t9/Irongrid-DNS/internal/catalog"
	"github.com/eoghan2t9/Irongrid-DNS/internal/config"
	"github.com/eoghan2t9/Irongrid-DNS/internal/dnsname"
	"github.com/eoghan2t9/Irongrid-DNS/internal/filter"
)

// ---- blocklists ----

func (h *Handler) getLists(w http.ResponseWriter) {
	snapshot := h.Lists.Snapshot()
	slices.SortFunc(snapshot, func(a, b filter.StoredList) int { return cmp.Compare(a.Spec.ID, b.Spec.ID) })
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
	//nolint:gosec // G705: served as text/plain to the operator's own dashboard;
	// blocklist content is never executed as HTML.
	_, _ = w.Write(content)
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
	name := dnsname.CanonicalDomain(p.Entry)
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
