package api

import (
	"context"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/eoghan2t9/Irongrid-DNS/internal/cfapi"
	"github.com/eoghan2t9/Irongrid-DNS/internal/config"
	"github.com/eoghan2t9/Irongrid-DNS/internal/dnsplan"
)

// ---- DNS records for the encrypted protocols ----
//
// The server listens for DoH, DoT and DoQ, but clients only find those
// listeners if the right public DNS records exist: address records for the
// hostname, SVCB records under _dns.<hostname> that say which protocols and
// ports are offered (mirroring what the server itself answers for DDR), and
// an HTTPS record for the hostname. This works out those records from the
// live listener configuration, shows what would change, applies it on request
// and, if switched on, keeps it in step in the background.

// detectPublicIPs finds the server's public addresses; replaced in tests.
var detectPublicIPs = dnsplan.DetectPublic

// dnsRecordTTL is the TTL of the records we publish: short enough that an
// address change propagates quickly, long enough not to hammer resolvers.
const dnsRecordTTL = 300

type cfdnsProto struct {
	Name string `json:"name"`
	Port int    `json:"port"`
	Path string `json:"path,omitempty"`
}

type cfdnsItemView struct {
	Type     string `json:"type"`
	Name     string `json:"name"`
	Purpose  string `json:"purpose,omitempty"`
	Want     string `json:"want,omitempty"`
	Have     string `json:"have,omitempty"`
	State    string `json:"state"`
	Action   string `json:"action"`
	Detail   string `json:"detail,omitempty"`
	RecordID string `json:"record_id,omitempty"`
}

type cfdnsSettingsView struct {
	Host      string `json:"host"`
	AutoSync  bool   `json:"auto_sync"`
	IPv4      string `json:"ipv4"`
	IPv6      string `json:"ipv6"`
	SkipHTTPS bool   `json:"skip_https"`
}

// cfdnsSyncStatus is the outcome of the last background sync run.
type cfdnsSyncStatus struct {
	At        time.Time `json:"at"`
	Changed   bool      `json:"changed"`
	Applied   int       `json:"applied"`
	Failed    int       `json:"failed"`
	Conflicts int       `json:"conflicts"`
	Error     string    `json:"error,omitempty"`
}

type cfdnsPlanResp struct {
	Host        string            `json:"host"`
	HostDefault string            `json:"host_default"`
	NeedsHost   bool              `json:"needs_host,omitempty"`
	Zone        string            `json:"zone,omitempty"`
	Protocols   []cfdnsProto      `json:"protocols"`
	IPv4        []string          `json:"ipv4"`
	IPv6        []string          `json:"ipv6"`
	Detected    map[string]string `json:"detected"`
	Notes       []string          `json:"notes"`
	Settings    cfdnsSettingsView `json:"settings"`
	Items       []cfdnsItemView   `json:"items"`
	Counts      map[string]int    `json:"counts"`
	InSync      bool              `json:"in_sync"`
	Sync        *cfdnsSyncStatus  `json:"sync,omitempty"`
	Error       string            `json:"error,omitempty"`
	Permission  bool              `json:"permission,omitempty"`
}

func addrPort(addr string) int {
	_, p, err := net.SplitHostPort(addr)
	if err != nil {
		return 0
	}
	n, err := strconv.Atoi(p)
	if err != nil || n < 1 || n > 65535 {
		return 0
	}
	return n
}

// cfdnsInputs is what the plan is built from, read once under the config lock.
type cfdnsInputs struct {
	s           config.CloudflareDNSConfig
	host        string
	hostDefault string
	ep          dnsplan.Endpoint
}

func (h *Handler) cfdnsInputs() cfdnsInputs {
	h.cfgMu.Lock()
	defer h.cfgMu.Unlock()
	srv, s := h.Cfg.Server, h.Cfg.CloudflareDNS
	def := dnsplan.Normalize(srv.DiscoveryHost)
	for i := 0; def == "" && i < len(h.Cfg.TLS.ACME.Domains); i++ {
		if d := dnsplan.Normalize(h.Cfg.TLS.ACME.Domains[i]); d != "" && !strings.HasPrefix(d, "*.") {
			def = d
		}
	}
	host := dnsplan.Normalize(s.Host)
	if host == "" {
		host = def
	}
	return cfdnsInputs{
		s: s, host: host, hostDefault: def,
		ep: dnsplan.Endpoint{
			Host: host, DoT: addrPort(srv.ListenDoT), DoQ: addrPort(srv.ListenDoQ),
			DoH: addrPort(srv.ListenDoH), DoH3: addrPort(srv.ListenDoH3), DoHPath: srv.DoHPath,
		},
	}
}

func (in cfdnsInputs) protocols() []cfdnsProto {
	path := in.ep.DoHPath
	if path == "" {
		path = "/dns-query"
	}
	var out []cfdnsProto
	if in.ep.DoH != 0 {
		out = append(out, cfdnsProto{Name: "DoH", Port: in.ep.DoH, Path: path})
	}
	if in.ep.DoH3 != 0 {
		out = append(out, cfdnsProto{Name: "DoH3", Port: in.ep.DoH3, Path: path})
	}
	if in.ep.DoT != 0 {
		out = append(out, cfdnsProto{Name: "DoT", Port: in.ep.DoT})
	}
	if in.ep.DoQ != 0 {
		out = append(out, cfdnsProto{Name: "DoQ", Port: in.ep.DoQ})
	}
	return out
}

// addresses decides which addresses to publish: an explicit override wins,
// "off" publishes none for that family, otherwise the detected public one.
func addresses(s config.CloudflareDNSConfig) (v4, v6 []string, detected map[string]string, notes []string) {
	d4, d6 := detectPublicIPs()
	detected = map[string]string{"ipv4": d4, "ipv6": d6}
	pick := func(override, det string) []string {
		switch override {
		case "off":
			return nil
		case "":
			if det != "" {
				return []string{det}
			}
			return nil
		}
		return []string{override}
	}
	v4, v6 = pick(s.IPv4, d4), pick(s.IPv6, d6)
	if len(v4) == 0 && s.IPv4 != "off" {
		notes = append(notes, "No public IPv4 address was detected (is this server behind NAT?). Enter its public address under Advanced.")
	}
	for _, ip := range append(append([]string(nil), v4...), v6...) {
		if p := net.ParseIP(ip); p != nil && !dnsplan.Public4(p) && !dnsplan.Public6(p) {
			notes = append(notes, ip+" is a private address; only devices on your own network will be able to use it.")
		}
	}
	return v4, v6, detected, notes
}

type cfdnsPlan struct {
	resp  cfdnsPlanResp
	zone  *cfapi.Zone
	items []dnsplan.Item
}

// recordContent is a record's value as one string, whichever way Cloudflare
// returned it.
func recordContent(r cfapi.Record) string {
	if (r.Type != "SVCB" && r.Type != "HTTPS") || r.Content != "" {
		return r.Content
	}
	prio, _ := r.Data["priority"].(float64)
	target, _ := r.Data["target"].(string)
	value, _ := r.Data["value"].(string)
	return strings.TrimSpace(strconv.Itoa(int(prio)) + " " + target + " " + value)
}

func wantInput(w dnsplan.Want) cfapi.RecordInput {
	in := cfapi.RecordInput{Type: w.Type, Name: w.Name, TTL: dnsRecordTTL}
	switch w.Type {
	case "A", "AAAA":
		in.Content = w.Content
	default:
		in.Data = map[string]any{"priority": w.Priority, "target": w.Target, "value": w.Value()}
	}
	return in
}

// buildCFDNSPlan compares the wanted records with Cloudflare. The returned
// error is a Cloudflare failure; a plan that simply cannot be built yet (no
// hostname, no zone) is described in the response instead.
func (h *Handler) buildCFDNSPlan(ctx context.Context, c cfCtx) (*cfdnsPlan, error) {
	in := h.cfdnsInputs()
	v4, v6, detected, notes := addresses(in.s)
	p := &cfdnsPlan{resp: cfdnsPlanResp{
		Host: in.host, HostDefault: in.hostDefault, Protocols: in.protocols(),
		IPv4: v4, IPv6: v6, Detected: detected, Notes: notes, Items: []cfdnsItemView{}, Counts: map[string]int{},
		Settings: cfdnsSettingsView{Host: in.s.Host, AutoSync: in.s.AutoSync, IPv4: in.s.IPv4, IPv6: in.s.IPv6, SkipHTTPS: in.s.SkipHTTPS},
	}}
	// Always send arrays, never null, so the dashboard needs no guards.
	for _, s := range []*[]string{&p.resp.IPv4, &p.resp.IPv6, &p.resp.Notes} {
		if *s == nil {
			*s = []string{}
		}
	}
	if p.resp.Protocols == nil {
		p.resp.Protocols = []cfdnsProto{}
	}
	h.cfSyncMu.Lock()
	if h.cfSyncLast != nil {
		last := *h.cfSyncLast
		p.resp.Sync = &last
	}
	h.cfSyncMu.Unlock()

	if in.host == "" {
		p.resp.NeedsHost = true
		return p, nil
	}
	if len(p.resp.Protocols) == 0 {
		p.resp.Notes = append(p.resp.Notes, "No encrypted protocol (DoH, DoT, DoQ) is enabled, so there is nothing to publish.")
		return p, nil
	}
	zones, err := c.dns.ListZones(ctx)
	if err != nil {
		return nil, err
	}
	z := cfapi.ZoneFor(zones, in.host)
	if z == nil {
		p.resp.Error = "No Cloudflare zone for " + in.host + " is visible to the API token."
		return p, nil
	}
	p.zone, p.resp.Zone = z, z.Name

	var haves []dnsplan.Have
	for _, name := range []string{in.host, "_dns." + in.host} {
		recs, err := c.dns.RecordsNamed(ctx, z.ID, name)
		if err != nil {
			return nil, dnsDenied(z.Name, err)
		}
		for _, r := range recs {
			haves = append(haves, dnsplan.Have{ID: r.ID, Type: r.Type, Name: r.Name, Content: recordContent(r), Proxied: r.Proxied})
		}
	}
	p.items = dnsplan.Diff(dnsplan.Build(in.ep, v4, v6, !in.s.SkipHTTPS), haves)
	for _, it := range p.items {
		v := cfdnsItemView{State: string(it.State), Action: string(it.Action), Detail: it.Detail}
		if it.Want != nil {
			v.Type, v.Name, v.Purpose, v.Want = it.Want.Type, it.Want.Name, it.Want.Purpose, it.Want.Display()
		}
		if it.Have != nil {
			v.RecordID, v.Have = it.Have.ID, it.Have.Content
			if it.Want == nil {
				v.Type, v.Name = it.Have.Type, dnsplan.Normalize(it.Have.Name)
			}
		}
		p.resp.Items = append(p.resp.Items, v)
		if it.Action != dnsplan.ActionNone {
			p.resp.Counts[string(it.Action)]++
		}
		if it.State == dnsplan.StateConflict {
			p.resp.Counts["conflict"]++
		}
	}
	// "In sync" means nothing needs creating or changing; extras and
	// conflicts are reported but do not make the plan out of date.
	p.resp.InSync = p.resp.Counts["create"] == 0 && p.resp.Counts["update"] == 0 && p.resp.Counts["conflict"] == 0
	return p, nil
}

type cfdnsResult struct {
	Type   string `json:"type"`
	Name   string `json:"name"`
	Action string `json:"action"`
	OK     bool   `json:"ok"`
	Error  string `json:"error,omitempty"`
}

// applyCFDNSPlan carries out create and update actions, and delete actions
// only when allowDelete is set. One failing record does not stop the others.
func applyCFDNSPlan(ctx context.Context, c cfCtx, p *cfdnsPlan, allowDelete bool) []cfdnsResult {
	var out []cfdnsResult
	for _, it := range p.items {
		var err error
		switch it.Action {
		case dnsplan.ActionCreate:
			_, err = c.dns.CreateRecord(ctx, p.zone.ID, wantInput(*it.Want))
		case dnsplan.ActionUpdate:
			_, err = c.dns.UpdateRecord(ctx, p.zone.ID, it.Have.ID, wantInput(*it.Want))
		case dnsplan.ActionDelete:
			if !allowDelete {
				continue
			}
			err = c.dns.DeleteRecord(ctx, p.zone.ID, it.Have.ID)
		default:
			continue
		}
		r := cfdnsResult{Action: string(it.Action), OK: err == nil}
		if it.Want != nil {
			r.Type, r.Name = it.Want.Type, it.Want.Name
		} else {
			r.Type, r.Name = it.Have.Type, dnsplan.Normalize(it.Have.Name)
		}
		if err != nil {
			r.Error = dnsDenied(p.zone.Name, err).Error()
		}
		out = append(out, r)
	}
	return out
}

func (h *Handler) cfDNSReady(w http.ResponseWriter) (cfCtx, bool) {
	c := h.cfContext()
	if !c.hasToken {
		badRequest(w, "Add a Cloudflare API token first.", map[string]any{"needs": "api_token"})
		return c, false
	}
	return c, true
}

func (h *Handler) cfDNSPlan(ctx context.Context, w http.ResponseWriter) {
	c, ok := h.cfDNSReady(w)
	if !ok {
		return
	}
	h.cfDNSMu.Lock()
	defer h.cfDNSMu.Unlock()
	p, err := h.buildCFDNSPlan(ctx, c)
	if err != nil {
		cfFail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, p.resp)
}

// cfDNSApply creates and updates the records in the plan. Deleting records
// that are no longer wanted needs {"prune": true}.
func (h *Handler) cfDNSApply(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	var req struct {
		Prune bool `json:"prune"`
	}
	if r.ContentLength != 0 && !decodeJSON(w, r, &req) {
		return
	}
	c, ok := h.cfDNSReady(w)
	if !ok {
		return
	}
	h.cfDNSMu.Lock()
	defer h.cfDNSMu.Unlock()
	p, err := h.buildCFDNSPlan(ctx, c)
	if err != nil {
		cfFail(w, err)
		return
	}
	if p.zone == nil {
		msg := p.resp.Error
		if p.resp.NeedsHost {
			msg = "Choose the hostname to publish first."
		} else if msg == "" {
			msg = "There is nothing to publish."
		}
		badRequest(w, msg, nil)
		return
	}
	results := applyCFDNSPlan(ctx, c, p, req.Prune)
	after, err := h.buildCFDNSPlan(ctx, c)
	if err != nil {
		cfFail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"results": results, "plan": after.resp, "via_acme": c.dns.used.Load()})
}

type cfdnsSettingsReq struct {
	Host      string `json:"host"`
	AutoSync  bool   `json:"auto_sync"`
	IPv4      string `json:"ipv4"`
	IPv6      string `json:"ipv6"`
	SkipHTTPS bool   `json:"skip_https"`
}

// validOverride checks an address override: empty, "off", or a usable address
// of the right family.
func validOverride(s string, v6 bool) string {
	if s == "" || s == "off" {
		return ""
	}
	ip := net.ParseIP(s)
	switch {
	case ip == nil, (ip.To4() == nil) != v6:
		if v6 {
			return "Enter an IPv6 address, or \"off\" to publish none."
		}
		return "Enter an IPv4 address, or \"off\" to publish none."
	case ip.IsLoopback(), ip.IsUnspecified(), ip.IsLinkLocalUnicast(), ip.IsMulticast():
		return s + " is not an address clients could use."
	}
	return ""
}

func (h *Handler) cfDNSSettings(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	var req cfdnsSettingsReq
	if !decodeJSON(w, r, &req) {
		return
	}
	req.Host = dnsplan.Normalize(req.Host)
	req.IPv4, req.IPv6 = strings.TrimSpace(strings.ToLower(req.IPv4)), strings.TrimSpace(strings.ToLower(req.IPv6))
	if req.Host != "" && !validCFHostname(req.Host) {
		badRequest(w, "Enter a full hostname such as dns.example.com, or leave it empty to use the default.", nil)
		return
	}
	if msg := validOverride(req.IPv4, false); msg != "" {
		badRequest(w, msg, nil)
		return
	}
	if msg := validOverride(req.IPv6, true); msg != "" {
		badRequest(w, msg, nil)
		return
	}
	h.cfgMu.Lock()
	h.Cfg.CloudflareDNS = config.CloudflareDNSConfig{Host: req.Host, AutoSync: req.AutoSync, IPv4: req.IPv4, IPv6: req.IPv6, SkipHTTPS: req.SkipHTTPS}
	err := h.SaveConfig()
	h.cfgMu.Unlock()
	h.cfSyncMu.Lock()
	h.cfSyncKey = "" // settings changed: the next sync run must look again
	h.cfSyncMu.Unlock()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "settings not saved: " + err.Error()})
		return
	}
	c := h.cfContext()
	if !c.hasToken {
		writeJSON(w, http.StatusOK, map[string]any{"saved": true, "needs": "api_token"})
		return
	}
	h.cfDNSMu.Lock()
	defer h.cfDNSMu.Unlock()
	p, err := h.buildCFDNSPlan(ctx, c)
	if err != nil {
		cfFail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, p.resp)
}

// ---- background sync ----

const (
	dnsSyncEvery   = 5 * time.Minute  // how often the loop wakes
	dnsSyncRecheck = 30 * time.Minute // look at Cloudflare at least this often
)

// RunDNSSync keeps the published records in step with this server while
// auto-sync is on, until ctx ends. It creates and updates records but never
// deletes any, and it leaves conflicts for a person to resolve. It only talks
// to Cloudflare when the server's addresses or settings changed, or every 30
// minutes to catch records edited by hand.
func (h *Handler) RunDNSSync(ctx context.Context) {
	t := time.NewTicker(dnsSyncEvery)
	defer t.Stop()
	first := time.After(45 * time.Second) // let the server finish starting up
	for {
		select {
		case <-ctx.Done():
			return
		case <-first:
		case <-t.C:
		}
		h.dnsSyncOnce(ctx)
	}
}

func (h *Handler) dnsSyncOnce(ctx context.Context) {
	in := h.cfdnsInputs()
	c := h.cfContext()
	if !in.s.AutoSync || !c.hasToken || in.host == "" {
		return
	}
	d4, d6 := detectPublicIPs()
	key := strings.Join([]string{in.host, d4, d6, in.s.IPv4, in.s.IPv6, strconv.FormatBool(in.s.SkipHTTPS),
		strconv.Itoa(in.ep.DoT), strconv.Itoa(in.ep.DoQ), strconv.Itoa(in.ep.DoH), strconv.Itoa(in.ep.DoH3), in.ep.DoHPath}, "|")
	h.cfSyncMu.Lock()
	unchanged := key == h.cfSyncKey && time.Since(h.cfSyncChecked) < dnsSyncRecheck
	h.cfSyncMu.Unlock()
	if unchanged {
		return
	}

	ctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	h.cfDNSMu.Lock()
	defer h.cfDNSMu.Unlock()
	st := &cfdnsSyncStatus{At: time.Now()}
	p, err := h.buildCFDNSPlan(ctx, c)
	switch {
	case err != nil:
		st.Error = err.Error()
	case p.zone == nil:
		st.Error = p.resp.Error
	default:
		for _, r := range applyCFDNSPlan(ctx, c, p, false) {
			if r.OK {
				st.Applied++
			} else {
				st.Failed++
				if st.Error == "" {
					st.Error = r.Type + " " + r.Name + ": " + r.Error
				}
			}
		}
		st.Changed = st.Applied > 0
		st.Conflicts = p.resp.Counts["conflict"]
	}
	h.cfSyncMu.Lock()
	h.cfSyncLast = st
	h.cfSyncChecked = time.Now()
	if st.Error == "" {
		h.cfSyncKey = key
	} else {
		h.cfSyncKey = "" // retry on the next wake-up
	}
	h.cfSyncMu.Unlock()
	switch {
	case st.Changed:
		slog.Info("dns records synced", "host", in.host, "applied", st.Applied, "failed", st.Failed)
	case st.Error != "":
		slog.Warn("dns record sync failed", "host", in.host, "error", st.Error)
	}
	h.cfCacheClear()
}
