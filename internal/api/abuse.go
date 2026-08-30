package api

import (
	"cmp"
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"
)

// Endpoints are package vars so tests can point them at httptest servers.
var (
	abuseIPDBReportURL  = "https://api.abuseipdb.com/api/v2/report"
	ripestatNetworkInfo = "https://stat.ripe.net/data/network-info/data.json"
	ripestatASOverview  = "https://stat.ripe.net/data/as-overview/data.json"
	abuseHTTPClient     = &http.Client{Timeout: 15 * time.Second}
	// abuseIPDBCategoryDDoS is AbuseIPDB category 4 (DDoS Attack) — the
	// closest fit for a DNS flood against the resolver. See
	// https://www.abuseipdb.com/categories.
	abuseIPDBCategoryDDoS = "4"
)

// abuseReport submits a blocked attacker IP to AbuseIPDB on the operator's
// behalf using the key configured under abuse.abuseipdb_key. Only IPs that
// Irongrid auto-blocked over a real handshake (honeypot hits) are reported
// from the dashboard — a spoofed-UDP source is not evidence of the attacker.
func (h *Handler) abuseReport(w http.ResponseWriter, r *http.Request) {
	var p struct {
		IP string `json:"ip"`
	}
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil || net.ParseIP(strings.TrimSpace(p.IP)) == nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "a valid ip is required"})
		return
	}
	h.cfgMu.Lock()
	key := h.Cfg.Abuse.AbuseIPDBKey
	h.cfgMu.Unlock()
	if key == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "no AbuseIPDB API key configured — add it under Abuse reporting in Settings"})
		return
	}
	ip := net.ParseIP(strings.TrimSpace(p.IP)).String()
	comment := "DNS flood: source auto-blocked after querying a configured honeypot trap domain over a connection-oriented transport (TCP/DoT/DoH/DoQ) against a self-hosted Irongrid DNS resolver."
	score, err := reportAbuseIPDB(r.Context(), key, ip, abuseIPDBCategoryDDoS, comment)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "AbuseIPDB: " + err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "ip": ip, "abuse_confidence_score": score})
}

// reportAbuseIPDB POSTs one report to the AbuseIPDB API v2 and returns the
// resulting abuse-confidence score for the IP.
func reportAbuseIPDB(ctx context.Context, key, ip, categories, comment string) (int, error) {
	form := url.Values{}
	form.Set("ip", ip)
	form.Set("categories", categories)
	form.Set("comment", comment)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, abuseIPDBReportURL, strings.NewReader(form.Encode()))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Key", key)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := abuseHTTPClient.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	var body struct {
		Data struct {
			AbuseConfidenceScore int `json:"abuseConfidenceScore"`
		} `json:"data"`
		Errors []struct {
			Detail string `json:"detail"`
		} `json:"errors"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return 0, fmt.Errorf("unparseable response (HTTP %d)", resp.StatusCode)
	}
	if resp.StatusCode != http.StatusOK {
		msg := fmt.Sprintf("HTTP %d", resp.StatusCode)
		if len(body.Errors) > 0 && body.Errors[0].Detail != "" {
			msg += ": " + body.Errors[0].Detail
		}
		return 0, errors.New(msg)
	}
	return body.Data.AbuseConfidenceScore, nil
}

// abuseExport streams a CSV of the currently blocked attacker clients
// (honeypot auto-blocks and rate-limit auto-blocks) for bulk abuse reporting
// to hosting providers. Rate-limit clients are labelled separately so the
// operator can decide which rows are genuine attack traffic.
func (h *Handler) abuseExport(w http.ResponseWriter) {
	type row struct {
		ip, source, blockedUntil, queries, firstSeen string
	}
	var rows []row
	if h.DNS != nil {
		if b := h.DNS.CurrentIPBanner(); b != nil {
			for _, ip := range b.AutoList() {
				rows = append(rows, row{ip: ip, source: "honeypot"})
			}
		}
		for _, c := range h.DNS.BlockedClients() {
			r := row{ip: c.IP, source: "rate-limit", queries: fmt.Sprintf("%d", c.Queries)}
			if !c.BlockedUntil.IsZero() {
				r.blockedUntil = c.BlockedUntil.UTC().Format(time.RFC3339)
			}
			if !c.FirstSeen.IsZero() {
				r.firstSeen = c.FirstSeen.UTC().Format(time.RFC3339)
			}
			rows = append(rows, r)
		}
	}
	slices.SortFunc(rows, func(a, b row) int { return cmp.Compare(a.ip, b.ip) })

	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="irongrid-blocked-clients-`+time.Now().Format("20060102")+`.csv"`)
	cw := csv.NewWriter(w)
	_ = cw.Write([]string{"ip", "source", "blocked_until", "queries", "first_seen"})
	for _, r := range rows {
		_ = cw.Write([]string{r.ip, r.source, r.blockedUntil, r.queries, r.firstSeen})
	}
	cw.Flush()
}

// asnInfo is the enriched owner information for one IP, returned by
// GET /api/abuse/asn so the operator can route reports to the right host.
type asnInfo struct {
	ASN     string `json:"asn"`
	Prefix  string `json:"prefix"`
	Name    string `json:"name"`
	Holder  string `json:"holder"`
	Country string `json:"country"`
}

// abuseASN looks up the owning ASN / network / registrant of an IP via the
// free RIPEstat API (no key required).
func (h *Handler) abuseASN(w http.ResponseWriter, r *http.Request) {
	var p struct {
		IP string `json:"ip"`
	}
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil || net.ParseIP(strings.TrimSpace(p.IP)) == nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "a valid ip is required"})
		return
	}
	info, err := lookupASN(r.Context(), net.ParseIP(strings.TrimSpace(p.IP)).String())
	if err != nil {
		// A definitive "no routing information" answer is not a failure —
		// the address simply isn't announced (reserved / unassigned / not
		// routed), so it is reported as an empty result (HTTP 200) and the
		// dashboard shows "no routing information" instead of an error
		// banner, exactly like the query-log label path (logASN). Only
		// transient failures (RIPEstat down, unparseable response) surface
		// as 502.
		if strings.Contains(err.Error(), "no routing information") {
			writeJSON(w, http.StatusOK, asnInfo{})
			return
		}
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, info)
}

// lookupASN resolves an IP to its BGP origin ASN, covering prefix and (via a
// second AS-overview call) the registrant/holder of that ASN. A failure of the
// optional second call does not fail the lookup.
func lookupASN(ctx context.Context, ip string) (asnInfo, error) {
	var info asnInfo
	//nolint:gosec // G704 SSRF: ip was validated with net.ParseIP by the caller
	// (abuseASN) before lookupASN is reached — it is a literal IP, not a URL.
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, ripestatNetworkInfo+"?resource="+url.QueryEscape(ip), nil)
	if err != nil {
		return info, err
	}
	//nolint:gosec // G704 SSRF: req targets a fixed package-level endpoint URL
	// with an IP-only query param (validated by the caller).
	resp, err := abuseHTTPClient.Do(req)
	if err != nil {
		return info, fmt.Errorf("RIPEstat network-info: %w", err)
	}
	defer resp.Body.Close()
	// The real network-info payload carries the origin ASN(s) as the
	// asns ARRAY ("data.asns": ["15169"]) — there is no "data.asn" field.
	// Decoding the singular form always left ASN empty and made every
	// lookup report "no routing information" even for routed addresses.
	var body struct {
		Data struct {
			ASNs    []string `json:"asns"`
			Prefix  string   `json:"prefix"`
			Name    string   `json:"name"`
			Country string   `json:"country"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return info, fmt.Errorf("RIPEstat network-info: unparseable response (HTTP %d)", resp.StatusCode)
	}
	if len(body.Data.ASNs) == 0 {
		return info, fmt.Errorf("no routing information available for %s", ip)
	}
	// RIPEstat returns bare numbers ("15169"); normalize to the "AS15169"
	// form the dashboard renders and the as-overview call below expects.
	info.ASN = "AS" + strings.TrimPrefix(body.Data.ASNs[0], "AS")
	info.Prefix, info.Name, info.Country = body.Data.Prefix, body.Data.Name, body.Data.Country

	//nolint:gosec // G704 SSRF: the ASN string comes from RIPEstat's own
	// network-info response, not from user input.
	req2, err := http.NewRequestWithContext(ctx, http.MethodGet,
		ripestatASOverview+"?resource="+url.QueryEscape(strings.TrimPrefix(info.ASN, "AS")), nil)
	if err != nil {
		return info, nil // holder is optional enrichment
	}
	resp2, err := abuseHTTPClient.Do(req2)
	if err != nil {
		return info, nil
	}
	defer resp2.Body.Close()
	var b2 struct {
		Data struct {
			Holder string `json:"holder"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp2.Body).Decode(&b2); err == nil {
		info.Holder = b2.Data.Holder
	}
	return info, nil
}
