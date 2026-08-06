package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/eoghan2t9/Irongrid-DNS/internal/filter"
)

// Site-scan limits: 2 MiB of HTML and a 10s overall budget keep the "fix a
// broken site" tool from becoming a slow, expensive blind fetch.
const (
	siteMaxBody   = 2 << 20
	siteTimeout   = 10 * time.Second
	siteMaxRedirs = 5
)

// siteFetchClient fetches pages for the site scanner. It is a package-level
// variable so tests can swap in a client that reaches local httptest servers
// without tripping the SSRF guard.
var siteFetchClient = newSiteScanClient()

// newSiteScanClient returns an HTTP client whose DialContext refuses
// connections to loopback, private (RFC 1918 / CGNAT / ULA), link-local,
// multicast and unspecified addresses — the scanner must not become an SSRF
// probe into the host's LAN or this very server (Dragonfly, the API, …).
// The hostname is resolved once and the validated address dialed directly,
// so a DNS-rebinding resolver can't hand out a public address for the check
// and a private one for the connection; the same dial-time check guards every
// redirect hop. Scheme-based redirects (file:, gopher:…) are rejected up
// front too.
func newSiteScanClient() *http.Client {
	dialer := &net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}
	return &http.Client{
		Timeout: siteTimeout,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				host, port, err := net.SplitHostPort(addr)
				if err != nil {
					return nil, err
				}
				ip, err := resolvePublicIP(ctx, host)
				if err != nil {
					return nil, err
				}
				return dialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
			},
			MaxIdleConns:        8,
			IdleConnTimeout:     30 * time.Second,
			TLSHandshakeTimeout: 5 * time.Second,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= siteMaxRedirs {
				return errors.New("too many redirects")
			}
			if req.URL.Scheme != "http" && req.URL.Scheme != "https" {
				return fmt.Errorf("refusing redirect to %s://", req.URL.Scheme)
			}
			return nil
		},
	}
}

// resolvePublicIP resolves host once and returns a single address that passes
// the reserved-address guard — the exact address DialContext will connect to.
// IP literals pass through checked; hostnames get a fresh LookupIPAddr so the
// check and the dial share one resolution (no DNS-rebinding window).
func resolvePublicIP(ctx context.Context, host string) (net.IP, error) {
	if ip := net.ParseIP(host); ip != nil {
		if reservedIP(ip) {
			return nil, fmt.Errorf("refusing to connect to reserved address %s", host)
		}
		return ip, nil
	}
	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}
	for _, a := range addrs {
		if !reservedIP(a.IP) {
			return a.IP, nil
		}
	}
	return nil, fmt.Errorf("refusing to connect to %s: no non-reserved address", host)
}

func reservedIP(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsUnspecified() || ip.IsMulticast() {
		return true
	}
	// RFC 6598 shared address space (CGNAT) — not on the public internet.
	if ip4 := ip.To4(); ip4 != nil && ip4[0] == 100 && ip4[1]&0xc0 == 64 {
		return true
	}
	return false
}

type siteCheckPayload struct {
	URL string `json:"url"`
}

type siteDomainResult struct {
	Domain  string `json:"domain"`
	Blocked bool   `json:"blocked"`
	Reason  string `json:"reason"`
	List    string `json:"list"`
}

type siteCheckResult struct {
	URL          string             `json:"url"`
	FinalURL     string             `json:"final_url"`
	Title        string             `json:"title"`
	Domains      []siteDomainResult `json:"domains"`
	Total        int                `json:"total"`
	BlockedCount int                `json:"blocked_count"`
	Truncated    bool               `json:"truncated"`
	FetchMS      int64              `json:"fetch_ms"`
}

// siteCheck scans a URL for the domains its page references and reports which
// ones the current filter config blocks — the "fix a broken site" tool. Only
// http(s) targets are accepted; the page is fetched with the SSRF-guarded
// client, its HTML is scanned for resource hostnames, and each one is run
// through the filter engine so the dashboard can offer one-click whitelisting.
func (h *Handler) siteCheck(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	var p siteCheckPayload
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil || strings.TrimSpace(p.URL) == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "url required"})
		return
	}
	raw := strings.TrimSpace(p.URL)
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "must be an http(s) URL like example.com or https://example.com"})
		return
	}

	ctx, cancel := context.WithTimeout(ctx, siteTimeout)
	defer cancel()

	start := time.Now()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	req.Header.Set("User-Agent", "Irongrid-DNS site-check/1.0 (+https://github.com/eoghan2t9/Irongrid-DNS)")

	resp, err := siteFetchClient.Do(req)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "fetch failed: " + err.Error()})
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": fmt.Sprintf("site returned HTTP %d", resp.StatusCode)})
		return
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, siteMaxBody+1))
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "read failed: " + err.Error()})
		return
	}
	truncated := len(body) > siteMaxBody
	if truncated {
		body = body[:siteMaxBody]
	}

	domains, title := filter.ExtractSitePage(bytes.NewReader(body), resp.Request.URL)
	blocked := 0
	out := make([]siteDomainResult, 0, len(domains))
	for _, d := range domains {
		bl := false
		reason, list := "", ""
		if h.Engine != nil {
			dec := h.Engine.DecideDomain(d)
			bl = dec.Action == filter.Block
			reason, list = dec.Reason, dec.ListName
		}
		if bl {
			blocked++
		}
		out = append(out, siteDomainResult{Domain: d, Blocked: bl, Reason: reason, List: list})
	}

	writeJSON(w, http.StatusOK, siteCheckResult{
		URL:          u.String(),
		FinalURL:     resp.Request.URL.String(),
		Title:        title,
		Domains:      out,
		Total:        len(out),
		BlockedCount: blocked,
		Truncated:    truncated,
		FetchMS:      time.Since(start).Milliseconds(),
	})
}
