package api

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/eoghan2t9/Irongrid-DNS/internal/filter"
)

func TestSiteCheck(t *testing.T) {
	// A filter with a couple of blocklist entries, like a real list would
	// produce.
	eng := filter.NewEngine()
	if _, err := eng.LoadList("test", "Test Ads", []byte("ads.example.com\ntracker.example.net\n")); err != nil {
		t.Fatal(err)
	}
	eng.Compile()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = io.WriteString(w, `<html><head><title>Demo</title></head><body>
			<script src="https://ads.example.com/pixel.js"></script>
			<script src="/local.js"></script>
			<img src="https://tracker.example.net/t.png">
			<img src="https://ok.example.org/i.png">
		</body></html>`)
	}))
	defer srv.Close()

	// The SSRF guard refuses loopback, so swap in a plain client for the test.
	old := siteFetchClient
	siteFetchClient = &http.Client{Timeout: siteTimeout}
	defer func() { siteFetchClient = old }()

	h := &Handler{Engine: eng}
	req := httptest.NewRequest(http.MethodPost, "/api/filter/site",
		strings.NewReader(`{"url": "`+srv.URL+`/page"}`))
	rr := httptest.NewRecorder()
	h.siteCheck(context.Background(), rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body: %s", rr.Code, rr.Body.String())
	}
	var res siteCheckResult
	if err := json.Unmarshal(rr.Body.Bytes(), &res); err != nil {
		t.Fatal(err)
	}

	if res.Title != "Demo" {
		t.Errorf("title = %q, want Demo", res.Title)
	}
	if res.BlockedCount != 2 {
		t.Errorf("blocked_count = %d, want 2", res.BlockedCount)
	}
	if res.Total != 4 {
		t.Errorf("total = %d, want 4 (page host, 3 distinct resources)", res.Total)
	}
	byDomain := map[string]siteDomainResult{}
	for _, d := range res.Domains {
		byDomain[d.Domain] = d
	}
	for _, want := range []string{"ads.example.com", "tracker.example.net"} {
		if !byDomain[want].Blocked {
			t.Errorf("%s: blocked = false, want true (%+v)", want, byDomain[want])
		}
	}
	if byDomain["ok.example.org"].Blocked {
		t.Errorf("ok.example.org: blocked = true, want false")
	}
	if byDomain["ads.example.com"].List != "Test Ads" {
		t.Errorf("ads.example.com list = %q, want %q", byDomain["ads.example.com"].List, "Test Ads")
	}
}

func TestSiteCheckBadInput(t *testing.T) {
	h := &Handler{}
	for _, body := range []string{`{}`, `{"url": ""}`, `{"url": "ftp://example.com"}`, `{"url": "file:///etc/passwd"}`} {
		req := httptest.NewRequest(http.MethodPost, "/api/filter/site", strings.NewReader(body))
		rr := httptest.NewRecorder()
		h.siteCheck(context.Background(), rr, req)
		if rr.Code != http.StatusBadRequest {
			t.Errorf("body %s: status = %d, want 400", body, rr.Code)
		}
	}
}

func TestResolvePublicIP(t *testing.T) {
	ctx := context.Background()
	// Addresses a site scan must never reach (loopback, private, CGNAT,
	// link-local, unspecified — both IP literals and a resolving hostname).
	for _, host := range []string{
		"127.0.0.1", "10.0.0.5", "192.168.1.1", "172.16.4.9", "100.64.0.1",
		"169.254.169.254", "::1", "fe80::1", "0.0.0.0", "localhost",
	} {
		if ip, err := resolvePublicIP(ctx, host); err == nil {
			t.Errorf("resolvePublicIP(%q) = %v, want error", host, ip)
		}
	}
	// Public IP literals pass through without any DNS lookup.
	for _, host := range []string{"8.8.8.8", "1.1.1.1", "2606:4700:4700::1111"} {
		if ip, err := resolvePublicIP(ctx, host); err != nil || ip == nil {
			t.Errorf("resolvePublicIP(%q) = %v, %v; want a public IP", host, ip, err)
		}
	}
}

func TestSiteRedirectGuard(t *testing.T) {
	c := newSiteScanClient()
	via := make([]*http.Request, 0)

	// Non-http(s) redirect schemes are refused.
	fileReq := httptest.NewRequest(http.MethodGet, "file:///etc/passwd", nil)
	if err := c.CheckRedirect(fileReq, via); err == nil {
		t.Error("file:// redirect allowed, want error")
	}

	// More than the hop budget is refused.
	req := httptest.NewRequest(http.MethodGet, "https://example.com/", nil)
	for range siteMaxRedirs {
		via = append(via, req)
	}
	if err := c.CheckRedirect(req, via); err == nil {
		t.Error("too many redirects allowed, want error")
	}

	// A plain http(s) redirect within the budget passes.
	if err := c.CheckRedirect(req, via[:2]); err != nil {
		t.Errorf("valid redirect rejected: %v", err)
	}
}

func TestSiteCheckTruncatesBigPages(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "<html><body>")
		chunk := strings.Repeat("<b>x</b>", 1024) // ~8 KiB per write
		for written := int64(len(chunk)); written < int64(siteMaxBody)+1024; written += int64(len(chunk)) {
			_, _ = io.WriteString(w, chunk)
		}
		_, _ = io.WriteString(w, "</body></html>")
	}))
	defer srv.Close()

	old := siteFetchClient
	siteFetchClient = &http.Client{Timeout: siteTimeout}
	defer func() { siteFetchClient = old }()

	h := &Handler{}
	req := httptest.NewRequest(http.MethodPost, "/api/filter/site",
		strings.NewReader(`{"url": "`+srv.URL+`/big"}`))
	rr := httptest.NewRecorder()
	h.siteCheck(context.Background(), rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body: %s", rr.Code, rr.Body.String())
	}
	var res siteCheckResult
	if err := json.Unmarshal(rr.Body.Bytes(), &res); err != nil {
		t.Fatal(err)
	}
	if !res.Truncated {
		t.Error("truncated = false, want true for a >2 MiB page")
	}
}

func TestSiteCheckNonHTML(t *testing.T) {
	// A binary 200 (e.g. an image pasted by accident) must degrade to a
	// page-host-only result, not an error.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/png")
		_, _ = w.Write([]byte{0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0xff, 0xff})
	}))
	defer srv.Close()

	old := siteFetchClient
	siteFetchClient = &http.Client{Timeout: siteTimeout}
	defer func() { siteFetchClient = old }()

	h := &Handler{}
	req := httptest.NewRequest(http.MethodPost, "/api/filter/site",
		strings.NewReader(`{"url": "`+srv.URL+`/img.png"}`))
	rr := httptest.NewRecorder()
	h.siteCheck(context.Background(), rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body: %s", rr.Code, rr.Body.String())
	}
	var res siteCheckResult
	if err := json.Unmarshal(rr.Body.Bytes(), &res); err != nil {
		t.Fatal(err)
	}
	if res.BlockedCount != 0 {
		t.Errorf("blocked_count = %d, want 0", res.BlockedCount)
	}
}

func TestSiteCheckRouteDispatch(t *testing.T) {
	// The endpoint is reachable through HandleAPI, not just the method.
	eng := filter.NewEngine()
	if _, err := eng.LoadList("test", "Test Ads", []byte("ads.example.com\n")); err != nil {
		t.Fatal(err)
	}
	eng.Compile()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `<script src="https://ads.example.com/p.js"></script>`)
	}))
	defer srv.Close()

	old := siteFetchClient
	siteFetchClient = &http.Client{Timeout: siteTimeout}
	defer func() { siteFetchClient = old }()

	h := &Handler{Engine: eng}
	req := httptest.NewRequest(http.MethodPost, "/api/filter/site",
		strings.NewReader(`{"url": "`+srv.URL+`"}`))
	rr := httptest.NewRecorder()
	h.HandleAPI(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body: %s", rr.Code, rr.Body.String())
	}
	var res siteCheckResult
	if err := json.Unmarshal(rr.Body.Bytes(), &res); err != nil {
		t.Fatal(err)
	}
	if res.BlockedCount != 1 {
		t.Errorf("blocked_count = %d, want 1", res.BlockedCount)
	}
}
