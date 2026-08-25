package api

import (
	"bytes"
	"encoding/csv"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/eoghan2t9/Irongrid-DNS/internal/config"
	"github.com/eoghan2t9/Irongrid-DNS/internal/dnsserver"
	"github.com/eoghan2t9/Irongrid-DNS/internal/filter"
	"github.com/eoghan2t9/Irongrid-DNS/internal/geoip"
)

// withAbuseIPDBMock points the report endpoint at an httptest server that
// asserts the request shape and returns the canned response, restoring the
// real URL afterwards.
func withAbuseIPDBMock(t *testing.T, wantKey string, status int, body string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", r.Method)
		}
		if got := r.Header.Get("Key"); got != wantKey {
			t.Errorf("Key header = %q, want %q", got, wantKey)
		}
		if got := r.FormValue("ip"); got != "203.0.113.9" {
			t.Errorf("ip form = %q", got)
		}
		if got := r.FormValue("categories"); got != abuseIPDBCategoryDDoS {
			t.Errorf("categories form = %q, want %q", got, abuseIPDBCategoryDDoS)
		}
		if r.FormValue("comment") == "" {
			t.Error("comment form must not be empty")
		}
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	old := abuseIPDBReportURL
	abuseIPDBReportURL = srv.URL
	t.Cleanup(func() { abuseIPDBReportURL = old })
	return srv
}

func TestReportAbuseIPDB(t *testing.T) {
	withAbuseIPDBMock(t, "test-key", http.StatusOK, `{"data":{"ipAddress":"203.0.113.9","abuseConfidenceScore":88}}`)
	score, err := reportAbuseIPDB(t.Context(), "test-key", "203.0.113.9", abuseIPDBCategoryDDoS, "DNS flood")
	if err != nil {
		t.Fatalf("reportAbuseIPDB: %v", err)
	}
	if score != 88 {
		t.Fatalf("score = %d, want 88", score)
	}
}

func TestReportAbuseIPDBError(t *testing.T) {
	withAbuseIPDBMock(t, "test-key", http.StatusTooManyRequests, `{"errors":[{"detail":"rate limited: one report per IP per 15 minutes"}]}`)
	_, err := reportAbuseIPDB(t.Context(), "test-key", "203.0.113.9", "4", "comment")
	if err == nil || !strings.Contains(err.Error(), "rate limited") {
		t.Fatalf("err = %v, want a rate-limit error", err)
	}
}

func TestAbuseReportHandler(t *testing.T) {
	withAbuseIPDBMock(t, "cfg-key", http.StatusOK, `{"data":{"abuseConfidenceScore":75}}`)
	h := &Handler{Cfg: &config.Config{Abuse: config.AbuseConfig{AbuseIPDBKey: "cfg-key"}}}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/abuse/report", bytes.NewBufferString(`{"ip":"203.0.113.9"}`))
	h.abuseReport(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body %s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), `"abuse_confidence_score":75`) {
		t.Fatalf("body = %s, want abuse_confidence_score", rr.Body.String())
	}
}

func TestAbuseReportHandlerNoKey(t *testing.T) {
	t.Parallel()
	h := &Handler{Cfg: config.Default()} // key empty
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/abuse/report", bytes.NewBufferString(`{"ip":"203.0.113.9"}`))
	h.abuseReport(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("no-key status = %d, want 400", rr.Code)
	}
}

func TestAbuseReportHandlerBadIP(t *testing.T) {
	t.Parallel()
	h := &Handler{Cfg: config.Default()}
	for _, body := range []string{`{}`, `{"ip":""}`, `{"ip":"not-an-ip"}`} {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/api/abuse/report", bytes.NewBufferString(body))
		h.abuseReport(rr, req)
		if rr.Code != http.StatusBadRequest {
			t.Errorf("body %s: status = %d, want 400", body, rr.Code)
		}
	}
}

func TestAbuseExportCSV(t *testing.T) {
	t.Parallel()
	dnsH := dnsserver.NewHandler(filter.NewEngine(), nil, nil, nil, "nxdomain", 600, 5)
	banner := geoip.NewBanner("", nil, nil, []string{"trap.example.com"})
	if err := banner.Block("203.0.113.9"); err != nil {
		t.Fatalf("banner.Block: %v", err)
	}
	dnsH.SetIPBanner(banner)
	// Trip a rate-limit auto-block so the export covers both sources.
	rl := dnsserver.NewRateLimiter(1, 1)
	rl.SetAutoBlock(3, time.Hour)
	for range 10 {
		rl.Allow("198.51.100.7")
	}
	dnsH.SetRateLimiter(rl)
	h := &Handler{DNS: dnsH, Cfg: config.Default()}

	rr := httptest.NewRecorder()
	h.abuseExport(rr)

	if ct := rr.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/csv") {
		t.Fatalf("Content-Type = %q, want text/csv", ct)
	}
	if cd := rr.Header().Get("Content-Disposition"); !strings.Contains(cd, "irongrid-blocked-clients-") {
		t.Fatalf("Content-Disposition = %q, want attachment filename", cd)
	}
	records, err := csv.NewReader(strings.NewReader(rr.Body.String())).ReadAll()
	if err != nil {
		t.Fatalf("parse CSV: %v", err)
	}
	if len(records) != 3 {
		t.Fatalf("CSV rows = %d, want header + honeypot + rate-limit: %v", len(records), records)
	}
	if records[0][0] != "ip" || records[0][1] != "source" {
		t.Fatalf("CSV header = %v", records[0])
	}
	byIP := map[string]string{records[1][0]: records[1][1], records[2][0]: records[2][1]}
	if byIP["203.0.113.9"] != "honeypot" {
		t.Fatalf("CSV rows = %v, want a honeypot row for 203.0.113.9", records)
	}
	if byIP["198.51.100.7"] != "rate-limit" {
		t.Fatalf("CSV rows = %v, want a rate-limit row for 198.51.100.7", records)
	}
}

// withRIPEstatMocks points the lookup endpoints at httptest servers that
// serve canned network-info and AS-overview payloads in the REAL RIPEstat
// shape ("data.asns" as an array — there is no "data.asn" field).
func withRIPEstatMocks(t *testing.T) {
	t.Helper()
	ni := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"asns":["15169"],"prefix":"8.8.8.0/24"}}`))
	}))
	ao := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"holder":"Google LLC"}}`))
	}))
	t.Cleanup(ni.Close)
	t.Cleanup(ao.Close)
	oldNI, oldAO := ripestatNetworkInfo, ripestatASOverview
	ripestatNetworkInfo, ripestatASOverview = ni.URL, ao.URL
	t.Cleanup(func() {
		ripestatNetworkInfo, ripestatASOverview = oldNI, oldAO
	})
}

func TestLookupASN(t *testing.T) {
	withRIPEstatMocks(t)
	info, err := lookupASN(t.Context(), "8.8.8.8")
	if err != nil {
		t.Fatalf("lookupASN: %v", err)
	}
	if info.ASN != "AS15169" || info.Prefix != "8.8.8.0/24" {
		t.Fatalf("info = %+v", info)
	}
	if info.Holder != "Google LLC" {
		t.Fatalf("holder = %q, want Google LLC", info.Holder)
	}
}

func TestAbuseASNHandler(t *testing.T) {
	withRIPEstatMocks(t)
	h := &Handler{}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/abuse/asn", bytes.NewBufferString(`{"ip":"8.8.8.8"}`))
	h.abuseASN(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body %s", rr.Code, rr.Body.String())
	}
	for _, want := range []string{`"asn":"AS15169"`, `"holder":"Google LLC"`, `"prefix":"8.8.8.0/24"`} {
		if !strings.Contains(rr.Body.String(), want) {
			t.Errorf("body missing %s: %s", want, rr.Body.String())
		}
	}
	// Bad IP is rejected without touching the network.
	rr2 := httptest.NewRecorder()
	req2 := httptest.NewRequest(http.MethodPost, "/api/abuse/asn", bytes.NewBufferString(`{"ip":"nope"}`))
	h.abuseASN(rr2, req2)
	if rr2.Code != http.StatusBadRequest {
		t.Fatalf("bad-IP status = %d, want 400", rr2.Code)
	}
}

// TestAbuseASNHandlerNoRouting verifies that a definitive "no routing
// information" answer (an address that isn't announced — reserved,
// unassigned or unadvertised) is reported as an empty 200 result, not as a
// 502 error: the dashboard must show "no routing information" instead of an
// "ASN lookup failed" banner, exactly like the query-log label path.
func TestAbuseASNHandlerNoRouting(t *testing.T) {
	// Point network-info at a server whose answer carries no ASN (the shape
	// RIPEstat returns for non-routed space), so lookupASN reports the
	// definitive negative.
	ni := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"data":{}}`))
	}))
	ao := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"data":{}}`))
	}))
	t.Cleanup(ni.Close)
	t.Cleanup(ao.Close)
	oldNI, oldAO := ripestatNetworkInfo, ripestatASOverview
	ripestatNetworkInfo, ripestatASOverview = ni.URL, ao.URL
	t.Cleanup(func() {
		ripestatNetworkInfo, ripestatASOverview = oldNI, oldAO
	})

	h := &Handler{}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/abuse/asn", bytes.NewBufferString(`{"ip":"104.243.35.153"}`))
	h.abuseASN(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body %s — want 200 (definitive negative, not an error)", rr.Code, rr.Body.String())
	}
	if strings.Contains(rr.Body.String(), `"error"`) {
		t.Fatalf("body carries an error for a definitive negative: %s", rr.Body.String())
	}
}
