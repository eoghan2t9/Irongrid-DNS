package acme

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

// mockCloudflare is an in-memory fake of the Cloudflare v4 API enough for the
// dns-01 flow: zone lookup, record create, record list + delete.
type mockCloudflare struct {
	mu      sync.Mutex
	records []cfDNSRecord
	// captured holds the create payloads for assertions.
	captured []map[string]any
}

func (m *mockCloudflare) handle(w http.ResponseWriter, r *http.Request) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Auth check.
	if r.Header.Get("Authorization") != "Bearer test-token" {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	// Zone lookup: GET /zones?name=example.com&status=active (exact path so
	// the per-zone record routes below are not shadowed).
	if r.Method == http.MethodGet && r.URL.Path == "/zones" {
		name := r.URL.Query().Get("name")
		if !strings.HasSuffix(name, "example.com") {
			_ = json.NewEncoder(w).Encode(cfResponse{Success: true, Result: json.RawMessage("[]")})
			return
		}
		res := []cfZone{{ID: "zone-1", Name: "example.com"}}
		b, _ := json.Marshal(res)
		_ = json.NewEncoder(w).Encode(cfResponse{Success: true, Result: b})
		return
	}

	// Record create: POST /zones/zone-1/dns_records
	if r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/dns_records") {
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		m.captured = append(m.captured, body)
		rec := cfDNSRecord{
			ID:      "rec-" + string(rune('a'+len(m.records))),
			Name:    body["name"].(string),
			Type:    body["type"].(string),
			Content: body["content"].(string),
		}
		m.records = append(m.records, rec)
		b, _ := json.Marshal(rec)
		_ = json.NewEncoder(w).Encode(cfResponse{Success: true, Result: b})
		return
	}

	// Record list: GET /zones/zone-1/dns_records?type=TXT&name=...
	if r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/dns_records") {
		name := r.URL.Query().Get("name")
		var out []cfDNSRecord
		for _, rec := range m.records {
			if rec.Name == name {
				out = append(out, rec)
			}
		}
		b, _ := json.Marshal(out)
		_ = json.NewEncoder(w).Encode(cfResponse{Success: true, Result: b})
		return
	}

	// Record delete: DELETE /zones/zone-1/dns_records/rec-X
	if r.Method == http.MethodDelete && strings.Contains(r.URL.Path, "/dns_records/") {
		id := r.URL.Path[strings.LastIndex(r.URL.Path, "/")+1:]
		for i, rec := range m.records {
			if rec.ID == id {
				m.records = slices.Delete(m.records, i, i+1)
				break
			}
		}
		_ = json.NewEncoder(w).Encode(cfResponse{Success: true, Result: json.RawMessage("null")})
		return
	}

	w.WriteHeader(http.StatusNotFound)
}

// newMockCFProvider spins up the fake API and returns a provider pointed at
// it. The provider's do() uses http.DefaultClient against cfAPI; we swap the
// base URL via a test hook (cloudflareProvider.apiBase).
func newMockCFProvider(t *testing.T, mock *mockCloudflare) *cloudflareProvider {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(mock.handle))
	t.Cleanup(srv.Close)
	old := cfAPI
	cfAPI = srv.URL
	t.Cleanup(func() { cfAPI = old })
	return &cloudflareProvider{token: "test-token", hc: &http.Client{Timeout: 10 * time.Second}}
}

func TestCloudflarePresentAndCleanup(t *testing.T) {
	mock := &mockCloudflare{}
	p := newMockCFProvider(t, mock)

	ctx := context.Background()
	if err := p.Present(ctx, "dns.example.com", "abc123"); err != nil {
		t.Fatalf("Present: %v", err)
	}
	if len(mock.records) != 1 {
		t.Fatalf("records = %d, want 1", len(mock.records))
	}
	rec := mock.records[0]
	if rec.Name != "_acme-challenge.dns.example.com" {
		t.Errorf("record name = %q, want _acme-challenge.dns.example.com", rec.Name)
	}
	if rec.Content != "abc123" || rec.Type != "TXT" {
		t.Errorf("record = %+v, want TXT abc123", rec)
	}
	if len(mock.captured) != 1 || mock.captured[0]["ttl"] != float64(120) {
		t.Errorf("captured payload = %+v, want ttl 120", mock.captured)
	}

	if err := p.CleanUp(ctx, "dns.example.com", "abc123"); err != nil {
		t.Fatalf("CleanUp: %v", err)
	}
	if len(mock.records) != 0 {
		t.Errorf("records after cleanup = %d, want 0", len(mock.records))
	}
}

func TestCloudflareWildcardChallengeName(t *testing.T) {
	mock := &mockCloudflare{}
	p := newMockCFProvider(t, mock)
	// Wildcard authz identifiers in ACME arrive as "example.com" with the
	// wildcard flag; make sure a "*.example.com" style domain is normalized.
	if got := challengeRecordName("*.example.com"); got != "_acme-challenge.example.com" {
		t.Errorf("wildcard name = %q", got)
	}
	if err := p.Present(context.Background(), "example.com", "v"); err != nil {
		t.Fatalf("Present: %v", err)
	}
	if mock.records[0].Name != "_acme-challenge.example.com" {
		t.Errorf("name = %q", mock.records[0].Name)
	}
}

func TestCloudflareZoneSearchWalksUp(t *testing.T) {
	mock := &mockCloudflare{}
	// Present a domain that isn't directly a zone: sub.example.com lives in
	// zone example.com, so the provider must walk up labels.
	if err := newMockCFProvider(t, mock).Present(context.Background(), "deep.sub.example.com", "v"); err != nil {
		t.Fatalf("Present: %v", err)
	}
	if len(mock.records) != 1 {
		t.Fatalf("records = %d, want 1", len(mock.records))
	}
	if mock.records[0].Name != "_acme-challenge.deep.sub.example.com" {
		t.Errorf("name = %q", mock.records[0].Name)
	}
}

func TestCloudflareNoZoneFound(t *testing.T) {
	mock := &mockCloudflare{}
	p := newMockCFProvider(t, mock)
	err := p.Present(context.Background(), "other.org", "v")
	if err == nil || !strings.Contains(err.Error(), "no active zone") {
		t.Fatalf("err = %v, want no-active-zone error", err)
	}
}

func TestCloudflareUnauthorized(t *testing.T) {
	mock := &mockCloudflare{}
	p := &cloudflareProvider{token: "wrong-token", hc: &http.Client{Timeout: 10 * time.Second}}
	old := cfAPI
	srv := httptest.NewServer(http.HandlerFunc(mock.handle))
	defer srv.Close()
	cfAPI = srv.URL
	defer func() { cfAPI = old }()

	err := p.Present(context.Background(), "dns.example.com", "v")
	if err == nil || !strings.Contains(err.Error(), "401") {
		t.Fatalf("err = %v, want 401 error", err)
	}
}

func TestNewDNSProvider(t *testing.T) {
	if p, err := NewDNSProvider("", DNSProviderConfig{}, time.Second); err != nil || p != nil {
		t.Fatalf("empty provider = %v, %v; want nil,nil", p, err)
	}
	if _, err := NewDNSProvider("cloudflare", DNSProviderConfig{CloudflareToken: "tok"}, time.Second); err != nil {
		t.Fatalf("cloudflare: %v", err)
	}
	if _, err := NewDNSProvider("cloudflare", DNSProviderConfig{}, time.Second); err == nil {
		t.Fatal("cloudflare without token: expected error")
	}
	if _, err := NewDNSProvider("route53", DNSProviderConfig{AWSAccessKeyID: "a", AWSSecretAccessKey: "s"}, time.Second); err != nil {
		t.Fatalf("route53: %v", err)
	}
	if _, err := NewDNSProvider("nonsense", DNSProviderConfig{}, time.Second); err == nil {
		t.Fatal("nonsense: expected unsupported error")
	}
}
