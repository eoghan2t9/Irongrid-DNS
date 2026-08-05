package acme

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// mockServer runs fn on every request so each provider test can assert the
// request path/method and return canned JSON.
func mockServer(t *testing.T, fn func(w http.ResponseWriter, r *http.Request)) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(fn))
	t.Cleanup(srv.Close)
	return srv
}

// ---- DigitalOcean ----

func TestDigitalOceanPresentAndCleanup(t *testing.T) {
	var mu sync.Mutex
	created := map[string]bool{}
	zoneChecked := false

	srv := mockServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer do-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		mu.Lock()
		defer mu.Unlock()
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/domains/example.com/records":
			var b map[string]any
			_ = json.NewDecoder(r.Body).Decode(&b)
			// Relative label inside the example.com zone.
			if b["type"] != "TXT" || b["name"] != "_acme-challenge.dns" || b["data"] != "val123" {
				t.Errorf("bad create payload: %v", b)
			}
			created["_acme-challenge"] = true
			json.NewEncoder(w).Encode(map[string]any{"domain_record": map[string]any{"id": 7, "type": "TXT"}})
		case r.Method == http.MethodGet && r.URL.Path == "/domains/example.com/records":
			recs := []map[string]any{{"id": 7, "type": "TXT", "name": "_acme-challenge.example.com.", "data": "val123"}}
			json.NewEncoder(w).Encode(map[string]any{"domain_records": recs})
		case r.Method == http.MethodDelete && r.URL.Path == "/domains/example.com/records/7":
			created["_acme-challenge"] = false
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/domains/"):
			// Walk-up probe: only example.com is a real zone.
			if r.URL.Path != "/domains/example.com" {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			zoneChecked = true
			json.NewEncoder(w).Encode(map[string]any{"domain": map[string]any{"name": "example.com"}})
		default:
			t.Errorf("unexpected DO request: %s %s", r.Method, r.URL.Path)
		}
	})

	old := doAPI
	doAPI = srv.URL
	defer func() { doAPI = old }()

	p := &digitalOceanProvider{token: "do-token", hc: srv.Client()}
	ctx := context.Background()
	if err := p.Present(ctx, "dns.example.com", "val123"); err != nil {
		t.Fatalf("Present: %v", err)
	}
	if !zoneChecked || !created["_acme-challenge"] {
		t.Fatal("zone not probed or record not created")
	}
	if err := p.CleanUp(ctx, "dns.example.com", "val123"); err != nil {
		t.Fatalf("CleanUp: %v", err)
	}
	if created["_acme-challenge"] {
		t.Fatal("record not deleted")
	}
}

// ---- Hetzner ----

func TestHetznerPresentAndCleanup(t *testing.T) {
	var mu sync.Mutex
	createdID := ""
	srv := mockServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Auth-API-Token") != "hz-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		mu.Lock()
		defer mu.Unlock()
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/zones":
			zones := []map[string]any{{"id": "zone-1", "name": "example.com"}}
			json.NewEncoder(w).Encode(map[string]any{"zones": zones})
		case r.Method == http.MethodPost && r.URL.Path == "/records":
			var b map[string]any
			_ = json.NewDecoder(r.Body).Decode(&b)
			if b["zone_id"] != "zone-1" || b["type"] != "TXT" || b["name"] != "_acme-challenge.dns" || b["value"] != "val123" {
				t.Errorf("bad create payload: %v", b)
			}
			createdID = "rec-1"
			json.NewEncoder(w).Encode(map[string]any{"record": map[string]any{"id": "rec-1", "type": "TXT"}})
		case r.Method == http.MethodGet && r.URL.Path == "/records":
			recs := []map[string]any{{"id": "rec-1", "type": "TXT", "name": "_acme-challenge.dns", "value": "val123"}}
			json.NewEncoder(w).Encode(map[string]any{"records": recs})
		case r.Method == http.MethodDelete && r.URL.Path == "/records/rec-1":
			createdID = ""
			w.WriteHeader(http.StatusOK)
		default:
			t.Errorf("unexpected Hetzner request: %s %s", r.Method, r.URL.Path)
		}
	})

	old := hetznerAPI
	hetznerAPI = srv.URL
	defer func() { hetznerAPI = old }()

	p := &hetznerProvider{token: "hz-token", hc: srv.Client()}
	ctx := context.Background()
	if err := p.Present(ctx, "dns.example.com", "val123"); err != nil {
		t.Fatalf("Present: %v", err)
	}
	if createdID != "rec-1" {
		t.Fatal("record not created")
	}
	if err := p.CleanUp(ctx, "dns.example.com", "val123"); err != nil {
		t.Fatalf("CleanUp: %v", err)
	}
	if createdID != "" {
		t.Fatal("record not deleted")
	}
}

// ---- GoDaddy ----

func TestGoDaddyPresentAndCleanup(t *testing.T) {
	var mu sync.Mutex
	presented := false
	deleted := false

	srv := mockServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "sso-key gk:gs" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		mu.Lock()
		defer mu.Unlock()
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/domains/example.com":
			json.NewEncoder(w).Encode(map[string]any{"domainId": "x"})
		case r.Method == http.MethodPut && r.URL.Path == "/domains/example.com/records/TXT/_acme-challenge":
			var body []map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			if len(body) != 1 || body[0]["data"] != "val123" {
				t.Errorf("bad put payload: %v", body)
			}
			presented = true
			w.WriteHeader(http.StatusOK)
		case r.Method == http.MethodDelete && r.URL.Path == "/domains/example.com/records/TXT/_acme-challenge":
			deleted = true
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Errorf("unexpected GoDaddy request: %s %s", r.Method, r.URL.Path)
		}
	})

	old := godaddyAPI
	godaddyAPI = srv.URL
	defer func() { godaddyAPI = old }()

	p := &goDaddyProvider{key: "gk", secret: "gs", hc: srv.Client()}
	ctx := context.Background()
	if err := p.Present(ctx, "example.com", "val123"); err != nil {
		t.Fatalf("Present: %v", err)
	}
	if !presented {
		t.Fatal("record not presented")
	}
	if err := p.CleanUp(ctx, "example.com", "val123"); err != nil {
		t.Fatalf("CleanUp: %v", err)
	}
	if !deleted {
		t.Fatal("record not deleted")
	}
}

// ---- Route53 ----

func TestRoute53PresentAndCleanup(t *testing.T) {
	var mu sync.Mutex
	changes := []string{}

	srv := mockServer(t, func(w http.ResponseWriter, r *http.Request) {
		// SigV4 signed requests carry the auth header.
		if r.Header.Get("Authorization") == "" || !strings.Contains(r.Header.Get("Authorization"), "AWS4-HMAC-SHA256") {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		mu.Lock()
		defer mu.Unlock()
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/hostedzone":
			zones := `<ListHostedZonesByNameResponse><HostedZones><HostedZone><Id>/hostedzone/Z123</Id><Name>example.com.</Name></HostedZone></HostedZones></ListHostedZonesByNameResponse>`
			w.Header().Set("Content-Type", "application/xml")
			w.Write([]byte(zones))
		case r.Method == http.MethodPost && r.URL.Path == "/hostedzone/Z123/rrset":
			raw, _ := io.ReadAll(r.Body)
			body := string(raw)
			// The challenge record for dns.example.com lives at the FQDN
			// _acme-challenge.dns.example.com.; XML escapes the quotes
			// around the TXT value (&#34;).
			if !strings.Contains(body, "_acme-challenge.dns.example.com.") ||
				!strings.Contains(body, "&#34;val123&#34;") {
				t.Errorf("bad rrset body: %s", body)
			}
			if strings.Contains(body, "<Action>UPSERT</Action>") {
				changes = append(changes, "UPSERT")
			}
			if strings.Contains(body, "<Action>DELETE</Action>") {
				changes = append(changes, "DELETE")
			}
			w.Header().Set("Content-Type", "application/xml")
			w.Write([]byte(`<ChangeResourceRecordSetsResponse><ChangeInfo><Status>PENDING</Status></ChangeInfo></ChangeResourceRecordSetsResponse>`))
		default:
			t.Errorf("unexpected Route53 request: %s %s", r.Method, r.URL.Path)
		}
	})

	old := route53API
	route53API = srv.URL
	defer func() { route53API = old }()

	p := &route53Provider{accessKey: "AKIA", secretKey: "secret", hc: srv.Client()}
	ctx := context.Background()
	if err := p.Present(ctx, "dns.example.com", "val123"); err != nil {
		t.Fatalf("Present: %v", err)
	}
	if err := p.CleanUp(ctx, "dns.example.com", "val123"); err != nil {
		t.Fatalf("CleanUp: %v", err)
	}
	if len(changes) != 2 || changes[0] != "UPSERT" || changes[1] != "DELETE" {
		t.Fatalf("changes = %v, want [UPSERT DELETE]", changes)
	}
}

func TestSupportedProviders(t *testing.T) {
	got := SupportedProviders()
	want := []string{"cloudflare", "digitalocean", "hetzner", "godaddy", "route53"}
	if len(got) != len(want) {
		t.Fatalf("providers = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("providers = %v, want %v", got, want)
		}
	}
}
