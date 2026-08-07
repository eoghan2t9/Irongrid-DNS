package api

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/eoghan2t9/Irongrid-DNS/internal/config"
)

// newGeoTestHandler builds a Handler with a throwaway config and stubbed
// side effects (SaveConfig/RebuildGeo) so geoBlockIP can be tested without a
// real config file or country-data fetch.
func newGeoTestHandler() *Handler {
	return &Handler{
		Cfg:        config.Default(),
		SaveConfig: func() error { return nil },
		RebuildGeo: func(cfg config.GeoBlockConfig) error { return nil },
	}
}

func TestGeoBlockIP(t *testing.T) {
	h := newGeoTestHandler()
	h.Cfg.GeoBlock.Enabled = true

	post := func(body string) *httptest.ResponseRecorder {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/api/geo/blockip", bytes.NewBufferString(body))
		h.geoBlockIP(rr, req)
		return rr
	}

	// Bare IP, and the response reports the canonical entry.
	if rr := post(`{"ip":"203.0.113.9"}`); rr.Code != http.StatusOK {
		t.Fatalf("bare-IP block: status = %d, body %s", rr.Code, rr.Body.String())
	} else if !strings.Contains(rr.Body.String(), `"entry":"203.0.113.9"`) {
		t.Fatalf("bare-IP block body = %s, want entry 203.0.113.9", rr.Body.String())
	}
	// /24 network around a client.
	if rr := post(`{"ip":"198.51.100.42","prefix":24}`); rr.Code != http.StatusOK {
		t.Fatalf("/24 block: status = %d, body %s", rr.Code, rr.Body.String())
	}
	// IPv6 /64 network.
	if rr := post(`{"ip":"2001:db8::1234","prefix":64}`); rr.Code != http.StatusOK {
		t.Fatalf("IPv6 /64 block: status = %d, body %s", rr.Code, rr.Body.String())
	}
	want := []string{"203.0.113.9", "198.51.100.0/24", "2001:db8::/64"}
	if len(h.Cfg.GeoBlock.IPs) != 3 {
		t.Fatalf("GeoBlock.IPs = %v, want %v", h.Cfg.GeoBlock.IPs, want)
	}
	for i, e := range want {
		if h.Cfg.GeoBlock.IPs[i] != e {
			t.Fatalf("GeoBlock.IPs[%d] = %q, want %q (full: %v)", i, h.Cfg.GeoBlock.IPs[i], e, h.Cfg.GeoBlock.IPs)
		}
	}

	// Duplicate is a no-op and is reported as already present.
	n := len(h.Cfg.GeoBlock.IPs)
	if rr := post(`{"ip":"203.0.113.9"}`); rr.Code != http.StatusOK || len(h.Cfg.GeoBlock.IPs) != n {
		t.Fatalf("duplicate block: status = %d, IPs = %v", rr.Code, h.Cfg.GeoBlock.IPs)
	} else if !strings.Contains(rr.Body.String(), `"already":true`) {
		t.Fatalf("duplicate block body = %s, want already:true", rr.Body.String())
	}

	// Invalid inputs are rejected.
	for _, body := range []string{`{}`, `{"ip":""}`, `{"ip":"not-an-ip"}`, `{"ip":"203.0.113.9","prefix":33}`, `{"ip":"2001:db8::1","prefix":129}`} {
		if rr := post(body); rr.Code != http.StatusBadRequest {
			t.Errorf("body %s: status = %d, want 400 (body %s)", body, rr.Code, rr.Body.String())
		}
	}
}

// TestGeoBlockIPRequiresEnabled guards against silently adding entries that
// are never enforced: with geo blocking disabled the banner doesn't exist, so
// the quick-block must refuse rather than pretend the block took effect.
func TestGeoBlockIPRequiresEnabled(t *testing.T) {
	h := newGeoTestHandler() // config.Default() has GeoBlock.Enabled == false
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/geo/blockip", bytes.NewBufferString(`{"ip":"203.0.113.9"}`))
	h.geoBlockIP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("block with geo disabled: status = %d, body %s, want 400", rr.Code, rr.Body.String())
	}
	if len(h.Cfg.GeoBlock.IPs) != 0 {
		t.Fatalf("block with geo disabled mutated GeoBlock.IPs: %v", h.Cfg.GeoBlock.IPs)
	}
}
