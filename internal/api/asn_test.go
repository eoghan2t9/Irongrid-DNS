package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestLogASN verifies the batch endpoint resolves owner info through
// RIPEstat (mocked), reports ASN + holder, and omits invalid entries.
func TestLogASN(t *testing.T) {
	withRIPEstatMocks(t)
	h := &Handler{}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/log/asn?ips=8.8.8.8,not-an-ip", nil)
	h.logASN(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body %s", rr.Code, rr.Body.String())
	}
	var out struct {
		ASN map[string]asnInfo `json:"asn"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	info, ok := out.ASN["8.8.8.8"]
	if !ok {
		t.Fatalf("8.8.8.8 missing from response: %v", out.ASN)
	}
	if info.ASN != "AS15169" || info.Holder != "Google LLC" || info.Prefix != "8.8.8.0/24" {
		t.Fatalf("8.8.8.8 info = %+v", info)
	}
	if _, ok := out.ASN["not-an-ip"]; ok {
		t.Fatalf("invalid entry must be ignored: %v", out.ASN)
	}
}

// TestLogASNEmpty verifies the endpoint with no usable IPs returns a clean
// empty map.
func TestLogASNEmpty(t *testing.T) {
	h := &Handler{}
	rr := httptest.NewRecorder()
	h.logASN(rr, httptest.NewRequest(http.MethodGet, "/api/log/asn?ips=,not-an-ip,,", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d", rr.Code)
	}
	var out struct {
		ASN map[string]asnInfo `json:"asn"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(out.ASN) != 0 {
		t.Fatalf("empty batch returned %v, want {}", out.ASN)
	}
}

// TestASNCache covers positive, negative and expiry behaviour.
func TestASNCache(t *testing.T) {
	c := newASNCache()
	now := time.Now()
	if _, ok := c.get("8.8.8.8", now); ok {
		t.Fatal("cold cache must miss")
	}
	c.put("8.8.8.8", asnInfo{ASN: "AS15169", Holder: "Google LLC"}, now)
	if info, ok := c.get("8.8.8.8", now.Add(time.Hour)); !ok || info.ASN != "AS15169" {
		t.Fatalf("positive cache miss: %+v %v", info, ok)
	}
	c.put("1.2.3.4", asnInfo{}, now) // negative hit
	if info, ok := c.get("1.2.3.4", now.Add(asnTTL-2*time.Hour)); !ok || info.ASN != "" {
		t.Fatalf("negative cache miss: %+v %v", info, ok)
	}
	if _, ok := c.get("1.2.3.4", now.Add(asnTTL+time.Hour)); ok {
		t.Fatal("expired negative entry must miss")
	}
	if info, ok := c.get("8.8.8.8", now.Add(asnTTL+time.Hour)); ok && info.ASN != "" {
		t.Fatal("expired positive entry must miss")
	}
	// Over the cap the cache resets instead of growing without limit.
	for i := range asnCap {
		c.put(fmt.Sprintf("k%d", i), asnInfo{ASN: "AS1"}, now)
	}
	c.put("trigger", asnInfo{ASN: "AS2"}, now) // crosses the cap and resets
	if _, ok := c.get("8.8.8.8", now); ok {
		t.Fatal("cache should have reset after exceeding the cap")
	}
}

// TestResolveASNCoalescesConcurrentLookups verifies concurrent owner lookups
// for the same IP collapse into one RIPEstat round trip: two dashboard views
// polling at once must not double the external API calls.
func TestResolveASNCoalescesConcurrentLookups(t *testing.T) {
	var niHits, aoHits atomic.Int64
	ni := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		niHits.Add(1)
		time.Sleep(300 * time.Millisecond) // keep the lookups overlapping
		_, _ = w.Write([]byte(`{"data":{"asn":"AS15169","prefix":"8.8.8.0/24","name":"GOOGLE","country":"US"}}`))
	}))
	defer ni.Close()
	ao := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		aoHits.Add(1)
		_, _ = w.Write([]byte(`{"data":{"holder":"Google LLC"}}`))
	}))
	defer ao.Close()
	oldNI, oldAO := ripestatNetworkInfo, ripestatASOverview
	ripestatNetworkInfo = ni.URL
	ripestatASOverview = ao.URL
	defer func() { ripestatNetworkInfo, ripestatASOverview = oldNI, oldAO }()

	h := &Handler{}
	const n = 4
	var wg sync.WaitGroup
	for range n {
		wg.Go(func() {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if info := h.resolveASN(ctx, "8.8.8.8"); info.ASN != "AS15169" || info.Holder != "Google LLC" {
				t.Errorf("resolveASN = %+v, want AS15169/Google LLC", info)
			}
		})
	}
	wg.Wait()
	if got := niHits.Load(); got != 1 {
		t.Fatalf("RIPEstat network-info endpoint hit %d times, want 1 (concurrent ASN lookups coalesced)", got)
	}
	if got := aoHits.Load(); got != 1 {
		t.Fatalf("RIPEstat AS-overview endpoint hit %d times, want 1", got)
	}
}

// TestResolveASNNoRoutingNegativelyCached verifies that a definitive
// "no routing information" answer is remembered (the upstream is not asked
// again within the TTL), while a transient network failure is not cached.
func TestResolveASNNoRoutingNegativelyCached(t *testing.T) {
	// 1. Empty routing info for everything: the first resolve must cache the
	//    negative result so the second resolve does not hit the upstream.
	var hits atomic.Int64
	empty := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		_, _ = w.Write([]byte(`{"data":{"asn":"","prefix":"","name":"","country":""}}`))
	}))
	defer empty.Close()
	oldNI, oldAO := ripestatNetworkInfo, ripestatASOverview
	ripestatNetworkInfo = empty.URL
	defer func() { ripestatNetworkInfo = oldNI }()

	h := &Handler{}
	ctx := context.Background()
	if info := h.resolveASN(ctx, "1.2.3.4"); info.ASN != "" {
		t.Fatal("expected no ASN for the empty mock")
	}
	if info := h.resolveASN(ctx, "1.2.3.4"); info.ASN != "" {
		t.Fatal("expected cached negative result")
	}
	if hits.Load() != 1 {
		t.Fatalf("upstream hit %d times, want 1 (negative result must be cached)", hits.Load())
	}

	// 2. A transient failure (unreachable server) must NOT be cached: after
	//    it, a working upstream is consulted again on the next resolve.
	down := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	downURL := down.URL
	down.Close() // now unreachable — lookups fail immediately
	oldClient := abuseHTTPClient
	abuseHTTPClient = &http.Client{Timeout: 500 * time.Millisecond}
	defer func() { abuseHTTPClient = oldClient }()

	ripestatNetworkInfo = downURL
	ripestatASOverview = downURL
	_ = h.resolveASN(ctx, "9.9.9.9") // fails, must not be cached

	hits.Store(0)
	goodNI := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		_, _ = w.Write([]byte(`{"data":{"asn":"AS64500","prefix":"10.0.0.0/24","name":"TEST","country":"ZZ"}}`))
	}))
	defer goodNI.Close()
	goodAO := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"holder":"Test Holder"}}`))
	}))
	defer goodAO.Close()
	ripestatNetworkInfo = goodNI.URL
	ripestatASOverview = goodAO.URL
	defer func() { ripestatASOverview = oldAO }()

	info := h.resolveASN(ctx, "9.9.9.9")
	if info.ASN != "AS64500" || info.Holder != "Test Holder" {
		t.Fatalf("transient failure was cached (got %+v) or enrichment failed", info)
	}
	if hits.Load() == 0 {
		t.Fatal("fresh lookup did not reach the upstream")
	}
}
