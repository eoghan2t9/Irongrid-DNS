package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// TestLogHostnames verifies the batch endpoint resolves PTR records through
// the configured upstream, omits IPs without a PTR (and invalid entries), and
// reports the reverse name without its trailing dot.
func TestLogHostnames(t *testing.T) {
	addr := startUDPDNS(t, map[string][]dns.RR{
		"4.3.2.1.in-addr.arpa.|PTR": {&dns.PTR{
			Hdr: dns.RR_Header{Name: "4.3.2.1.in-addr.arpa.", Rrtype: dns.TypePTR, Class: dns.ClassINET, Ttl: 300},
			Ptr: "host.example.net.",
		}},
	})
	h := handlerFor(t, addr)

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/log/hostnames?ips=1.2.3.4,not-an-ip,8.8.8.8", nil)
	h.logHostnames(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body %s", rr.Code, rr.Body.String())
	}
	var out struct {
		Hostnames map[string]string `json:"hostnames"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got := out.Hostnames["1.2.3.4"]; got != "host.example.net" {
		t.Fatalf("1.2.3.4 resolved to %q, want host.example.net (no trailing dot)", got)
	}
	// Unresolved (NXDOMAIN from the test server) and invalid IPs are omitted.
	if _, ok := out.Hostnames["8.8.8.8"]; ok {
		t.Fatalf("IP without a PTR record must be omitted: %v", out.Hostnames)
	}
	if _, ok := out.Hostnames["not-an-ip"]; ok {
		t.Fatalf("invalid entry must be ignored: %v", out.Hostnames)
	}
}

// TestResolveHostnameCoalescesConcurrentLookups verifies concurrent PTR
// lookups for the same IP collapse into one upstream query: parallel
// dashboard polls must not double upstream reverse-DNS traffic.
func TestResolveHostnameCoalescesConcurrentLookups(t *testing.T) {
	var hits atomic.Int64
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		hits.Add(1)
		time.Sleep(300 * time.Millisecond) // keep the lookups overlapping
		m := new(dns.Msg)
		m.SetReply(r)
		m.Answer = append(m.Answer, &dns.PTR{
			Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypePTR, Class: dns.ClassINET, Ttl: 300},
			Ptr: "host.example.net.",
		})
		_ = w.WriteMsg(m)
	})}
	go func() { _ = srv.ActivateAndServe() }()
	t.Cleanup(func() { _ = srv.Shutdown() })

	h := handlerFor(t, pc.LocalAddr().String())

	const n = 4
	var wg sync.WaitGroup
	for range n {
		wg.Go(func() {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			if name := h.resolveHostname(ctx, "1.2.3.4"); name != "host.example.net" {
				t.Errorf("resolveHostname = %q, want host.example.net", name)
			}
		})
	}
	wg.Wait()
	if got := hits.Load(); got != 1 {
		t.Fatalf("upstream PTR server answered %d times, want 1 (concurrent hostname lookups coalesced)", got)
	}
}

// TestLogHostnamesEmpty verifies the endpoint with no usable IPs returns a
// clean empty map rather than an error.
func TestLogHostnamesEmpty(t *testing.T) {
	h := &Handler{}
	rr := httptest.NewRecorder()
	h.logHostnames(rr, httptest.NewRequest(http.MethodGet, "/api/log/hostnames?ips=,not-an-ip,,", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d", rr.Code)
	}
	var out struct {
		Hostnames map[string]string `json:"hostnames"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(out.Hostnames) != 0 {
		t.Fatalf("empty batch returned %v, want {}", out.Hostnames)
	}
}

// TestHostCache covers positive, negative and expiry behaviour — including
// that a repeated lookup for a PTR-less IP is served from the negative cache
// instead of re-querying.
func TestHostCache(t *testing.T) {
	c := newHostCache()
	now := time.Now()
	if _, ok := c.get("1.2.3.4", now); ok {
		t.Fatal("cold cache must miss")
	}

	c.put("1.2.3.4", "host.example.net", now)
	if name, ok := c.get("1.2.3.4", now.Add(time.Minute)); !ok || name != "host.example.net" {
		t.Fatalf("positive cache miss: %q %v", name, ok)
	}

	c.put("5.6.7.8", "", now) // negative hit
	if name, ok := c.get("5.6.7.8", now.Add(hostNegTTL-2*time.Minute)); !ok || name != "" {
		t.Fatalf("negative cache miss: %q %v", name, ok)
	}
	if _, ok := c.get("5.6.7.8", now.Add(hostNegTTL+time.Minute)); ok {
		t.Fatal("expired negative entry must miss")
	}
	if name, ok := c.get("1.2.3.4", now.Add(hostPosTTL+time.Minute)); ok && name != "" {
		t.Fatal("expired positive entry must miss")
	}

	// Re-caching refreshes the TTL.
	c.put("1.2.3.4", "host.example.net", now.Add(hostPosTTL))
	if _, ok := c.get("1.2.3.4", now.Add(hostPosTTL+time.Minute)); !ok {
		t.Fatal("refreshed entry must still be cached")
	}

	// Over the cap, the cache resets instead of growing without limit.
	for i := range hostCap {
		c.put(fmt.Sprintf("k%d", i), "", now)
	}
	c.put("trigger", "", now) // this put crosses the cap and resets the cache
	if _, ok := c.get("1.2.3.4", now); ok {
		t.Fatal("cache should have reset after exceeding the cap")
	}
}
