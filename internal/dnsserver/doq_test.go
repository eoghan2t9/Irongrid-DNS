package dnsserver

import (
	"crypto/x509"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/eoghan2t9/Irongrid-DNS/internal/cache"
	"github.com/eoghan2t9/Irongrid-DNS/internal/cert"
	"github.com/eoghan2t9/Irongrid-DNS/internal/filter"
	"github.com/eoghan2t9/Irongrid-DNS/internal/upstream"
)

// TestDoQRoundTrip verifies the RFC 9250 DoQ server answers a query sent by
// the DoQ client, including the blocking path.
func TestDoQRoundTrip(t *testing.T) {
	engine := filter.NewEngine()
	if _, err := engine.LoadList("test", "test list", []byte("||doubleclick.net^\nbad-domain.org\n")); err != nil {
		t.Fatalf("load list: %v", err)
	}
	engine.Compile()

	// A UDP upstream plus a response cache so the cache-hit path — served
	// from the stored packed bytes via writeRaw's RFC 9250 length-prefixed
	// write — is exercised over a real QUIC stream too.
	upAddr := startUDPTestServer(t, "9.9.9.9", 0)
	c := cache.NewLocalOnly(time.Hour, time.Minute, 512, 0)
	h := NewHandler(engine, c, []*upstream.Upstream{
		{Transport: upstream.UDP, Addr: upAddr},
	}, nil, "nxdomain", 600, 5*time.Second)

	certDir := filepath.Join(t.TempDir(), "certs")
	tlsConf, err := cert.LoadOrGenerate("", "", certDir, []string{"localhost", "127.0.0.1"})
	if err != nil {
		t.Fatalf("tls: %v", err)
	}
	mgr := NewManager(h, tlsConf)
	if _, err := mgr.Start("", "", "", "", "", "127.0.0.1:0", "/dns-query"); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer mgr.Shutdown(t.Context())

	addr := mgr.DoQAddr()
	if addr == "" {
		t.Fatal("no DoQ address")
	}
	t.Logf("DoQ listening on %s", addr)

	clientTLS := tlsConf.Clone()
	clientTLS.ServerName = "localhost"
	// Trust the generated self-signed certificate.
	certPEM, err := os.ReadFile(filepath.Join(certDir, "cert.pem"))
	if err == nil {
		pool := x509.NewCertPool()
		pool.AppendCertsFromPEM(certPEM)
		clientTLS.RootCAs = pool
	}
	client := upstream.NewWithTLS(upstream.QUIC, addr, "localhost", clientTLS)

	// Allowed path: without an upstream configured this returns SERVFAIL,
	// which still proves the DoQ transport round-trips.
	m := new(dns.Msg)
	m.SetQuestion("example.com.", dns.TypeA)
	resp, err := client.Query(t.Context(), m)
	if err != nil {
		t.Fatalf("doq query failed: %v", err)
	}
	if resp == nil {
		t.Fatal("nil response")
	}
	t.Logf("allowed-path rcode: %d", resp.Rcode)

	// Blocked path: the filter answers NXDOMAIN before upstream is used.
	m2 := new(dns.Msg)
	m2.SetQuestion("doubleclick.net.", dns.TypeA)
	resp2, err := client.Query(t.Context(), m2)
	if err != nil {
		t.Fatalf("doq blocked query failed: %v", err)
	}
	if resp2.Rcode != dns.RcodeNameError {
		t.Fatalf("expected NXDOMAIN for blocked domain, got rcode %d", resp2.Rcode)
	}
	t.Log("blocked domain correctly answered NXDOMAIN over DoQ")

	// Cache-hit path: resolve once (populating the cache), wait for the
	// background cache write, then resolve again — the second answer comes
	// from the stored packed bytes over the raw DoQ write path.
	warm := new(dns.Msg)
	warm.SetQuestion("cached.example.com.", dns.TypeA)
	if resp3, err := client.Query(t.Context(), warm); err != nil || resp3 == nil || len(resp3.Answer) == 0 {
		t.Fatalf("cache-warm query failed: resp=%v err=%v", resp3, err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if c.Lookup(warm.Question[0]).Msg() != nil {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	hit := new(dns.Msg)
	hit.SetQuestion("cached.example.com.", dns.TypeA)
	resp4, err := client.Query(t.Context(), hit)
	if err != nil {
		t.Fatalf("cache-hit query failed: %v", err)
	}
	if resp4 == nil || len(resp4.Answer) == 0 {
		t.Fatalf("expected a cached answer, got %v", resp4)
	}
	if a, ok := resp4.Answer[0].(*dns.A); !ok || a.A.String() != "9.9.9.9" {
		t.Fatalf("cached answer = %v, want A 9.9.9.9", resp4.Answer[0])
	}
	t.Log("cache-hit path answered from the raw packed bytes over DoQ")
}
