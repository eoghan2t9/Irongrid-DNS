package dnsserver

import (
	"context"
	"crypto/x509"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/miekg/dns"

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

	h := NewHandler(engine, nil, nil, nil, "nxdomain", 600, 5*time.Second)

	certDir := filepath.Join(t.TempDir(), "certs")
	tlsConf, err := cert.LoadOrGenerate("", "", certDir, []string{"localhost", "127.0.0.1"})
	if err != nil {
		t.Fatalf("tls: %v", err)
	}
	mgr := NewManager(h, tlsConf)
	if _, err := mgr.Start("", "", "", "", "127.0.0.1:0", "/dns-query"); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer mgr.Shutdown(context.Background())

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
	resp, err := client.Query(context.Background(), m)
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
	resp2, err := client.Query(context.Background(), m2)
	if err != nil {
		t.Fatalf("doq blocked query failed: %v", err)
	}
	if resp2.Rcode != dns.RcodeNameError {
		t.Fatalf("expected NXDOMAIN for blocked domain, got rcode %d", resp2.Rcode)
	}
	t.Log("blocked domain correctly answered NXDOMAIN over DoQ")
}
