package dnsserver

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"

	"github.com/eoghan2t9/Irongrid-DNS/internal/cert"
	"github.com/eoghan2t9/Irongrid-DNS/internal/filter"
)

// TestDoH3RoundTrip verifies the RFC 8484-over-HTTP/3 listener answers a
// GET /dns-query request from a real HTTP/3 client, including the blocked
// path (which proves the handler pipeline, not just the transport, runs).
func TestDoH3RoundTrip(t *testing.T) {
	engine := filter.NewEngine()
	if _, err := engine.LoadList("test", "test list", []byte("||doubleclick.net^\n")); err != nil {
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
	if _, err := mgr.Start("", "", "", "", "127.0.0.1:0", "", "/dns-query"); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer mgr.Shutdown(t.Context())

	addr := mgr.DoH3Addr()
	if addr == "" {
		t.Fatal("no DoH3 address")
	}
	t.Logf("DoH3 listening on %s", addr)

	// Trust the generated self-signed certificate.
	certPEM, err := os.ReadFile(filepath.Join(certDir, "cert.pem"))
	if err != nil {
		t.Fatalf("read cert: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(certPEM)
	clientTLS := &tls.Config{
		ServerName: "localhost",
		RootCAs:    pool,
	}
	rt := &http3.Transport{
		TLSClientConfig: clientTLS,
		QUICConfig:      &quic.Config{},
		Dial: func(ctx context.Context, addr string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
			return quic.DialAddrEarly(ctx, addr, tlsCfg, cfg)
		},
	}
	defer rt.Close()

	doh3Query := func(name string, qtype uint16) *dns.Msg {
		t.Helper()
		m := new(dns.Msg)
		m.SetQuestion(name, qtype)
		packed, err := m.Pack()
		if err != nil {
			t.Fatalf("pack query: %v", err)
		}
		url := "https://" + addr + "/dns-query?dns=" + base64.RawURLEncoding.EncodeToString(packed)
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, url, nil)
		if err != nil {
			t.Fatalf("request: %v", err)
		}
		resp, err := rt.RoundTrip(req)
		if err != nil {
			t.Fatalf("doh3 GET %s: %v", name, err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("doh3 GET %s: HTTP %d", name, resp.StatusCode)
		}
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("read body: %v", err)
		}
		out := new(dns.Msg)
		if err := out.Unpack(body); err != nil {
			t.Fatalf("unpack DoH3 response: %v", err)
		}
		if out.Id != m.Id {
			t.Fatalf("response ID %d != query ID %d", out.Id, m.Id)
		}
		return out
	}

	// Allowed path: without an upstream this resolves to SERVFAIL, which
	// still proves the DoH3 transport round-trips the handler pipeline.
	resp := doh3Query("example.com.", dns.TypeA)
	t.Logf("allowed-path rcode: %d", resp.Rcode)

	// Blocked path: the filter answers NXDOMAIN before upstream is used.
	resp2 := doh3Query("doubleclick.net.", dns.TypeA)
	if resp2.Rcode != dns.RcodeNameError {
		t.Fatalf("expected NXDOMAIN for blocked domain, got rcode %d", resp2.Rcode)
	}

	// The transport must tag queries with its own protocol, not lump them
	// under DoH: stats and per-protocol policy depend on the tag.
	if n := h.Stats.ByProtocol["doh3"].Load(); n < 2 {
		t.Fatalf("doh3 stats counter = %d, want >= 2 (allowed + blocked queries)", n)
	}
	if n := h.Stats.ByProtocol["doh"].Load(); n != 0 {
		t.Fatalf("doh stats counter = %d, want 0 (DoH3 queries must not be tagged doh)", n)
	}
}
