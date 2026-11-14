package dnsserver

import (
	"crypto/tls"
	"crypto/x509"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"

	"github.com/eoghan2t9/Irongrid-DNS/internal/cache"
	"github.com/eoghan2t9/Irongrid-DNS/internal/cert"
	"github.com/eoghan2t9/Irongrid-DNS/internal/filter"
	"github.com/eoghan2t9/Irongrid-DNS/internal/upstream"
)

func reserveTCPAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve tcp addr: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	return addr
}

// TestDoTRoundTrip verifies the DoT listener (used by Android Private DNS)
// accepts TLS connections and answers DNS queries, both with and without
// the "dot" ALPN extension.
func TestDoTRoundTrip(t *testing.T) {
	engine := filter.NewEngine()
	if _, err := engine.LoadList("test", "test list", []byte("||doubleclick.net^\n")); err != nil {
		t.Fatalf("load list: %v", err)
	}
	engine.Compile()

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

	dotAddr := reserveTCPAddr(t)
	tcpAddr := reserveTCPAddr(t)

	mgr := NewManager(h, tlsConf)
	results, err := mgr.Start("", tcpAddr, dotAddr, "", "", "", "/dns-query")
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	defer mgr.Shutdown(t.Context())

	// Ensure neither listener reported an asynchronous bind/serve error.
	select {
	case res := <-results:
		if res.Err != nil {
			t.Fatalf("listener %s (%s) failed: %v", res.Proto, res.Addr, res.Err)
		}
	case <-time.After(50 * time.Millisecond):
	}

	certPEM, err := os.ReadFile(filepath.Join(certDir, "cert.pem"))
	if err != nil {
		t.Fatalf("read cert: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(certPEM)

	for _, tc := range []struct {
		name  string
		alpn  []string
		qname string
		rcode uint16
	}{
		{name: "with dot ALPN", alpn: []string{"dot"}, qname: "example.com.", rcode: dns.RcodeSuccess},
		{name: "without ALPN", alpn: nil, qname: "doubleclick.net.", rcode: dns.RcodeNameError},
	} {
		t.Run(tc.name, func(t *testing.T) {
			clientTLS := &tls.Config{
				RootCAs:    pool,
				ServerName: "localhost",
				NextProtos: tc.alpn,
			}
			client := upstream.NewWithTLS(upstream.TLS, dotAddr, "localhost", clientTLS)
			m := new(dns.Msg)
			dnsutil.SetQuestion(m, tc.qname, dns.TypeA)
			resp, err := client.Query(t.Context(), m)
			if err != nil {
				t.Fatalf("dot query failed: %v", err)
			}
			if resp.Rcode != tc.rcode {
				t.Fatalf("rcode = %d, want %d", resp.Rcode, tc.rcode)
			}
		})
	}

	// Verify the plain TCP listener also serves its pre-bound socket.
	tcpClient := &upstream.Upstream{Transport: upstream.TCP, Addr: tcpAddr}
	m := new(dns.Msg)
	dnsutil.SetQuestion(m, "example.com.", dns.TypeA)
	resp, err := tcpClient.Query(t.Context(), m)
	if err != nil {
		t.Fatalf("tcp query failed: %v", err)
	}
	if resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("tcp rcode = %d, want %d", resp.Rcode, dns.RcodeSuccess)
	}
}
