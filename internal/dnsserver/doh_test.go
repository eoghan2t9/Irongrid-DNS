package dnsserver

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/eoghan2t9/Irongrid-DNS/internal/cert"
	"github.com/eoghan2t9/Irongrid-DNS/internal/filter"
)

func TestClientIPFromRequest(t *testing.T) {
	newReq := func(remote, xff string) *http.Request {
		r := httptest.NewRequest(http.MethodGet, "/dns-query?dns=AA", nil)
		r.RemoteAddr = remote
		if xff != "" {
			r.Header.Set("X-Forwarded-For", xff)
		}
		return r
	}
	// No header: the direct remote address wins.
	if got := clientIPFromRequest(newReq("93.0.0.1:53000", "")); got != "93.0.0.1" {
		t.Errorf("no XFF: got %q, want 93.0.0.1", got)
	}
	// XFF from a loopback peer (cloudflared / nginx on the same box) is
	// honored — this is what makes geo blocking work behind the tunnel.
	if got := clientIPFromRequest(newReq("127.0.0.1:53000", "185.220.101.34")); got != "185.220.101.34" {
		t.Errorf("loopback proxy XFF: got %q, want 185.220.101.34", got)
	}
	// XFF from a private-LAN proxy is honored.
	if got := clientIPFromRequest(newReq("10.0.0.5:443", "185.220.101.34")); got != "185.220.101.34" {
		t.Errorf("private proxy XFF: got %q, want 185.220.101.34", got)
	}
	// XFF from a PUBLIC peer must be ignored (spoofing protection): the
	// header claiming 8.8.8.8 must not mask the real 185.220.101.34.
	if got := clientIPFromRequest(newReq("185.220.101.34:53000", "8.8.8.8")); got != "185.220.101.34" {
		t.Errorf("public peer XFF must be ignored: got %q, want 185.220.101.34", got)
	}
	// Malformed XFF is ignored.
	if got := clientIPFromRequest(newReq("127.0.0.1:53000", "not-an-ip")); got != "127.0.0.1" {
		t.Errorf("malformed XFF: got %q, want 127.0.0.1", got)
	}
	// The first hop of a proxy chain is used.
	if got := clientIPFromRequest(newReq("127.0.0.1:53000", "185.220.101.34, 10.1.1.1")); got != "185.220.101.34" {
		t.Errorf("proxy chain: got %q, want 185.220.101.34", got)
	}
	// A loopback remote address with no XFF resolves to the remote host.
	if got := clientIPFromRequest(newReq("[::1]:443", "")); got != "::1" {
		t.Errorf("v6 remote: got %q, want ::1", got)
	}
}

func TestIsTrustedProxy(t *testing.T) {
	cases := []struct {
		remote string
		want   bool
	}{
		{"127.0.0.1:443", true},       // loopback (cloudflared / local nginx)
		{"[::1]:443", true},           // v6 loopback
		{"127.0.0.1", true},           // bare IP without port
		{"10.0.0.5:443", true},        // private LAN proxy
		{"192.168.1.10:443", true},    // private LAN proxy
		{"185.220.101.34:443", false}, // public peer — never trusted
		{"proxy.local:443", false},    // hostname peer
		{"", false},                   // empty RemoteAddr
		{"not-an-address", false},     // unparseable
	}
	for _, c := range cases {
		if got := isTrustedProxy(c.remote); got != c.want {
			t.Errorf("isTrustedProxy(%q) = %v, want %v", c.remote, got, c.want)
		}
	}
}

// TestDoHHandlerShared verifies the handler returned by DoHHandler() (used
// when the dashboard shares its HTTPS port with DoH) answers RFC 8484
// requests over HTTP, including the blocking path.
func TestDoHHandlerShared(t *testing.T) {
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

	// Trust the generated self-signed certificate for the client.
	certPEM, err := os.ReadFile(filepath.Join(certDir, "cert.pem"))
	if err != nil {
		t.Fatalf("read cert: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(certPEM)

	newServer := func() (*httptest.Server, *http.Client) {
		// Serve the shared handler over TLS using the same generated cert
		// (mirrors the dashboard sharing its HTTPS listener with DoH).
		srv := httptest.NewUnstartedServer(mgr.DoHHandler())
		srv.TLS = tlsConf.Clone()
		srv.StartTLS()
		client := srv.Client()
		if tr, ok := client.Transport.(*http.Transport); ok {
			tr.TLSClientConfig = &tls.Config{RootCAs: pool, ServerName: "localhost"}
		}
		return srv, client
	}
	doH := func(name string) *dns.Msg {
		m := new(dns.Msg)
		m.SetQuestion(name, dns.TypeA)
		raw, err := m.Pack()
		if err != nil {
			t.Fatalf("pack: %v", err)
		}
		b64 := base64.RawURLEncoding.EncodeToString(raw)
		srv, client := newServer()
		defer srv.Close()

		resp, err := client.Get(srv.URL + "/dns-query?dns=" + b64)
		if err != nil {
			t.Fatalf("get %s: %v", name, err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status = %d, want 200", resp.StatusCode)
		}
		if ct := resp.Header.Get("Content-Type"); ct != dnsMessageContentType {
			t.Fatalf("content-type = %q, want %q", ct, dnsMessageContentType)
		}
		var body bytes.Buffer
		if _, err := body.ReadFrom(resp.Body); err != nil {
			t.Fatalf("read body: %v", err)
		}
		out := new(dns.Msg)
		if err := out.Unpack(body.Bytes()); err != nil {
			t.Fatalf("unpack: %v", err)
		}
		return out
	}

	// Blocked domain: the filter answers NXDOMAIN before upstream is used.
	if out := doH("doubleclick.net."); out.Rcode != dns.RcodeNameError {
		t.Fatalf("blocked rcode = %d, want NXDOMAIN", out.Rcode)
	}
	// Allowed path: without an upstream this returns SERVFAIL, which still
	// proves the transport round-trips through the shared handler.
	if out := doH("example.com."); out.Rcode == 0 {
		t.Fatal("expected a real response (SERVFAIL) for an allowed domain, got NOERROR placeholder")
	}

	// A GET without a ?dns= parameter is a malformed DoH request: the shared
	// handler must answer HTTP 400 (not panic, not serve a page).
	srv, client := newServer()
	defer srv.Close()
	resp, err := client.Get(srv.URL + "/dns-query")
	if err != nil {
		t.Fatalf("get /dns-query: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("GET /dns-query without dns param: status = %d, want 400", resp.StatusCode)
	}
	_ = context.Background()
}
