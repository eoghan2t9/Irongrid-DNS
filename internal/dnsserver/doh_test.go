package dnsserver

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/eoghan2t9/Irongrid-DNS/internal/cert"
	"github.com/eoghan2t9/Irongrid-DNS/internal/filter"
	"github.com/eoghan2t9/Irongrid-DNS/internal/geoip"
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
	if got := clientIPFromRequest(newReq("93.0.0.1:53000", ""), nil, 1); got != "93.0.0.1" {
		t.Errorf("no XFF: got %q, want 93.0.0.1", got)
	}
	// XFF from a loopback peer (cloudflared / nginx on the same box) is
	// honored — this is what makes geo blocking work behind the tunnel.
	if got := clientIPFromRequest(newReq("127.0.0.1:53000", "185.220.101.34"), nil, 1); got != "185.220.101.34" {
		t.Errorf("loopback proxy XFF: got %q, want 185.220.101.34", got)
	}
	// XFF from a private-LAN proxy is honored.
	if got := clientIPFromRequest(newReq("10.0.0.5:443", "185.220.101.34"), nil, 1); got != "185.220.101.34" {
		t.Errorf("private proxy XFF: got %q, want 185.220.101.34", got)
	}
	// XFF from a PUBLIC peer must be ignored (spoofing protection): the
	// header claiming 8.8.8.8 must not mask the real 185.220.101.34.
	if got := clientIPFromRequest(newReq("185.220.101.34:53000", "8.8.8.8"), nil, 1); got != "185.220.101.34" {
		t.Errorf("public peer XFF must be ignored: got %q, want 185.220.101.34", got)
	}
	// Malformed XFF is ignored.
	if got := clientIPFromRequest(newReq("127.0.0.1:53000", "not-an-ip"), nil, 1); got != "127.0.0.1" {
		t.Errorf("malformed XFF: got %q, want 127.0.0.1", got)
	}
	// With the default hop limit of 1 the rightmost entry is used — the
	// address the trusted peer itself saw, which cannot be spoofed by an
	// upstream hop claiming a different client.
	if got := clientIPFromRequest(newReq("127.0.0.1:53000", "185.220.101.34, 10.1.1.1"), nil, 1); got != "10.1.1.1" {
		t.Errorf("proxy chain hop_limit 1: got %q, want 10.1.1.1", got)
	}
	// Hop limit 2 trusts two hops: the client is the 2nd entry from the
	// right, and spoofed entries further left are discarded.
	if got := clientIPFromRequest(newReq("127.0.0.1:53000", "6.6.6.6, 185.220.101.34, 10.1.1.1"), nil, 2); got != "185.220.101.34" {
		t.Errorf("proxy chain hop_limit 2: got %q, want 185.220.101.34", got)
	}
	// A chain shorter than the hop limit clamps to the leftmost entry.
	if got := clientIPFromRequest(newReq("127.0.0.1:53000", "185.220.101.34"), nil, 3); got != "185.220.101.34" {
		t.Errorf("chain shorter than hop limit: got %q, want 185.220.101.34", got)
	}
	// A loopback remote address with no XFF resolves to the remote host.
	if got := clientIPFromRequest(newReq("[::1]:443", ""), nil, 1); got != "::1" {
		t.Errorf("v6 remote: got %q, want ::1", got)
	}
}

func TestClientIPFromRequestTrustedProxies(t *testing.T) {
	// A public reverse proxy listed in server.trusted_proxies may stamp XFF
	// — that is the whole point of the knob (e.g. a CDN in front of DoH).
	_, cdn, err := net.ParseCIDR("203.0.113.0/24")
	if err != nil {
		t.Fatalf("parse cidr: %v", err)
	}
	trusted := []*net.IPNet{cdn}
	newReq := func(remote, xff string) *http.Request {
		r := httptest.NewRequest(http.MethodGet, "/dns-query?dns=AA", nil)
		r.RemoteAddr = remote
		if xff != "" {
			r.Header.Set("X-Forwarded-For", xff)
		}
		return r
	}
	// Peer inside the trusted CDN range: XFF honored.
	if got := clientIPFromRequest(newReq("203.0.113.7:443", "198.51.100.9"), trusted, 1); got != "198.51.100.9" {
		t.Errorf("trusted CDN peer XFF: got %q, want 198.51.100.9", got)
	}
	// A public peer NOT in the list is still untrusted: spoofing stays
	// impossible unless the operator explicitly listed the proxy.
	if got := clientIPFromRequest(newReq("198.51.100.9:443", "8.8.8.8"), trusted, 1); got != "198.51.100.9" {
		t.Errorf("unlisted public peer XFF must be ignored: got %q, want 198.51.100.9", got)
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
		{"185.220.101.34:443", false}, // public peer — never trusted by default
		{"proxy.local:443", false},    // hostname peer
		{"", false},                   // empty RemoteAddr
		{"not-an-address", false},     // unparseable
	}
	for _, c := range cases {
		if got := isTrustedProxy(c.remote, nil); got != c.want {
			t.Errorf("isTrustedProxy(%q) = %v, want %v", c.remote, got, c.want)
		}
	}
	// A public peer inside an extra trusted net becomes trusted; one
	// outside it stays untrusted.
	_, cdn, err := net.ParseCIDR("203.0.113.0/24")
	if err != nil {
		t.Fatalf("parse cidr: %v", err)
	}
	if !isTrustedProxy("203.0.113.7:443", []*net.IPNet{cdn}) {
		t.Error("public peer inside trusted net must be trusted")
	}
	if isTrustedProxy("198.51.100.9:443", []*net.IPNet{cdn}) {
		t.Error("public peer outside trusted net must stay untrusted")
	}
}

// TestDoHASNHeader verifies the X-Irongrid-Client-ASN response header: it is
// emitted — with the ASN the server attributes to the client — only when
// server.doh_asn_header is on AND the client's ISP is in a configured ASN
// list (a client group's table here); clients with no ASN data, or with the
// toggle off, get no header.
func TestDoHASNHeader(t *testing.T) {
	h := NewHandler(filter.NewEngine(), nil, nil, nil, "nxdomain", 600, 5*time.Second)
	// A client router carrying an ASN table covering 1.1.1.0/24 -> AS13335.
	allow, _, err := geoip.LoadASNTables(
		[]byte("1.1.1.0\t1.1.1.255\t13335\tUS\tCloudflare\n"), nil,
		map[uint32]bool{13335: true}, nil)
	if err != nil {
		t.Fatalf("asn table: %v", err)
	}
	router := NewClientRouter()
	router.SetPolicies(nil, allow)
	h.SetClientRouter(router)

	mgr := NewManager(h, nil)
	mgr.SetDoHASNHeader(true)

	doH := func(remote string) *httptest.ResponseRecorder {
		m := new(dns.Msg)
		m.SetQuestion("example.com.", dns.TypeA)
		raw, err := m.Pack()
		if err != nil {
			t.Fatalf("pack: %v", err)
		}
		r := httptest.NewRequest(http.MethodGet, "/dns-query?dns="+base64.RawURLEncoding.EncodeToString(raw), nil)
		r.RemoteAddr = remote
		w := httptest.NewRecorder()
		mgr.handleDoH(w, r, "doh")
		return w
	}

	// Client inside the table's range: the header carries AS13335 and the
	// stats counter ticks.
	if w := doH("1.1.1.1:53000"); w.Header().Get(asnResponseHeader) != "13335" {
		t.Errorf("ASN header = %q, want 13335", w.Header().Get(asnResponseHeader))
	}
	if got := h.Stats.ASNHeader.Load(); got != 1 {
		t.Errorf("ASNHeader counter = %d, want 1", got)
	}
	// Client with no ASN data: no header, no counter tick.
	if w := doH("9.9.9.9:53000"); w.Header().Get(asnResponseHeader) != "" {
		t.Errorf("ASN header for unknown client = %q, want absent", w.Header().Get(asnResponseHeader))
	}
	// Toggle off: no header even for a known client, and the counter stays.
	mgr.SetDoHASNHeader(false)
	if w := doH("1.1.1.1:53000"); w.Header().Get(asnResponseHeader) != "" {
		t.Errorf("ASN header with toggle off = %q, want absent", w.Header().Get(asnResponseHeader))
	}
	if got := h.Stats.ASNHeader.Load(); got != 1 {
		t.Errorf("ASNHeader counter = %d after toggle-off request, want 1", got)
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
}

// TestClientASNMemoized verifies ClientASN's per-client memo: repeat calls
// for the same client are served from the cache, a client with no
// attribution is cached as not-found, and swapping the client router (which
// replaces the ASN table) clears the memo so it never serves attribution
// computed against the previous tables.
func TestClientASNMemoized(t *testing.T) {
	h := NewHandler(filter.NewEngine(), nil, nil, nil, "nxdomain", 600, 5*time.Second)
	table, _, err := geoip.LoadASNTables(
		[]byte("1.1.1.0\t1.1.1.255\t13335\tUS\tCloudflare\n"), nil,
		map[uint32]bool{13335: true}, nil)
	if err != nil {
		t.Fatalf("asn table: %v", err)
	}
	router := NewClientRouter()
	router.SetPolicies(nil, table)
	h.SetClientRouter(router)

	if asn, ok := h.ClientASN("1.1.1.1"); !ok || asn != 13335 {
		t.Fatalf("ClientASN(1.1.1.1) = %d,%v want 13335,true", asn, ok)
	}
	// Memoized hit: same result without touching the tables.
	if asn, ok := h.ClientASN("1.1.1.1"); !ok || asn != 13335 {
		t.Fatalf("memoized ClientASN(1.1.1.1) = %d,%v want 13335,true", asn, ok)
	}
	// A client with no attribution is cached as not-found and stays that way.
	if _, ok := h.ClientASN("9.9.9.9"); ok {
		t.Fatal("ClientASN(9.9.9.9) = found, want not found")
	}
	if _, ok := h.ClientASN("9.9.9.9"); ok {
		t.Fatal("memoized ClientASN(9.9.9.9) = found, want not found")
	}

	// Swapping the router swaps the table — the memo must not serve the old
	// attribution (1.1.1.1 now belongs to a different ISP).
	table2, _, err := geoip.LoadASNTables(
		[]byte("1.1.1.0\t1.1.1.255\t15169\tUS\tGoogle\n"), nil,
		map[uint32]bool{15169: true}, nil)
	if err != nil {
		t.Fatalf("asn table 2: %v", err)
	}
	router2 := NewClientRouter()
	router2.SetPolicies(nil, table2)
	h.SetClientRouter(router2)

	if asn, ok := h.ClientASN("1.1.1.1"); !ok || asn != 15169 {
		t.Fatalf("after swap ClientASN(1.1.1.1) = %d,%v want 15169,true", asn, ok)
	}
}
