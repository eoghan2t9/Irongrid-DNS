package upstream

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"

	"github.com/eoghan2t9/Irongrid-DNS/internal/cert"
)

func aQuery() *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion("example.com.", dns.TypeA)
	return m
}

// writeLenPrefixed / readLenPrefixed implement the 2-byte length-prefixed
// framing shared by DNS-over-TCP, DoT and DoQ.
func writeLenPrefixed(w io.Writer, packed []byte) error {
	buf := make([]byte, 2+len(packed))
	binary.BigEndian.PutUint16(buf[:2], uint16(len(packed)))
	copy(buf[2:], packed)
	_, err := w.Write(buf)
	return err
}

func readLenPrefixed(r io.Reader) ([]byte, error) {
	var lenBuf [2]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return nil, err
	}
	buf := make([]byte, binary.BigEndian.Uint16(lenBuf[:]))
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

// serveOneAnswer answers one length-prefixed DNS query on conn with a fixed
// A record, looping to serve further queries on the same connection (so a
// reused connection is indistinguishable from a fresh one to the client).
func serveOneAnswer(conn net.Conn, ip string) {
	defer conn.Close()
	for {
		reqBytes, err := readLenPrefixed(conn)
		if err != nil {
			return
		}
		req := new(dns.Msg)
		if err := req.Unpack(reqBytes); err != nil {
			return
		}
		resp := new(dns.Msg)
		resp.SetReply(req)
		resp.Answer = append(resp.Answer, &dns.A{
			Hdr: dns.RR_Header{Name: req.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
			A:   net.ParseIP(ip),
		})
		packed, err := resp.Pack()
		if err != nil {
			return
		}
		if err := writeLenPrefixed(conn, packed); err != nil {
			return
		}
	}
}

// startTCPTestServer runs a plain (non-TLS) length-prefixed DNS test server
// and returns its address plus a live counter of accepted connections.
func startTCPTestServer(t *testing.T) (addr string, accepted *atomic.Int32) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	accepted = &atomic.Int32{}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			accepted.Add(1)
			go serveOneAnswer(conn, "1.2.3.4")
		}
	}()
	t.Cleanup(func() { ln.Close() })
	return ln.Addr().String(), accepted
}

// testTLSConfig returns a self-signed server TLS config plus a client config
// that trusts it, for DoT/DoQ test servers.
func testTLSConfig(t *testing.T) (server *tls.Config, client *tls.Config) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "certs")
	server, err := cert.LoadOrGenerate("", "", dir, []string{"localhost", "127.0.0.1"})
	if err != nil {
		t.Fatalf("generate cert: %v", err)
	}
	client = &tls.Config{ServerName: "localhost"}
	if pem, err := os.ReadFile(filepath.Join(dir, "cert.pem")); err == nil {
		pool := x509.NewCertPool()
		pool.AppendCertsFromPEM(pem)
		client.RootCAs = pool
	}
	return server, client
}

// startDoTTestServer runs a TLS-wrapped length-prefixed DNS test server.
func startDoTTestServer(t *testing.T) (addr string, clientTLS *tls.Config, accepted *atomic.Int32) {
	t.Helper()
	serverTLS, clientTLS := testTLSConfig(t)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", serverTLS)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	accepted = &atomic.Int32{}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			accepted.Add(1)
			go serveOneAnswer(conn, "5.6.7.8")
		}
	}()
	t.Cleanup(func() { ln.Close() })
	return ln.Addr().String(), clientTLS, accepted
}

// startDoQTestServer runs a minimal RFC 9250 DoQ test server: one stream per
// query, on however many connections the client actually opens.
func startDoQTestServer(t *testing.T) (addr string, clientTLS *tls.Config, accepted *atomic.Int32) {
	t.Helper()
	serverTLS, clientTLS := testTLSConfig(t)
	serverTLS = serverTLS.Clone()
	serverTLS.NextProtos = []string{"doq"}
	ln, err := quic.ListenAddr("127.0.0.1:0", serverTLS, &quic.Config{MaxIdleTimeout: 30 * time.Second})
	if err != nil {
		t.Fatalf("quic listen: %v", err)
	}
	accepted = &atomic.Int32{}
	go func() {
		for {
			conn, err := ln.Accept(t.Context())
			if err != nil {
				return
			}
			accepted.Add(1)
			go func() {
				for {
					stream, err := conn.AcceptStream(t.Context())
					if err != nil {
						return
					}
					go func() {
						defer stream.Close()
						reqBytes, err := readLenPrefixed(stream)
						if err != nil {
							return
						}
						req := new(dns.Msg)
						if err := req.Unpack(reqBytes); err != nil {
							return
						}
						resp := new(dns.Msg)
						resp.SetReply(req)
						resp.Answer = append(resp.Answer, &dns.A{
							Hdr: dns.RR_Header{Name: req.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
							A:   net.ParseIP("9.9.9.9"),
						})
						packed, err := resp.Pack()
						if err != nil {
							return
						}
						_ = writeLenPrefixed(stream, packed)
					}()
				}
			}()
		}
	}()
	t.Cleanup(func() { ln.Close() })
	return ln.Addr().String(), clientTLS, accepted
}

func TestTCPUpstreamReusesConnection(t *testing.T) {
	addr, accepted := startTCPTestServer(t)
	u := NewWithTLS(TCP, addr, "", nil)
	t.Cleanup(u.Close)
	for i := range 3 {
		r, err := u.Query(t.Context(), aQuery())
		if err != nil {
			t.Fatalf("query %d: %v", i, err)
		}
		if len(r.Answer) == 0 {
			t.Fatalf("query %d: no answer", i)
		}
	}
	if got := accepted.Load(); got != 1 {
		t.Fatalf("server accepted %d connections for 3 sequential queries, want 1 (pooled reuse)", got)
	}
}

// TestUDPUpstreamReusesSocket verifies the UDP socket pool: only the first
// of several sequential queries dials a fresh socket; the rest reuse the
// pooled connected socket instead of paying socket/connect/close syscalls
// per query. The dial count comes from the Dialer's Control hook, which the
// kernel invokes once per socket.
func TestUDPUpstreamReusesSocket(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Answer = append(m.Answer, &dns.A{
			Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
			A:   net.ParseIP("1.2.3.4"),
		})
		_ = w.WriteMsg(m)
	})}
	go func() { _ = srv.ActivateAndServe() }()
	t.Cleanup(func() { _ = srv.Shutdown() })

	var dials atomic.Int32
	u := &Upstream{Transport: UDP, Addr: pc.LocalAddr().String()}
	u.udpPool = make(chan *pooledConn, upstreamPoolSize)
	u.udpClient = &dns.Client{Net: "udp", Timeout: 8 * time.Second, Dialer: &net.Dialer{
		Timeout: 8 * time.Second,
		Control: func(network, address string, c syscall.RawConn) error {
			dials.Add(1)
			return nil
		},
	}}
	t.Cleanup(u.Close)

	for i := range 3 {
		r, err := u.Query(t.Context(), aQuery())
		if err != nil {
			t.Fatalf("query %d: %v", i, err)
		}
		if len(r.Answer) == 0 {
			t.Fatalf("query %d: no answer", i)
		}
	}
	if got := dials.Load(); got != 1 {
		t.Fatalf("client dialed %d sockets for 3 sequential queries, want 1 (pooled reuse)", got)
	}
}

func TestDoTUpstreamReusesConnection(t *testing.T) {
	addr, clientTLS, accepted := startDoTTestServer(t)
	u := NewWithTLS(TLS, addr, "localhost", clientTLS)
	t.Cleanup(u.Close)
	for i := range 3 {
		r, err := u.Query(t.Context(), aQuery())
		if err != nil {
			t.Fatalf("query %d: %v", i, err)
		}
		if len(r.Answer) == 0 {
			t.Fatalf("query %d: no answer", i)
		}
	}
	if got := accepted.Load(); got != 1 {
		t.Fatalf("server accepted %d TLS connections for 3 sequential queries, want 1 (pooled reuse, avoiding a repeat handshake)", got)
	}
}

func TestDoQUpstreamReusesConnection(t *testing.T) {
	addr, clientTLS, accepted := startDoQTestServer(t)
	u := NewWithTLS(QUIC, addr, "localhost", clientTLS)
	t.Cleanup(u.Close)
	for i := range 3 {
		r, err := u.Query(t.Context(), aQuery())
		if err != nil {
			t.Fatalf("query %d: %v", i, err)
		}
		if len(r.Answer) == 0 {
			t.Fatalf("query %d: no answer", i)
		}
	}
	if got := accepted.Load(); got != 1 {
		t.Fatalf("server accepted %d QUIC connections for 3 sequential queries, want 1 (one connection, one stream per query)", got)
	}
}

// startDoQTestServerWithHang runs a DoQ test server like startDoQTestServer,
// except every stream it accepts while hang is true is read and then never
// answered — the exchange goes silent without the QUIC connection itself
// erroring or closing, exactly the black-hole this test suite guards
// against. The caller flips hang back to false once the hung exchange under
// test has been issued.
func startDoQTestServerWithHang(t *testing.T) (addr string, clientTLS *tls.Config, hang *atomic.Bool) {
	t.Helper()
	serverTLS, clientTLS := testTLSConfig(t)
	serverTLS = serverTLS.Clone()
	serverTLS.NextProtos = []string{"doq"}
	ln, err := quic.ListenAddr("127.0.0.1:0", serverTLS, &quic.Config{MaxIdleTimeout: 30 * time.Second})
	if err != nil {
		t.Fatalf("quic listen: %v", err)
	}
	hang = &atomic.Bool{}
	go func() {
		for {
			conn, err := ln.Accept(t.Context())
			if err != nil {
				return
			}
			go func() {
				for {
					stream, err := conn.AcceptStream(t.Context())
					if err != nil {
						return
					}
					go func() {
						reqBytes, err := readLenPrefixed(stream)
						if err != nil {
							return
						}
						if hang.Load() {
							// Leave the stream open and never respond.
							return
						}
						defer stream.Close()
						req := new(dns.Msg)
						if err := req.Unpack(reqBytes); err != nil {
							return
						}
						resp := new(dns.Msg)
						resp.SetReply(req)
						resp.Answer = append(resp.Answer, &dns.A{
							Hdr: dns.RR_Header{Name: req.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
							A:   net.ParseIP("9.9.9.9"),
						})
						packed, err := resp.Pack()
						if err != nil {
							return
						}
						_ = writeLenPrefixed(stream, packed)
					}()
				}
			}()
		}
	}()
	t.Cleanup(func() { ln.Close() })
	return ln.Addr().String(), clientTLS, hang
}

// TestDoQStreamRespectsDeadline guards against the resolver-wide hang this
// package used to be exposed to: doQStream read/wrote a QUIC stream with no
// deadline, so an upstream that opened a stream and then went silent (while
// its QUIC connection stayed alive via keepalives) blocked the query
// goroutine on io.ReadFull forever and permanently consumed one slot of the
// connection's peer-granted stream credit. Enough of those and every future
// query on that persistent connection would eventually wedge too. The query
// must now fail within its own context deadline, and the abandoned stream
// must not prevent a subsequent query from succeeding on the same
// connection.
func TestDoQStreamRespectsDeadline(t *testing.T) {
	addr, clientTLS, hang := startDoQTestServerWithHang(t)
	u := NewWithTLS(QUIC, addr, "localhost", clientTLS)
	t.Cleanup(u.Close)

	hang.Store(true)
	ctx, cancel := context.WithTimeout(t.Context(), 500*time.Millisecond)
	defer cancel()
	start := time.Now()
	if _, err := u.Query(ctx, aQuery()); err == nil {
		t.Fatal("expected the black-holed query to fail, got a response")
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("query on a black-holed stream took %v to fail — it did not respect ctx's deadline", elapsed)
	}

	// The stream leaked by the hung query above must not have wedged the
	// shared persistent connection: a normal query right after must still
	// get through.
	hang.Store(false)
	r, err := u.Query(t.Context(), aQuery())
	if err != nil {
		t.Fatalf("query after a black-holed stream: %v", err)
	}
	if len(r.Answer) == 0 {
		t.Fatal("query after a black-holed stream: no answer")
	}
}

// TestRecursiveUpstreamDispatches verifies Transport == Recursive routes
// through the iterative resolver rather than dialing Addr (which is empty
// for this transport) — a single fake "root" that answers directly is
// enough to prove the wiring; internal/recursive's own tests cover the
// referral-walking logic in depth.
func TestRecursiveUpstreamDispatches(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Authoritative = true
		m.Answer = append(m.Answer, &dns.A{
			Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
			A:   net.ParseIP("203.0.113.9"),
		})
		_ = w.WriteMsg(m)
	})}
	go func() { _ = srv.ActivateAndServe() }()
	t.Cleanup(func() { _ = srv.Shutdown() })

	u := NewRecursive([]string{pc.LocalAddr().String()})
	r, err := u.Query(t.Context(), aQuery())
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if len(r.Answer) != 1 {
		t.Fatalf("answers = %d, want 1", len(r.Answer))
	}
	if a, ok := r.Answer[0].(*dns.A); !ok || a.A.String() != "203.0.113.9" {
		t.Fatalf("unexpected answer: %v", r.Answer[0])
	}
}

// TestParseRecursiveScheme verifies "recursive://" parses to the Recursive
// transport without requiring a host.
func TestParseRecursiveScheme(t *testing.T) {
	u, err := Parse("recursive://")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if u.Transport != Recursive {
		t.Fatalf("transport = %q, want %q", u.Transport, Recursive)
	}
}

// TestIsRecursiveSpec verifies the scheme pre-check matches what Parse
// actually treats as the recursive transport, so the startup root-hints
// fetch can't drift from the real classification.
func TestIsRecursiveSpec(t *testing.T) {
	cases := map[string]bool{
		"recursive://":     true,
		"recursive://root": true,
		"  recursive://":   true,
		"RECURSIVE://":     true,
		"udp://1.1.1.1:53": false,
		"recursive:foo":    false, // no :// — Parse rewrites this to udp://
		"1.1.1.1":          false,
		"":                 false,
	}
	for spec, want := range cases {
		if got := IsRecursiveSpec(spec); got != want {
			t.Fatalf("IsRecursiveSpec(%q) = %v, want %v", spec, got, want)
		}
	}
}

// TestPoolEvictsStaleConnection verifies that a connection which sat idle in
// the pool past poolMaxIdle is closed and replaced with a fresh dial instead
// of being reused — resolvers close idle DoT/TCP connections on their own
// schedule, and reusing one would waste a query on a guaranteed EOF.
func TestPoolEvictsStaleConnection(t *testing.T) {
	addr, accepted := startTCPTestServer(t)
	u := NewWithTLS(TCP, addr, "", nil)
	t.Cleanup(u.Close)
	if _, err := u.Query(t.Context(), aQuery()); err != nil {
		t.Fatalf("first query: %v", err)
	}
	if got := accepted.Load(); got != 1 {
		t.Fatalf("server accepted %d connections, want 1", got)
	}
	// Age the pooled connection past the eviction threshold, then return it
	// to the pool — as if it had sat idle there the whole time.
	pc := <-u.connPool
	pc.pooledAt = time.Now().Add(-2 * poolMaxIdle)
	u.connPool <- pc

	if _, err := u.Query(t.Context(), aQuery()); err != nil {
		t.Fatalf("second query: %v", err)
	}
	if got := accepted.Load(); got != 2 {
		t.Fatalf("server accepted %d connections after eviction, want 2 (stale conn must not be reused)", got)
	}
}

// TestDoHRetriesStaleConnection verifies a query whose request lands on a
// keep-alive connection the server closed while idle is retried once on a
// fresh connection instead of failing: Go's http.Transport never retries
// POSTs, so without this every post-idle query against a DoH upstream would
// fail with "unexpected EOF" — and that the blip is not counted as an
// upstream failure (the retry succeeded, so the server was never down).
func TestDoHRetriesStaleConnection(t *testing.T) {
	var mu sync.Mutex
	answered := 0
	closing := true // first request closes its connection after answering
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		req := new(dns.Msg)
		_ = req.Unpack(body)
		resp := new(dns.Msg)
		resp.SetReply(req)
		resp.Answer = append(resp.Answer, &dns.A{
			Hdr: dns.RR_Header{Name: req.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
			A:   net.ParseIP("1.2.3.4"),
		})
		packed, _ := resp.Pack()
		mu.Lock()
		answered++
		closeThis := closing
		closing = false
		mu.Unlock()
		w.Header().Set("Content-Type", "application/dns-message")
		w.Header().Set("Content-Length", strconv.Itoa(len(packed)))
		_, _ = w.Write(packed)
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		if closeThis {
			// Abruptly close the connection after the response so the client
			// pools a dead connection; the retried request must land on a
			// fresh one.
			if hj, ok := w.(http.Hijacker); ok {
				conn, _, _ := hj.Hijack()
				conn.Close()
			}
		}
	}))
	defer srv.Close()

	u := &Upstream{Transport: HTTPS}
	u.URL, _ = url.Parse(srv.URL + "/dns-query")
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	u.client = &http.Client{
		Transport: &http.Transport{
			TLSClientConfig:   &tls.Config{RootCAs: pool},
			ForceAttemptHTTP2: false, // exercise the HTTP/1.1 stale-conn path deterministically
		},
		Timeout: 5 * time.Second,
	}
	q := aQuery()
	q.SetEdns0(4096, false)
	// Query 1 dials fresh and pools the connection; the server answers then
	// closes it. Query 2 lands on that dead pooled connection — without the
	// retry it would fail with "unexpected EOF" — and must recover on a
	// fresh dial. The server should therefore have answered exactly twice.
	for i := 1; i <= 2; i++ {
		r, err := u.Query(t.Context(), q)
		if err != nil {
			t.Fatalf("query %d: %v", i, err)
		}
		if len(r.Answer) != 1 {
			t.Fatalf("query %d: answers = %d, want 1", i, len(r.Answer))
		}
	}
	mu.Lock()
	got := answered
	mu.Unlock()
	if got != 2 {
		t.Fatalf("server handled %d requests, want 2 (original + retry)", got)
	}
	if u.Fails() != 0 {
		t.Fatalf("Fails() = %d, want 0 (a stale-connection blip must not count as a failure)", u.Fails())
	}
}

// TestUpstreamCloseDrainsPoolAndQUICConn verifies Close doesn't panic and
// actually clears the pooled/persistent connections it holds — the property
// SetUpstreams' hot-swap relies on to avoid leaking sockets on reload.
func TestUpstreamCloseDrainsPoolAndQUICConn(t *testing.T) {
	tcpAddr, _ := startTCPTestServer(t)
	tcpUp := NewWithTLS(TCP, tcpAddr, "", nil)
	if _, err := tcpUp.Query(t.Context(), aQuery()); err != nil {
		t.Fatalf("tcp query: %v", err)
	}
	tcpUp.Close()
	select {
	case c := <-tcpUp.connPool:
		t.Fatalf("pool still holds a connection after Close: %v", c)
	default:
	}

	quicAddr, clientTLS, _ := startDoQTestServer(t)
	quicUp := NewWithTLS(QUIC, quicAddr, "localhost", clientTLS)
	if _, err := quicUp.Query(t.Context(), aQuery()); err != nil {
		t.Fatalf("doq query: %v", err)
	}
	quicUp.Close()
	quicUp.quicMu.Lock()
	stillSet := quicUp.quicConn != nil
	quicUp.quicMu.Unlock()
	if stillSet {
		t.Fatal("quicConn still set after Close")
	}
}

// TestCircuitBreaker verifies the consecutive-failure circuit: three failures
// open it (Available false), a success closes it, and an open circuit re-arms
// once the cooldown elapses so the next query probes the upstream again.
func TestCircuitBreaker(t *testing.T) {
	u := &Upstream{Transport: UDP, Addr: "127.0.0.1:1"}
	for range circuitOpenFails {
		u.markResult(context.DeadlineExceeded)
	}
	if u.Available() {
		t.Fatal("expected the circuit to be open after circuitOpenFails consecutive failures")
	}
	if u.Fails() != circuitOpenFails {
		t.Fatalf("Fails() = %d, want %d", u.Fails(), circuitOpenFails)
	}

	u.markResult(nil)
	if !u.Available() {
		t.Fatal("expected a success to close the circuit")
	}
	if u.Fails() != 0 {
		t.Fatalf("Fails() = %d after success, want 0", u.Fails())
	}

	// Reopen, then let the cooldown elapse: the circuit re-arms and the
	// upstream becomes tryable again.
	for range circuitOpenFails {
		u.markResult(context.DeadlineExceeded)
	}
	if u.Available() {
		t.Fatal("expected the circuit to be open again")
	}
	u.cooldownUntil.Store(time.Now().Add(-time.Second).UnixNano())
	if !u.Available() {
		t.Fatal("expected the circuit to re-arm once the cooldown elapsed")
	}
}

// TestUDPTruncatedFallsBackToTCP verifies the classic UDP resilience path: a
// truncated UDP reply (the answer outgrew the negotiated EDNS buffer) is
// retried over TCP on the same server address instead of failing the query.
func TestUDPTruncatedFallsBackToTCP(t *testing.T) {
	// The TCP and UDP listeners must share one address (the fallback retries
	// the same server over TCP): the TCP side answers 1.2.3.4, the UDP side
	// always truncates.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen tcp: %v", err)
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go serveOneAnswer(conn, "1.2.3.4")
		}
	}()
	t.Cleanup(func() { ln.Close() })
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	udpAddr := net.JoinHostPort("127.0.0.1", port)
	pc, err := net.ListenPacket("udp", udpAddr)
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	udpSrv := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Truncated = true
		_ = w.WriteMsg(m)
	})}
	go func() { _ = udpSrv.ActivateAndServe() }()
	t.Cleanup(func() { _ = udpSrv.Shutdown() })

	u := NewWithTLS(UDP, udpAddr, "", nil)
	r, err := u.Query(t.Context(), aQuery())
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if len(r.Answer) != 1 {
		t.Fatalf("answers = %d, want 1 (the TCP fallback's answer)", len(r.Answer))
	}
	if a, ok := r.Answer[0].(*dns.A); !ok || !a.A.Equal(net.ParseIP("1.2.3.4")) {
		t.Fatalf("answer = %v, want 1.2.3.4", r.Answer[0])
	}
}

// TestUDPQueryAdvertisesEDNS1232 verifies the query the client sends carries
// the Flag Day 2020 recommended 1232-byte EDNS UDP payload — large enough
// for realistic answers without risking IP fragmentation (the old 4096
// could be dropped silently on fragmented paths).
func TestUDPQueryAdvertisesEDNS1232(t *testing.T) {
	var gotSize atomic.Int32
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		for _, rr := range r.Extra {
			if opt, ok := rr.(*dns.OPT); ok {
				gotSize.Store(int32(opt.UDPSize()))
			}
		}
		m := new(dns.Msg)
		m.SetReply(r)
		_ = w.WriteMsg(m)
	})}
	go func() { _ = srv.ActivateAndServe() }()
	t.Cleanup(func() { _ = srv.Shutdown() })

	u := NewWithTLS(UDP, pc.LocalAddr().String(), "", nil)
	q := aQuery()
	q.SetEdns0(1232, false)
	if _, err := u.Query(t.Context(), q); err != nil {
		t.Fatalf("query: %v", err)
	}
	if got := gotSize.Load(); got != 1232 {
		t.Fatalf("server saw EDNS %d bytes, want 1232", got)
	}
}

// TestDoHHTTPErrorCountsAsFailure verifies the breaker blind spot is closed:
// a DoH endpoint answering an HTTP error status trips the circuit-breaker
// failure counter exactly like every other transport's errors, so a 5xx
// storm on an up-but-misbehaving endpoint can no longer hide from
// availability checks and cooldowns.
func TestDoHHTTPErrorCountsAsFailure(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "upstream unhappy", http.StatusInternalServerError)
	}))
	defer srv.Close()
	u := &Upstream{Transport: HTTPS}
	u.URL, _ = url.Parse(srv.URL + "/dns-query")
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	u.client = &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}}}

	if _, err := u.Query(t.Context(), aQuery()); err == nil {
		t.Fatal("expected an error for HTTP 500")
	}
	if u.Fails() != 1 {
		t.Fatalf("Fails() = %d, want 1 (an HTTP error status must count as an upstream failure)", u.Fails())
	}
}

// TestRecursiveFailureCountsAsFailure verifies the other breaker blind spot:
// a recursive:// upstream with no reachable path to the root servers fails
// on every query, and that must feed the circuit breaker like any other
// transport — so race mode skips it instead of burning its timeout per
// query.
func TestRecursiveFailureCountsAsFailure(t *testing.T) {
	u := NewRecursive([]string{"127.0.0.1:1"}) // nothing listening there
	if _, err := u.Query(t.Context(), aQuery()); err == nil {
		t.Fatal("expected an error for an unreachable root hint")
	}
	if u.Fails() == 0 {
		t.Fatal("Fails() = 0, want >= 1 (a recursive resolution failure must feed the circuit breaker)")
	}
}
