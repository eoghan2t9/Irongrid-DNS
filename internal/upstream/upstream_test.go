package upstream

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync/atomic"
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
			conn, err := ln.Accept(context.Background())
			if err != nil {
				return
			}
			accepted.Add(1)
			go func() {
				for {
					stream, err := conn.AcceptStream(context.Background())
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
	for i := 0; i < 3; i++ {
		r, err := u.Query(context.Background(), aQuery())
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

func TestDoTUpstreamReusesConnection(t *testing.T) {
	addr, clientTLS, accepted := startDoTTestServer(t)
	u := NewWithTLS(TLS, addr, "localhost", clientTLS)
	t.Cleanup(u.Close)
	for i := 0; i < 3; i++ {
		r, err := u.Query(context.Background(), aQuery())
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
	for i := 0; i < 3; i++ {
		r, err := u.Query(context.Background(), aQuery())
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
	r, err := u.Query(context.Background(), aQuery())
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

// TestUpstreamCloseDrainsPoolAndQUICConn verifies Close doesn't panic and
// actually clears the pooled/persistent connections it holds — the property
// SetUpstreams' hot-swap relies on to avoid leaking sockets on reload.
func TestUpstreamCloseDrainsPoolAndQUICConn(t *testing.T) {
	tcpAddr, _ := startTCPTestServer(t)
	tcpUp := NewWithTLS(TCP, tcpAddr, "", nil)
	if _, err := tcpUp.Query(context.Background(), aQuery()); err != nil {
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
	if _, err := quicUp.Query(context.Background(), aQuery()); err != nil {
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
	for i := 0; i < circuitOpenFails; i++ {
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
	for i := 0; i < circuitOpenFails; i++ {
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
