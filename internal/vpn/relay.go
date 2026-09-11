package vpn

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"

	"github.com/eoghan2t9/Irongrid-DNS/internal/upstream"
)

// routeRenewInterval re-adds a relayed connection's destination IP to its
// profile's nftables set periodically for as long as the connection stays
// open, so a long-lived connection (a large download, a video stream)
// never loses its policy-routing mark mid-transfer — the set entry
// otherwise expires on its own timeout (routing.go's min/maxSetTimeout)
// regardless of whether the connection using it is still alive.
const routeRenewInterval = 45 * time.Second

// sniffTimeout bounds how long the relay waits for a client to finish
// sending its TLS ClientHello or HTTP request line — a slow-loris-style
// connection that opens a socket and trickles bytes must not tie up a
// goroutine (or the underlying fd) forever.
const sniffTimeout = 10 * time.Second

// Relay is the SNI/Host-based connection relay behind config.VPNProxyConfig
// — see that type's doc comment for the full picture. It owns the
// public-facing TCP listeners; Manager still owns the WireGuard tunnels and
// the route table Relay consults for every new connection via
// MatchProxyRoute.
//
// Security invariant: a connection is relayed to the real destination ONLY
// when its sniffed hostname matches a Proxy-enabled route whose profile is
// currently connected. Everything else — including a connection where
// sniffing itself fails — is forwarded unchanged to Fallback (or dropped,
// for a malformed/non-TLS connection on the TLS listener). The Relay must
// never become a general-purpose open proxy for arbitrary destinations.
type Relay struct {
	mgr      *Manager
	fallback string
	resolver *upstream.Upstream

	mu     sync.Mutex
	lnTLS  net.Listener
	lnHTTP net.Listener
}

// NewRelay creates a Relay. fallback is where a connection whose
// SNI/Host doesn't match any Proxy-enabled route is forwarded (typically
// the dashboard/DoH listener). resolverAddr is a fixed upstream (e.g.
// "udp://1.1.1.1:53") used ONLY to resolve a proxied domain's real IP —
// deliberately never Irongrid's own resolution path, which would just
// return this same relay's public IP right back (the very answer being
// relayed around) and loop.
func NewRelay(mgr *Manager, fallback string, resolverAddr string) (*Relay, error) {
	up, err := upstream.Parse(resolverAddr)
	if err != nil {
		return nil, fmt.Errorf("vpn: relay resolver %q: %w", resolverAddr, err)
	}
	return &Relay{mgr: mgr, fallback: fallback, resolver: up}, nil
}

// Start binds the TLS/SNI listener at listenTLS (required) and, if
// listenHTTP is non-empty, the plain-HTTP listener too.
func (r *Relay) Start(listenTLS, listenHTTP string) error {
	ln, err := net.Listen("tcp", listenTLS)
	if err != nil {
		return fmt.Errorf("vpn: relay TLS listen %s: %w", listenTLS, err)
	}
	r.mu.Lock()
	r.lnTLS = ln
	r.mu.Unlock()
	go r.serve(ln, r.handleTLS)

	if listenHTTP != "" {
		lnh, err := net.Listen("tcp", listenHTTP)
		if err != nil {
			_ = ln.Close()
			return fmt.Errorf("vpn: relay HTTP listen %s: %w", listenHTTP, err)
		}
		r.mu.Lock()
		r.lnHTTP = lnh
		r.mu.Unlock()
		go r.serve(lnh, r.handleHTTP)
	}
	return nil
}

// Stop closes the listeners; in-flight relayed connections are left to
// finish on their own.
func (r *Relay) Stop() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.lnTLS != nil {
		_ = r.lnTLS.Close()
		r.lnTLS = nil
	}
	if r.lnHTTP != nil {
		_ = r.lnHTTP.Close()
		r.lnHTTP = nil
	}
}

func (r *Relay) serve(ln net.Listener, handle func(net.Conn)) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return // listener closed (Stop) or a fatal accept error
		}
		go handle(conn)
	}
}

// recordingConn wraps a net.Conn, saving every byte Read through it — so
// the exact bytes consumed while sniffing (a ClientHello) can be replayed
// to the real upstream connection afterward, byte-for-byte.
type recordingConn struct {
	net.Conn
	buf bytes.Buffer
}

func (c *recordingConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.buf.Write(p[:n])
	}
	return n, err
}

// errSNIExtracted aborts the TLS handshake the instant the ClientHello's
// SNI has been parsed — sniffSNI never intends to complete a real
// handshake, only to read and parse the ClientHello using the standard
// library's own parser rather than a hand-rolled one.
var errSNIExtracted = errors.New("vpn: sni extracted")

// sniffSNI reads and parses conn's TLS ClientHello just far enough to
// extract the SNI hostname, using crypto/tls's own parser via the
// GetConfigForClient hook (so record/handshake framing, extension parsing
// and version quirks are handled by the standard library, not reinvented).
// It never completes the handshake or writes anything to conn. Returns the
// lowercased SNI and the raw bytes consumed so far (to replay to whichever
// destination the caller relays to).
func sniffSNI(conn net.Conn) (hostname string, peeked []byte, err error) {
	rec := &recordingConn{Conn: conn}
	var sni string
	tlsConn := tls.Server(rec, &tls.Config{
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			sni = hello.ServerName
			return nil, errSNIExtracted
		},
	})
	hsErr := tlsConn.Handshake()
	if !errors.Is(hsErr, errSNIExtracted) {
		if hsErr == nil {
			hsErr = errors.New("vpn: TLS handshake completed without SNI extraction")
		}
		return "", rec.buf.Bytes(), hsErr
	}
	if sni == "" {
		return "", rec.buf.Bytes(), errors.New("vpn: client presented no SNI")
	}
	return strings.ToLower(sni), rec.buf.Bytes(), nil
}

func (r *Relay) handleTLS(conn net.Conn) {
	defer func() { _ = recover() }() // never let one bad connection take the process down
	_ = conn.SetReadDeadline(time.Now().Add(sniffTimeout))
	hostname, peeked, err := sniffSNI(conn)
	_ = conn.SetReadDeadline(time.Time{})
	if err != nil {
		slog.Debug("vpn: relay TLS sniff failed", "remote", conn.RemoteAddr(), "error", err)
		_ = conn.Close()
		return
	}
	r.route(conn, peeked, hostname, "443")
}

func (r *Relay) handleHTTP(conn net.Conn) {
	defer func() { _ = recover() }()
	_ = conn.SetReadDeadline(time.Now().Add(sniffTimeout))
	br := bufio.NewReader(conn)
	req, err := http.ReadRequest(br)
	_ = conn.SetReadDeadline(time.Time{})
	if err != nil {
		slog.Debug("vpn: relay HTTP sniff failed", "remote", conn.RemoteAddr(), "error", err)
		_ = conn.Close()
		return
	}
	host := strings.ToLower(req.Host)
	if h, _, splitErr := net.SplitHostPort(host); splitErr == nil {
		host = h
	}
	var peeked bytes.Buffer
	if writeErr := req.Write(&peeked); writeErr != nil {
		_ = conn.Close()
		return
	}
	r.route(conn, peeked.Bytes(), host, "80")
}

// route decides, for a connection whose destination hostname is now known,
// whether to relay it to the real destination via a matched VPN profile or
// forward it unchanged to Fallback — see the Relay doc comment's security
// invariant.
func (r *Relay) route(clientConn net.Conn, peeked []byte, hostname, port string) {
	profileID, matched := r.mgr.MatchProxyRoute(hostname)
	if !matched {
		r.forward(clientConn, peeked, r.fallback)
		return
	}

	ip, err := r.resolveIP(hostname)
	if err != nil {
		slog.Warn("vpn: relay could not resolve real address", "host", hostname, "error", err)
		_ = clientConn.Close()
		return
	}
	if err := r.mgr.EnsureRouted(profileID, ip, maxSetTimeout); err != nil {
		slog.Warn("vpn: relay could not route destination", "host", hostname, "profile", profileID, "error", err)
		_ = clientConn.Close()
		return
	}

	upstreamConn, err := net.DialTimeout("tcp", net.JoinHostPort(ip.String(), port), 10*time.Second)
	if err != nil {
		slog.Warn("vpn: relay dial failed", "host", hostname, "ip", ip, "error", err)
		_ = clientConn.Close()
		return
	}

	stop := make(chan struct{})
	go func() {
		t := time.NewTicker(routeRenewInterval)
		defer t.Stop()
		for {
			select {
			case <-t.C:
				if err := r.mgr.EnsureRouted(profileID, ip, maxSetTimeout); err != nil {
					slog.Debug("vpn: relay route renewal failed", "host", hostname, "error", err)
				}
			case <-stop:
				return
			}
		}
	}()
	defer close(stop)

	if _, err := upstreamConn.Write(peeked); err != nil {
		_ = clientConn.Close()
		_ = upstreamConn.Close()
		return
	}
	spliceAndClose(clientConn, upstreamConn)
}

// forward relays a connection whose destination didn't match any
// Proxy-enabled route straight through to addr unchanged — no VPN
// involvement, no destination-IP lookup, just a local TCP hop (addr is
// meant to be the dashboard/DoH listener, typically on loopback).
func (r *Relay) forward(clientConn net.Conn, peeked []byte, addr string) {
	if addr == "" {
		_ = clientConn.Close()
		return
	}
	backend, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		slog.Warn("vpn: relay fallback dial failed", "addr", addr, "error", err)
		_ = clientConn.Close()
		return
	}
	if _, err := backend.Write(peeked); err != nil {
		_ = clientConn.Close()
		_ = backend.Close()
		return
	}
	spliceAndClose(clientConn, backend)
}

// resolveIP looks up hostname's first A record via r.resolver — a fixed
// upstream, never Irongrid's own resolution path (see NewRelay).
func (r *Relay) resolveIP(hostname string) (net.IP, error) {
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(hostname), dns.TypeA)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	resp, err := r.resolver.Query(ctx, msg)
	if err != nil {
		return nil, err
	}
	for _, rr := range resp.Answer {
		if a, ok := rr.(*dns.A); ok {
			return a.A, nil
		}
	}
	return nil, fmt.Errorf("no A record for %s", hostname)
}

// spliceAndClose copies bytes in both directions between a and b until one
// side finishes (EOF or error), then closes both — unblocking the other
// direction's copy — and waits for it to actually finish before returning,
// so no goroutine is leaked.
func spliceAndClose(a, b net.Conn) {
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(a, b); done <- struct{}{} }()
	go func() { _, _ = io.Copy(b, a); done <- struct{}{} }()
	<-done
	_ = a.Close()
	_ = b.Close()
	<-done
}
