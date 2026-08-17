package dnsserver

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/http2"

	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"

	"github.com/eoghan2t9/Irongrid-DNS/internal/tuning"
)

const dnsMessageContentType = "application/dns-message"

// DoHHandler returns an http.Handler serving RFC 8484 DNS-over-HTTPS
// requests. It is used when the web server shares its HTTPS listener with
// DoH (server.web_listen and server.listen_doh on the same port), so the
// dashboard and /dns-query are served from one port.
func (m *Manager) DoHHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		m.handleDoH(w, r, "doh")
	})
}

// dohMux returns the mux serving the RFC 8484 DoH endpoint plus a landing
// page at "/". It is shared by the DoH (TCP) and DoH3 (QUIC) listeners so
// both transports serve the same paths and handler. proto tags every query
// with the transport ("doh" or "doh3") so stats and per-protocol policy see
// the real listener, not a lumped "doh".
func (m *Manager) dohMux(path, proto string) *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
		m.handleDoH(w, r, proto)
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = io.WriteString(w, dohLandingPage)
			return
		}
		http.NotFound(w, r)
	})
	return mux
}

// HTTPConnState returns the ConnState callback enforcing the per-IP HTTP
// connection cap (server.max_http_conns_per_ip), or nil when unlimited. The
// standalone DoH listener and main's shared dashboard+DoH HTTPS listener both
// attach it, so one knob covers every HTTP transport that serves /dns-query.
//
// net/http always fires StateClosed for a connection it accepted — including
// one this callback closed at StateNew — so acquisitions are tracked per
// connection (acquiredConns) and a StateClosed only releases a slot that was
// actually acquired. Without that, closing an over-cap connection at StateNew
// would later release another client's slot.
func (m *Manager) HTTPConnState() func(net.Conn, http.ConnState) {
	m.mu.Lock()
	lim := m.httpLim
	m.mu.Unlock()
	if lim == nil {
		return nil
	}
	var acquired sync.Map // net.Conn -> struct{}: conns holding a slot
	return func(c net.Conn, s http.ConnState) {
		ip := clientIPOf(c.RemoteAddr())
		switch s {
		case http.StateNew:
			if lim.acquire(ip) {
				acquired.Store(c, struct{}{})
			} else {
				// Over the cap: refuse the connection outright rather than
				// letting it sit in the accept queue. Not stored in
				// acquiredConns, so its StateClosed (which always follows)
				// releases nothing.
				_ = c.Close()
			}
		case http.StateClosed, http.StateHijacked:
			if _, ok := acquired.LoadAndDelete(c); ok {
				lim.release(ip)
			}
		}
	}
}

// startDoH launches the RFC 8484 DNS-over-HTTPS server.
func (m *Manager) startDoH(addr, path string) error {
	mux := m.dohMux(path, "doh")

	// RFC 8484 recommends HTTP/2; Go only negotiates h2 automatically via
	// ServeTLS, so configure it explicitly for the DoH listener.
	dohTLS := m.tlsConf.Clone()
	dohTLS.NextProtos = []string{"h2", "http/1.1"}
	srv := &http.Server{
		Addr:         addr,
		Handler:      mux,
		TLSConfig:    dohTLS,
		ConnState:    m.HTTPConnState(),
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  120 * time.Second,
	}
	if err := http2.ConfigureServer(srv, &http2.Server{}); err != nil {
		return err
	}

	m.httpSrv = srv

	// Create the TCP socket ourselves so the receive/send buffers are raised
	// (tls.Listen would dial a plain net.Listen with the OS defaults).
	rawLn, err := tuning.ListenConfig().Listen(context.Background(), "tcp", addr)
	if err != nil {
		return err
	}
	ln := tls.NewListener(rawLn, dohTLS)
	slog.Info("DoH listener started", "addr", addr, "path", path, "http2", true)
	go func() {
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			slog.Error("DoH listener stopped", "addr", addr, "error", err)
			m.results <- Listener{Proto: "doh", Addr: addr, Err: err}
		}
	}()
	return nil
}

// startDoH3 launches RFC 8484 DNS-over-HTTP/3: the DoH endpoint served over
// QUIC (RFC 9114, ALPN "h3") on a UDP address — typically the same port as
// the TCP DoH listener (443), since TCP and UDP ports are independent. HTTP/3
// multiplexes many queries over one connection and supports 0-RTT resumption,
// making it the fastest transport for mobile/roaming clients; AdGuard, NextDNS
// and Cloudflare all serve it. It shares the DoH mux, so the same /dns-query
// path and RFC 8484 GET/POST semantics work over both transports.
func (m *Manager) startDoH3(addr, path string) error {
	tlsConf := m.tlsConf.Clone()
	// http3.Server's ConfigureTLSConfig sets the "h3" ALPN token
	// automatically (RFC 9114 requires it).
	quicConf := &quic.Config{
		MaxIdleTimeout:       60 * time.Second,
		KeepAlivePeriod:      20 * time.Second,
		HandshakeIdleTimeout: 8 * time.Second,
	}
	// Same tuned, SO_REUSEPORT-bound sockets as the DoQ listener: the kernel
	// hashes each QUIC connection to one socket while receive processing
	// spreads across per-socket read goroutines. Each socket gets its own
	// http3.Server (Serve does not own the connection it is given, so both
	// the server and the socket are tracked for shutdown).
	pcs, err := newUDPListeners(addr, m.udpSocketCount())
	if err != nil {
		return err
	}
	noun := "socket"
	if len(pcs) > 1 {
		noun = "sockets"
	}
	slog.Info("DoH3 listener started", "addr", addr, "sockets", len(pcs), "socket_noun", noun, "path", path)
	for _, pc := range pcs {
		srv := &http3.Server{
			TLSConfig:  tlsConf,
			QUICConfig: quicConf,
			Handler:    m.dohMux(path, "doh3"),
		}
		m.mu.Lock()
		m.http3Pcs = append(m.http3Pcs, pc)
		m.http3Srvs = append(m.http3Srvs, srv)
		m.mu.Unlock()
		go func() {
			// The close errors from a deliberate shutdown are not listener
			// failures — reporting them would spam the reload log.
			if err := srv.Serve(pc); err != nil &&
				!errors.Is(err, net.ErrClosed) && !errors.Is(err, quic.ErrServerClosed) {
				slog.Error("DoH3 listener stopped", "addr", addr, "error", err)
				m.results <- Listener{Proto: "doh3", Addr: addr, Err: err}
			}
		}()
	}
	return nil
}

// DoH3Addr returns the bound address of the DoH3 listener (useful when
// binding to port 0 for tests or dynamic ports).
func (m *Manager) DoH3Addr() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.http3Pcs) == 0 {
		return ""
	}
	return m.http3Pcs[len(m.http3Pcs)-1].LocalAddr().String()
}

func (m *Manager) handleDoH(w http.ResponseWriter, r *http.Request, proto string) {
	var msg *dns.Msg
	var err error

	switch r.Method {
	case http.MethodGet:
		// RFC 8484 §4.1: GET with ?dns=<base64url>
		b64 := r.URL.Query().Get("dns")
		if b64 == "" {
			http.Error(w, "missing dns parameter", http.StatusBadRequest)
			return
		}
		var raw []byte
		raw, err = base64.RawURLEncoding.DecodeString(strings.TrimRight(b64, "="))
		if err != nil {
			http.Error(w, "invalid dns parameter", http.StatusBadRequest)
			return
		}
		msg = new(dns.Msg)
		err = msg.Unpack(raw)
	case http.MethodPost:
		if ct := r.Header.Get("Content-Type"); ct != "" && !strings.Contains(ct, dnsMessageContentType) {
			http.Error(w, "unsupported content type", http.StatusUnsupportedMediaType)
			return
		}
		body, rerr := io.ReadAll(io.LimitReader(r.Body, 65536))
		if rerr != nil {
			http.Error(w, "read error", http.StatusBadRequest)
			return
		}
		msg = new(dns.Msg)
		err = msg.Unpack(body)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err != nil {
		http.Error(w, "malformed DNS message", http.StatusBadRequest)
		return
	}

	clientIP := clientIPFromRequest(r)
	// Replies are written back through this writer as the DNS response bytes.
	// proto tags the transport ("doh" or "doh3") for stats and policy.
	httpWriter := &dohResponseWriter{httpW: w, clientIP: clientIP}
	m.handler.ServeDNSFromContext(httpWriter, msg, clientIP, proto)
}

func clientIPFromRequest(r *http.Request) string {
	// Trust X-Forwarded-For only when the DIRECT peer is a loopback or
	// private address — a local reverse proxy (nginx/Caddy on the same box
	// or LAN) or the baked-in cloudflared tunnel, both of which stamp the
	// real client IP. A publicly reachable DoH listener must never honor a
	// client-supplied header: sending `X-Forwarded-For: 8.8.8.8` would
	// bypass geo-blocking, rate limiting and per-client policy in one
	// request. Without this guard, trusting XFF from the open internet is
	// an open door for exactly the blocked-country traffic geo blocking is
	// supposed to refuse.
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" && isTrustedProxy(r.RemoteAddr) {
		first := strings.TrimSpace(strings.Split(xff, ",")[0])
		if ip := net.ParseIP(first); ip != nil {
			return first
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// isTrustedProxy reports whether an HTTP connection's direct peer is a
// loopback or private address — the only peers whose X-Forwarded-For header
// is accepted (a proxy on the same host or LAN). Remote peers on public IPs
// are never trusted, so the header cannot be spoofed from the internet.
// Link-local (169.254/16, fe80::/10) and CGNAT (100.64/10) peers are
// deliberately not trusted — a local proxy there is vanishingly rare, and
// erring closed is the point.
func isTrustedProxy(remote string) bool {
	host, _, err := net.SplitHostPort(remote)
	if err != nil {
		host = remote
	}
	ip := net.ParseIP(host)
	return ip != nil && (ip.IsLoopback() || ip.IsPrivate())
}

// dohResponseWriter adapts the dns.ResponseWriter interface to an HTTP
// response.
type dohResponseWriter struct {
	httpW    http.ResponseWriter
	clientIP string
}

func (w *dohResponseWriter) WriteMsg(m *dns.Msg) error {
	buf := getPackBuf()
	packed, err := m.PackBuffer(buf)
	if err != nil {
		putPackBuf(buf)
		return err
	}
	w.httpW.Header().Set("Content-Type", dnsMessageContentType)
	w.httpW.Header().Set("Cache-Control", "no-store")
	w.httpW.WriteHeader(http.StatusOK)
	// http.ResponseWriter.Write copies/sends packed synchronously before
	// returning, so it's safe to recycle right after regardless of error.
	_, err = w.httpW.Write(packed)
	putPackBuf(packed)
	return err
}

func (w *dohResponseWriter) Write(b []byte) (int, error) {
	w.httpW.Header().Set("Content-Type", dnsMessageContentType)
	w.httpW.Header().Set("Cache-Control", "no-store")
	return w.httpW.Write(b)
}

func (w *dohResponseWriter) LocalAddr() net.Addr  { return nil }
func (w *dohResponseWriter) RemoteAddr() net.Addr { return addrOnly(w.clientIP) }
func (w *dohResponseWriter) Close() error         { return nil }
func (w *dohResponseWriter) TsigStatus() error    { return nil }
func (w *dohResponseWriter) TsigTimersOnly(bool)  {}
func (w *dohResponseWriter) Hijack()              {}

func addrOnly(ip string) net.Addr { return &fakeAddr{ip: ip} }

type fakeAddr struct{ ip string }

func (f *fakeAddr) Network() string { return "doh" }
func (f *fakeAddr) String() string  { return f.ip + ":0" }

const dohLandingPage = `<!DOCTYPE html>
<html><head><title>Irongrid DNS</title></head>
<body style="font-family:system-ui,sans-serif;max-width:40em;margin:4em auto;line-height:1.6">
<h1>Irongrid DNS</h1>
<p>This endpoint serves DNS over HTTPS (RFC 8484) at <code>/dns-query</code>.</p>
<p>Configure it in Android as a Private DNS provider:
<code>https://YOUR-HOSTNAME/dns-query</code></p>
</body></html>`
