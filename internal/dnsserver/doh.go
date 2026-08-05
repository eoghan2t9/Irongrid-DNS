package dnsserver

import (
	"crypto/tls"
	"encoding/base64"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	"golang.org/x/net/http2"

	"github.com/miekg/dns"
)

const dnsMessageContentType = "application/dns-message"

// DoHHandler returns an http.Handler serving RFC 8484 DNS-over-HTTPS
// requests. It is used when the web server shares its HTTPS listener with
// DoH (server.web_listen and server.listen_doh on the same port), so the
// dashboard and /dns-query are served from one port.
func (m *Manager) DoHHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		m.handleDoH(w, r)
	})
}

// startDoH launches the RFC 8484 DNS-over-HTTPS server.
func (m *Manager) startDoH(addr, path string) error {
	mux := http.NewServeMux()
	mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
		m.handleDoH(w, r)
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			io.WriteString(w, dohLandingPage)
			return
		}
		http.NotFound(w, r)
	})

	// RFC 8484 recommends HTTP/2; Go only negotiates h2 automatically via
	// ServeTLS, so configure it explicitly for the DoH listener.
	dohTLS := m.tlsConf.Clone()
	dohTLS.NextProtos = []string{"h2", "http/1.1"}
	srv := &http.Server{
		Addr:        addr,
		Handler:     mux,
		TLSConfig:   dohTLS,
		ReadTimeout: 10 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout: 120 * time.Second,
	}
	if err := http2.ConfigureServer(srv, &http2.Server{}); err != nil {
		return err
	}

	m.httpSrv = srv

	ln, err := tls.Listen("tcp", addr, dohTLS)
	if err != nil {
		return err
	}
	log.Printf("[dns] DoH listener on %s (path %s, HTTP/2 enabled)", addr, path)
	go func() {
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("[dns] DoH listener on %s stopped: %v", addr, err)
			m.results <- Listener{Proto: "doh", Addr: addr, Err: err}
		}
	}()
	return nil
}

func (m *Manager) handleDoH(w http.ResponseWriter, r *http.Request) {
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
	httpWriter := &dohResponseWriter{httpW: w, clientIP: clientIP}
	m.handler.ServeDNSFromContext(httpWriter, msg, clientIP, "doh")
}

func clientIPFromRequest(r *http.Request) string {
	// Respect X-Forwarded-For when sitting behind a reverse proxy.
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
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

// dohResponseWriter adapts the dns.ResponseWriter interface to an HTTP
// response.
type dohResponseWriter struct {
	httpW    http.ResponseWriter
	clientIP string
}

func (w *dohResponseWriter) WriteMsg(m *dns.Msg) error {
	packed, err := m.Pack()
	if err != nil {
		return err
	}
	w.httpW.Header().Set("Content-Type", dnsMessageContentType)
	w.httpW.Header().Set("Cache-Control", "no-store")
	w.httpW.WriteHeader(http.StatusOK)
	_, err = w.httpW.Write(packed)
	return err
}

func (w *dohResponseWriter) Write(b []byte) (int, error) {
	w.httpW.Header().Set("Content-Type", dnsMessageContentType)
	return w.httpW.Write(b)
}

func (w *dohResponseWriter) LocalAddr() net.Addr  { return nil }
func (w *dohResponseWriter) RemoteAddr() net.Addr { return addrOnly(w.clientIP) }
func (w *dohResponseWriter) Close() error        { return nil }
func (w *dohResponseWriter) TsigStatus() error   { return nil }
func (w *dohResponseWriter) TsigTimersOnly(bool) {}
func (w *dohResponseWriter) Hijack()             {}

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
