package dnsserver

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"

	"github.com/eoghan2t9/Irongrid-DNS/internal/tuning"
)

const (
	// udpMaxPacketSize is the largest datagram the reader accepts (large
	// EDNS0 queries), vs miekg/dns's 512-byte default which silently
	// truncates anything bigger.
	udpMaxPacketSize = 4096
)

// protoHandler tags every query with the listener's protocol so stats stay
// accurate regardless of which transport served it.
type protoHandler struct {
	inner *Handler
	proto string
}

func (p protoHandler) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	p.inner.ServeDNSWithProto(w, r, p.proto)
}

// Listener describes one running DNS listener.
type Listener struct {
	Proto string // udp, tcp, dot, doh, doq
	Addr  string
	Err   error
}

// Manager owns all configured listeners and coordinates shutdown.
type Manager struct {
	handler *Handler
	tlsConf *tls.Config
	mu      sync.Mutex
	servers []*dns.Server
	httpSrv interface {
		Shutdown(ctx context.Context) error
	}
	doqLns  []*quic.Listener
	results chan Listener
}

// NewManager creates a listener manager.
func NewManager(h *Handler, tlsConf *tls.Config) *Manager {
	return &Manager{handler: h, tlsConf: tlsConf, results: make(chan Listener, 8)}
}

// Start launches listeners for the configured addresses ("" disables a proto).
// It returns a channel that reports per-listener bind errors (bound ports are
// a hard failure; other listener types are logged).
func (m *Manager) Start(udpAddr, tcpAddr, dotAddr, dohAddr, doqAddr, dohPath string) (<-chan Listener, error) {
	if m.tlsConf == nil {
		log.Printf("[dns] warning: no TLS config; DoT/DoH/DoQ listeners disabled")
		dotAddr, dohAddr, doqAddr = "", "", ""
	}

	if udpAddr != "" {
		m.startClassic("udp", udpAddr, false)
	}
	if tcpAddr != "" {
		m.startClassic("tcp", tcpAddr, true)
	}
	if dotAddr != "" {
		m.startDoT(dotAddr)
	}
	if dohAddr != "" {
		if err := m.startDoH(dohAddr, dohPath); err != nil {
			return m.results, err
		}
	}
	if doqAddr != "" {
		if err := m.startDoQ(doqAddr); err != nil {
			return m.results, err
		}
	}
	return m.results, nil
}

func (m *Manager) startClassic(proto, addr string, tcp bool) {
	var handler dns.Handler = m.handler
	if tcp {
		// Tag TCP queries with the right protocol for stats.
		handler = protoHandler{m.handler, "tcp"}
	}
	if !tcp {
		// UDP: create the socket ourselves so the kernel receive/send
		// buffers can be raised (miekg/dns dials its own listener with the
		// OS defaults otherwise). ActivateAndServe is used because
		// ListenAndServe would replace the injected PacketConn with its
		// own socket.
		pc, err := net.ListenPacket("udp", addr)
		if err != nil {
			m.results <- Listener{Proto: proto, Addr: addr, Err: err}
			return
		}
		tuning.SetPacketBuffers(pc)
		srv := &dns.Server{Net: "udp", PacketConn: pc, UDPSize: udpMaxPacketSize, Handler: handler}
		m.servers = append(m.servers, srv)
		go func() {
			log.Printf("[dns] %s listener on %s", proto, addr)
			if err := srv.ActivateAndServe(); err != nil {
				log.Printf("[dns] %s listener on %s stopped: %v", proto, addr, err)
				m.results <- Listener{Proto: proto, Addr: addr, Err: err}
			}
		}()
		return
	}
	// TCP: create the listener ourselves with a tuned ListenConfig so the
	// socket buffers are raised here too (accepted connections inherit them).
	// Handing the pre-built listener to the dns.Server means ActivateAndServe
	// must serve it (ListenAndServe would replace it with its own socket).
	ln, err := tuning.ListenConfig().Listen(context.Background(), "tcp", addr)
	if err != nil {
		m.results <- Listener{Proto: proto, Addr: addr, Err: err}
		return
	}
	srv := &dns.Server{Net: "tcp", Listener: ln, Handler: handler}
	m.servers = append(m.servers, srv)
	go func() {
		log.Printf("[dns] %s listener on %s", proto, addr)
		if err := srv.ActivateAndServe(); err != nil {
			log.Printf("[dns] %s listener on %s stopped: %v", proto, addr, err)
			m.results <- Listener{Proto: proto, Addr: addr, Err: err}
		}
	}()
}

func (m *Manager) startDoT(addr string) {
	// Same tuned socket as plain TCP; miekg/dns serves a Listener we hand it
	// as-is, so the TLS wrapping is done here before it is passed along.
	ln, err := tuning.ListenConfig().Listen(context.Background(), "tcp", addr)
	if err != nil {
		m.results <- Listener{Proto: "dot", Addr: addr, Err: err}
		return
	}
	srv := &dns.Server{
		Addr:      addr,
		Net:       "tcp-tls",
		Listener:  tls.NewListener(ln, m.tlsConf),
		TLSConfig: m.tlsConf,
		Handler:   protoHandler{m.handler, "dot"},
	}
	m.servers = append(m.servers, srv)
	go func() {
		log.Printf("[dns] DoT listener on %s", addr)
		if err := srv.ActivateAndServe(); err != nil {
			log.Printf("[dns] DoT listener on %s stopped: %v", addr, err)
			m.results <- Listener{Proto: "dot", Addr: addr, Err: err}
		}
	}()
}

// Shutdown gracefully stops all listeners.
func (m *Manager) Shutdown(ctx context.Context) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, s := range m.servers {
		_ = s.ShutdownContext(ctx)
	}
	if m.httpSrv != nil {
		_ = m.httpSrv.Shutdown(ctx)
	}
	for _, ln := range m.doqLns {
		_ = ln.Close()
	}
}

// SetTLS replaces the TLS config used by the DoT/DoH/DoQ listeners.
func (m *Manager) SetTLS(conf *tls.Config) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.tlsConf = conf
}

// Restart stops every current listener and starts fresh ones with the given
// addresses and TLS config. It is used by the config-reload flow so listener
// changes apply without killing the process. Returns a bind error if any hard
// listener (DoH/DoQ) fails to come back up.
func (m *Manager) Restart(udpAddr, tcpAddr, dotAddr, dohAddr, doqAddr, dohPath string, tlsConf *tls.Config) error {
	// Bound the shutdown so a stuck listener can't wedge the reload forever.
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	m.Shutdown(shutdownCtx)
	cancel()
	m.mu.Lock()
	m.servers = nil
	m.httpSrv = nil
	m.doqLns = nil
	m.tlsConf = tlsConf
	m.mu.Unlock()
	_, err := m.Start(udpAddr, tcpAddr, dotAddr, dohAddr, doqAddr, dohPath)
	return err
}

// ensureTLSListener helper for DoT uses the shared TLS config.
var _ = tls.Listen
var _ = fmt.Sprintf
