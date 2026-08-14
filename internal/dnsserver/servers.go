package dnsserver

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"runtime"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"

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
	Proto string // udp, tcp, dot, doh, doh3, doq
	Addr  string
	Err   error
}

// Manager owns all configured listeners and coordinates shutdown.
type Manager struct {
	handler *Handler
	tlsConf *tls.Config
	// udpSockets is the configured UDP socket count for the plain UDP and
	// DoQ listeners (server.udp_sockets): 0 = auto (one per CPU, capped), 1
	// = a single exclusive socket. Applied by main at boot and on reload
	// before the listeners are (re)started.
	udpSockets int
	// udpWorkers is the configured handler-worker count per plain-UDP socket
	// (server.udp_workers): 0 = auto (4 × CPU, floor 16, capped 256), N =
	// exactly N per socket. Same lifecycle as udpSockets.
	udpWorkers int
	// udpBound / doqBound are the socket counts the plain UDP and DoQ
	// listeners actually bound (what server.udp_sockets resolved to on this
	// platform), for the dashboard's status. Reset on Restart, re-set by
	// startClassic/startDoQ.
	udpBound int
	doqBound int
	mu       sync.Mutex
	servers  []*dns.Server
	// udpSrvs are the plain-UDP worker-pool listeners (one per socket).
	// They are tracked separately from dns.Server because their shutdown is
	// their own Close, not a dns.Server's ShutdownContext.
	udpSrvs []*udpServer
	httpSrv interface {
		Shutdown(ctx context.Context) error
	}
	doqLns []*quic.Listener
	// http3Srvs and http3Pcs are the DoH3 (HTTP/3) servers and their packet
	// conns. Unlike a quic.Listener (which owns its socket), http3.Server's
	// Serve does not close the connection it is given, so the sockets are
	// tracked separately and closed alongside the servers on shutdown.
	http3Srvs []*http3.Server
	http3Pcs  []net.PacketConn
	results   chan Listener
}

// SetUDPSockets sets how many SO_REUSEPORT sockets the UDP-family listeners
// bind (server.udp_sockets): 0 = auto (one per CPU, capped), 1 = a single
// exclusive socket, N = exactly N. Applied before Start/Restart; the running
// listeners are not touched by a call after they are up.
func (m *Manager) SetUDPSockets(n int) {
	m.mu.Lock()
	m.udpSockets = n
	m.mu.Unlock()
}

// SetUDPWorkers sets how many handler workers each plain-UDP socket's read
// loop dispatches to (server.udp_workers): 0 = auto (4 × CPU per socket,
// floor 16, capped 256), N = exactly N per socket (capped at 512). Applied
// before Start/Restart like SetUDPSockets; the running listeners are not
// touched by a call after they are up.
func (m *Manager) SetUDPWorkers(n int) {
	m.mu.Lock()
	m.udpWorkers = n
	m.mu.Unlock()
}

// udpSocketCount returns how many sockets the UDP-family listeners bind,
// resolving the configured server.udp_sockets value (see udpSocketCountFor).
func (m *Manager) udpSocketCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return udpSocketCountFor(m.udpSockets)
}

// udpWorkerCount returns how many handler workers each plain-UDP socket's
// read loop dispatches to, resolving the configured server.udp_workers value
// (see udpWorkersFor).
func (m *Manager) udpWorkerCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return udpWorkersFor(m.udpWorkers)
}

// UDPListenerSockets reports how many sockets the plain UDP and DoQ
// listeners are currently bound with (0 when the listener isn't running),
// for the dashboard's status endpoint.
func (m *Manager) UDPListenerSockets() (udp, doq int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.udpBound, m.doqBound
}

// NewManager creates a listener manager.
func NewManager(h *Handler, tlsConf *tls.Config) *Manager {
	return &Manager{handler: h, tlsConf: tlsConf, results: make(chan Listener, 8)}
}

// Start launches listeners for the configured addresses ("" disables a proto).
// It returns a channel that reports per-listener bind errors (bound ports are
// a hard failure; other listener types are logged).
func (m *Manager) Start(udpAddr, tcpAddr, dotAddr, dohAddr, doh3Addr, doqAddr, dohPath string) (<-chan Listener, error) {
	if m.tlsConf == nil {
		log.Printf("[dns] warning: no TLS config; DoT/DoH/DoH3/DoQ listeners disabled")
		dotAddr, dohAddr, doh3Addr, doqAddr = "", "", "", ""
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
	if doh3Addr != "" {
		if err := m.startDoH3(doh3Addr, dohPath); err != nil {
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
		// UDP: create the sockets ourselves so the kernel receive/send
		// buffers can be raised (miekg/dns dials its own listener with the
		// OS defaults otherwise), then serve each from a worker-pool server
		// (see udpServer) instead of miekg/dns's goroutine-per-packet loop.
		//
		// Where the platform supports it, the address is bound from several
		// SO_REUSEPORT sockets (one per CPU, capped — see udpSocketCount):
		// the kernel then hashes incoming datagrams across per-socket
		// receive queues, each drained by its own read goroutine, so a burst
		// can't queue up behind a single recvfrom loop. Platforms without
		// SO_REUSEPORT (Windows) and any bind failure fall back to one plain
		// socket, so the listener always comes up.
		pcs, err := newUDPListeners(addr, m.udpSocketCount())
		if err != nil {
			m.results <- Listener{Proto: proto, Addr: addr, Err: err}
			return
		}
		m.mu.Lock()
		m.udpBound = len(pcs)
		m.mu.Unlock()
		noun := "sockets"
		if len(pcs) == 1 {
			noun = "socket"
		}
		log.Printf("[dns] %s listener on %s (%d %s)", proto, addr, len(pcs), noun)
		for _, pc := range pcs {
			srv := newUDPServer(pc, handler, m.udpWorkerCount())
			m.mu.Lock()
			m.udpSrvs = append(m.udpSrvs, srv)
			m.mu.Unlock()
			go func() {
				if err := srv.Serve(); err != nil {
					log.Printf("[dns] %s listener on %s stopped: %v", proto, addr, err)
					m.results <- Listener{Proto: proto, Addr: addr, Err: err}
				}
			}()
		}
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
	for _, s := range m.udpSrvs {
		s.Close()
	}
	if m.httpSrv != nil {
		_ = m.httpSrv.Shutdown(ctx)
	}
	for _, ln := range m.doqLns {
		_ = ln.Close()
	}
	for _, srv := range m.http3Srvs {
		_ = srv.Close()
	}
	for _, pc := range m.http3Pcs {
		_ = pc.Close()
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
// listener (DoH/DoH3/DoQ) fails to come back up.
func (m *Manager) Restart(udpAddr, tcpAddr, dotAddr, dohAddr, doh3Addr, doqAddr, dohPath string, tlsConf *tls.Config) error {
	// Bound the shutdown so a stuck listener can't wedge the reload forever.
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	m.Shutdown(shutdownCtx)
	cancel()
	m.mu.Lock()
	m.servers = nil
	m.udpSrvs = nil
	m.httpSrv = nil
	m.doqLns = nil
	m.http3Srvs = nil
	m.http3Pcs = nil
	m.udpBound = 0
	m.doqBound = 0
	m.tlsConf = tlsConf
	m.mu.Unlock()
	_, err := m.Start(udpAddr, tcpAddr, dotAddr, dohAddr, doh3Addr, doqAddr, dohPath)
	return err
}

// maxUDPSockets caps the auto socket count for one UDP address: each socket
// carries its own SocketBufferSize kernel receive/send buffers, so past a
// handful the extra kernel memory buys nothing measurable on any box this
// runs on.
const maxUDPSockets = 8

// maxExplicitUDPSockets bounds an explicit server.udp_sockets value so a
// typo (say 1000) can't open a thousand 2 MiB-buffered sockets.
const maxExplicitUDPSockets = 64

// udpSocketCountFor is how many sockets a UDP listen address is bound from.
// An explicit operator setting (server.udp_sockets > 0) is honored — 1
// restores the strictly-exclusive single socket — up to maxExplicitUDPSockets
// (clamped past that). The default (0) is one per available CPU (the
// runtime's tuned GOMAXPROCS, which the tuning package makes cgroup-aware),
// capped at maxUDPSockets. The kernel hashes incoming datagrams across the
// sockets, each with its own receive queue and read goroutine.
func udpSocketCountFor(cfg int) int {
	if cfg > 0 {
		if cfg > maxExplicitUDPSockets {
			log.Printf("[dns] udp_sockets=%d exceeds the %d maximum — using %d sockets", cfg, maxExplicitUDPSockets, maxExplicitUDPSockets)
			cfg = maxExplicitUDPSockets
		}
		return cfg
	}
	n := runtime.GOMAXPROCS(0)
	if n < 1 {
		n = 1
	}
	if n > maxUDPSockets {
		n = maxUDPSockets
	}
	return n
}

// newUDPListeners binds addr from n sockets and raises the receive/send
// buffers on each. With n > 1 it first tries SO_REUSEPORT so the kernel
// spreads incoming datagrams across the sockets; when the platform lacks
// reuseport or a bind fails, it closes what it opened and falls back to a
// single plain socket so the listener always comes up.
func newUDPListeners(addr string, n int) ([]net.PacketConn, error) {
	if n > 1 {
		pcs, err := reuseportUDPListeners(addr, n)
		if err == nil {
			return pcs, nil
		}
		log.Printf("[dns] reuseport UDP unavailable on %s (%v) — using a single socket", addr, err)
	}
	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		return nil, err
	}
	tuning.SetPacketBuffers(pc)
	return []net.PacketConn{pc}, nil
}

// reuseportUDPListeners binds addr from n SO_REUSEPORT sockets with the
// receive/send buffers raised on each. On any bind failure it closes every
// socket it opened and returns the error so the caller can fall back to a
// single socket.
func reuseportUDPListeners(addr string, n int) ([]net.PacketConn, error) {
	lc := &net.ListenConfig{Control: tuning.ReuseportControl}
	pcs := make([]net.PacketConn, 0, n)
	for i := 0; i < n; i++ {
		pc, err := lc.ListenPacket(context.Background(), "udp", addr)
		if err != nil {
			for _, p := range pcs {
				_ = p.Close()
			}
			return nil, err
		}
		tuning.SetPacketBuffers(pc)
		pcs = append(pcs, pc)
	}
	return pcs, nil
}

// ensureTLSListener helper for DoT uses the shared TLS config.
var _ = tls.Listen
var _ = fmt.Sprintf
