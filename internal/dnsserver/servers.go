package dnsserver

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"runtime"
	"strings"
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

	// tcpReadTimeout / tcpWriteTimeout bound each read/write on the plain-TCP
	// and DoT listeners (miekg/dns defaults: 2s read, 2s write). Slightly more
	// generous so a slow but legitimate client on a congested link isn't cut
	// off mid-message, while still bounding a slowloris-style connection that
	// sends nothing.
	tcpReadTimeout  = 5 * time.Second
	tcpWriteTimeout = 5 * time.Second
	// tcpIdleTimeout bounds how long a connection may sit idle between
	// queries (miekg/dns default: 8s per RFC 5966). Kept at the default.
	tcpIdleTimeout = 8 * time.Second
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
	// connLim caps concurrent connections per client IP on the plain-TCP and
	// DoT listeners (server.max_tcp_conns_per_ip; nil = unlimited). Built by
	// SetConnLimits, applied at Start/Restart, and replaced on reload.
	connLim *connLimiter
	// httpLim caps concurrent connections per client IP on the DoH listener
	// and the shared dashboard+DoH HTTPS listener (server.max_http_conns_per_ip;
	// nil = unlimited). Same lifecycle as connLim.
	httpLim *connLimiter
	mu      sync.Mutex
	servers []*dns.Server
	// udpSrvs are the plain-UDP worker-pool listeners (one per socket).
	// They are tracked separately from dns.Server because their shutdown is
	// their own Close, not a dns.Server's ShutdownContext.
	udpSrvs []*udpServer
	httpSrv interface {
		Shutdown(ctx context.Context) error
	}
	// trustedProxies are reverse-proxy peers beyond loopback/private whose
	// X-Forwarded-For header the DoH endpoint honors (server.trusted_proxies;
	// nil = loopback/private only). Read per request under m.mu.
	trustedProxies []*net.IPNet
	// xffHops is how many trusted proxy hops the X-Forwarded-For chain may
	// contain (server.xff_hop_limit): the client IP is the hop_limit-th
	// entry from the right of the chain, so 1 (the default) means the
	// direct peer is the only trusted hop. 0 is normalized to 1 by
	// SetProxyConfig.
	xffHops int
	// asnHeader adds X-Irongrid-Client-ASN to DoH responses
	// (server.doh_asn_header).
	asnHeader bool
	doqLns    []*quic.Listener
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

// limitTCPListener wraps ln with the per-IP connection cap when one is
// configured (server.max_tcp_conns_per_ip), returning ln unchanged otherwise.
// The caller hands the result to a dns.Server (or tls.NewListener for DoT).
func (m *Manager) limitTCPListener(ln net.Listener) net.Listener {
	m.mu.Lock()
	lim := m.connLim
	m.mu.Unlock()
	if lim == nil {
		return ln
	}
	return &limitListener{Listener: ln, lim: lim}
}

// SetConnLimits sets the per-IP concurrent-connection caps for the TCP/DoT
// listeners (maxTCP) and the DoH/shared-HTTP listener (maxHTTP); a value <= 0
// leaves that transport unlimited. Applied before Start/Restart like the
// other listener knobs; the running listeners are not touched by a call after
// they are up (reload restarts them via Restart).
func (m *Manager) SetConnLimits(maxTCP, maxHTTP int) {
	m.mu.Lock()
	if maxTCP > 0 {
		m.connLim = newConnLimiter(maxTCP)
	} else {
		m.connLim = nil
	}
	if maxHTTP > 0 {
		m.httpLim = newConnLimiter(maxHTTP)
	} else {
		m.httpLim = nil
	}
	m.mu.Unlock()
}

// SetProxyConfig configures reverse-proxy trust for DoH client
// identification (server.trusted_proxies / server.xff_hop_limit): which
// peers — in addition to loopback/private ones — may stamp X-Forwarded-For,
// and how many trusted hops the chain may contain. Entries are IPs or
// CIDRs; an invalid entry returns an error. Applied at boot and on every
// reload; the DoH handler reads the values per request, so no listener
// restart is needed.
func (m *Manager) SetProxyConfig(trusted []string, hopLimit int) error {
	var nets []*net.IPNet
	for _, e := range trusted {
		e = strings.TrimSpace(e)
		if e == "" {
			continue
		}
		if ip := net.ParseIP(e); ip != nil {
			bits := 32
			if ip.To4() == nil {
				bits = 128
			}
			nets = append(nets, &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)})
			continue
		}
		_, n, err := net.ParseCIDR(e)
		if err != nil {
			return fmt.Errorf("trusted proxy %q: %w", e, err)
		}
		nets = append(nets, n)
	}
	if hopLimit < 1 {
		hopLimit = 1
	}
	m.mu.Lock()
	m.trustedProxies = nets
	m.xffHops = hopLimit
	m.mu.Unlock()
	return nil
}

// SetDoHASNHeader toggles the X-Irongrid-Client-ASN response header on the
// DoH endpoint (server.doh_asn_header). Applied at boot and on every
// reload; read per request, so no listener restart is needed.
func (m *Manager) SetDoHASNHeader(on bool) {
	m.mu.Lock()
	m.asnHeader = on
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
		slog.Warn("no TLS config; DoT/DoH/DoH3/DoQ listeners disabled")
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
		slog.Info("dns listener started", "proto", proto, "addr", addr, "sockets", len(pcs), "socket_noun", noun)
		for _, pc := range pcs {
			srv := newUDPServer(pc, handler, m.handler.Stats, m.udpWorkerCount())
			m.mu.Lock()
			m.udpSrvs = append(m.udpSrvs, srv)
			m.mu.Unlock()
			go func() {
				if err := srv.Serve(); err != nil {
					slog.Error("dns listener stopped", "proto", proto, "addr", addr, "error", err)
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
	// When a per-IP connection cap is configured, the listener is wrapped so
	// connections past the cap are closed at accept without a reply.
	ln, err := tuning.ListenConfig().Listen(context.Background(), "tcp", addr)
	if err != nil {
		m.results <- Listener{Proto: proto, Addr: addr, Err: err}
		return
	}
	srv := &dns.Server{
		Net:          "tcp",
		Listener:     m.limitTCPListener(ln),
		Handler:      handler,
		ReadTimeout:  tcpReadTimeout,
		WriteTimeout: tcpWriteTimeout,
		IdleTimeout:  func() time.Duration { return tcpIdleTimeout },
	}
	m.servers = append(m.servers, srv)
	go func() {
		slog.Info("dns listener started", "proto", proto, "addr", addr)
		if err := srv.ActivateAndServe(); err != nil {
			slog.Error("dns listener stopped", "proto", proto, "addr", addr, "error", err)
			m.results <- Listener{Proto: proto, Addr: addr, Err: err}
		}
	}()
}

func (m *Manager) startDoT(addr string) {
	// Same tuned socket as plain TCP; miekg/dns serves a Listener we hand it
	// as-is, so the TLS wrapping is done here before it is passed along. The
	// per-IP connection cap wraps the raw TCP listener (before TLS), so a
	// rejected connection never even starts a handshake.
	ln, err := tuning.ListenConfig().Listen(context.Background(), "tcp", addr)
	if err != nil {
		m.results <- Listener{Proto: "dot", Addr: addr, Err: err}
		return
	}
	// RFC 7858 §9.2: a DoT server SHOULD support the "dot" ALPN identifier.
	dotTLS := m.tlsConf.Clone()
	dotTLS.NextProtos = []string{"dot"}
	srv := &dns.Server{
		Addr:         addr,
		Net:          "tcp-tls",
		Listener:     tls.NewListener(m.limitTCPListener(ln), dotTLS),
		TLSConfig:    dotTLS,
		Handler:      protoHandler{m.handler, "dot"},
		ReadTimeout:  tcpReadTimeout,
		WriteTimeout: tcpWriteTimeout,
		IdleTimeout:  func() time.Duration { return tcpIdleTimeout },
	}
	m.servers = append(m.servers, srv)
	go func() {
		slog.Info("DoT listener started", "addr", addr)
		if err := srv.ActivateAndServe(); err != nil {
			slog.Error("DoT listener stopped", "addr", addr, "error", err)
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
		if err := s.Shutdown(ctx); err != nil {
			slog.Warn("UDP listener shutdown timed out", "error", err)
		}
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
			slog.Warn("udp_sockets exceeds maximum, clamping", "configured", cfg, "max", maxExplicitUDPSockets)
			cfg = maxExplicitUDPSockets
		}
		return cfg
	}
	n := min(max(runtime.GOMAXPROCS(0), 1), maxUDPSockets)
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
		slog.Warn("reuseport UDP unavailable, using a single socket", "addr", addr, "error", err)
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
	for range n {
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
