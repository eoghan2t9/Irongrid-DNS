package dnsserver

import (
	"log"
	"net"
	"runtime"
	"sync"
	"sync/atomic"

	"github.com/miekg/dns"
)

// dnsHeaderLen is the fixed DNS message header size (RFC 1035 §4.1.1).
// Anything shorter cannot be a valid query and is dropped without a reply —
// answering garbage would hand a spoofed source amplification, exactly why
// miekg/dns drops sub-header packets too.
const dnsHeaderLen = 12

// udpServer is the plain-UDP listener: a read loop per socket that hands
// each datagram to a fixed pool of worker goroutines. It replaces
// miekg/dns's goroutine-per-packet model, where every datagram spawned (and
// later reaped) a goroutine plus its stack — real per-query cost at flat-out
// rates, and unbounded goroutine growth under a flood. Here the workers are
// pre-spawned once per socket, so a burst costs zero goroutine creation and
// bounded memory, and the read loop stays ahead of the handler: it only ever
// pushes to the jobs channel, and when the channel is full it blocks, giving
// the kernel receive buffer natural backpressure instead of spawning more
// goroutines.
//
// The worker pool is safe for the handler because the handler is stateless
// with respect to the socket: every goroutine-safe facility it touches
// (cache, filters, rate limiter, singleflight, message/buffer pools, query
// log) is already shared across the per-packet goroutines miekg spawned.
type udpServer struct {
	pc      net.PacketConn
	conn    *net.UDPConn // nil when pc isn't a *net.UDPConn (never today)
	handler dns.Handler
	workers int

	// jobs is the handoff queue from the read loop to the workers. Buffered
	// at the worker count so a burst beyond that blocks the reader (kernel
	// buffer backpressure) rather than growing memory.
	jobs chan udpJob
	// bufs pools the read buffers as *[]byte — a pointer-like pool argument
	// avoids boxing an allocation per datagram (see packBufPool). Each
	// buffer is returned after its packet has been handled (dns.Msg.Unpack
	// copies everything it needs).
	bufs sync.Pool

	closeOnce sync.Once
	closed    atomic.Bool
	done      chan struct{}
	wg        sync.WaitGroup
}

// udpJob is one datagram handed from the read loop to a worker. bp is the
// pooled read buffer (pointer so the worker can return it to the pool); n
// and addr scope the packet within it.
type udpJob struct {
	bp   *[]byte
	n    int
	addr *net.UDPAddr
}

// newUDPServer builds a worker-pool UDP server over an already-bound packet
// connection (see newUDPListeners). workers is the per-socket worker count.
func newUDPServer(pc net.PacketConn, handler dns.Handler, workers int) *udpServer {
	if workers < 1 {
		workers = 1
	}
	s := &udpServer{
		pc:      pc,
		handler: handler,
		workers: workers,
		jobs:    make(chan udpJob, workers),
		done:    make(chan struct{}),
	}
	s.bufs.New = func() any {
		b := make([]byte, udpMaxPacketSize)
		return &b
	}
	if c, ok := pc.(*net.UDPConn); ok {
		s.conn = c
	}
	return s
}

// udpWorkersPerSocket is how many handler workers each plain-UDP socket's
// read loop dispatches to. Sized off the tuned GOMAXPROCS like the socket
// count; the jobs channel absorbs bursts beyond the workers. A floor keeps a
// tiny VM from collapsing to a handful of workers, and the cap bounds total
// pre-spawned stacks (each worker's stack grows only as deep as one query
// actually needs).
func udpWorkersPerSocket() int {
	n := runtime.GOMAXPROCS(0)
	if n < 4 {
		n = 4
	}
	if n > 64 {
		n = 64
	}
	return 4 * n
}

// maxExplicitUDPWorkers bounds an explicit server.udp_workers value so a typo
// (e.g. 100000) can't pre-spawn tens of thousands of goroutines per socket.
const maxExplicitUDPWorkers = 512

// udpWorkersFor resolves the configured per-socket worker count
// (server.udp_workers): 0 = auto (udpWorkersPerSocket), N = exactly N
// workers per socket, capped at maxExplicitUDPWorkers with a warning like
// the socket-count resolver.
func udpWorkersFor(cfg int) int {
	if cfg < 1 {
		return udpWorkersPerSocket()
	}
	if cfg > maxExplicitUDPWorkers {
		log.Printf("[dns] udp_workers=%d exceeds the %d maximum — using %d workers", cfg, maxExplicitUDPWorkers, maxExplicitUDPWorkers)
		cfg = maxExplicitUDPWorkers
	}
	return cfg
}

// Serve runs the read loop and workers until Close is called (directly, or
// by the deferred Close on a read-loop error). It returns nil for a clean
// shutdown and the read-loop error otherwise — never both running past
// Close, so the Manager's shutdown path can rely on it terminating.
func (s *udpServer) Serve() error {
	defer s.Close()
	for i := 0; i < s.workers; i++ {
		s.wg.Add(1)
		go s.worker()
	}
	s.wg.Add(1)
	err := s.readLoop()
	s.wg.Wait()
	return err
}

// Close stops the server: workers exit after their current packet, the read
// loop unblocks on the closed socket and returns, and Serve's wg.Wait
// releases. Safe to call more than once (and from both Manager.Shutdown and
// Serve's deferred close).
func (s *udpServer) Close() {
	s.closeOnce.Do(func() {
		s.closed.Store(true)
		close(s.done)
		_ = s.pc.Close() // unblocks the read loop and frees the socket
	})
}

// readLoop reads datagrams and dispatches them to the worker pool. It
// returns nil on a clean shutdown, or the first read error that isn't the
// socket closing underneath us (no read deadline is set, so a spurious
// timeout can't occur).
func (s *udpServer) readLoop() error {
	for {
		bp := s.bufs.Get().(*[]byte)
		buf := *bp
		var (
			n    int
			addr *net.UDPAddr
			err  error
		)
		if s.conn != nil {
			// ReadMsgUDP returns (n, oobn, flags, addr, err); the ancillary
			// data and flags are unused here.
			n, _, _, addr, err = s.conn.ReadMsgUDP(buf, nil)
		} else {
			var ra net.Addr
			n, ra, err = s.pc.ReadFrom(buf)
			addr, _ = ra.(*net.UDPAddr)
			if addr == nil && n > 0 {
				s.bufs.Put(bp)
				continue
			}
		}
		if err != nil {
			s.bufs.Put(bp)
			if s.closed.Load() {
				return nil
			}
			return err
		}
		if n < dnsHeaderLen {
			// Too short to be a DNS message: drop without a reply (a reply
			// to garbage is an amplification vector).
			s.bufs.Put(bp)
			continue
		}
		select {
		case s.jobs <- udpJob{bp: bp, n: n, addr: addr}:
		case <-s.done:
			s.bufs.Put(bp)
			return nil
		}
	}
}

// worker processes datagrams until the server is closed. It handles one
// packet at a time inline (unpack → handler → write), so a single worker
// can never have two in-flight responses racing on the same buffer.
func (s *udpServer) worker() {
	for {
		select {
		case job := <-s.jobs:
			s.handleRecovered(job)
		case <-s.done:
			return
		}
	}
}

// handleRecovered runs handle with a panic guard. Handler.serve has its own
// recover, but req.Unpack below runs before the handler is ever reached —
// this is the last line of defense so a single malformed datagram can't take
// down the worker pool (and, unrecovered, the whole process).
func (s *udpServer) handleRecovered(job udpJob) {
	defer recoverPanic("UDP worker")
	s.handle(job)
}

// reqPool recycles the inbound *dns.Msg across datagrams. Handler.serve
// (handler.go) only ever lets the request's *question* escape past its
// synchronous return — as a dns.Question value copy into the background
// cache-write goroutines and querylog — never the *dns.Msg itself: every
// reply is built with SetReply/newReply, which copies request.Question[0]
// into a fresh slice rather than aliasing the request's, and the one
// outbound-forwarding path (upstreamQuery := r.Copy() in resolveUpstreams)
// takes a deep copy rather than the pointer. So once ServeDNS returns, req
// is exclusively this worker's again.
var reqPool = sync.Pool{New: func() any { return new(dns.Msg) }}

// handle unpacks one datagram and runs the handler, then returns the read
// buffer and request to their pools. Unpack copies every name and record
// into the *dns.Msg, so the buffer is free the moment it returns.
func (s *udpServer) handle(job udpJob) {
	defer s.bufs.Put(job.bp)
	req := reqPool.Get().(*dns.Msg)
	defer func() {
		*req = dns.Msg{}
		reqPool.Put(req)
	}()
	if err := req.Unpack((*job.bp)[:job.n]); err != nil {
		// Unparseable: drop, matching miekg/dns's serveDNS (a FORMERR reply
		// to a malformed datagram is amplification surface).
		return
	}
	w := &udpResponseWriter{conn: s.conn, pc: s.pc, addr: job.addr}
	s.handler.ServeDNS(w, req)
}

// udpResponseWriter adapts dns.ResponseWriter to an unconnected UDP socket:
// every response is a WriteToUDP addressed to the querying client, so the
// reply's source address is exactly the socket the query arrived on (which
// matters to clients behind NAT).
type udpResponseWriter struct {
	conn *net.UDPConn
	pc   net.PacketConn
	addr *net.UDPAddr
}

func (w *udpResponseWriter) WriteMsg(m *dns.Msg) error {
	packed, err := m.Pack()
	if err != nil {
		return err
	}
	_, err = w.Write(packed)
	return err
}

func (w *udpResponseWriter) Write(b []byte) (int, error) {
	if w.conn != nil {
		// WriteMsgUDP returns (n, oobn, err); the bytes written are all
		// that matter here.
		n, _, err := w.conn.WriteMsgUDP(b, nil, w.addr)
		return n, err
	}
	return w.pc.WriteTo(b, w.addr)
}

func (w *udpResponseWriter) LocalAddr() net.Addr  { return w.pc.LocalAddr() }
func (w *udpResponseWriter) RemoteAddr() net.Addr { return w.addr }
func (w *udpResponseWriter) Close() error         { return nil }
func (w *udpResponseWriter) TsigStatus() error    { return nil }
func (w *udpResponseWriter) TsigTimersOnly(bool)  {}
func (w *udpResponseWriter) Hijack()              {}
