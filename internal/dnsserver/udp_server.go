package dnsserver

import (
	"context"
	"log/slog"
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/net/ipv4"
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
// bounded memory. The read loop stays ahead of the handler while queue space
// remains; at capacity it counts and rejects excess datagrams rather than
// blocking and allowing the kernel receive queue to overflow invisibly.
//
// The worker pool is safe for the handler because the handler is stateless
// with respect to the socket: every goroutine-safe facility it touches
// (cache, filters, rate limiter, singleflight, message/buffer pools, query
// log) is already shared across the per-packet goroutines miekg spawned.
type udpServer struct {
	pc      net.PacketConn
	conn    *net.UDPConn // nil when pc isn't a *net.UDPConn (never today)
	handler dns.Handler
	stats   *Stats
	workers int

	// batchPC drives a recvmmsg-batched read loop instead of one ReadMsgUDP
	// syscall per datagram — profiling under load showed the raw syscall
	// trap (not handler/cache/filter logic) as the dominant CPU cost at high
	// QPS, roughly split across the read and write paths. batchPC is nil
	// unless both hold: GOOS is linux (x/net's ipv4.PacketConn.ReadBatch
	// transparently falls back to one message per call everywhere else, so
	// there's no correctness risk in leaving it enabled elsewhere — this is
	// scoped to Linux purely because that's the only platform tested here)
	// and the socket is IPv4-bound (the common case; ipv4.Message and
	// ipv6.Message are the same underlying type, but IPv6 batching isn't
	// exercised by this codebase's test suite yet, so it stays on the
	// original single-message path for now). readLoop dispatches on this
	// field; nothing else about the worker pool, response writer, or stats
	// changes — only how datagrams are pulled off the socket.
	batchPC *ipv4.PacketConn
	// writes is the batching writer's input queue (see udpServer.batchWriter);
	// nil on the same conditions as batchPC. A worker's udpResponseWriter.Write
	// pushes a request here and blocks on its own result channel — the actual
	// sendmmsg call is issued by the single batchWriter goroutine, but from
	// the worker's perspective Write remains fully synchronous: it only
	// returns once the syscall has actually run, so WriteErrors/UDPCompleted
	// accounting and buffer-lifetime assumptions (the caller may reuse its
	// packed bytes the instant Write returns) are unchanged from the
	// unbatched path.
	writes chan *udpWriteReq

	// jobs is the bounded handoff queue from the read loop to the workers.
	// The read loop never blocks on it: continuing to drain the socket keeps
	// short bursts out of the kernel receive queue, while a full queue is an
	// explicit, measurable overload rejection instead of an opaque kernel
	// packet drop.
	jobs chan udpJob
	// bufs pools the read buffers as *[]byte — a pointer-like pool argument
	// avoids boxing an allocation per datagram (see packBufPool). Each
	// buffer is returned after its packet has been handled (dns.Msg.Unpack
	// copies everything it needs).
	bufs sync.Pool

	closeOnce  func()
	socketOnce func()
	closed     atomic.Bool
	finished   chan struct{}
	wg         sync.WaitGroup
}

// udpQueuePerWorker absorbs short scheduling and upstream-latency bursts
// without allowing stale UDP work to grow without bound. At the largest
// explicit pool this is 8 MiB of 4 KiB packet buffers per socket.
const udpQueuePerWorker = 4

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
func newUDPServer(pc net.PacketConn, handler dns.Handler, stats *Stats, workers int) *udpServer {
	if workers < 1 {
		workers = 1
	}
	s := &udpServer{
		pc:       pc,
		handler:  handler,
		stats:    stats,
		workers:  workers,
		jobs:     make(chan udpJob, workers*udpQueuePerWorker),
		finished: make(chan struct{}),
	}
	s.bufs.New = func() any {
		b := make([]byte, udpMaxPacketSize)
		return &b
	}
	s.closeOnce = sync.OnceFunc(func() {
		s.closed.Store(true)
		if err := s.pc.SetReadDeadline(time.Now()); err != nil {
			s.closeSocket()
		}
	})
	s.socketOnce = sync.OnceFunc(func() { _ = s.pc.Close() })
	if c, ok := pc.(*net.UDPConn); ok {
		s.conn = c
	}
	if runtime.GOOS == "linux" {
		if udpAddr, ok := pc.LocalAddr().(*net.UDPAddr); ok && udpAddr.IP.To4() != nil {
			s.batchPC = ipv4.NewPacketConn(pc)
			s.writes = make(chan *udpWriteReq, workers*udpQueuePerWorker)
		}
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
	n := min(max(runtime.GOMAXPROCS(0), 4), 64)
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
		slog.Warn("udp_workers exceeds maximum, clamping", "configured", cfg, "max", maxExplicitUDPWorkers)
		cfg = maxExplicitUDPWorkers
	}
	return cfg
}

// Serve runs the read loop and workers until Close is called (directly, or
// by the deferred Close on a read-loop error). It returns nil for a clean
// shutdown and the read-loop error otherwise — never both running past
// Close, so the Manager's shutdown path can rely on it terminating.
func (s *udpServer) Serve() error {
	defer s.closeSocket()
	defer close(s.finished)
	for range s.workers {
		s.wg.Go(s.worker)
	}
	var writerDone chan struct{}
	if s.writes != nil {
		writerDone = make(chan struct{})
		go func() { s.batchWriter(); close(writerDone) }()
	}
	err := s.readLoop()
	// readLoop is the only sender, so it owns channel closure. Workers drain
	// every accepted job before exiting.
	close(s.jobs)
	s.wg.Wait()
	// Workers are the only senders on s.writes, and they've all exited by
	// now (s.wg.Wait returned), so it's safe to close it and let the
	// batch writer drain its remaining queue and exit.
	if s.writes != nil {
		close(s.writes)
		<-writerDone
	}
	return err
}

// Close stops accepting new packets. A read deadline wakes the read loop but
// leaves the socket writable while workers drain accepted jobs. Serve closes
// the socket after the drain completes. Safe to call more than once.
func (s *udpServer) Close() {
	s.closeOnce()
}

func (s *udpServer) closeSocket() {
	s.socketOnce()
}

// Shutdown stops accepting datagrams and waits for already-accepted jobs to
// drain, bounded by ctx. Close remains the non-blocking primitive used by
// Serve's error path.
func (s *udpServer) Shutdown(ctx context.Context) error {
	s.Close()
	select {
	case <-s.finished:
		return nil
	case <-ctx.Done():
		s.closeSocket()
		return ctx.Err()
	}
}

// udpReadBatchSize is how many datagrams one recvmmsg call pulls off the
// socket at once on the batched path. Sized as a middle ground: large enough
// that a busy socket actually amortizes the syscall trap cost across many
// datagrams, small enough that the per-socket buffer footprint (each slot
// holds one pooled udpMaxPacketSize buffer) stays modest even across every
// reuseport socket. Unlike udpQueuePerWorker this isn't a backpressure
// knob — it's purely how many buffers one syscall can fill.
const udpReadBatchSize = 32

// readLoop reads datagrams and dispatches them to the worker pool. It
// returns nil on a clean shutdown, or the first read error that isn't the
// shutdown deadline waking the socket.
func (s *udpServer) readLoop() error {
	if s.batchPC != nil {
		return s.readLoopBatch()
	}
	return s.readLoopSingle()
}

// readLoopBatch is the recvmmsg-batched read loop (see udpServer.batchPC):
// one syscall fills as many of udpReadBatchSize pooled buffers as the kernel
// has queued, instead of one syscall per datagram. Dispatch to the worker
// pool is identical to readLoopSingle — only how datagrams are pulled off
// the wire differs.
func (s *udpServer) readLoopBatch() error {
	msgs := make([]ipv4.Message, udpReadBatchSize)
	bps := make([]*[]byte, udpReadBatchSize)
	for i := range msgs {
		bp := s.bufs.Get().(*[]byte)
		bps[i] = bp
		msgs[i].Buffers = [][]byte{*bp}
	}
	release := func() {
		for _, bp := range bps {
			if bp != nil {
				s.bufs.Put(bp)
			}
		}
	}
	for {
		n, err := s.batchPC.ReadBatch(msgs, 0)
		if err != nil {
			release()
			if s.closed.Load() {
				return nil
			}
			return err
		}
		if s.closed.Load() {
			release()
			return nil
		}
		for i := range n {
			m := &msgs[i]
			bp := bps[i]
			nRead := m.N
			addr, _ := m.Addr.(*net.UDPAddr)
			if s.stats != nil {
				s.stats.UDPReceived.Add(1)
			}
			switch {
			case addr == nil || nRead < dnsHeaderLen:
				// Unaddressed or too short to be a DNS message: drop without
				// a reply, same amplification rationale as readLoopSingle.
				s.bufs.Put(bp)
				if s.stats != nil {
					s.stats.UDPInvalid.Add(1)
				}
			default:
				select {
				case s.jobs <- udpJob{bp: bp, n: nRead, addr: addr}:
				default:
					s.bufs.Put(bp)
					if s.stats != nil {
						s.stats.UDPQueueDrops.Add(1)
					}
				}
			}
			// This slot's buffer is now either owned by a job or already
			// returned to the pool above — refill it for the next ReadBatch.
			nbp := s.bufs.Get().(*[]byte)
			bps[i] = nbp
			msgs[i].Buffers = [][]byte{*nbp}
			msgs[i].N = 0
		}
	}
}

// readLoopSingle is the original one-syscall-per-datagram read loop, used
// whenever udpServer.batchPC is nil (non-Linux, or a non-IPv4 socket).
func (s *udpServer) readLoopSingle() error {
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
		if s.closed.Load() {
			s.bufs.Put(bp)
			return nil
		}
		if s.stats != nil {
			s.stats.UDPReceived.Add(1)
		}
		if n < dnsHeaderLen {
			// Too short to be a DNS message: drop without a reply (a reply
			// to garbage is an amplification vector).
			s.bufs.Put(bp)
			if s.stats != nil {
				s.stats.UDPInvalid.Add(1)
			}
			continue
		}
		select {
		case s.jobs <- udpJob{bp: bp, n: n, addr: addr}:
		default:
			s.bufs.Put(bp)
			if s.stats != nil {
				s.stats.UDPQueueDrops.Add(1)
			}
		}
	}
}

// worker processes datagrams until the server is closed. It handles one
// packet at a time inline (unpack → handler → write), so a single worker
// can never have two in-flight responses racing on the same buffer.
func (s *udpServer) worker() {
	for job := range s.jobs {
		s.handleRecovered(job)
		if s.stats != nil {
			s.stats.UDPCompleted.Add(1)
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

// udpWriterPool recycles the short-lived response-writer wrapper created for
// each datagram. ServeDNS is synchronous, so the wrapper cannot be reused
// until the handler returns; clearing its socket/address references before
// putting it back also prevents retaining a client's address unnecessarily.
var udpWriterPool = sync.Pool{New: func() any { return new(udpResponseWriter) }}

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
		if s.stats != nil {
			s.stats.UDPInvalid.Add(1)
		}
		return
	}
	w := udpWriterPool.Get().(*udpResponseWriter)
	w.conn, w.pc, w.addr, w.batchWrites = s.conn, s.pc, job.addr, s.writes
	defer func() {
		w.conn, w.pc, w.addr, w.batchWrites = nil, nil, nil, nil
		udpWriterPool.Put(w)
	}()
	s.handler.ServeDNS(w, req)
}

// udpWriteBatchSize mirrors udpReadBatchSize on the write side: the most
// datagrams one sendmmsg call will flush from udpServer.writes at a time.
const udpWriteBatchSize = 32

// udpWriteReq is one queued write for the batch writer. res is a
// size-1 buffered channel so the sender (udpResponseWriter.Write) can block
// on it without a rendezvous; pooled via udpWriteReqPool since res itself is
// reusable across requests (only ever one pending value at a time).
type udpWriteReq struct {
	b    []byte
	addr *net.UDPAddr
	res  chan error
}

var udpWriteReqPool = sync.Pool{New: func() any { return &udpWriteReq{res: make(chan error, 1)} }}

// batchWriter is the single goroutine per batching-enabled socket that turns
// queued writes into sendmmsg calls: it blocks for the first request, then
// opportunistically drains whatever else is already queued (non-blocking,
// up to udpWriteBatchSize) before issuing one WriteBatch for the lot. Under
// light load a "batch" is just one message — no worse than the unbatched
// path; under concurrent load from many workers, batches form naturally
// without adding artificial delay (nothing here ever waits to fill a
// batch). sendmmsg sends messages in order and stops at the first failure,
// so ms[:n] succeeded and ms[n:] were never attempted — those get retried
// individually (writeSingle) rather than reported as failed outright: the
// failure belongs to whatever came before them in the batch, not to them.
// Without that retry, one flaky destination (a full send buffer, a bad
// address) would silently drop every unrelated reply queued behind it in
// the same batch — a correlated-failure mode the unbatched path never had,
// since every write there was its own independent syscall.
func (s *udpServer) batchWriter() {
	reqs := make([]*udpWriteReq, 0, udpWriteBatchSize)
	msgs := make([]ipv4.Message, 0, udpWriteBatchSize)
	for {
		req, ok := <-s.writes
		if !ok {
			return
		}
		reqs = append(reqs, req)
		msgs = append(msgs, ipv4.Message{Buffers: [][]byte{req.b}, Addr: req.addr})
	drain:
		for len(reqs) < udpWriteBatchSize {
			select {
			case req, ok := <-s.writes:
				if !ok {
					break drain
				}
				reqs = append(reqs, req)
				msgs = append(msgs, ipv4.Message{Buffers: [][]byte{req.b}, Addr: req.addr})
			default:
				break drain
			}
		}
		n, err := s.batchPC.WriteBatch(msgs, 0)
		for i, r := range reqs {
			switch {
			case i < n:
				r.res <- nil
			case err != nil:
				r.res <- err
			default:
				// n < len(reqs) but no error: sendmmsg stopped at the
				// first failed message and never attempted this one, so
				// retry it on its own rather than dropping a reply that
				// may have nothing wrong with it.
				r.res <- s.writeSingle(r)
			}
		}
		reqs = reqs[:0]
		msgs = msgs[:0]
	}
}

// writeSingle issues one non-batched write, used by batchWriter to retry a
// message sendmmsg stopped short of attempting (see batchWriter's doc
// comment). Mirrors udpResponseWriter.Write's unbatched path exactly.
func (s *udpServer) writeSingle(req *udpWriteReq) error {
	if s.conn != nil {
		_, _, err := s.conn.WriteMsgUDP(req.b, nil, req.addr)
		return err
	}
	_, err := s.pc.WriteTo(req.b, req.addr)
	return err
}

// udpResponseWriter adapts dns.ResponseWriter to an unconnected UDP socket:
// every response is a WriteToUDP addressed to the querying client, so the
// reply's source address is exactly the socket the query arrived on (which
// matters to clients behind NAT).
type udpResponseWriter struct {
	conn        *net.UDPConn
	pc          net.PacketConn
	addr        *net.UDPAddr
	batchWrites chan *udpWriteReq // nil unless the owning udpServer batches writes
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
	if w.batchWrites != nil {
		req := udpWriteReqPool.Get().(*udpWriteReq)
		req.b, req.addr = b, w.addr
		w.batchWrites <- req
		// Blocks until batchWriter actually issues the sendmmsg call this
		// request landed in — Write stays synchronous from the caller's
		// point of view (see udpServer.writes's doc comment), so it's safe
		// for the caller to reuse/return b the instant this returns.
		err := <-req.res
		req.b, req.addr = nil, nil
		udpWriteReqPool.Put(req)
		if err != nil {
			return 0, err
		}
		return len(b), nil
	}
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
