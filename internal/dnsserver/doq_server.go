package dnsserver

import (
	"context"
	"encoding/binary"
	"io"
	"log"
	"net"
	"time"

	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
)

// startDoQ launches the RFC 9250 DNS-over-QUIC listener.
func (m *Manager) startDoQ(addr string) error {
	tlsConf := m.tlsConf.Clone()
	// RFC 9250 requires the "doq" ALPN token.
	tlsConf.NextProtos = []string{"doq"}

	quicConf := &quic.Config{
		MaxIdleTimeout:       60 * time.Second,
		KeepAlivePeriod:      20 * time.Second,
		HandshakeIdleTimeout: 8 * time.Second,
	}
	// Listen on our own UDP sockets so the kernel receive/send buffers are
	// raised (quic.ListenAddr dials its own socket with the OS defaults).
	// Where the platform supports it, the address is bound from several
	// SO_REUSEPORT sockets (same count as the plain UDP listener): the
	// kernel hashes each QUIC connection's 4-tuple to one socket, so every
	// packet of a connection reaches the listener that accepted it while
	// receive processing spreads across per-socket read goroutines. On
	// platforms without reuseport it falls back to a single socket (see
	// newUDPListeners). Caveat: because the listeners are independent, a
	// connection that migrates (changes its 4-tuple) would be re-hashed to
	// a different socket and dropped — acceptable for DoQ, whose clients
	// don't migrate mid-connection.
	pcs, err := newUDPListeners(addr, m.udpSocketCount())
	if err != nil {
		return err
	}
	lns := make([]*quic.Listener, 0, len(pcs))
	for _, pc := range pcs {
		ln, err := quic.Listen(pc, tlsConf, quicConf)
		if err != nil {
			// Close everything this call opened: successfully-wrapped
			// listeners (which own their packet conns) plus the unwrapped
			// tail of sockets. Nothing was registered in m.doqLns yet.
			for _, l := range lns {
				_ = l.Close()
			}
			for _, p := range pcs[len(lns):] {
				_ = p.Close()
			}
			return err
		}
		lns = append(lns, ln)
	}
	m.mu.Lock()
	m.doqLns = append(m.doqLns, lns...)
	m.doqBound = len(lns)
	m.mu.Unlock()
	noun := "sockets"
	if len(lns) == 1 {
		noun = "socket"
	}
	log.Printf("[dns] DoQ listener on %s (%d %s)", addr, len(lns), noun)
	for _, ln := range lns {
		go func(ln *quic.Listener) {
			for {
				conn, err := ln.Accept(context.Background())
				if err != nil {
					log.Printf("[dns] DoQ listener on %s stopped: %v", addr, err)
					m.results <- Listener{Proto: "doq", Addr: addr, Err: err}
					return
				}
				go m.handleDoQConn(conn)
			}
		}(ln)
	}
	return nil
}

// DoQAddr returns the bound address of the DoQ listener (useful when
// binding to port 0 for tests or dynamic ports).
func (m *Manager) DoQAddr() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.doqLns) == 0 {
		return ""
	}
	return m.doqLns[len(m.doqLns)-1].Addr().String()
}

func (m *Manager) handleDoQConn(conn quic.Connection) {
	defer func() { _ = conn.CloseWithError(0, "") }()
	for {
		stream, err := conn.AcceptStream(context.Background())
		if err != nil {
			return
		}
		go m.handleDoQStream(stream, conn.RemoteAddr())
	}
}

func (m *Manager) handleDoQStream(stream quic.Stream, remote net.Addr) {
	defer stream.Close()
	// RFC 9250: each message is prefixed with a 2-byte length field.
	var lenBuf [2]byte
	if _, err := io.ReadFull(stream, lenBuf[:]); err != nil {
		return
	}
	msgLen := binary.BigEndian.Uint16(lenBuf[:])
	// msgLen is already uint16, so it can't exceed 65535 — only the zero
	// (empty message) case is worth rejecting (staticcheck SA4003).
	if msgLen == 0 {
		return
	}
	msgBuf := make([]byte, msgLen)
	if _, err := io.ReadFull(stream, msgBuf); err != nil {
		return
	}
	req := new(dns.Msg)
	if err := req.Unpack(msgBuf); err != nil {
		return
	}

	clientIP := ""
	if remote != nil {
		if host, _, err := net.SplitHostPort(remote.String()); err == nil {
			clientIP = host
		}
	}
	w := &doqResponseWriter{stream: stream, clientIP: clientIP}
	m.handler.ServeDNSFromContext(w, req, clientIP, "doq")
}

// doqResponseWriter adapts dns.ResponseWriter to a QUIC stream.
type doqResponseWriter struct {
	stream   quic.Stream
	clientIP string
}

func (w *doqResponseWriter) WriteMsg(m *dns.Msg) error {
	buf := getPackBuf()
	packed, err := m.PackBuffer(buf)
	if err != nil {
		putPackBuf(buf)
		return err
	}
	// RFC 9250 prefixes each message with its 2-byte length. Two writes
	// (instead of copying packed into a combined buffer) avoids needing to
	// know whether PackBuffer packed into buf in place or had to allocate
	// its own — either way packed is written and recycled untouched.
	var lenBuf [2]byte
	binary.BigEndian.PutUint16(lenBuf[:], uint16(len(packed)))
	if _, err := w.stream.Write(lenBuf[:]); err != nil {
		putPackBuf(packed)
		return err
	}
	_, err = w.stream.Write(packed)
	putPackBuf(packed)
	return err
}

func (w *doqResponseWriter) Write(b []byte) (int, error) {
	// RFC 9250: each message is prefixed with its 2-byte length. Write is
	// the raw-byte path the handler's pack-once write uses, so the framing
	// lives here (WriteMsg keeps its own packing + framing).
	var lenBuf [2]byte
	binary.BigEndian.PutUint16(lenBuf[:], uint16(len(b)))
	if _, err := w.stream.Write(lenBuf[:]); err != nil {
		return 0, err
	}
	return w.stream.Write(b)
}

func (w *doqResponseWriter) LocalAddr() net.Addr  { return addrOnly("") }
func (w *doqResponseWriter) RemoteAddr() net.Addr { return addrOnly(w.clientIP) }
func (w *doqResponseWriter) Close() error         { return nil }
func (w *doqResponseWriter) TsigStatus() error    { return nil }
func (w *doqResponseWriter) TsigTimersOnly(bool)  {}
func (w *doqResponseWriter) Hijack()              {}
