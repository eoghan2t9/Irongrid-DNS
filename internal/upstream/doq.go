package upstream

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"

	"github.com/eoghan2t9/Irongrid-DNS/internal/tuning"
)

// queryDoQClient implements RFC 9250 (DNS over QUIC): a 2-byte length
// prefixed DNS message on its own bidirectional stream. It reuses a
// persistent connection across queries — QUIC's whole point is multiplexed
// streams on one connection, so paying for a fresh QUIC+TLS 1.3 handshake
// per query (the previous behavior) wasted the protocol's main advantage on
// top of the handshake cost itself.
func queryDoQClient(ctx context.Context, u *Upstream, m *dns.Msg) (*dns.Msg, error) {
	conn, err := u.getQUICConn(ctx)
	if err != nil {
		u.markResult(err)
		return nil, fmt.Errorf("doq dial: %w", err)
	}
	r, err := doQStream(ctx, conn, m)
	if err == nil {
		u.markResult(nil)
		return r, nil
	}
	// The connection may have died between queries (idle timeout, network
	// change, upstream restart) — drop it and retry once on a fresh
	// connection rather than failing over a stale-connection hiccup.
	u.dropQUICConn(conn)
	conn, err = u.getQUICConn(ctx)
	if err != nil {
		u.markResult(err)
		return nil, fmt.Errorf("doq redial: %w", err)
	}
	r, err = doQStream(ctx, conn, m)
	if err != nil {
		u.markResult(err)
		u.dropQUICConn(conn)
		return nil, err
	}
	u.markResult(nil)
	return r, nil
}

// getQUICConn returns the upstream's persistent QUIC connection, dialing one
// if there isn't a live one yet.
func (u *Upstream) getQUICConn(ctx context.Context) (*quic.Conn, error) {
	u.quicMu.Lock()
	defer u.quicMu.Unlock()
	if u.quicConn != nil && u.quicConn.Context().Err() == nil {
		return u.quicConn, nil
	}
	quicConf := &quic.Config{
		MaxIdleTimeout:       30 * time.Second,
		KeepAlivePeriod:      15 * time.Second,
		HandshakeIdleTimeout: 8 * time.Second,
	}
	// RFC 9250 requires the "doq" ALPN token on both endpoints.
	qTLS := u.tlsConf.Clone()
	qTLS.NextProtos = []string{"doq"}
	// Dial on our own UDP socket so the receive/send buffers are raised
	// (quic.DialAddr creates its own socket with the OS defaults). quic-go's
	// Dial does not take ownership of a caller-provided packet conn, so the
	// socket is closed alongside the connection (dropQUICConn / Close).
	pc, err := net.ListenPacket("udp", ":0")
	if err != nil {
		return nil, err
	}
	tuning.SetPacketBuffers(pc)
	addr, err := net.ResolveUDPAddr("udp", u.Addr)
	if err != nil {
		_ = pc.Close()
		return nil, err
	}
	conn, err := quic.Dial(ctx, pc, addr, qTLS, quicConf)
	if err != nil {
		_ = pc.Close()
		return nil, err
	}
	u.quicConn = conn
	u.quicPc = pc
	return conn, nil
}

// dropQUICConn closes conn (and the UDP socket backing it) and clears it if
// it's still the upstream's current connection (a concurrent call may have
// already replaced it).
func (u *Upstream) dropQUICConn(conn *quic.Conn) {
	u.quicMu.Lock()
	var pc net.PacketConn
	if u.quicConn == conn {
		u.quicConn = nil
		pc = u.quicPc
		u.quicPc = nil
	}
	u.quicMu.Unlock()
	_ = conn.CloseWithError(0, "")
	if pc != nil {
		_ = pc.Close()
	}
}

// doqStreamIODeadline bounds a DoQ stream's read/write when the caller's
// ctx carries no deadline (defensive — every real call path sets one via
// context.WithTimeout). quic-go's Stream.Write/Read take no context, only
// their own deadline, unlike OpenStreamSync above which does — so without
// an explicit deadline, an upstream that goes silent mid-exchange while its
// QUIC connection otherwise stays alive (keepalives still succeeding) blocks
// this goroutine on io.ReadFull forever. That leaked stream permanently
// holds one slot of the peer-granted stream credit; enough of them and
// every future DoQ query on this connection blocks in OpenStreamSync until
// its own timeout too — resolution "randomly" stops for good on that
// upstream until the process restarts.
const doqStreamIODeadline = 10 * time.Second

// doQStream runs one query on its own stream over an existing connection.
// Opening a stream is cheap (no handshake) and safe to do concurrently from
// multiple goroutines sharing the same conn — that concurrency-safety is
// exactly what QUIC's stream multiplexing is for.
func doQStream(ctx context.Context, conn *quic.Conn, m *dns.Msg) (*dns.Msg, error) {
	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return nil, fmt.Errorf("doq open stream: %w", err)
	}
	defer stream.Close()

	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(doqStreamIODeadline)
	}
	if err := stream.SetDeadline(deadline); err != nil {
		return nil, fmt.Errorf("doq set deadline: %w", err)
	}

	packed, err := m.Pack()
	if err != nil {
		return nil, err
	}
	buf := make([]byte, 2+len(packed))
	binary.BigEndian.PutUint16(buf[:2], uint16(len(packed)))
	copy(buf[2:], packed)
	if _, err := stream.Write(buf); err != nil {
		// Release the peer's stream credit immediately rather than
		// waiting out the deadline on an otherwise-abandoned stream.
		stream.CancelWrite(0)
		return nil, fmt.Errorf("doq write: %w", err)
	}
	if err := stream.Close(); err != nil {
		return nil, err
	}

	// Read the 2-byte length, then the message.
	var lenBuf [2]byte
	if _, err := io.ReadFull(stream, lenBuf[:]); err != nil {
		stream.CancelRead(0)
		return nil, fmt.Errorf("doq read length: %w", err)
	}
	msgLen := binary.BigEndian.Uint16(lenBuf[:])
	// msgLen is already uint16, so it can't exceed 65535 — only the zero
	// (empty message) case is worth rejecting (staticcheck SA4003).
	if msgLen == 0 {
		stream.CancelRead(0)
		return nil, fmt.Errorf("doq invalid message length %d", msgLen)
	}
	msgBuf := make([]byte, msgLen)
	if _, err := io.ReadFull(stream, msgBuf); err != nil {
		stream.CancelRead(0)
		return nil, fmt.Errorf("doq read message: %w", err)
	}
	r := new(dns.Msg)
	if err := r.Unpack(msgBuf); err != nil {
		return nil, err
	}
	return r, nil
}
