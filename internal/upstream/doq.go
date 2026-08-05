package upstream

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"time"

	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
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
		u.fails.Add(1)
		return nil, fmt.Errorf("doq dial: %w", err)
	}
	r, err := doQStream(ctx, conn, m)
	if err == nil {
		return r, nil
	}
	// The connection may have died between queries (idle timeout, network
	// change, upstream restart) — drop it and retry once on a fresh
	// connection rather than failing over a stale-connection hiccup.
	u.dropQUICConn(conn)
	conn, err = u.getQUICConn(ctx)
	if err != nil {
		u.fails.Add(1)
		return nil, fmt.Errorf("doq redial: %w", err)
	}
	r, err = doQStream(ctx, conn, m)
	if err != nil {
		u.fails.Add(1)
		u.dropQUICConn(conn)
		return nil, err
	}
	return r, nil
}

// getQUICConn returns the upstream's persistent QUIC connection, dialing one
// if there isn't a live one yet.
func (u *Upstream) getQUICConn(ctx context.Context) (quic.Connection, error) {
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
	conn, err := quic.DialAddr(ctx, u.Addr, qTLS, quicConf)
	if err != nil {
		return nil, err
	}
	u.quicConn = conn
	return conn, nil
}

// dropQUICConn closes conn and clears it if it's still the upstream's
// current connection (a concurrent call may have already replaced it).
func (u *Upstream) dropQUICConn(conn quic.Connection) {
	u.quicMu.Lock()
	if u.quicConn == conn {
		u.quicConn = nil
	}
	u.quicMu.Unlock()
	_ = conn.CloseWithError(0, "")
}

// doQStream runs one query on its own stream over an existing connection.
// Opening a stream is cheap (no handshake) and safe to do concurrently from
// multiple goroutines sharing the same conn — that concurrency-safety is
// exactly what QUIC's stream multiplexing is for.
func doQStream(ctx context.Context, conn quic.Connection, m *dns.Msg) (*dns.Msg, error) {
	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return nil, fmt.Errorf("doq open stream: %w", err)
	}
	defer stream.Close()

	packed, err := m.Pack()
	if err != nil {
		return nil, err
	}
	buf := make([]byte, 2+len(packed))
	binary.BigEndian.PutUint16(buf[:2], uint16(len(packed)))
	copy(buf[2:], packed)
	if _, err := stream.Write(buf); err != nil {
		return nil, fmt.Errorf("doq write: %w", err)
	}
	if err := stream.Close(); err != nil {
		return nil, err
	}

	// Read the 2-byte length, then the message.
	var lenBuf [2]byte
	if _, err := io.ReadFull(stream, lenBuf[:]); err != nil {
		return nil, fmt.Errorf("doq read length: %w", err)
	}
	msgLen := binary.BigEndian.Uint16(lenBuf[:])
	if msgLen == 0 || msgLen > 65535 {
		return nil, fmt.Errorf("doq invalid message length %d", msgLen)
	}
	msgBuf := make([]byte, msgLen)
	if _, err := io.ReadFull(stream, msgBuf); err != nil {
		return nil, fmt.Errorf("doq read message: %w", err)
	}
	r := new(dns.Msg)
	if err := r.Unpack(msgBuf); err != nil {
		return nil, err
	}
	return r, nil
}
