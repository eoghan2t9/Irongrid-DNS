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
// prefixed DNS message on a single bidirectional stream per query.
func queryDoQClient(ctx context.Context, u *Upstream, m *dns.Msg) (*dns.Msg, error) {
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
		u.fails.Add(1)
		return nil, fmt.Errorf("doq dial: %w", err)
	}
	defer conn.CloseWithError(0, "")

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
		u.fails.Add(1)
		return nil, fmt.Errorf("doq write: %w", err)
	}
	if err := stream.Close(); err != nil {
		return nil, err
	}

	// Read the 2-byte length, then the message.
	var lenBuf [2]byte
	if _, err := io.ReadFull(stream, lenBuf[:]); err != nil {
		u.fails.Add(1)
		return nil, fmt.Errorf("doq read length: %w", err)
	}
	msgLen := binary.BigEndian.Uint16(lenBuf[:])
	if msgLen == 0 || msgLen > 65535 {
		return nil, fmt.Errorf("doq invalid message length %d", msgLen)
	}
	msgBuf := make([]byte, msgLen)
	if _, err := io.ReadFull(stream, msgBuf); err != nil {
		u.fails.Add(1)
		return nil, fmt.Errorf("doq read message: %w", err)
	}
	r := new(dns.Msg)
	if err := r.Unpack(msgBuf); err != nil {
		return nil, err
	}
	return r, nil
}
