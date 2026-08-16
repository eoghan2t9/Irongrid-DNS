package dnsserver

import (
	"net"
	"sync"
	"time"
)

// connLimitShards bounds lock contention on the per-IP connection counter:
// each client IP hashes to one shard, so concurrent accepts from different
// clients rarely block each other. Same scheme as the rate limiter's shards.
const connLimitShards = 64

// connLimiter tracks how many concurrent connections each client IP
// currently holds against a listener, refusing new ones past max. It exists
// to stop connection-flood and slowloris attacks from exhausting file
// descriptors and goroutines: the rate limiter throttles queries per IP, but
// a flood of half-open TCP connections never sends a query, so only a
// connection counter can bound them. max <= 0 disables the cap.
type connLimiter struct {
	shards [connLimitShards]*connShard
	max    int
}

type connShard struct {
	mu    sync.Mutex
	conns map[string]int
}

func newConnLimiter(max int) *connLimiter {
	cl := &connLimiter{max: max}
	for i := range cl.shards {
		cl.shards[i] = &connShard{conns: make(map[string]int, 8)}
	}
	return cl
}

func (cl *connLimiter) shard(ip string) *connShard {
	var h uint32 = 2166136261
	for i := 0; i < len(ip); i++ {
		h ^= uint32(ip[i])
		h *= 16777619
	}
	return cl.shards[h&(connLimitShards-1)]
}

// acquire reserves a connection slot for ip, reporting false when the cap is
// already met (or the limiter is disabled). The caller must pair a
// successful acquire with a release when the connection closes.
func (cl *connLimiter) acquire(ip string) bool {
	if ip == "" || cl.max <= 0 {
		return true
	}
	s := cl.shard(ip)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.conns[ip] >= cl.max {
		return false
	}
	s.conns[ip]++
	return true
}

// release frees a connection slot for ip.
func (cl *connLimiter) release(ip string) {
	if ip == "" || cl.max <= 0 {
		return
	}
	s := cl.shard(ip)
	s.mu.Lock()
	defer s.mu.Unlock()
	if n := s.conns[ip]; n > 1 {
		s.conns[ip] = n - 1
	} else {
		delete(s.conns, ip)
	}
}

// limitListener wraps a net.Listener with a per-IP concurrent-connection
// cap: accepted connections are counted against their client IP, and a
// connection past the cap is closed immediately and replaced with a
// rejectedConn whose reads fail — the server's accept loop keeps running for
// everyone else. For the DoT listener this wraps the raw TCP listener, so a
// rejected connection never even starts a TLS handshake.
type limitListener struct {
	net.Listener
	lim *connLimiter
}

func (l *limitListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	ip := clientIPOf(c.RemoteAddr())
	if l.lim.acquire(ip) {
		return &trackedConn{Conn: c, lim: l.lim, ip: ip}, nil
	}
	_ = c.Close()
	return rejectedConn{}, nil
}

// trackedConn releases its limiter slot when the connection closes.
type trackedConn struct {
	net.Conn
	lim *connLimiter
	ip  string
}

func (c *trackedConn) Close() error {
	err := c.Conn.Close()
	c.lim.release(c.ip)
	return err
}

// rejectedConn is handed to the server for a connection that exceeded the
// per-IP cap: every operation fails immediately, so the connection's handler
// goroutine exits on its first read and the accept loop stays healthy. It
// never holds a socket (the real connection was closed by the limiter).
type rejectedConn struct{}

func (rejectedConn) Read([]byte) (int, error)         { return 0, net.ErrClosed }
func (rejectedConn) Write([]byte) (int, error)        { return 0, net.ErrClosed }
func (rejectedConn) Close() error                     { return nil }
func (rejectedConn) LocalAddr() net.Addr              { return nil }
func (rejectedConn) RemoteAddr() net.Addr             { return nil }
func (rejectedConn) SetDeadline(time.Time) error      { return nil }
func (rejectedConn) SetReadDeadline(time.Time) error  { return nil }
func (rejectedConn) SetWriteDeadline(time.Time) error { return nil }
