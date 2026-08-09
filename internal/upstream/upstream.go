// Package upstream implements DNS forwarders supporting UDP, TCP, DNS-over-
// TLS and DNS-over-HTTPS upstream servers.
package upstream

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
	"golang.org/x/net/http2"

	"github.com/eoghan2t9/Irongrid-DNS/internal/recursive"
)

// upstreamPoolSize bounds the number of warm TCP/DoT connections kept per
// upstream. It's a cache of ready-to-reuse connections, not a hard
// concurrency limit — a query that finds the pool empty just dials fresh,
// same as before pooling existed.
const upstreamPoolSize = 8

// Circuit breaker: after circuitOpenFails consecutive failures an upstream
// is skipped for circuitCooldown instead of letting every query burn its
// full timeout against a dead or unreachable server. The first query after
// the cooldown elapses probes it again; any success closes the circuit and
// resets the failure count.
const (
	circuitOpenFails = 3
	circuitCooldown  = 30 * time.Second
)

// Transport identifies the wire protocol used to reach an upstream.
type Transport string

const (
	UDP       Transport = "udp"
	TCP       Transport = "tcp"
	TLS       Transport = "tls"
	HTTPS     Transport = "https"
	QUIC      Transport = "quic"
	Recursive Transport = "recursive"
)

// Upstream is a configured forwarder.
type Upstream struct {
	Transport Transport
	Addr      string // host:port
	Host      string // hostname only (for SNI / Host header)
	URL       *url.URL
	client    *http.Client // for DoH (its own internal connection pool)
	tlsConf   *tls.Config  // for DoT/DoH/DoQ

	// fails is the consecutive-failure count driving the circuit breaker;
	// cooldownUntil (unix nanos, 0 = closed) is when an open circuit re-arms.
	fails         atomic.Int64
	cooldownUntil atomic.Int64

	// Reusable transport clients. dns.Client is safe for concurrent use
	// (each Exchange dials its own connection), so one per transport avoids
	// allocating a fresh client on every query. nil for transports that
	// don't use them (Recursive, and HTTPS which has its own http.Client).
	udpClient *dns.Client
	tcpClient *dns.Client
	dotClient *dns.Client

	// connPool holds warm TCP/DoT connections (nil for other transports).
	// TCP and — worse — DoT pay for a full connection setup (a TLS
	// handshake, for DoT) on every query without this; miekg/dns's
	// Client.Exchange has no pooling of its own.
	connPool chan *dns.Conn

	// DoQ keeps a single persistent QUIC connection and opens a new stream
	// per query instead of a new connection — that's the entire point of
	// QUIC's multiplexing, which a fresh quic.DialAddr per query (the
	// previous behavior) completely wasted, on top of paying for a fresh
	// QUIC+TLS 1.3 handshake every time.
	quicMu   sync.Mutex
	quicConn quic.Connection

	// resolver performs the walk for Transport == Recursive; nil for every
	// other transport.
	resolver *recursive.Resolver
}

// Parse builds an Upstream from a spec string:
//
//	udp://1.1.1.1:53        tcp://8.8.8.8:53
//	tls://1.1.1.1:853       https://cloudflare-dns.com/dns-query
//	quic://dns.adguard-dns.com:853
//	recursive://            iterative resolution from the root servers,
//	                        no forwarder involved
func Parse(spec string) (*Upstream, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return nil, fmt.Errorf("empty upstream")
	}
	u := &Upstream{}
	if !strings.Contains(spec, "://") {
		// Bare address defaults to UDP with the standard port.
		spec = "udp://" + spec
	}
	parsed, err := url.Parse(spec)
	if err != nil {
		return nil, fmt.Errorf("parse upstream %q: %w", spec, err)
	}
	u.URL = parsed
	switch parsed.Scheme {
	case "recursive":
		// No host to dial — resolution starts at the root servers and walks
		// referrals itself. "recursive://" (or "recursive://root", any host
		// part is ignored) is the whole spec.
		u.Transport = Recursive
		u.resolver = recursive.New(nil)
		return u, nil
	case "udp", "tcp", "tls", "quic":
		u.Transport = Transport(parsed.Scheme)
		u.Host = parsed.Hostname()
		host := parsed.Host
		if parsed.Port() == "" {
			host = net.JoinHostPort(parsed.Hostname(), "53")
		}
		if u.Transport == TLS && parsed.Port() == "" {
			host = net.JoinHostPort(parsed.Hostname(), "853")
		}
		if u.Transport == QUIC && parsed.Port() == "" {
			host = net.JoinHostPort(parsed.Hostname(), "853")
		}
		u.Addr = host
	case "https":
		u.Transport = HTTPS
		u.Host = parsed.Hostname()
		u.Addr = parsed.Host
	default:
		return nil, fmt.Errorf("unsupported upstream scheme %q", parsed.Scheme)
	}

	switch u.Transport {
	case TLS, HTTPS, QUIC:
		u.tlsConf = &tls.Config{ServerName: u.Host, MinVersion: tls.VersionTLS12}
	}
	switch u.Transport {
	case TCP, TLS:
		u.connPool = make(chan *dns.Conn, upstreamPoolSize)
	}
	switch u.Transport {
	case UDP:
		u.udpClient = &dns.Client{Net: "udp", Timeout: 8 * time.Second}
	case TCP:
		u.tcpClient = &dns.Client{Net: "tcp", Timeout: 8 * time.Second}
	case TLS:
		u.dotClient = &dns.Client{Net: "tcp-tls", TLSConfig: u.tlsConf, Timeout: 8 * time.Second}
	}
	if u.Transport == HTTPS {
		path := parsed.Path
		if path == "" {
			path = "/dns-query"
		}
		u.URL.Path = path
		transport := &http.Transport{
			TLSClientConfig: u.tlsConf,
			MaxIdleConns:    32,
			IdleConnTimeout: 90 * time.Second,
			DialContext: (&net.Dialer{
				Timeout:   5 * time.Second,
				KeepAlive: 30 * time.Second,
			}).DialContext,
		}
		// HTTP/2 on the DoH transport is best-effort: ConfigureTransport only
		// errors when the transport already pins NextProtos (never the case
		// here), and DoH over HTTP/1.1 works fine — so log and continue
		// instead of failing the upstream over a non-fatal limitation.
		if cErr := http2.ConfigureTransport(transport); cErr != nil {
			log.Printf("[upstream] %s: HTTP/2 unavailable (%v) — using HTTP/1.1", u.Host, cErr)
		}
		u.client = &http.Client{Transport: transport, Timeout: 10 * time.Second}
	}
	return u, nil
}

// NewWithTLS builds an upstream from explicit fields, using the provided TLS
// config (used by tests and programmatic callers).
func NewWithTLS(transport Transport, addr, host string, tlsConf *tls.Config) *Upstream {
	u := &Upstream{Transport: transport, Addr: addr, Host: host, tlsConf: tlsConf}
	switch u.Transport {
	case TCP:
		u.connPool = make(chan *dns.Conn, upstreamPoolSize)
		u.tcpClient = &dns.Client{Net: "tcp", Timeout: 8 * time.Second}
	case TLS:
		u.connPool = make(chan *dns.Conn, upstreamPoolSize)
		u.dotClient = &dns.Client{Net: "tcp-tls", TLSConfig: tlsConf, Timeout: 8 * time.Second}
	case HTTPS:
		u.client = &http.Client{Timeout: 10 * time.Second}
	}
	return u
}

// NewRecursive builds a Recursive-transport Upstream seeded with the given
// root hints instead of the real root servers — for tests that need an
// iterative resolver pointed at a local fake root/TLD/authoritative chain.
func NewRecursive(rootHints []string) *Upstream {
	return &Upstream{Transport: Recursive, resolver: recursive.New(rootHints)}
}

// IsRecursiveSpec reports whether spec names the recursive transport,
// mirroring the scheme check Parse performs — so startup code can decide
// whether a recursive upstream is configured (and fetch authoritative root
// hints for it) without parsing the spec into a full Upstream.
func IsRecursiveSpec(spec string) bool {
	spec = strings.TrimSpace(spec)
	i := strings.Index(spec, "://")
	return i > 0 && strings.EqualFold(spec[:i], "recursive")
}

// Address returns the dial address.
func (u *Upstream) Address() string { return u.Addr }

// Name returns a human-readable identifier.
func (u *Upstream) Name() string {
	if u.URL != nil {
		return u.URL.String()
	}
	return fmt.Sprintf("%s://%s", u.Transport, u.Addr)
}

// Query forwards a single DNS message and returns the response.
func (u *Upstream) Query(ctx context.Context, m *dns.Msg) (*dns.Msg, error) {
	switch u.Transport {
	case UDP, TCP:
		return u.queryClassic(ctx, m, u.Transport == TCP)
	case TLS:
		return u.queryDoT(ctx, m)
	case HTTPS:
		return u.queryDoH(ctx, m)
	case QUIC:
		return u.queryDoQ(ctx, m)
	case Recursive:
		return u.resolver.Resolve(ctx, m)
	}
	return nil, fmt.Errorf("unknown transport %s", u.Transport)
}

func (u *Upstream) queryClassic(ctx context.Context, m *dns.Msg, tcp bool) (*dns.Msg, error) {
	if !tcp {
		// UDP is connectionless — there's no handshake to amortize, so
		// pooling buys nothing (a fresh "dial" is just a local socket()).
		c := u.udpClient
		if c == nil {
			c = &dns.Client{Net: "udp", Timeout: 8 * time.Second}
		}
		r, _, err := c.ExchangeContext(ctx, m, u.Addr)
		u.markResult(err)
		return r, err
	}
	c := u.tcpClient
	if c == nil {
		c = &dns.Client{Net: "tcp", Timeout: 8 * time.Second}
	}
	return u.pooledExchange(ctx, m, c)
}

func (u *Upstream) queryDoT(ctx context.Context, m *dns.Msg) (*dns.Msg, error) {
	c := u.dotClient
	if c == nil {
		c = &dns.Client{Net: "tcp-tls", TLSConfig: u.tlsConf, Timeout: 8 * time.Second}
	}
	return u.pooledExchange(ctx, m, c)
}

// pooledExchange runs m over client, reusing a warm connection from the
// upstream's pool when one is available and dialing fresh otherwise. For
// DoT in particular this avoids a full TLS handshake per query. Success and
// failure are fed to the circuit breaker (markResult) so a warm-connection
// hiccup that ultimately recovers on a fresh dial still counts as one
// failure, and a fully recovered upstream resets its counter.
func (u *Upstream) pooledExchange(ctx context.Context, m *dns.Msg, client *dns.Client) (*dns.Msg, error) {
	if conn := u.getConn(); conn != nil {
		r, _, err := client.ExchangeWithConnContext(ctx, m, conn)
		if err == nil {
			u.markResult(nil)
			u.putConn(conn)
			return r, nil
		}
		conn.Close()
		u.markResult(err)
		// The pooled connection may have gone stale while idle (the
		// upstream closed it, a NAT dropped it, a restart on their end) —
		// fall through to a fresh dial rather than failing the query over
		// a warm-connection hiccup.
	}
	conn, err := client.DialContext(ctx, u.Addr)
	if err != nil {
		u.markResult(err)
		return nil, err
	}
	r, _, err := client.ExchangeWithConnContext(ctx, m, conn)
	if err != nil {
		u.markResult(err)
		conn.Close()
		return nil, err
	}
	u.markResult(nil)
	u.putConn(conn)
	return r, nil
}

// markResult feeds the circuit breaker: a success closes the circuit and
// resets the consecutive-failure count; a failure increments it and, once it
// crosses circuitOpenFails, opens the circuit until circuitCooldown elapses.
func (u *Upstream) markResult(err error) {
	if err == nil {
		u.fails.Store(0)
		u.cooldownUntil.Store(0)
		return
	}
	if u.fails.Add(1) >= circuitOpenFails {
		u.cooldownUntil.Store(time.Now().Add(circuitCooldown).UnixNano())
	}
}

// Available reports whether the upstream should be tried for a query: it is
// unavailable only while its circuit is open (circuitOpenFails+ consecutive
// failures inside the cooldown window). The first query after the cooldown
// elapses probes it again; a success closes the circuit.
func (u *Upstream) Available() bool {
	if u.fails.Load() < circuitOpenFails {
		return true
	}
	return time.Now().UnixNano() >= u.cooldownUntil.Load()
}

// getConn pops a warm connection from the pool, or returns nil if none are
// available (including when connPool is nil, so this degrades cleanly for
// transports/constructors that don't set one up).
func (u *Upstream) getConn() *dns.Conn {
	select {
	case c := <-u.connPool:
		return c
	default:
		return nil
	}
}

// putConn returns a connection to the pool, closing it instead if the pool
// is full (or nil).
func (u *Upstream) putConn(c *dns.Conn) {
	select {
	case u.connPool <- c:
	default:
		c.Close()
	}
}

// Close releases any pooled/persistent connections this upstream holds.
// Called when a config reload replaces the upstream list — without it, the
// TCP/DoT pool and DoQ's persistent QUIC connection would leak sockets on
// every reload for the lifetime of the process.
func (u *Upstream) Close() {
	if u.connPool != nil {
	drain:
		for {
			select {
			case c := <-u.connPool:
				c.Close()
			default:
				break drain
			}
		}
	}
	u.quicMu.Lock()
	if u.quicConn != nil {
		_ = u.quicConn.CloseWithError(0, "")
		u.quicConn = nil
	}
	u.quicMu.Unlock()
}

func (u *Upstream) queryDoH(ctx context.Context, m *dns.Msg) (*dns.Msg, error) {
	packed, err := m.Pack()
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.URL.String(), bytes.NewReader(packed))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")
	resp, err := u.client.Do(req)
	if err != nil {
		u.markResult(err)
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("DoH upstream returned HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 65536))
	if err != nil {
		u.markResult(err)
		return nil, err
	}
	r := new(dns.Msg)
	if err := r.Unpack(body); err != nil {
		u.markResult(err)
		return nil, err
	}
	u.markResult(nil)
	return r, nil
}

func (u *Upstream) queryDoQ(ctx context.Context, m *dns.Msg) (*dns.Msg, error) {
	// Delegated to the DoQ client in internal/doq to keep upstream simple;
	// a bare DoQ implementation lives alongside the server.
	return queryDoQClient(ctx, u, m)
}

// Fails returns the consecutive failure counter (reset on every success).
func (u *Upstream) Fails() int64 { return u.fails.Load() }

// CooldownUntil returns when an open circuit re-arms, or nil when the
// circuit is closed (no cooldown scheduled). Exposed for the dashboard's
// upstream-health view.
func (u *Upstream) CooldownUntil() *time.Time {
	ns := u.cooldownUntil.Load()
	if ns == 0 {
		return nil
	}
	t := time.Unix(0, ns)
	return &t
}
