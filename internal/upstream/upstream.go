// Package upstream implements DNS forwarders supporting UDP, TCP, DNS-over-
// TLS and DNS-over-HTTPS upstream servers.
package upstream

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/net/http2"
)

// Transport identifies the wire protocol used to reach an upstream.
type Transport string

const (
	UDP  Transport = "udp"
	TCP  Transport = "tcp"
	TLS  Transport = "tls"
	HTTPS Transport = "https"
	QUIC Transport = "quic"
)

// Upstream is a configured forwarder.
type Upstream struct {
	Transport Transport
	Addr      string // host:port
	Host      string // hostname only (for SNI / Host header)
	URL       *url.URL
	client    *http.Client // for DoH
	tlsConf   *tls.Config  // for DoT/DoH
	fails     atomic.Int64
}

// Parse builds an Upstream from a spec string:
//
//	udp://1.1.1.1:53        tcp://8.8.8.8:53
//	tls://1.1.1.1:853       https://cloudflare-dns.com/dns-query
//	quic://dns.adguard-dns.com:853
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
		http2.ConfigureTransport(transport)
		u.client = &http.Client{Transport: transport, Timeout: 10 * time.Second}
	}
	return u, nil
}

// NewWithTLS builds an upstream from explicit fields, using the provided TLS
// config (used by tests and programmatic callers).
func NewWithTLS(transport Transport, addr, host string, tlsConf *tls.Config) *Upstream {
	u := &Upstream{Transport: transport, Addr: addr, Host: host, tlsConf: tlsConf}
	if u.Transport == HTTPS {
		u.client = &http.Client{Timeout: 10 * time.Second}
	}
	return u
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
	}
	return nil, fmt.Errorf("unknown transport %s", u.Transport)
}

func (u *Upstream) queryClassic(ctx context.Context, m *dns.Msg, tcp bool) (*dns.Msg, error) {
	c := &dns.Client{Net: map[bool]string{true: "tcp", false: "udp"}[tcp], Timeout: 8 * time.Second}
	r, _, err := c.ExchangeContext(ctx, m, u.Addr)
	if err != nil {
		u.fails.Add(1)
	}
	return r, err
}

func (u *Upstream) queryDoT(ctx context.Context, m *dns.Msg) (*dns.Msg, error) {
	c := &dns.Client{Net: "tcp-tls", TLSConfig: u.tlsConf, Timeout: 8 * time.Second}
	r, _, err := c.ExchangeContext(ctx, m, u.Addr)
	if err != nil {
		u.fails.Add(1)
	}
	return r, err
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
		u.fails.Add(1)
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("DoH upstream returned HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 65536))
	if err != nil {
		return nil, err
	}
	r := new(dns.Msg)
	if err := r.Unpack(body); err != nil {
		return nil, err
	}
	return r, nil
}

func (u *Upstream) queryDoQ(ctx context.Context, m *dns.Msg) (*dns.Msg, error) {
	// Delegated to the DoQ client in internal/doq to keep upstream simple;
	// a bare DoQ implementation lives alongside the server.
	return queryDoQClient(ctx, u, m)
}

// Fails returns the consecutive failure counter.
func (u *Upstream) Fails() int64 { return u.fails.Load() }
