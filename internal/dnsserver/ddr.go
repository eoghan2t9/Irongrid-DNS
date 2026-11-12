package dnsserver

import (
	"net"
	"sort"
	"strconv"
	"strings"

	"github.com/miekg/dns"
)

// ddrName is the special-use name a client queries to discover the encrypted
// endpoints of the resolver it is already talking to (RFC 9462, "DDR").
const ddrName = "_dns.resolver.arpa"

// ddrTTL is short so a changed certificate host or port propagates quickly.
const ddrTTL = 300

// DDRConfig describes the encrypted endpoints this server advertises through
// Discovery of Designated Resolvers. A zero port means the transport is not
// offered. Host is the authentication domain name: the name clients
// validate the TLS certificate against, so it must be covered by the served
// certificate.
type DDRConfig struct {
	Host    string
	DoT     int
	DoQ     int
	DoH     int
	DoH3    int
	DoHPath string
}

// NewDDRConfig builds a DDRConfig from the listener addresses ("" disables a
// transport). It returns nil when there is no host or nothing encrypted to
// advertise, in which case _dns.resolver.arpa is answered with NODATA.
func NewDDRConfig(host, dot, doh, doh3, doq, dohPath string) *DDRConfig {
	host = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	if host == "" {
		return nil
	}
	c := &DDRConfig{
		Host:    host,
		DoT:     portOf(dot),
		DoQ:     portOf(doq),
		DoH:     portOf(doh),
		DoH3:    portOf(doh3),
		DoHPath: dohPath,
	}
	if c.DoHPath == "" {
		c.DoHPath = "/dns-query"
	}
	if c.DoT == 0 && c.DoQ == 0 && c.DoH == 0 && c.DoH3 == 0 {
		return nil
	}
	return c
}

func portOf(addr string) int {
	if addr == "" {
		return 0
	}
	_, p, err := net.SplitHostPort(addr)
	if err != nil {
		return 0
	}
	n, err := strconv.Atoi(p)
	if err != nil || n < 1 || n > 65535 {
		return 0
	}
	return n
}

// SetDDR hot-swaps the Discovery of Designated Resolvers configuration. nil
// stops advertising encrypted endpoints (the name is still answered locally).
func (h *Handler) SetDDR(c *DDRConfig) {
	h.ddr.Store(c)
}

// isDDRQuery reports whether qname (canonical form) is the DDR special-use
// name. It is intercepted unconditionally: forwarding it would let an
// upstream resolver advertise itself as this client's designated resolver.
func isDDRQuery(qname string) bool {
	return qname == ddrName
}

// ddrAnswer builds the response to a _dns.resolver.arpa query. Types other
// than SVCB (and a server with nothing to advertise) get NODATA, which RFC
// 9462 §6.4 prescribes for a resolver that has no designation to offer.
// local is the address the query arrived on; it becomes the ipv4hint /
// ipv6hint so a client can reach the designated resolver without a lookup.
func ddrAnswer(r *dns.Msg, q dns.Question, cfg *DDRConfig, local net.IP) *dns.Msg {
	m := newReply(r)
	if cfg == nil || q.Qtype != dns.TypeSVCB {
		return m
	}
	target := dns.Fqdn(cfg.Host)

	var hints []dns.SVCBKeyValue
	if len(local) > 0 && !local.IsUnspecified() {
		if v4 := local.To4(); v4 != nil {
			hints = append(hints, &dns.SVCBIPv4Hint{Hint: []net.IP{v4}})
		} else {
			hints = append(hints, &dns.SVCBIPv6Hint{Hint: []net.IP{local}})
		}
	}

	add := func(prio uint16, alpn []string, port, defPort int, dohPath string) {
		kv := []dns.SVCBKeyValue{&dns.SVCBAlpn{Alpn: alpn}}
		if port != defPort {
			kv = append(kv, &dns.SVCBPort{Port: uint16(port)})
		}
		kv = append(kv, hints...)
		if dohPath != "" {
			kv = append(kv, &dns.SVCBDoHPath{Template: dohPath + "{?dns}"})
		}
		// SvcParams must be in ascending key order on the wire.
		sort.Slice(kv, func(i, j int) bool { return kv[i].Key() < kv[j].Key() })
		m.Answer = append(m.Answer, &dns.SVCB{
			Hdr:      dns.RR_Header{Name: q.Name, Rrtype: dns.TypeSVCB, Class: dns.ClassINET, Ttl: ddrTTL},
			Priority: prio,
			Target:   target,
			Value:    kv,
		})
	}

	prio := uint16(1)
	if cfg.DoH != 0 {
		alpn := []string{"h2"}
		// HTTP/3 on the same port number (UDP vs TCP) rides in the same record.
		if cfg.DoH3 == cfg.DoH {
			alpn = append(alpn, "h3")
		}
		add(prio, alpn, cfg.DoH, 443, cfg.DoHPath)
		prio++
	}
	if cfg.DoH3 != 0 && cfg.DoH3 != cfg.DoH {
		add(prio, []string{"h3"}, cfg.DoH3, 443, cfg.DoHPath)
		prio++
	}
	if cfg.DoT != 0 {
		add(prio, []string{"dot"}, cfg.DoT, 853, "")
		prio++
	}
	if cfg.DoQ != 0 {
		add(prio, []string{"doq"}, cfg.DoQ, 853, "")
	}
	return m
}

// ddrLocalIP is the server address to advertise as the hint: the address the
// query arrived on when the transport reports a specific one, otherwise the
// address the OS would use to reach the client. The fallback matters because
// the UDP listener is bound to the wildcard address and the DoH and DoQ
// writers expose no local address at all, so without it nearly every answer
// would carry no hint — and a client discovering a resolver on a private
// address uses the hint to confirm the designated resolver is the same host.
func ddrLocalIP(local net.Addr, client string) net.IP {
	if ip := localIPOf(local); len(ip) > 0 && !ip.IsUnspecified() {
		return ip
	}
	return routeSourceIP(client)
}

// routeSourceIP returns the local address the OS routing table selects for
// reaching client. Connecting a UDP socket only performs the route lookup and
// sends nothing.
func routeSourceIP(client string) net.IP {
	ip := net.ParseIP(client)
	if ip == nil {
		return nil
	}
	c, err := net.DialUDP("udp", nil, &net.UDPAddr{IP: ip, Port: 9})
	if err != nil {
		return nil
	}
	defer func() { _ = c.Close() }()
	if a, ok := c.LocalAddr().(*net.UDPAddr); ok && !a.IP.IsUnspecified() {
		return a.IP
	}
	return nil
}

// localIPOf returns the IP of a connection's local address, or nil.
func localIPOf(a net.Addr) net.IP {
	switch v := a.(type) {
	case *net.UDPAddr:
		return v.IP
	case *net.TCPAddr:
		return v.IP
	case nil:
		return nil
	}
	host, _, err := net.SplitHostPort(a.String())
	if err != nil {
		return nil
	}
	return net.ParseIP(host)
}
