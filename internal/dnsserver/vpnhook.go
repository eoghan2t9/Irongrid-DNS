package dnsserver

import (
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"

	"github.com/eoghan2t9/Irongrid-DNS/internal/vpn"
)

// SetVPNRouter installs (or, passed nil, removes) the domain-based VPN
// split-tunnel manager. Called once at boot right after the Manager is
// constructed — there is nothing to hot-swap here since the Manager owns
// its own hot-swappable route table (see vpn.Manager.Reconcile); a config
// reload that changes vpn.routes/vpn.profiles goes through the Manager
// directly, not through the Handler.
func (h *Handler) SetVPNRouter(m *vpn.Manager) {
	h.vpnRouter.Store(m)
}

// proxyAnswerTTL is short deliberately: if the matching profile's tunnel
// drops, a client should stop being pointed at the relay (and fall back to
// the real address) within seconds of its next query, not minutes.
const proxyAnswerTTL = 30

// tryProxyAnswer checks whether q's name is a Proxy-enabled VPN route
// domain whose profile is currently connected (see config.VPNProxyConfig)
// — if so, it returns a synthesized, authoritative A/AAAA answer pointing
// at this server's own public IP instead of resolving the real address, so
// the client's connection lands on internal/vpn.Relay instead. Returns nil
// when unused or the name doesn't match.
//
// Both query types are handled even though the public IP is normally only
// one address family: a family that doesn't match gets an authoritative
// NODATA reply rather than falling through to real resolution — otherwise
// a dual-stack client's Happy-Eyeballs AAAA query would get the real
// address and connect over IPv6 directly, bypassing the relay entirely.
func (h *Handler) tryProxyAnswer(r *dns.Msg, q dns.Question) *dns.Msg {
	vr := h.vpnRouter.Load()
	if vr == nil || (q.Qtype != dns.TypeA && q.Qtype != dns.TypeAAAA) {
		return nil
	}
	name := strings.ToLower(strings.TrimSuffix(q.Name, "."))
	ip, ok := vr.ProxyAnswer(name)
	if !ok {
		return nil
	}
	m := newReply(r)
	m.Authoritative = true
	is4 := ip.To4() != nil
	switch {
	case q.Qtype == dns.TypeA && is4:
		m.Answer = append(m.Answer, &dns.A{
			Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: proxyAnswerTTL},
			A:   ip.To4(),
		})
	case q.Qtype == dns.TypeAAAA && !is4:
		m.Answer = append(m.Answer, &dns.AAAA{
			Hdr:  dns.RR_Header{Name: q.Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: proxyAnswerTTL},
			AAAA: ip.To16(),
		})
	}
	return m
}

// observeVPN is called from write() for every response actually sent to a
// client. It is a no-op unless a VPN router is installed — the common
// case, checked first so the disabled path costs one atomic load — and
// even then only does real work if the query matched a configured VPN
// route; see internal/vpn.Manager.Observe, which itself never blocks.
func (h *Handler) observeVPN(r, m *dns.Msg) {
	vr := h.vpnRouter.Load()
	if vr == nil || len(r.Question) == 0 || len(m.Answer) == 0 {
		return
	}
	var ips []net.IP
	var minTTL uint32
	for _, rr := range m.Answer {
		var ip net.IP
		switch v := rr.(type) {
		case *dns.A:
			ip = v.A
		case *dns.AAAA:
			ip = v.AAAA
		default:
			continue
		}
		ips = append(ips, ip)
		if ttl := rr.Header().Ttl; minTTL == 0 || ttl < minTTL {
			minTTL = ttl
		}
	}
	if len(ips) == 0 {
		return
	}
	name := strings.ToLower(strings.TrimSuffix(r.Question[0].Name, "."))
	vr.Observe(vpn.Answer{Name: name, IPs: ips, TTL: time.Duration(minTTL) * time.Second})
}
