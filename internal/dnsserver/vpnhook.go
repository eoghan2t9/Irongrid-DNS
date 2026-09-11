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
