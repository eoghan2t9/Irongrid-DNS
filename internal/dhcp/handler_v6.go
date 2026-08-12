package dhcp

import (
	"log"
	"net"
	"strings"
	"time"

	"github.com/insomniacslk/dhcp/dhcpv6"
	"github.com/insomniacslk/dhcp/iana"
)

// handleV6 is the server6 handler. Relayed messages are unwrapped via
// GetInnerMessage; a home-LAN server has no relays, but unwrapping keeps the
// state machine correct if a router forwards a packet.
func (s *Server) handleV6(conn net.PacketConn, peer net.Addr, m dhcpv6.DHCPv6) {
	msg, err := m.GetInnerMessage()
	if err != nil || msg == nil {
		return
	}
	clientID := msg.Options.ClientID()
	if clientID == nil {
		return
	}
	hexID := duidHex(clientID)
	if hexID == "" {
		return
	}
	// A client that names a server must be talking to us.
	if sid := msg.Options.ServerID(); sid != nil && !sid.Equal(s.srvDUID()) {
		return
	}
	switch msg.Type() {
	case dhcpv6.MessageTypeSolicit:
		s.v6Solicit(conn, peer, msg, hexID)
	case dhcpv6.MessageTypeRequest, dhcpv6.MessageTypeRenew, dhcpv6.MessageTypeRebind:
		s.v6Request(conn, peer, msg, hexID)
	case dhcpv6.MessageTypeRelease:
		s.v6Release(msg, hexID)
	case dhcpv6.MessageTypeConfirm:
		s.v6Confirm(conn, peer, msg, hexID)
	case dhcpv6.MessageTypeDecline:
		s.v6Decline(msg, hexID)
	case dhcpv6.MessageTypeInformationRequest:
		s.v6InfoRequest(conn, peer, msg, hexID)
	}
}

func (s *Server) srvDUID() dhcpv6.DUID {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.serverDUID
}

func (s *Server) v6Solicit(conn net.PacketConn, peer net.Addr, m *dhcpv6.Message, clientHex string) {
	hostname := clientHostname6(m)
	ip, static := s.allocV6(clientHex, hostname, requestedAddr6(m))
	mods := s.v6BaseMods(m, clientHex)
	rapid := m.Options.GetOne(dhcpv6.OptionRapidCommit) != nil
	if ip != nil {
		mods = append(mods, dhcpv6.WithOption(s.v6IANA(m, ip, static)))
	}
	var reply *dhcpv6.Message
	var err error
	if rapid {
		// RFC 8415 §18.3.1: a server that accepts Rapid Commit answers the
		// SOLICIT with a REPLY that commits the assignment immediately.
		reply, err = dhcpv6.NewReplyFromMessage(m, mods...)
	} else {
		reply, err = dhcpv6.NewAdvertiseFromSolicit(m, mods...)
	}
	if err != nil || reply == nil {
		return
	}
	if ip != nil && rapid {
		s.commit(&Lease{Key: string(v6Key(clientHex)), DUID: clientHex, IP: ip.String(), Hostname: hostname, Static: static})
	}
	s.sendV6(conn, peer, reply.ToBytes())
}

func (s *Server) v6Request(conn net.PacketConn, peer net.Addr, m *dhcpv6.Message, clientHex string) {
	key := v6Key(clientHex)
	hostname := clientHostname6(m)
	requested := requestedAddr6(m)
	if requested == nil {
		// RENEW with no IA addresses: fall back to the client's current
		// lease, if any.
		s.mu.RLock()
		if l := s.leases[key]; l != nil {
			requested = net.ParseIP(l.IP)
		}
		s.mu.RUnlock()
	}
	if requested == nil || !s.addrInPool(requested, true) || s.inUse(requested, key) {
		log.Printf("[dhcp] v6 %s request for unavailable %s", clientHex, requested)
		s.v6NoAddrs(conn, peer, m, clientHex)
		return
	}
	// A static reservation binds the client to its fixed address.
	static := false
	if st := s.staticFor(nil, clientHex); st != nil && st.IP.Equal(requested) {
		static = true
	}
	s.commit(&Lease{Key: string(key), DUID: clientHex, IP: requested.String(), Hostname: hostname, Static: static})

	mods := s.v6BaseMods(m, clientHex)
	mods = append(mods, dhcpv6.WithOption(s.v6IANA(m, requested, static)))
	reply, err := dhcpv6.NewReplyFromMessage(m, mods...)
	if err != nil || reply == nil {
		return
	}
	s.sendV6(conn, peer, reply.ToBytes())
}

// v6Release frees the client's lease; the address it releases (if named)
// must match.
func (s *Server) v6Release(m *dhcpv6.Message, clientHex string) {
	key := v6Key(clientHex)
	var ip net.IP
	if addrs := iaAddrs6(m); len(addrs) > 0 {
		ip = addrs[0].IPv6Addr
	}
	if s.releaseLease(key, ip) {
		log.Printf("[dhcp] v6 %s released %s", clientHex, ip)
	}
}

// v6Confirm verifies the client's addresses are on a network we serve. A
// REPLY with the addresses back (status Success) tells it they are; the
// reply is sent without committing anything (RFC 8415 §18.3.4).
func (s *Server) v6Confirm(conn net.PacketConn, peer net.Addr, m *dhcpv6.Message, clientHex string) {
	onLink := true
	for _, a := range iaAddrs6(m) {
		if !s.addrInPool(a.IPv6Addr, true) {
			onLink = false
		}
	}
	mods := s.v6BaseMods(m, clientHex)
	if !onLink {
		mods = append(mods, dhcpv6.WithOption(&dhcpv6.OptStatusCode{StatusCode: iana.StatusNotOnLink}))
	}
	reply, err := dhcpv6.NewReplyFromMessage(m, mods...)
	if err != nil || reply == nil {
		return
	}
	s.sendV6(conn, peer, reply.ToBytes())
}

func (s *Server) v6Decline(m *dhcpv6.Message, clientHex string) {
	for _, a := range iaAddrs6(m) {
		s.declineLease(a.IPv6Addr)
		log.Printf("[dhcp] v6 %s declined %s — withholding the address", clientHex, a.IPv6Addr)
	}
}

// v6InfoRequest serves a stateless client (SLAAC): options only, no lease.
func (s *Server) v6InfoRequest(conn net.PacketConn, peer net.Addr, m *dhcpv6.Message, clientHex string) {
	mods := s.v6BaseMods(m, clientHex)
	reply, err := dhcpv6.NewReplyFromMessage(m, mods...)
	if err != nil || reply == nil {
		return
	}
	s.sendV6(conn, peer, reply.ToBytes())
}

// v6NoAddrs answers a request we cannot honour with a polite status code.
func (s *Server) v6NoAddrs(conn net.PacketConn, peer net.Addr, m *dhcpv6.Message, clientHex string) {
	mods := s.v6BaseMods(m, clientHex)
	mods = append(mods, dhcpv6.WithOption(&dhcpv6.OptStatusCode{StatusCode: iana.StatusNoAddrsAvail}))
	reply, err := dhcpv6.NewReplyFromMessage(m, mods...)
	if err != nil || reply == nil {
		return
	}
	s.sendV6(conn, peer, reply.ToBytes())
}

// v6BaseMods are the options every reply carries: identity (server + client
// DUID) and the stateless options (DNS servers, domain search list).
func (s *Server) v6BaseMods(m *dhcpv6.Message, clientHex string) []dhcpv6.Modifier {
	mods := []dhcpv6.Modifier{
		dhcpv6.WithServerID(s.srvDUID()),
		dhcpv6.WithClientID(m.Options.ClientID()),
	}
	if dns := s.dns6(); len(dns) > 0 {
		mods = append(mods, dhcpv6.WithDNS(dns...))
	}
	if dom := s.domain(); dom != "" {
		mods = append(mods, dhcpv6.WithDomainSearchList(dom))
	}
	return mods
}

// v6IANA builds the IA_NA for the client's first IAID carrying the given
// address with the current lease lifetimes (effectively infinite for static
// reservations).
func (s *Server) v6IANA(m *dhcpv6.Message, ip net.IP, static bool) *dhcpv6.OptIANA {
	var iaid [4]byte
	if ias := m.Options.IANA(); len(ias) > 0 {
		iaid = ias[0].IaId
	}
	valid := s.leaseTime()
	if static {
		valid = time.Duration(0xffffffff) * time.Second // ~136 years
	}
	pref := valid / v6PreferredFraction
	return &dhcpv6.OptIANA{
		IaId: iaid,
		Options: dhcpv6.IdentityOptions{Options: dhcpv6.Options{
			&dhcpv6.OptIAAddress{IPv6Addr: ip, PreferredLifetime: pref, ValidLifetime: valid},
		}},
	}
}

// iaAddrs6 returns every address the client asks for across its IA_NAs.
func iaAddrs6(m *dhcpv6.Message) []*dhcpv6.OptIAAddress {
	var out []*dhcpv6.OptIAAddress
	for _, ia := range m.Options.IANA() {
		out = append(out, ia.Options.Addresses()...)
	}
	return out
}

// requestedAddr6 returns the first address the client asks for in any IA_NA.
func requestedAddr6(m *dhcpv6.Message) net.IP {
	if addrs := iaAddrs6(m); len(addrs) > 0 {
		return addrs[0].IPv6Addr
	}
	return nil
}

// dns6 returns the DNS servers advertised to v6 clients (config list, else
// the server's own v6 address).
func (s *Server) dns6() []net.IP {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if len(s.cfg.DNS) > 0 {
		return s.cfg.DNS
	}
	if s.cfg.ServerIPv6 != nil {
		return []net.IP{s.cfg.ServerIPv6}
	}
	return nil
}

// clientHostname6 extracts the client's hostname from its FQDN option
// (RFC 4704, option 39), first label only.
func clientHostname6(m *dhcpv6.Message) string {
	fq := m.Options.GetOne(dhcpv6.OptionFQDN)
	opt, ok := fq.(*dhcpv6.OptFQDN)
	if !ok || opt == nil || opt.DomainName == nil {
		return ""
	}
	name := strings.Join(opt.DomainName.Labels, ".")
	if i := strings.IndexByte(name, '.'); i >= 0 {
		name = name[:i]
	}
	return sanitizeHostname(name)
}

// sendV6 replies to the peer (a link-local unicast source works for every
// state) or, when the source was a multicast/unknown address, to the DHCPv6
// servers-and-relays multicast group on the LAN.
func (s *Server) sendV6(conn net.PacketConn, peer net.Addr, data []byte) {
	dst := peer
	if dst == nil {
		dst = &net.UDPAddr{IP: net.ParseIP("ff02::1:2"), Port: 547}
	} else if ip := addrIP(peer); ip != nil && ip.IsMulticast() {
		dst = &net.UDPAddr{IP: ip, Port: 547}
	}
	if _, err := conn.WriteTo(data, dst); err != nil {
		log.Printf("[dhcp] v6 reply to %s: %v", dst, err)
	}
}

func addrIP(a net.Addr) net.IP {
	switch v := a.(type) {
	case *net.UDPAddr:
		return v.IP
	case *net.IPAddr:
		return v.IP
	}
	return nil
}
