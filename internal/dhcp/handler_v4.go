package dhcp

import (
	"log"
	"net"
	"strings"
	"time"

	"github.com/insomniacslk/dhcp/dhcpv4"
)

// handleV4 is the server4 handler: one DHCPv4 exchange per packet.
func (s *Server) handleV4(conn net.PacketConn, peer net.Addr, m *dhcpv4.DHCPv4) {
	if m == nil {
		return
	}
	switch m.MessageType() {
	case dhcpv4.MessageTypeDiscover:
		s.v4Discover(conn, m)
	case dhcpv4.MessageTypeRequest:
		s.v4Request(conn, m)
	case dhcpv4.MessageTypeRelease:
		s.v4Release(m)
	case dhcpv4.MessageTypeDecline:
		s.v4Decline(m)
	case dhcpv4.MessageTypeInform:
		s.v4Inform(conn, m)
	}
}

// v4OfferFor builds an OFFER or ACK skeleton for the client.
func (s *Server) v4Reply(m *dhcpv4.DHCPv4, msgType dhcpv4.MessageType, yiaddr net.IP) (*dhcpv4.DHCPv4, error) {
	s.mu.RLock()
	cfg := s.cfg
	s.mu.RUnlock()
	mods := []dhcpv4.Modifier{
		dhcpv4.WithMessageType(msgType),
		dhcpv4.WithServerIP(cfg.ServerIPv4),
	}
	if yiaddr != nil {
		mods = append(mods, dhcpv4.WithYourIP(yiaddr))
	}
	if msgType == dhcpv4.MessageTypeOffer || msgType == dhcpv4.MessageTypeAck {
		lt := uint32(s.leaseTime().Seconds())
		mods = append(mods, dhcpv4.WithLeaseTime(lt))
		if cfg.Subnet != nil {
			mods = append(mods, dhcpv4.WithNetmask(cfg.Subnet.Mask))
		}
		if cfg.Gateway != nil {
			mods = append(mods, dhcpv4.WithRouter(cfg.Gateway))
		}
		dns := cfg.DNS
		if len(dns) == 0 && cfg.ServerIPv4 != nil {
			dns = []net.IP{cfg.ServerIPv4}
		}
		if len(dns) > 0 {
			mods = append(mods, dhcpv4.WithDNS(dns...))
		}
		if cfg.Domain != "" {
			mods = append(mods, dhcpv4.WithDomainSearchList(cfg.Domain))
		}
		// RFC 2131 §4.1: set the broadcast bit when the client asked for it
		// (it cannot unicast yet). NewReplyFromRequest copies the request
		// flags, so override only when needed.
		if m.IsBroadcast() {
			mods = append(mods, dhcpv4.WithBroadcast(true))
		}
	}
	return dhcpv4.NewReplyFromRequest(m, mods...)
}

func (s *Server) leaseTime() time.Duration {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.leaseTimeLocked()
}

func (s *Server) v4Discover(conn net.PacketConn, m *dhcpv4.DHCPv4) {
	// A DISCOVER carrying a server identifier belongs to a different
	// server's conversation (SELECTING for another server's offer).
	if sid := m.ServerIdentifier(); sid != nil && !sid.Equal(s.serverIPv4()) {
		return
	}
	hostname := clientHostname4(m)
	ip, _ := s.allocV4(m.ClientHWAddr, m.RequestedIPAddress(), hostname)
	if ip == nil {
		log.Printf("[dhcp] v4 pool exhausted for %s", m.ClientHWAddr)
		return
	}
	reply, err := s.v4Reply(m, dhcpv4.MessageTypeOffer, ip)
	if err != nil {
		log.Printf("[dhcp] v4 offer build: %v", err)
		return
	}
	s.sendV4(conn, m, reply.ToBytes())
}

func (s *Server) v4Request(conn net.PacketConn, m *dhcpv4.DHCPv4) {
	// SELECTING: the request names our server; anything else is not ours.
	if sid := m.ServerIdentifier(); sid != nil && !sid.Equal(s.serverIPv4()) {
		return
	}
	key := v4Key(m.ClientHWAddr)
	requested := m.RequestedIPAddress()
	if requested == nil || requested.Equal(net.IPv4zero) {
		// RENEWING state: the client already has the address in ciaddr.
		if m.ClientIPAddr != nil && !m.ClientIPAddr.Equal(net.IPv4zero) {
			requested = m.ClientIPAddr
		}
	}
	hostname := clientHostname4(m)

	// INIT-REBOOT without a server id: only accept the address when we are
	// the ones who leased it (or it is free in our pool).
	if m.ServerIdentifier() == nil {
		if requested == nil || !s.addrInPool(requested, false) ||
			(s.byIPOf(requested) != "" && s.byIPOf(requested) != string(key)) {
			s.v4Nak(conn, m)
			return
		}
	}

	if requested == nil || !s.addrInPool(requested, false) || s.inUse(requested, key) {
		s.v4Nak(conn, m)
		return
	}

	// Commit the lease for the requested address.
	if st := s.staticFor(m.ClientHWAddr, ""); st != nil && st.IP.To4() != nil && st.IP.Equal(requested) {
		h := st.Hostname
		if h == "" {
			h = hostname
		}
		s.commit(&Lease{Key: string(key), MAC: m.ClientHWAddr.String(), IP: requested.String(), Hostname: h, Static: true})
	} else {
		s.commit(&Lease{Key: string(key), MAC: m.ClientHWAddr.String(), IP: requested.String(), Hostname: hostname})
	}

	reply, err := s.v4Reply(m, dhcpv4.MessageTypeAck, requested)
	if err != nil {
		log.Printf("[dhcp] v4 ack build: %v", err)
		return
	}
	s.sendV4(conn, m, reply.ToBytes())
}

func (s *Server) v4Nak(conn net.PacketConn, m *dhcpv4.DHCPv4) {
	reply, err := dhcpv4.NewReplyFromRequest(m,
		dhcpv4.WithMessageType(dhcpv4.MessageTypeNak),
		dhcpv4.WithServerIP(s.serverIPv4()),
	)
	if err != nil {
		return
	}
	s.sendV4(conn, m, reply.ToBytes())
}

func (s *Server) v4Release(m *dhcpv4.DHCPv4) {
	ip := m.ClientIPAddr
	if ip == nil || ip.Equal(net.IPv4zero) {
		return
	}
	if s.releaseLease(v4Key(m.ClientHWAddr), ip) {
		log.Printf("[dhcp] v4 %s released %s", m.ClientHWAddr, ip)
	}
}

func (s *Server) v4Decline(m *dhcpv4.DHCPv4) {
	ip := m.RequestedIPAddress()
	if ip == nil {
		ip = m.ClientIPAddr
	}
	s.declineLease(ip)
	log.Printf("[dhcp] v4 %s declined %s — withholding the address", m.ClientHWAddr, ip)
}

func (s *Server) v4Inform(conn net.PacketConn, m *dhcpv4.DHCPv4) {
	// The client already has an address; it only wants options.
	reply, err := s.v4Reply(m, dhcpv4.MessageTypeAck, nil)
	if err != nil {
		return
	}
	s.sendV4(conn, m, reply.ToBytes())
}

// sendV4 sends a reply to the right destination: a relay agent (giaddr), a
// client that has an address (ciaddr, RENEWING), or the LAN broadcast.
func (s *Server) sendV4(conn net.PacketConn, m *dhcpv4.DHCPv4, data []byte) {
	var dst net.IP
	var port int
	switch {
	case m.GatewayIPAddr != nil && !m.GatewayIPAddr.Equal(net.IPv4zero):
		dst, port = m.GatewayIPAddr, 67 // relay agent
	case m.ClientIPAddr != nil && !m.ClientIPAddr.Equal(net.IPv4zero):
		dst, port = m.ClientIPAddr, 68 // RENEWING client
	default:
		dst, port = net.IPv4bcast, 68
	}
	if _, err := conn.WriteTo(data, &net.UDPAddr{IP: dst, Port: port}); err != nil {
		log.Printf("[dhcp] v4 reply to %s: %v", dst, err)
	}
}

// serverIPv4 returns the server identifier address used in replies.
func (s *Server) serverIPv4() net.IP {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.cfg.ServerIPv4
}

// clientHostname4 extracts the hostname a v4 client offered, preferring the
// FQDN option (81) over the plain hostname option (12). The FQDN option
// payload is flags(1) + rcode1(1) + rcode2(1) + domain name.
func clientHostname4(m *dhcpv4.DHCPv4) string {
	if m == nil {
		return ""
	}
	if fq := m.Options.Get(dhcpv4.OptionFQDN); len(fq) > 3 {
		if name := parseLabelName(fq[3:]); name != "" {
			return sanitizeHostname(name)
		}
	}
	if hn := m.HostName(); hn != "" {
		return sanitizeHostname(hn)
	}
	return ""
}

// parseLabelName decodes a wire-format DNS name (labels + trailing zero) into
// its dotted form.
func parseLabelName(b []byte) string {
	var parts []string
	for i := 0; i < len(b); {
		l := int(b[i])
		if l == 0 {
			break
		}
		if l > 63 || i+1+l > len(b) {
			return ""
		}
		parts = append(parts, string(b[i+1:i+1+l]))
		i += 1 + l
	}
	return strings.Join(parts, ".")
}

// sanitizeHostname lowercases and trims a client-supplied hostname to a safe
// single-label form (letters/digits/hyphens, max 63 chars). A dotted input
// keeps only its first label, matching how the local resolver names things.
func sanitizeHostname(h string) string {
	h = strings.ToLower(strings.TrimSpace(h))
	if i := strings.IndexByte(h, '.'); i >= 0 {
		h = h[:i]
	}
	var b strings.Builder
	for _, r := range h {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' {
			b.WriteRune(r)
		}
	}
	out := b.String()
	if len(out) > 63 {
		out = out[:63]
	}
	return out
}

// thin wrappers that take the lock for the request path helpers.
func (s *Server) byIPOf(ip net.IP) string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if l := s.byIP[ip.String()]; l != nil {
		return l.Key
	}
	return ""
}

func (s *Server) inUse(ip net.IP, key leaseKey) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.inUseLocked(ip, key)
}

func (s *Server) commit(l *Lease) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.commitLocked(l)
}
