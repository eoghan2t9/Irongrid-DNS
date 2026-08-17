package dhcp

import (
	"net"
	"slices"
	"strings"
	"time"
)

// poolOfLocked returns the dynamic pool for a family (nil when not
// configured). Callers hold mu.
func (s *Server) poolOfLocked(v6 bool) (start, end net.IP) {
	if v6 {
		if !s.cfg.IPv6 {
			return nil, nil
		}
		return s.cfg.IPv6Start, s.cfg.IPv6End
	}
	return s.cfg.RangeStart, s.cfg.RangeEnd
}

// addrInPool reports whether ip lies inside the configured dynamic range
// (the network and broadcast addresses of a v4 subnet are excluded). Takes
// the read lock.
func (s *Server) addrInPool(ip net.IP, v6 bool) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.addrInPoolLocked(ip, v6)
}

// addrInPoolLocked is addrInPool without locking (callers hold mu).
func (s *Server) addrInPoolLocked(ip net.IP, v6 bool) bool {
	if ip == nil {
		return false
	}
	start, end := s.poolOfLocked(v6)
	if start == nil || end == nil {
		return false
	}
	if v6 {
		return bytesCompare(ip, start) >= 0 && bytesCompare(ip, end) <= 0
	}
	a := ip.To4()
	if a == nil {
		return false
	}
	netw := s.cfg.Subnet
	if netw == nil || !netw.Contains(a) {
		return false
	}
	// Exclude the network and broadcast addresses.
	netAddr := netw.IP.To4()
	bcast := make(net.IP, 4)
	for i := range netAddr {
		bcast[i] = netAddr[i] | ^netw.Mask[i]
	}
	if a.Equal(netAddr) || a.Equal(bcast) {
		return false
	}
	return bytesCompare(a, start.To4()) >= 0 && bytesCompare(a, end.To4()) <= 0
}

func bytesCompare(a, b net.IP) int {
	ab, bb := a.To16(), b.To16()
	if ab == nil || bb == nil {
		return 0
	}
	for i := range ab {
		if ab[i] < bb[i] {
			return -1
		}
		if ab[i] > bb[i] {
			return 1
		}
	}
	return 0
}

// inUseLocked reports whether ip is currently taken (by a live lease or an
// active reservation held by someone else). An expired dynamic lease no
// longer counts as in use — the address returns to the pool so transient
// clients don't leak addresses until restart. (Expired entries are dropped
// from the table lazily here, and on the next persist cycle.)
func (s *Server) inUseLocked(ip net.IP, key leaseKey) bool {
	ipStr := ip.String()
	if l := s.byIP[ipStr]; l != nil && l.Key != string(key) {
		if l.Static || l.Expires.After(time.Now()) {
			return true
		}
		// Lazy reclamation: the lease is expired, so the address is free.
		delete(s.leases, leaseKey(l.Key))
		delete(s.byIP, ipStr)
		s.rebuildHostsLocked()
		s.markDirtyLocked()
	}
	if r, ok := s.reserved[ipStr]; ok && r.until.After(time.Now()) && r.key != key {
		return true
	}
	return false
}

// staticFor returns the configured reservation for a client (MAC for v4,
// DUID hex for v6), or nil. Takes the read lock.
func (s *Server) staticFor(mac net.HardwareAddr, duidHex string) *StaticLease {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.staticForClientLocked(mac, duidHex)
}

// staticForClientLocked is staticFor without locking (callers hold mu).
func (s *Server) staticForClientLocked(mac net.HardwareAddr, duidHex string) *StaticLease {
	for i := range s.cfg.Static {
		st := &s.cfg.Static[i]
		if mac != nil && st.MAC != "" && strings.EqualFold(st.MAC, mac.String()) {
			return st
		}
		if duidHex != "" && st.DUID != "" && strings.EqualFold(st.DUID, duidHex) {
			return st
		}
	}
	return nil
}

// nextFree4 returns the next available pool address after the cursor,
// wrapping around. nil when the pool is exhausted. Callers hold mu.
func (s *Server) nextFree4(key leaseKey) net.IP {
	start, end := s.poolOfLocked(false)
	if start == nil {
		return nil
	}
	sb, eb := start.To4(), end.To4()
	total := int(eb[3]-sb[3]) + 256*int(eb[2]-sb[2]) + 65536*int(eb[1]-sb[1]) + 16777216*int(eb[0]-sb[0])
	if total < 0 {
		return nil
	}
	for i := 0; i <= total; i++ {
		idx := (int(s.cursor4) + i) % (total + 1)
		cand := poolAt(sb, idx)
		if !s.inUseLocked(cand, key) {
			s.cursor4 = uint32((idx + 1) % (total + 1))
			return cand
		}
	}
	return nil
}

func poolAt(base net.IP, offset int) net.IP {
	b := append(net.IP(nil), base...)
	for i := len(b) - 1; i >= 0 && offset > 0; i-- {
		b[i] += byte(offset & 0xff)
		offset >>= 8
	}
	return b
}

// nextFree6 is the IPv6 analogue of nextFree4. Callers hold mu.
func (s *Server) nextFree6(key leaseKey) net.IP {
	start, end := s.poolOfLocked(true)
	if start == nil {
		return nil
	}
	sb, eb := start.To16(), end.To16()
	cur := append(net.IP(nil), sb...)
	for bytesCompare(cur, eb) <= 0 {
		if !s.inUseLocked(cur, key) {
			return cur
		}
		incr(cur)
	}
	return nil
}

func incr(ip net.IP) {
	for i := range slices.Backward(ip) {
		ip[i]++
		if ip[i] != 0 {
			return
		}
	}
}

// allocV4 reserves an address for a v4 client: its static reservation when
// set, its existing lease, the requested address when free, else the next
// free pool address. A new client gets a short-lived offer reservation
// (committed by the REQUEST); a returning client's lease is refreshed.
func (s *Server) allocV4(mac net.HardwareAddr, requested net.IP, hostname string) (net.IP, bool) {
	if mac == nil {
		return nil, false
	}
	key := v4Key(mac)
	s.mu.Lock()
	defer s.mu.Unlock()

	// 1. Static reservation always wins and never expires.
	if st := s.staticForClientLocked(mac, ""); st != nil && st.IP.To4() != nil {
		ip := st.IP.To4()
		h := st.Hostname
		if h == "" {
			h = hostname
		}
		s.commitLocked(&Lease{Key: string(key), MAC: mac.String(), IP: ip.String(), Hostname: h, Static: true})
		return ip, true
	}
	// 2. Re-offer the client's own address when it has one: its committed
	//    lease, or its still-valid offer reservation (a re-DISCOVER before
	//    the REQUEST must get the same address, not a new one).
	if l := s.leases[key]; l != nil {
		if ip := net.ParseIP(l.IP); ip != nil {
			s.renewLocked(l, hostname)
			return ip, false
		}
	}
	for addr, r := range s.reserved {
		if r.key == key && r.until.After(time.Now()) {
			if ip := net.ParseIP(addr); ip != nil {
				return ip, false
			}
		}
	}
	// 3. Honour the requested address when it is available to this client.
	if requested != nil {
		if ip := requested.To4(); ip != nil && s.addrInPoolLocked(ip, false) && !s.inUseLocked(ip, key) {
			s.reserved[ip.String()] = reservation{key: key, until: time.Now().Add(offeredHold)}
			return ip, false
		}
	}
	// 4. Next free pool address.
	if ip := s.nextFree4(key); ip != nil {
		s.reserved[ip.String()] = reservation{key: key, until: time.Now().Add(offeredHold)}
		return ip, false
	}
	return nil, false
}

// allocV6 is the IPv6 analogue of allocV4.
func (s *Server) allocV6(duidHex, hostname string, requested net.IP) (net.IP, bool) {
	if duidHex == "" {
		return nil, false
	}
	key := v6Key(duidHex)
	s.mu.Lock()
	defer s.mu.Unlock()

	if st := s.staticForClientLocked(nil, duidHex); st != nil && st.IP.To4() == nil {
		ip := st.IP
		h := st.Hostname
		if h == "" {
			h = hostname
		}
		s.commitLocked(&Lease{Key: string(key), DUID: duidHex, IP: ip.String(), Hostname: h, Static: true})
		return ip, true
	}
	if l := s.leases[key]; l != nil {
		if ip := net.ParseIP(l.IP); ip != nil {
			s.renewLocked(l, hostname)
			return ip, false
		}
	}
	if requested != nil && requested.To4() == nil {
		if s.addrInPoolLocked(requested, true) && !s.inUseLocked(requested, key) {
			s.reserved[requested.String()] = reservation{key: key, until: time.Now().Add(offeredHold)}
			return requested, false
		}
	}
	if ip := s.nextFree6(key); ip != nil {
		s.reserved[ip.String()] = reservation{key: key, until: time.Now().Add(offeredHold)}
		return ip, false
	}
	return nil, false
}

// renewLocked refreshes a returning client's existing lease.
func (s *Server) renewLocked(l *Lease, hostname string) {
	if l.Static {
		return
	}
	l.Expires = time.Now().Add(s.leaseTimeLocked())
	if hostname != "" {
		l.Hostname = hostname
	}
	delete(s.reserved, l.IP)
	s.rebuildHostsLocked()
	s.markDirtyLocked()
}

// commitLocked records (or refreshes) a lease and updates the indexes.
func (s *Server) commitLocked(l *Lease) {
	now := time.Now()
	if !l.Static {
		l.Expires = now.Add(s.leaseTimeLocked())
	}
	// Clear any reservation on the address once the lease owns it.
	delete(s.reserved, l.IP)
	old := s.byIP[l.IP]
	if old != nil && old.Key != l.Key {
		delete(s.leases, leaseKey(old.Key))
	}
	s.leases[leaseKey(l.Key)] = l
	s.byIP[l.IP] = l
	s.rebuildHostsLocked()
	s.markDirtyLocked()
}

// releaseLease frees a client's lease for the given address (DHCPRELEASE /
// DHCPv6 RELEASE). Returns false when there is nothing to release.
func (s *Server) releaseLease(key leaseKey, ip net.IP) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	l := s.leases[key]
	if l == nil {
		return false
	}
	if ip != nil && !ip.Equal(net.ParseIP(l.IP)) {
		return false
	}
	delete(s.leases, key)
	delete(s.byIP, l.IP)
	s.rebuildHostsLocked()
	s.markDirtyLocked()
	return true
}

// declineLease withholds an address after a client DECLINE (or DHCPv6
// DECLINE): it is held away from everyone for a while in case the client saw
// a conflict on the LAN.
func (s *Server) declineLease(ip net.IP) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if ip == nil {
		return
	}
	// Drop any lease/offer on the address, then hold it for everyone.
	if l := s.byIP[ip.String()]; l != nil {
		delete(s.leases, leaseKey(l.Key))
		delete(s.byIP, ip.String())
	}
	s.reserved[ip.String()] = reservation{key: "", until: time.Now().Add(declinedHold)}
	s.rebuildHostsLocked()
	s.markDirtyLocked()
}
