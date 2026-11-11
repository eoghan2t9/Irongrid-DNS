package main

import (
	"log/slog"
	"net"

	"github.com/eoghan2t9/Irongrid-DNS/internal/config"
	"github.com/eoghan2t9/Irongrid-DNS/internal/dhcp"
)

// DHCP runtime construction helpers.

func buildDHCPRuntime(c config.DHCPConfig) dhcp.Config {
	_, subnet := parseCIDR(c.Subnet)
	_, ipv6net := parseCIDR(c.IPv6Prefix)
	var addrs dhcp.HostAddresses
	addrs.IPv4, addrs.IPv6, addrs.MAC = hostLANAddresses(subnet, ipv6net, c.Interface)
	return dhcp.ConfigFrom(c.Enabled, c.Interface, c.Subnet, c.RangeStart, c.RangeEnd,
		c.Gateway, c.DNS, c.LeaseTime, c.Domain, dhcpStatics(c.StaticLeases),
		c.IPv6, c.IPv6Prefix, c.IPv6RangeStart, c.IPv6RangeEnd, addrs)
}

// dhcpStatics converts the config's static-lease specs into the runtime type.
func dhcpStatics(leases []config.DHCPStaticLease) []dhcp.StaticLease {
	out := make([]dhcp.StaticLease, 0, len(leases))
	for _, sl := range leases {
		st := dhcp.StaticLease{MAC: sl.MAC, DUID: sl.DUID, Hostname: sl.Hostname}
		if ip := net.ParseIP(sl.IP); ip != nil {
			st.IP = ip
		}
		out = append(out, st)
	}
	return out
}

// parseCIDR returns the *net.IPNet for a CIDR string (nil when invalid — the
// config validator has already rejected bad values by the time this runs).
func parseCIDR(s string) (net.IP, *net.IPNet) {
	if s == "" {
		return nil, nil
	}
	ip, n, err := net.ParseCIDR(s)
	if err != nil {
		return nil, nil
	}
	return ip, n
}

// dhcpSummary renders a one-line description of the DHCP config for the boot
// log (only called when the server is enabled).
func dhcpSummary(c config.DHCPConfig) string {
	s := "DHCPv4 " + c.Subnet
	if c.RangeStart != "" {
		s += " (pool " + c.RangeStart + "-" + c.RangeEnd + ")"
	}
	if c.IPv6 {
		s += " + DHCPv6 " + c.IPv6Prefix
	}
	return s
}

// hostLANAddresses finds this host's own IPs (IPv4 and IPv6) inside the
// served networks and its hardware MAC, so the DHCP options can point at this
// box by default. Interface, when non-empty, restricts the search to that
// NIC. Any part can be nil — the DHCP handlers then fall back to the
// configured gateway/DNS values.
func hostLANAddresses(subnet, ipv6net *net.IPNet, iface string) (v4, v6 net.IP, mac net.HardwareAddr) {
	ifaces := []net.Interface{}
	if iface != "" {
		i, err := net.InterfaceByName(iface)
		if err != nil {
			slog.Error("dhcp interface not found", "interface", iface, "error", err)
			return nil, nil, nil
		}
		ifaces = append(ifaces, *i)
	} else {
		all, err := net.Interfaces()
		if err != nil {
			return nil, nil, nil
		}
		for _, i := range all {
			if i.Flags&net.FlagUp != 0 && i.Flags&net.FlagLoopback == 0 {
				ifaces = append(ifaces, i)
			}
		}
	}
	for _, i := range ifaces {
		if mac == nil && len(i.HardwareAddr) == 6 {
			mac = i.HardwareAddr
		}
		addrs, err := i.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ipnet, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			ip := ipnet.IP
			if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
				continue
			}
			if ip.To4() != nil && v4 == nil && subnet != nil && subnet.Contains(ip) {
				v4 = ip.To4()
			}
			if ip.To4() == nil && v6 == nil && ipv6net != nil && ipv6net.Contains(ip) {
				v6 = ip
			}
		}
	}
	return v4, v6, mac
}
