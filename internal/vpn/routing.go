package vpn

import (
	"fmt"
	"hash/crc32"
	"net"
	"strconv"
	"strings"
	"time"
)

// nftVPNTable is the single nftables table this package owns exclusively —
// namespaced like internal/firewall's "inet irongrid" so Clear/rebuild only
// ever touches objects this package created.
const nftVPNTable = "inet irongrid_vpn"

// minSetTimeout/maxSetTimeout clamp the TTL used for a dynamically-added nft
// set element: too short and a fast-expiring answer falls out of the set
// before the client's next request for the same IP; too long and a
// re-pointed domain (DNS changed, CDN rotated) keeps routing stale IPs
// through the tunnel long after they stopped resolving there.
const (
	minSetTimeout = 30 * time.Second
	maxSetTimeout = time.Hour
)

// profileNames derives the nftables/ip-rule/ip-route identifiers for a
// profile from a short hash of its ID, so arbitrary user-chosen profile IDs
// always produce valid nft identifiers and a unique routing table + fwmark
// + rule priority (20000 + hash%10000 keeps every value comfortably below
// the kernel's fwmark/table id ranges and ip rule's default priorities).
type profileNames struct {
	iface    string
	setV4    string
	setV6    string
	table    uint32
	mark     uint32
	priority uint32
}

func namesFor(profileID string) profileNames {
	h := crc32.ChecksumIEEE([]byte(profileID))
	id := 20000 + (h % 10000)
	return profileNames{
		iface:    ifaceName(profileID),
		setV4:    fmt.Sprintf("igvpn_%08x_v4", h),
		setV6:    fmt.Sprintf("igvpn_%08x_v6", h),
		table:    id,
		mark:     id,
		priority: id,
	}
}

// profileRouteUp adds the policy-routing rule + default route that sends
// fwmark-tagged traffic out iface via its own routing table. Call after
// wireguardUp has brought the interface up.
func profileRouteUp(r Runner, n profileNames) error {
	tbl := strconv.FormatUint(uint64(n.table), 10)
	mark := strconv.FormatUint(uint64(n.mark), 10)
	prio := strconv.FormatUint(uint64(n.priority), 10)
	if err := r.Run("ip", "rule", "add", "fwmark", mark, "table", tbl, "priority", prio); err != nil {
		return fmt.Errorf("adding policy route rule for %s: %w", n.iface, err)
	}
	if err := r.Run("ip", "route", "add", "default", "dev", n.iface, "table", tbl); err != nil {
		_ = r.Run("ip", "rule", "del", "fwmark", mark, "table", tbl, "priority", prio)
		return fmt.Errorf("adding default route for %s: %w", n.iface, err)
	}
	return nil
}

// profileRouteDown removes what profileRouteUp added (best-effort — errors
// are not fatal during teardown).
func profileRouteDown(r Runner, n profileNames) {
	tbl := strconv.FormatUint(uint64(n.table), 10)
	mark := strconv.FormatUint(uint64(n.mark), 10)
	prio := strconv.FormatUint(uint64(n.priority), 10)
	_ = r.Run("ip", "route", "flush", "table", tbl)
	_ = r.Run("ip", "rule", "del", "fwmark", mark, "table", tbl, "priority", prio)
}

// rebuildMarkingTable regenerates the shared nftables table from scratch:
// one address-family pair of sets and a mark rule per active profile, plus
// one masquerade rule per profile's interface. Called whenever the set of
// active profiles changes (never on the DNS hot path) — deleting and
// recreating the whole table is simpler and safer than diffing individual
// rules, and mirrors internal/firewall's Apply/Clear full-rebuild pattern.
// Existing set elements (the dynamically-added destination IPs) are lost on
// rebuild; they are re-populated as traffic for those domains is resolved
// again, which happens quickly since routed domains are typically queried
// often while their profile is active.
func rebuildMarkingTable(r Runner, profiles []profileNames) error {
	// Best-effort: fine if the table does not exist yet.
	_ = r.Run("nft", "delete", "table", strings.Fields(nftVPNTable)[0], strings.Fields(nftVPNTable)[1])

	var b strings.Builder
	fmt.Fprintf(&b, "add table %s\n", nftVPNTable)
	fmt.Fprintf(&b, "add chain %s mark_output { type filter hook output priority -1 ; }\n", nftVPNTable)
	fmt.Fprintf(&b, "add chain %s mark_prerouting { type filter hook prerouting priority -1 ; }\n", nftVPNTable)
	fmt.Fprintf(&b, "add chain %s postrouting { type nat hook postrouting priority 100 ; }\n", nftVPNTable)
	for _, n := range profiles {
		fmt.Fprintf(&b, "add set %s %s { type ipv4_addr ; flags timeout ; }\n", nftVPNTable, n.setV4)
		fmt.Fprintf(&b, "add set %s %s { type ipv6_addr ; flags timeout ; }\n", nftVPNTable, n.setV6)
		fmt.Fprintf(&b, "add rule %s mark_output ip daddr @%s meta mark set %d\n", nftVPNTable, n.setV4, n.mark)
		fmt.Fprintf(&b, "add rule %s mark_output ip6 daddr @%s meta mark set %d\n", nftVPNTable, n.setV6, n.mark)
		fmt.Fprintf(&b, "add rule %s mark_prerouting ip daddr @%s meta mark set %d\n", nftVPNTable, n.setV4, n.mark)
		fmt.Fprintf(&b, "add rule %s mark_prerouting ip6 daddr @%s meta mark set %d\n", nftVPNTable, n.setV6, n.mark)
		fmt.Fprintf(&b, "add rule %s postrouting oifname %q masquerade\n", nftVPNTable, n.iface)
	}
	if err := r.RunStdin("nft", []string{"-f", "-"}, []byte(b.String())); err != nil {
		return fmt.Errorf("programming nftables marking rules: %w", err)
	}
	return nil
}

// clearMarkingTable removes every object this package created (used on full
// shutdown, e.g. vpn.enabled flips to false).
func clearMarkingTable(r Runner) error {
	fields := strings.Fields(nftVPNTable)
	if err := r.Run("nft", "delete", "table", fields[0], fields[1]); err != nil {
		return fmt.Errorf("clearing nftables VPN table: %w", err)
	}
	return nil
}

// addDestination adds ip to a profile's nft set with a TTL-derived timeout,
// so newly-resolved answers start routing through the tunnel immediately.
// This is the only routing-side call on the hot path's tail (from the
// Manager's background worker, never from Observe itself) — it must stay
// cheap: one process exec, no table rebuild.
func addDestination(r Runner, n profileNames, ip net.IP, ttl time.Duration) error {
	if ttl < minSetTimeout {
		ttl = minSetTimeout
	} else if ttl > maxSetTimeout {
		ttl = maxSetTimeout
	}
	set := n.setV4
	if ip.To4() == nil {
		set = n.setV6
	}
	elem := fmt.Sprintf("add element %s %s { %s timeout %ds }\n", nftVPNTable, set, ip.String(), int(ttl.Seconds()))
	if err := r.RunStdin("nft", []string{"-f", "-"}, []byte(elem)); err != nil {
		return fmt.Errorf("adding %s to %s: %w", ip, set, err)
	}
	return nil
}
