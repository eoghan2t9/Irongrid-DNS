// ASN-based client rules (allow/block an ISP by its ASN number). Client IPs
// are mapped to their owning ASN through the free ip2asn dataset
// (iptoasn.com — same no-key, download-and-cache model as the country
// lists), pruned at load time to exactly the configured ASNs so memory and
// lookups stay tiny. Lookups are served from the same sorted-range layout
// as the country Table.
package geoip

import (
	"bytes"
	"cmp"
	"math/big"
	"math/bits"
	"net"
	"net/netip"
	"slices"
	"sort"
	"strconv"
	"strings"
)

// DefaultASNBaseURL is where the ip2asn dataset comes from. iptoasn.com
// publishes the RIR/BGP prefix-to-ASN mappings as two gzipped TSVs,
// refreshed daily, free to use with attribution.
const DefaultASNBaseURL = "https://iptoasn.com/data"

// Dataset filenames, appended to the ASN base URL.
const (
	asnV4File = "ip2asn-v4.tsv.gz"
	asnV6File = "ip2asn-v6.tsv.gz"
)

// ASNTable is the pruned IP→ASN map for one side of the ASN rules (the
// allow-listed ASNs, the block-listed ASNs, or a client group's ASN list):
// a sorted, disjoint list of [start,end] ranges, each tagged with the ASN
// that owns it. A range hit means the IP belongs to one of the configured
// ASNs — the tables never store ASNs the operator didn't configure. Unlike
// the country Table, adjacent ranges are never merged: they belong to
// different ASNs and must stay distinct.
type ASNTable struct {
	v4 []asnRange4
	v6 []asnRange6
}

type asnRange4 struct {
	start, end uint32
	asn        uint32
}

type asnRange6 struct {
	start, end [16]byte
	asn        uint32
}

// LoadASNTables parses the ip2asn v4 and v6 datasets (TSV:
// "<start>\t<end>\t<asn>\t<cc>\t<description>", one range per line) and
// returns two tables: the ranges owned by an ASN in allow, and those owned
// by an ASN in block. Ranges of any other ASN are dropped. Either dataset
// may be empty (family not downloaded). A malformed or blank line is
// skipped; ASN 0 ("not routed"/unassigned space) is never kept.
func LoadASNTables(ipv4, ipv6 []byte, allow, block map[uint32]bool) (allowT, blockT *ASNTable, err error) {
	allowT, blockT = &ASNTable{}, &ASNTable{}
	parse := func(content []byte, is6 bool) {
		for line := range strings.SplitSeq(string(content), "\n") {
			start, end, asn, ok := parseIP2ASNLine(line)
			if !ok {
				continue
			}
			var t *ASNTable
			switch {
			case allow[asn]:
				t = allowT
			case block[asn]:
				t = blockT
			default:
				continue
			}
			if is6 {
				// The v6 file can carry 4-in-6 ranges (::ffff:a.b.c.d);
				// those are already covered by the v4 dataset, so keeping
				// them would double-store and skew the family split. Plain
				// v4 addresses don't belong in the v6 table either.
				if start.Is4() || start.Is4In6() {
					continue
				}
				t.v6 = append(t.v6, asnRange6{start: start.As16(), end: end.As16(), asn: asn})
			} else {
				if !start.Is4() {
					continue
				}
				t.v4 = append(t.v4, asnRange4{start: addr4(start), end: addr4(end), asn: asn})
			}
		}
	}
	parse(ipv4, false)
	parse(ipv6, true)
	allowT.sort()
	blockT.sort()
	return allowT, blockT, nil
}

// parseIP2ASNLine parses one ip2asn dataset line into its start/end
// addresses and ASN. ok=false skips the line: blank, fewer than three
// fields, unparseable, mixed families, or ASN 0.
func parseIP2ASNLine(line string) (start, end netip.Addr, asn uint32, ok bool) {
	f := strings.Fields(line)
	if len(f) < 3 {
		return
	}
	s, err1 := netip.ParseAddr(f[0])
	e, err2 := netip.ParseAddr(f[1])
	if err1 != nil || err2 != nil || s.Is4() != e.Is4() {
		return
	}
	n, err := strconv.ParseUint(f[2], 10, 32)
	if err != nil || n == 0 { // ASN 0 = not routed / unknown space
		return
	}
	return s, e, uint32(n), true
}

func addr4(a netip.Addr) uint32 {
	b := a.As4()
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}

// sort orders each family by start address (the dataset is already sorted,
// but a custom file:// dataset may not be — lookups binary-search, so a
// sorted table is mandatory). Ranges are disjoint by construction, so no
// merge pass is needed.
func (t *ASNTable) sort() {
	slices.SortFunc(t.v4, func(a, b asnRange4) int { return cmp.Compare(a.start, b.start) })
	slices.SortFunc(t.v6, func(a, b asnRange6) int { return bytes.Compare(a.start[:], b.start[:]) })
}

// Contains reports whether ip falls inside any range of the table — i.e.
// whether it belongs to one of the ASNs this table was pruned to.
func (t *ASNTable) Contains(ip net.IP) bool {
	_, ok := t.Lookup(ip)
	return ok
}

// Lookup returns the ASN owning ip and whether the IP falls inside any
// range of the table — the same membership test as Contains, but reporting
// *which* ASN so a caller can match it against its own sets (the client
// router needs the number to pick a group; the blockers only need the
// boolean).
func (t *ASNTable) Lookup(ip net.IP) (asn uint32, ok bool) {
	if v4 := ip.To4(); v4 != nil {
		x := uint32(v4[0])<<24 | uint32(v4[1])<<16 | uint32(v4[2])<<8 | uint32(v4[3])
		i := sort.Search(len(t.v4), func(i int) bool { return t.v4[i].end >= x })
		if i < len(t.v4) && t.v4[i].start <= x {
			return t.v4[i].asn, true
		}
		return 0, false
	}
	var a [16]byte
	copy(a[:], ip.To16())
	i := sort.Search(len(t.v6), func(i int) bool { return bytes.Compare(t.v6[i].end[:], a[:]) >= 0 })
	if i < len(t.v6) && bytes.Compare(t.v6[i].start[:], a[:]) <= 0 {
		return t.v6[i].asn, true
	}
	return 0, false
}

// CIDRs expands every range of the table into CIDR prefixes, for the host
// firewall: block-listed ASNs are dropped like blocked countries, and
// allow-listed ASNs are exempted like the CIDR allowlist. A range that
// isn't a single prefix (BGP announcements are usually aligned, but not
// guaranteed) is split into the minimal set of aligned prefixes covering
// it.
func (t *ASNTable) CIDRs() []string {
	var out []string
	for _, r := range t.v4 {
		out = append(out, cidrs4(r.start, r.end)...)
	}
	for _, r := range t.v6 {
		out = append(out, cidrs6(r.start, r.end)...)
	}
	return out
}

// cidrs4 expands the IPv4 range [start,end] into the minimal set of aligned
// CIDR prefixes covering it. The arithmetic is exact in uint32: the largest
// aligned block at start always satisfies start+size <= 2^32, so the
// intermediate start+size-1 never overflows past the representable space.
func cidrs4(start, end uint32) []string {
	var out []string
	for start <= end {
		size := start & -start // largest power of two aligned to start
		if size == 0 {
			size = 1 << 31 // start == 0: the whole space is aligned
		}
		for start+size-1 > end {
			size >>= 1
		}
		ones := 32 - bits.TrailingZeros32(size)
		b := [4]byte{byte(start >> 24), byte(start >> 16), byte(start >> 8), byte(start)}
		out = append(out, netip.PrefixFrom(netip.AddrFrom4(b), ones).String())
		start += size
	}
	return out
}

// cidrs6 is cidrs4 for IPv6 ranges, with the 128-bit arithmetic done on
// big.Int (the expansion runs at refresh time, not on the DNS hot path, so
// the allocation cost is irrelevant).
func cidrs6(start, end [16]byte) []string {
	s := new(big.Int).SetBytes(start[:])
	e := new(big.Int).SetBytes(end[:])
	one := big.NewInt(1)
	var out []string
	for s.Cmp(e) <= 0 {
		size := new(big.Int).And(new(big.Int).Set(s), new(big.Int).Neg(new(big.Int).Set(s)))
		if size.Sign() == 0 {
			size.Lsh(one, 128) // s == 0: the whole space is aligned
		}
		for top := new(big.Int).Sub(new(big.Int).Add(new(big.Int).Set(s), size), one); top.Cmp(e) > 0; {
			size.Rsh(size, 1)
			top.Sub(new(big.Int).Add(new(big.Int).Set(s), size), one)
		}
		ones := 129 - size.BitLen()
		var b [16]byte
		s.FillBytes(b[:])
		out = append(out, netip.PrefixFrom(netip.AddrFrom16(b), ones).String())
		s.Add(s, size)
	}
	return out
}

// ParseASN parses an ASN config entry ("AS13335" or "13335") into its
// number, rejecting values outside the 32-bit ASN space (1..4294967295).
func ParseASN(s string) (uint32, bool) {
	s = strings.ToUpper(strings.TrimSpace(s))
	s = strings.TrimPrefix(s, "AS")
	n, err := strconv.ParseUint(s, 10, 32)
	if err != nil || n == 0 {
		return 0, false
	}
	return uint32(n), true
}
