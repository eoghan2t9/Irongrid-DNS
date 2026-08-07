package geoip

import (
	"bytes"
	"net"
	"net/netip"
	"sort"
	"strings"
)

// Table is a country's IPv4/IPv6 prefixes stored as sorted, overlap-merged
// [start,end] ranges, giving O(log n) containment checks with a flat memory
// layout — a country with ~100k CIDRs costs a few megabytes, not a trie with
// a node per prefix bit.
type Table struct {
	v4 []range4
	v6 []range6
}

type range4 struct{ start, end uint32 }
type range6 struct{ start, end [16]byte }

// LoadTable parses ipv4 and ipv6 text content (CIDR prefixes, one per line,
// '#' or ';' comments allowed, e.g. the ipverse/rir-ip *agg.txt files) into
// a merged range table. Either argument may be empty.
func LoadTable(ipv4, ipv6 []byte) (*Table, error) {
	t := &Table{}
	for _, line := range strings.Split(string(ipv4), "\n") {
		if p, ok := parsePrefixLine(line); ok && p.Addr().Is4() {
			t.v4 = append(t.v4, v4Range(p))
		}
	}
	for _, line := range strings.Split(string(ipv6), "\n") {
		if p, ok := parsePrefixLine(line); ok && p.Addr().Is6() && !p.Addr().Is4In6() {
			t.v6 = append(t.v6, v6Range(p))
		}
	}
	t.sortMerge()
	return t, nil
}

// parsePrefixLine extracts a netip.Prefix from a CIDR line, ignoring blank
// lines and comments.
func parsePrefixLine(line string) (netip.Prefix, bool) {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
		return netip.Prefix{}, false
	}
	// A trailing '#' comment after the prefix is also tolerated.
	if i := strings.IndexByte(line, '#'); i >= 0 {
		line = strings.TrimSpace(line[:i])
	}
	p, err := netip.ParsePrefix(line)
	if err != nil {
		return netip.Prefix{}, false
	}
	return p.Masked(), true
}

func v4Range(p netip.Prefix) range4 {
	a := p.Addr().As4()
	start := uint32(a[0])<<24 | uint32(a[1])<<16 | uint32(a[2])<<8 | uint32(a[3])
	ones := p.Bits()
	// mask = 0xFFFFFFFF << (32-ones); for /0 the shift count is 32 which Go
	// defines as yielding 0, so end covers the whole space.
	mask := uint32(0xFFFFFFFF) << (32 - ones)
	return range4{start: start & mask, end: start | ^mask}
}

func v6Range(p netip.Prefix) range6 {
	a := p.Addr().As16()
	ones := p.Bits()
	var r range6
	for i := 0; i < 16; i++ {
		rem := ones - i*8
		switch {
		case rem >= 8:
			r.start[i] = a[i]
			r.end[i] = a[i]
		case rem > 0:
			m := byte(0xFF) << (8 - rem)
			r.start[i] = a[i] & m
			r.end[i] = a[i] | ^m
		default:
			r.start[i] = 0
			r.end[i] = 0xFF
		}
	}
	return r
}

// sortMerge sorts each family by start address and merges overlapping or
// adjacent ranges, leaving a canonical disjoint, sorted table.
func (t *Table) sortMerge() {
	sort.Slice(t.v4, func(i, j int) bool { return t.v4[i].start < t.v4[j].start })
	t.v4 = mergeRanges4(t.v4)
	sort.Slice(t.v6, func(i, j int) bool { return bytes.Compare(t.v6[i].start[:], t.v6[j].start[:]) < 0 })
	t.v6 = mergeRanges6(t.v6)
}

func mergeRanges4(in []range4) []range4 {
	out := in[:0]
	for _, r := range in {
		if n := len(out); n > 0 && r.start <= out[n-1].end+1 { // +1 merges adjacent ranges
			if r.end > out[n-1].end {
				out[n-1].end = r.end
			}
			continue
		}
		out = append(out, r)
	}
	return out
}

func mergeRanges6(in []range6) []range6 {
	out := in[:0]
	for _, r := range in {
		if n := len(out); n > 0 {
			prevEnd := addOne128(out[n-1].end)
			if bytes.Compare(r.start[:], prevEnd[:]) <= 0 {
				if bytes.Compare(r.end[:], out[n-1].end[:]) > 0 {
					out[n-1].end = r.end
				}
				continue
			}
		}
		out = append(out, r)
	}
	return out
}

// addOne128 increments a big-endian 16-byte address, used for the adjacent-
// range merge. Wrapping past 0xFFFF... is irrelevant: no start address can be
// below 0, so the comparison then just appends a new range.
func addOne128(a [16]byte) [16]byte {
	for i := 15; i >= 0; i-- {
		a[i]++
		if a[i] != 0 {
			break
		}
	}
	return a
}

// Contains reports whether ip falls inside any range of the table.
func (t *Table) Contains(ip net.IP) bool {
	if v4 := ip.To4(); v4 != nil {
		x := uint32(v4[0])<<24 | uint32(v4[1])<<16 | uint32(v4[2])<<8 | uint32(v4[3])
		i := sort.Search(len(t.v4), func(i int) bool { return t.v4[i].end >= x })
		return i < len(t.v4) && t.v4[i].start <= x
	}
	var a [16]byte
	copy(a[:], ip.To16())
	i := sort.Search(len(t.v6), func(i int) bool { return bytes.Compare(t.v6[i].end[:], a[:]) >= 0 })
	return i < len(t.v6) && bytes.Compare(t.v6[i].start[:], a[:]) <= 0
}
