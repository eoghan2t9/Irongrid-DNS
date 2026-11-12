// Package dnsplan works out which public DNS records a server needs so that
// clients can reach and discover its encrypted DNS protocols (DoH, DoT, DoQ),
// and compares them with the records that already exist.
//
// It is pure: it builds the wanted records from a description of the
// listeners, parses and compares records in Cloudflare's presentation format,
// and produces a list of create / update / delete actions. Talking to a DNS
// provider is somebody else's job.
//
// The SVCB discovery records deliberately mirror what the server itself
// answers for Discovery of Designated Resolvers (RFC 9462), so the records
// published in DNS and the live answers never disagree.
package dnsplan

import (
	"net"
	"slices"
	"strconv"
	"strings"
)

// Endpoint describes the encrypted listeners to publish. A zero port means the
// transport is off.
type Endpoint struct {
	Host                string // hostname clients use, e.g. dns.example.com
	DoT, DoQ, DoH, DoH3 int
	DoHPath             string // "" means /dns-query
}

// Want is one record the server should have.
type Want struct {
	Type    string // A | AAAA | SVCB | HTTPS
	Name    string // fully qualified, lower-case, no trailing dot
	Content string // A / AAAA: the address
	// Priority, Target and Params describe SVCB / HTTPS records. A Target of
	// "." means "the owner name itself".
	Priority int
	Target   string
	Params   map[string]string
	Purpose  string
}

// paramOrder is the wire order of SvcParamKeys, which presentation format
// follows too.
var paramOrder = []string{"alpn", "no-default-alpn", "port", "ipv4hint", "ech", "ipv6hint", "dohpath"}

// Value is the SvcParams in presentation format: key="value" pairs in key
// order, e.g. alpn="h2" port="8443" ipv4hint="192.0.2.1".
func (w Want) Value() string {
	var parts []string
	for _, k := range paramOrder {
		if v, ok := w.Params[k]; ok {
			parts = append(parts, k+`="`+v+`"`)
		}
	}
	return strings.Join(parts, " ")
}

// Display is the record's value as it should be shown to a person.
func (w Want) Display() string {
	if w.Type == "A" || w.Type == "AAAA" {
		return w.Content
	}
	s := strconv.Itoa(w.Priority) + " " + w.Target
	if v := w.Value(); v != "" {
		s += " " + v
	}
	return s
}

// Normalize lower-cases a hostname and drops whitespace and a trailing dot.
func Normalize(host string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
}

const defaultDoHPath = "/dns-query"

// Build returns the records a server with these listeners should publish: the
// address records for the hostname, the SVCB discovery records under
// _dns.<host> (one per transport, in the same priority order the server uses
// for DDR) and, when asked and meaningful, an HTTPS record for the hostname.
// v4 and v6 are the server's public addresses; either may be empty.
func Build(ep Endpoint, v4, v6 []string, https bool) []Want {
	host := Normalize(ep.Host)
	if host == "" {
		return nil
	}
	v4, v6 = sorted(v4), sorted(v6)

	var out []Want
	for _, ip := range v4 {
		out = append(out, Want{Type: "A", Name: host, Content: ip,
			Purpose: "Server address for DoH, DoT and DoQ (DNS-only: Cloudflare's proxy does not carry port 853)"})
	}
	for _, ip := range v6 {
		out = append(out, Want{Type: "AAAA", Name: host, Content: ip,
			Purpose: "Server address for DoH, DoT and DoQ over IPv6 (DNS-only)"})
	}

	hints := func(p map[string]string) {
		if len(v4) > 0 {
			p["ipv4hint"] = strings.Join(v4, ",")
		}
		if len(v6) > 0 {
			p["ipv6hint"] = strings.Join(v6, ",")
		}
	}

	path := ep.DoHPath
	if path == "" {
		path = defaultDoHPath
	}
	name := "_dns." + host
	prio := 0
	add := func(alpn string, port, def int, dohPath, purpose string) {
		prio++
		p := map[string]string{"alpn": alpn}
		if port != def {
			p["port"] = strconv.Itoa(port)
		}
		hints(p)
		if dohPath != "" {
			p["dohpath"] = dohPath + "{?dns}"
		}
		out = append(out, Want{Type: "SVCB", Name: name, Priority: prio, Target: host, Params: p, Purpose: purpose})
	}
	if ep.DoH != 0 {
		alpn := "h2"
		if ep.DoH3 == ep.DoH { // HTTP/3 shares the port number (UDP vs TCP)
			alpn = "h2,h3"
		}
		add(alpn, ep.DoH, 443, path, "Discovery of the DNS-over-HTTPS endpoint")
	}
	if ep.DoH3 != 0 && ep.DoH3 != ep.DoH {
		add("h3", ep.DoH3, 443, path, "Discovery of the DNS-over-HTTP/3 endpoint")
	}
	if ep.DoT != 0 {
		add("dot", ep.DoT, 853, "", "Discovery of the DNS-over-TLS endpoint")
	}
	if ep.DoQ != 0 {
		add("doq", ep.DoQ, 853, "", "Discovery of the DNS-over-QUIC endpoint")
	}

	// An HTTPS record describes https://<host>/ on port 443, so it only means
	// something when the HTTPS service is there.
	if https {
		var alpn []string
		if ep.DoH == 443 {
			alpn = append(alpn, "h2")
		}
		if ep.DoH3 == 443 {
			alpn = append(alpn, "h3")
		}
		if len(alpn) > 0 {
			p := map[string]string{"alpn": strings.Join(alpn, ",")}
			hints(p)
			out = append(out, Want{Type: "HTTPS", Name: host, Priority: 1, Target: ".", Params: p,
				Purpose: "Tells browsers and DoH clients which HTTP versions this hostname speaks"})
		}
	}
	return out
}

func sorted(in []string) []string {
	out := slices.Clone(in)
	slices.Sort(out)
	return out
}

// Have is an existing record, as read from the DNS provider.
type Have struct {
	ID      string
	Type    string
	Name    string
	Content string
	Proxied bool
}

// State says how a wanted record compares with what exists.
type State string

// The possible States.
const (
	StateOK       State = "ok"       // present and correct
	StateMissing  State = "missing"  // not there at all
	StateDiffers  State = "differs"  // there, but with another value
	StateConflict State = "conflict" // blocked by a record that cannot coexist
	StateExtra    State = "extra"    // exists but this server no longer needs it
)

// Action is what applying the plan does for an Item.
type Action string

// The possible Actions.
const (
	ActionNone   Action = "none"
	ActionCreate Action = "create"
	ActionUpdate Action = "update"
	ActionDelete Action = "delete"
)

// Item is one line of the plan.
type Item struct {
	Want   *Want // nil for an extra record
	Have   *Have // nil when nothing exists yet
	State  State
	Action Action
	Detail string
}

// Diff compares what the server wants with what exists. It never plans to
// delete anything except records of a type it manages at a name it manages
// that are no longer wanted (State extra), and a CNAME at a managed name is
// reported as a conflict and left alone, because a CNAME cannot coexist with
// the records we need and may be serving something else.
func Diff(wants []Want, haves []Have) []Item {
	type key struct{ typ, name string }
	var order []key
	wg := map[key][]Want{}
	for _, w := range wants {
		k := key{w.Type, w.Name}
		if _, ok := wg[k]; !ok {
			order = append(order, k)
		}
		wg[k] = append(wg[k], w)
	}
	hg := map[key][]Have{}
	cname := map[string]*Have{}
	for i := range haves {
		h := haves[i]
		h.Name = Normalize(h.Name)
		hg[key{h.Type, h.Name}] = append(hg[key{h.Type, h.Name}], h)
		if h.Type == "CNAME" {
			c := h
			cname[h.Name] = &c
		}
	}

	var items []Item
	for _, k := range order {
		ws, hs := wg[k], hg[k]
		if c, ok := cname[k.name]; ok {
			for i := range ws {
				items = append(items, Item{Want: &ws[i], Have: c, State: StateConflict, Action: ActionNone,
					Detail: "a CNAME record already exists for " + k.name + " and cannot share the name with " + k.typ + " records"})
			}
			continue
		}
		if k.typ == "A" || k.typ == "AAAA" {
			items = append(items, diffAddresses(ws, hs)...)
		} else {
			items = append(items, diffByPriority(ws, hs)...)
		}
	}
	return items
}

func sameIP(a, b string) bool {
	x, y := net.ParseIP(strings.TrimSpace(a)), net.ParseIP(strings.TrimSpace(b))
	if x == nil || y == nil {
		return a == b
	}
	return x.Equal(y)
}

func diffAddresses(ws []Want, hs []Have) []Item {
	var items []Item
	used := make([]bool, len(hs))
	matched := make([]bool, len(ws))
	for i := range ws {
		for j := range hs {
			if !used[j] && !hs[j].Proxied && sameIP(hs[j].Content, ws[i].Content) {
				used[j], matched[i] = true, true
				items = append(items, Item{Want: &ws[i], Have: &hs[j], State: StateOK, Action: ActionNone})
				break
			}
		}
	}
	var free []int
	for j := range hs {
		if !used[j] {
			free = append(free, j)
		}
	}
	for i := range ws {
		if matched[i] {
			continue
		}
		if len(free) == 0 {
			items = append(items, Item{Want: &ws[i], State: StateMissing, Action: ActionCreate})
			continue
		}
		// An unmatched existing record is most likely this record with an old
		// address (the server's IP changed), so it is updated in place.
		j := free[0]
		free = free[1:]
		detail := "currently " + hs[j].Content
		if sameIP(hs[j].Content, ws[i].Content) {
			detail = "currently proxied; it must be DNS-only"
		}
		items = append(items, Item{Want: &ws[i], Have: &hs[j], State: StateDiffers, Action: ActionUpdate, Detail: detail})
	}
	for _, j := range free {
		items = append(items, Item{Have: &hs[j], State: StateExtra, Action: ActionDelete, Detail: "this server does not use this address"})
	}
	return items
}

func diffByPriority(ws []Want, hs []Have) []Item {
	type parsed struct {
		prio   int
		target string
		params map[string]string
		ok     bool
	}
	ps := make([]parsed, len(hs))
	for j := range hs {
		p, t, kv, ok := ParseSVCB(hs[j].Content)
		ps[j] = parsed{p, t, kv, ok}
	}
	var items []Item
	used := make([]bool, len(hs))
	for i := range ws {
		found := -1
		for j := range hs {
			if !used[j] && ps[j].ok && ps[j].prio == ws[i].Priority {
				found = j
				break
			}
		}
		if found < 0 {
			items = append(items, Item{Want: &ws[i], State: StateMissing, Action: ActionCreate})
			continue
		}
		used[found] = true
		wantTarget := ws[i].Target
		if wantTarget != "." {
			wantTarget = Normalize(wantTarget)
		}
		haveTarget := ps[found].target
		if haveTarget != "." {
			haveTarget = Normalize(haveTarget)
		}
		if haveTarget == wantTarget && sameParams(ws[i].Params, ps[found].params) {
			items = append(items, Item{Want: &ws[i], Have: &hs[found], State: StateOK, Action: ActionNone})
			continue
		}
		items = append(items, Item{Want: &ws[i], Have: &hs[found], State: StateDiffers, Action: ActionUpdate,
			Detail: "currently " + strings.TrimSpace(hs[found].Content)})
	}
	for j := range hs {
		if !used[j] {
			items = append(items, Item{Have: &hs[j], State: StateExtra, Action: ActionDelete,
				Detail: "no longer advertised by this server"})
		}
	}
	return items
}

// ParseSVCB parses a SVCB / HTTPS record in presentation format,
// "<priority> <target> key=value ...", tolerating quoting and any key order.
// Values are normalised so records can be compared: address hints are sorted
// and canonicalised.
func ParseSVCB(content string) (priority int, target string, params map[string]string, ok bool) {
	toks := tokenize(content)
	if len(toks) < 2 {
		return 0, "", nil, false
	}
	n, err := strconv.Atoi(toks[0])
	if err != nil || n < 0 {
		return 0, "", nil, false
	}
	params = map[string]string{}
	for _, t := range toks[2:] {
		k, v, _ := strings.Cut(t, "=")
		params[strings.ToLower(k)] = normaliseParam(strings.ToLower(k), strings.Trim(v, `"`))
	}
	return n, toks[1], params, true
}

// tokenize splits on whitespace but keeps quoted values together.
func tokenize(s string) []string {
	var toks []string
	var cur strings.Builder
	inQuote := false
	flush := func() {
		if cur.Len() > 0 {
			toks = append(toks, cur.String())
			cur.Reset()
		}
	}
	for _, r := range s {
		switch {
		case r == '"':
			inQuote = !inQuote
			cur.WriteRune(r)
		case (r == ' ' || r == '\t') && !inQuote:
			flush()
		default:
			cur.WriteRune(r)
		}
	}
	flush()
	return toks
}

func normaliseParam(key, v string) string {
	if key != "ipv4hint" && key != "ipv6hint" {
		return v
	}
	var ips []string
	for s := range strings.SplitSeq(v, ",") {
		if ip := net.ParseIP(strings.TrimSpace(s)); ip != nil {
			ips = append(ips, ip.String())
		}
	}
	slices.Sort(ips)
	return strings.Join(ips, ",")
}

func sameParams(want, have map[string]string) bool {
	norm := func(m map[string]string) map[string]string {
		out := make(map[string]string, len(m))
		for k, v := range m {
			out[k] = normaliseParam(k, v)
		}
		return out
	}
	w, h := norm(want), norm(have)
	if len(w) != len(h) {
		return false
	}
	for k, v := range w {
		if hv, ok := h[k]; !ok || hv != v {
			return false
		}
	}
	return true
}

// Public4 reports whether ip is an IPv4 address that can be reached from the
// internet: not private, loopback, link-local or carrier-grade NAT.
func Public4(ip net.IP) bool {
	v4 := ip.To4()
	if v4 == nil || !v4.IsGlobalUnicast() || v4.IsPrivate() {
		return false
	}
	return !(v4[0] == 100 && v4[1]&0xc0 == 64) // 100.64.0.0/10
}

// Public6 reports whether ip is a globally routable IPv6 address.
func Public6(ip net.IP) bool {
	return ip.To4() == nil && ip.To16() != nil && ip.IsGlobalUnicast() && !ip.IsPrivate()
}

// dial is replaced in tests.
var dial = net.Dial

// DetectPublic finds the server's public addresses without sending anything:
// it asks the operating system which local address it would use to reach the
// internet (connecting a UDP socket transmits no packets). The answer is only
// a public address when the server is directly attached; behind NAT the
// address is private and is reported as absent, so the caller can ask for it.
func DetectPublic() (v4, v6 string) {
	if c, err := dial("udp4", "1.1.1.1:53"); err == nil {
		if a, ok := c.LocalAddr().(*net.UDPAddr); ok && Public4(a.IP) {
			v4 = a.IP.String()
		}
		_ = c.Close()
	}
	if c, err := dial("udp6", "[2606:4700:4700::1111]:53"); err == nil {
		if a, ok := c.LocalAddr().(*net.UDPAddr); ok && Public6(a.IP) {
			v6 = a.IP.String()
		}
		_ = c.Close()
	}
	return v4, v6
}
