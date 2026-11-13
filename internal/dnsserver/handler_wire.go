package dnsserver

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
	"github.com/eoghan2t9/Irongrid-DNS/internal/cache"
	"github.com/eoghan2t9/Irongrid-DNS/internal/dnsname"
	"github.com/eoghan2t9/Irongrid-DNS/internal/filter"
	"github.com/eoghan2t9/Irongrid-DNS/internal/querylog"
)

// Wire-level helpers: stats writer, query recording, EDNS cookies/EDE/padding and response writing.

// statsResponseWriter records transport write failures in one place. Handler
// call sites deliberately remain free to ignore write errors because a DNS
// response cannot be retried safely after a partial stream write, but the
// failures must still be observable.
type statsResponseWriter struct {
	dns.ResponseWriter
	writeErrors *atomic.Int64
}

// statsWriterPool recycles the per-query statsResponseWriter wrapper: serve()
// used to heap-allocate one for every query. The wrapper is request-scoped
// like the dns.ResponseWriter it wraps, so it is released when serve() returns
// — except on the serve-stale race path, where a background goroutine keeps
// using it (see serve), which simply leaves it to the GC.
var statsWriterPool = sync.Pool{
	New: func() any { return new(statsResponseWriter) },
}

func getStatsWriter(w dns.ResponseWriter, errs *atomic.Int64) *statsResponseWriter {
	sw := statsWriterPool.Get().(*statsResponseWriter)
	sw.ResponseWriter, sw.writeErrors = w, errs
	return sw
}

func putStatsWriter(sw *statsResponseWriter) {
	// Clear the references so an idle pooled wrapper never pins a connection.
	sw.ResponseWriter, sw.writeErrors = nil, nil
	statsWriterPool.Put(sw)
}

func (w *statsResponseWriter) Write(b []byte) (int, error) {
	n, err := w.ResponseWriter.Write(b)
	if err != nil {
		w.writeErrors.Add(1)
	}
	return n, err
}

func (h *Handler) record(client, qname string, q dnsname.Question, action, reason, upstreamName string, start time.Time, m *dns.Msg) {
	rcode, answers := dns.RcodeServerFailure, 0
	if m != nil {
		rcode = int(m.Rcode)
		answers = len(m.Answer)
	}
	h.recordEntry(client, qname, q, action, reason, upstreamName, start, rcode, answers)
}

// recordRaw is record for a cache hit served from packed bytes: the rcode
// and answer count are header fields, read off the wire form without
// decoding the message into a dns.Msg.
func (h *Handler) recordRaw(client, qname string, q dnsname.Question, action, reason, upstreamName string, start time.Time, raw []byte) {
	h.recordEntry(client, qname, q, action, reason, upstreamName, start, packedRcode(raw), packedAnCount(raw))
}

// packedRcode returns the header rcode (lower 4 bits of byte 3) of a packed
// DNS message, or SERVFAIL for a too-short one. All cached negatives are
// NOERROR/NXDOMAIN/SERVFAIL — well under the 16 rcode values the header
// byte can express — so extended-rcode bits never matter here.
func packedRcode(raw []byte) int {
	if len(raw) < 4 {
		return dns.RcodeServerFailure
	}
	return int(raw[3] & 0x0F)
}

// packedAnCount returns the Answer-section record count from a packed DNS
// message's header (bytes 6-7), or 0 for a too-short one.
func packedAnCount(raw []byte) int {
	if len(raw) < 12 {
		return 0
	}
	return int(binary.BigEndian.Uint16(raw[6:8]))
}

func qtypeString(t uint16) string {
	switch t {
	case dns.TypeA:
		return "A"
	case dns.TypeAAAA:
		return "AAAA"
	case dns.TypeHTTPS:
		return "HTTPS"
	case dns.TypePTR:
		return "PTR"
	case dns.TypeTXT:
		return "TXT"
	case dns.TypeMX:
		return "MX"
	case dns.TypeSRV:
		return "SRV"
	case dns.TypeCNAME:
		return "CNAME"
	case dns.TypeNS:
		return "NS"
	case dns.TypeSOA:
		return "SOA"
	case dns.TypeSVCB:
		return "SVCB"
	case dns.TypeDNSKEY:
		return "DNSKEY"
	case dns.TypeDS:
		return "DS"
	default:
		return dnsutil.TypeToString(t)
	}
}

func (h *Handler) recordEntry(client, qname string, q dnsname.Question, action, reason, upstreamName string, start time.Time, rcode, answers int) {
	elapsed := time.Since(start)
	h.latency.record(elapsed)
	if h.Log == nil {
		return
	}
	// The client's ASN, attributed from the same pruned ip2asn tables the
	// X-Irongrid-Client-ASN DoH header uses. 0 when the ISP is in none of
	// the configured lists — the dashboard then falls back to its external
	// RIPEstat lookup. Resolved per logged query; a config without ASN data
	// resolves instantly (nil tables), one with it pays a binary search.
	asn, _ := h.ClientASN(client)
	h.Log.Record(querylog.Entry{
		Time:           start,
		Client:         client,
		Domain:         qname,
		Type:           qtypeString(q.Qtype),
		Action:         action,
		Reason:         reason,
		Upstream:       upstreamName,
		ResponseTimeMS: elapsed.Milliseconds(),
		Rcode:          rcode,
		Answers:        answers,
		ASN:            asn,
	})
}

// clientUDPSize returns the largest UDP payload this client will accept:
// its advertised EDNS0 buffer (RFC 6891), or the 512-byte RFC 1035 limit
// for legacy clients that send no OPT record. A nil request (the FORMERR
// path, where the query was unparseable) is treated as a legacy client.
func clientUDPSize(r *dns.Msg) int {
	if r != nil && int(r.UDPSize) >= dns.MinMsgSize {
		return int(r.UDPSize)
	}
	return dns.MinMsgSize
}

// clientCookieHexLen is the hex length of an RFC 7873 client cookie (8 bytes
// = 16 hex chars). The server cookie is generated at the same length, so a
// full cookie round-trips as 32 hex chars.
const clientCookieHexLen = 16

// requestCookieValue returns the request's COOKIE option value (a hex
// string), or "" when the message carries none — RFC 7873 clients may omit
// the option entirely, and a server must not force cookies on them.
func requestCookieValue(r *dns.Msg) string {
	if r == nil {
		return ""
	}
	for _, rr := range r.Pseudo {
		if c, ok := rr.(*dns.COOKIE); ok {
			return c.Cookie
		}
	}
	return ""
}

// requestClientCookie returns the request's client cookie — the first
// clientCookieHexLen hex chars of its COOKIE option. An option shorter than
// 8 bytes is malformed and ignored (RFC 7873 §5.2.3).
func requestClientCookie(r *dns.Msg) string {
	if c := requestCookieValue(r); len(c) >= clientCookieHexLen {
		return c[:clientCookieHexLen]
	}
	return ""
}

// serverCookie is the RFC 7873 server cookie for a client: the first 8 bytes
// of HMAC-SHA256(secret, clientIP || clientCookie), hex-encoded. It is
// deterministic — the same client IP and client cookie always produce the
// same value, so an echoed cookie validates on every later query — and
// binding it to the client IP means a cookie minted for one client is
// useless from another source, which is exactly what makes an off-path
// attacker's spoofed queries fail the BADCOOKIE check.
func (h *Handler) serverCookie(clientIP, clientCookie string) string {
	mac := hmac.New(sha256.New, h.cookieSecret)
	mac.Write([]byte(clientIP))
	mac.Write([]byte(clientCookie))
	return hex.EncodeToString(mac.Sum(nil))[:clientCookieHexLen]
}

// attachCookie returns a copy of m carrying the given COOKIE option (the
// client cookie echoed with the server cookie appended), replacing any
// existing COOKIE option. It copies so the caller's message — a cache hit,
// or resp about to be handed to the background cache writer — is never
// mutated.
func attachCookie(m *dns.Msg, cookie string) *dns.Msg {
	c := m.Copy()
	if c.UDPSize < dns.MinMsgSize {
		c.UDPSize = udpMaxPacketSize
	}
	keep := c.Pseudo[:0]
	for _, rr := range c.Pseudo {
		if _, ok := rr.(*dns.COOKIE); !ok {
			keep = append(keep, rr)
		}
	}
	c.Pseudo = append(keep, &dns.COOKIE{Cookie: cookie})
	return c
}

// attachEDE returns a copy of m carrying an Extended DNS Error option (RFC
// 8914) with the given info code and human-readable extra text, replacing
// any existing EDE option. Only meaningful for a client that sent its own
// OPT record — callers gate on r.UDPSize > 0 before calling this, the
// same convention attachCookie's caller uses for the COOKIE option.
func attachEDE(m *dns.Msg, code uint16, extra string) *dns.Msg {
	c := m.Copy()
	if c.UDPSize < dns.MinMsgSize {
		c.UDPSize = udpMaxPacketSize
	}
	keep := c.Pseudo[:0]
	for _, rr := range c.Pseudo {
		if _, ok := rr.(*dns.EDE); !ok {
			keep = append(keep, rr)
		}
	}
	c.Pseudo = append(keep, &dns.EDE{InfoCode: code, ExtraText: extra})
	return c
}

// padMessage returns a copy of m padded so its packed length is a multiple
// of block bytes (RFC 7830). Any padding option the message already carries
// (e.g. one forwarded from an upstream) is replaced by a single option that
// lands the total exactly on the boundary. The copy is mandatory: the
// caller's message is often resp about to be cached, and a padded answer
// must not be stored for every other client.
func padMessage(m *dns.Msg, block int) *dns.Msg {
	c := m.Copy()
	if c.UDPSize < dns.MinMsgSize {
		c.UDPSize = udpMaxPacketSize
	}
	keep := c.Pseudo[:0]
	for _, rr := range c.Pseudo {
		if _, ok := rr.(*dns.PADDING); !ok {
			keep = append(keep, rr)
		}
	}
	c.Pseudo = keep
	// Pack once without padding to get the exact wire length (including the
	// OPT pseudo-RR header), then size PADDING (4 bytes of framing + data)
	// so the packed total lands on a multiple of block.
	c.Data = nil
	if err := c.Pack(); err == nil {
		base := len(c.Data) + 4
		if need := block - (base % block); need != block {
			c.Pseudo = append(c.Pseudo, &dns.PADDING{Padding: strings.Repeat("00", need)})
		}
		c.Data = nil
	}
	return c
}

// write packs m for the client and sends it. DNS message compression
// (RFC 1035 §4.1.4) replaces repeated owner names with pointers to earlier
// occurrences in the message, typically cutting the wire form 20-40% — real
// bandwidth savings on the stream transports (TCP/DoT/DoH/DoQ) and smaller
// UDP datagrams that stay comfortably under the fragmentation threshold.
// Every reply path (rewritten, blocked, cached, upstream, error) funnels
// through here so no response goes out uncompressed.
//
// On UDP the response is also sized to the client's advertised buffer
// (clientUDPSize): an oversized datagram is silently dropped or ignored by
// many stacks, so a legacy 512-byte client must receive a truncated answer
// with the TC bit set (RFC 1035 §4.2.1, RFC 6891) to fall back over TCP —
// the previous code sent the full answer regardless of the client's limit,
// surfacing as silent resolution failures for exactly the clients most
// likely to be older devices. Stream transports have no size limit to
// respect. The truncation runs on a copy, never the caller's message: the
// success path hands resp to the background cache writer right after this,
// and a truncated answer must not poison the shared cache for every other
// client (a small-buffer client would otherwise evict everyone's full
// answer).
//
// With RFC 7830 padding enabled, responses on the encrypted transports
// (DoT/DoH/DoH3/DoQ) are padded to a 128-byte block boundary so message
// lengths don't reveal the query; plain UDP/TCP are never padded. With RFC
// 7873 cookies enabled, a request that carried a COOKIE option gets the
// cookie echoed with our server cookie attached. Padding and cookie
// attachment both run on a copy — the caller's message (resp, a cache hit)
// must never be mutated, for the same reason truncation copies: the success
// path caches resp right after the write, and a padded or cookie-laden
// answer must not be stored for every other client.
func (h *Handler) write(w dns.ResponseWriter, m *dns.Msg, r *dns.Msg, proto string) error {
	h.observeVPN(r, m)
	// Fast path: pack the response once and hand the bytes straight to the
	// transport. Only the rare per-client transformations below (an oversized
	// datagram for a small-buffer client, RFC 7830 padding, RFC 7873 cookie
	// attachment) fall back to the copy path, so the caller's message (resp
	// about to be handed to the background cache writer) is never mutated.
	pad := h.Padding.Load() && (proto == "dot" || proto == "doh" || proto == "doh3" || proto == "doq")
	cookie := h.Cookies.Load() && requestClientCookie(r) != ""
	if !pad && !cookie {
		m.Data = nil
		if err := m.Pack(); err != nil {
			return err
		}
		if proto != "udp" || len(m.Data) <= clientUDPSize(r) {
			if w.Conn() != nil {
				_, werr := m.WriteTo(w)
				return werr
			}
			_, werr := w.Write(m.Data)
			return werr
		}
	}
	// Slow path: a per-client transformation is needed. Padding only helps
	// where the stream is encrypted anyway — on plain UDP the padded
	// datagram length leaks just as much as the unpadded one, and padding
	// must not inflate a datagram toward the client's buffer limit.
	out := m
	if proto == "udp" {
		if limit := clientUDPSize(r); m.Len() > limit {
			c := m.Copy()
			dnsutil.Truncate(c)
			out = c
		}
	}
	if pad {
		out = padMessage(out, 128)
	}
	if cookie {
		cc := requestClientCookie(r)
		out = attachCookie(out, cc+h.serverCookie(clientIPOf(w.RemoteAddr()), cc))
	}
	out.Data = nil
	if w.Conn() != nil {
		_, err := out.WriteTo(w)
		return err
	}
	if err := out.Pack(); err != nil {
		return err
	}
	_, err := w.Write(out.Data)
	return err
}

func (h *Handler) writeRaw(w dns.ResponseWriter, res cache.LookupResult, r *dns.Msg, proto string, nowUnix int64) error {
	raw := res.Raw
	pad := h.Padding.Load() && (proto == "dot" || proto == "doh" || proto == "doh3" || proto == "doq")
	cookie := h.Cookies.Load() && requestClientCookie(r) != ""
	rebaseOK := res.Negative || len(res.TTLOffsets) > 0
	if !rebaseOK || pad || cookie || (proto == "udp" && len(raw) > clientUDPSize(r)) {
		m := res.Msg()
		if m == nil {
			return nil // corrupt entry: answer nothing rather than garbage
		}
		m.ID = r.ID
		return h.write(w, m, r, proto)
	}
	return h.writeRawPacked(w, res, r.ID, nowUnix)
}

// writeRawPacked patches the query ID and rebases positive-entry answer TTLs
// in a private pooled copy of res.Raw, then writes it out and recycles the
// buffer. Shared by writeRaw and ServeUDPRaw.
func (h *Handler) writeRawPacked(w dns.ResponseWriter, res cache.LookupResult, id uint16, nowUnix int64) error {
	raw := res.Raw
	buf := getPackBuf()
	if len(raw) > len(buf) {
		buf = make([]byte, len(raw))
	}
	n := copy(buf, raw)
	// Rebase the query ID to this request's (the stored bytes carry the
	// original query's ID).
	buf[0], buf[1] = byte(id>>8), byte(id)
	if !res.Negative {
		// Rebase every answer TTL to its remaining lifetime, floor 1 so a
		// client never caches a zero-TTL answer as immortal — the same
		// arithmetic unpackEntry performs on the decoded path.
		elapsed := nowUnix - res.StoredAt
		for _, off := range res.TTLOffsets {
			if int(off)+4 > n {
				break
			}
			ttl := binary.BigEndian.Uint32(buf[off : off+4])
			if elapsed > 0 && ttl > uint32(elapsed) {
				ttl -= uint32(elapsed)
			} else {
				ttl = 1
			}
			binary.BigEndian.PutUint32(buf[off:off+4], ttl)
		}
	}
	if w.Conn() != nil {
		_, err := (&dns.Msg{Data: buf[:n]}).WriteTo(w)
		putPackBuf(buf)
		return err
	}
	_, err := w.Write(buf[:n])
	putPackBuf(buf)
	return err
}

// parseUDPFastQuery extracts the query ID, single Question, and advertised
// EDNS0 UDP buffer size straight from a raw DNS query datagram without
// allocating a *dns.Msg. Returns ok=false for anything non-standard (multiple
// questions, non-zero answer/authority, >1 additional RR, compression pointers,
// non-zero EDNS version, or an RFC 7873 cookie when cookies are enabled) so
// the caller falls back to full dns.Msg.Unpack.
func parseUDPFastQuery(pkt []byte, checkCookie bool) (id uint16, q dnsname.Question, udpSize int, ok bool) {
	if len(pkt) < 17 {
		return 0, dnsname.Question{}, 0, false
	}
	flags := binary.BigEndian.Uint16(pkt[2:4])
	if (flags & 0xF800) != 0 { // must be QR=0 and Opcode=QUERY(0)
		return 0, dnsname.Question{}, 0, false
	}
	qd := binary.BigEndian.Uint16(pkt[4:6])
	an := binary.BigEndian.Uint16(pkt[6:8])
	ns := binary.BigEndian.Uint16(pkt[8:10])
	ar := binary.BigEndian.Uint16(pkt[10:12])
	if qd != 1 || an != 0 || ns != 0 || ar > 1 {
		return 0, dnsname.Question{}, 0, false
	}

	var nameBuf [256]byte
	off := 12
	n := 0
	for {
		if off >= len(pkt) {
			return 0, dnsname.Question{}, 0, false
		}
		l := int(pkt[off])
		off++
		if l == 0 {
			if n == 0 {
				nameBuf[0] = '.'
				n = 1
			}
			break
		}
		if l >= 64 || off+l > len(pkt) || n+l+1 >= len(nameBuf) {
			return 0, dnsname.Question{}, 0, false
		}
		for i := range l {
			b := pkt[off+i]
			if b >= 'A' && b <= 'Z' {
				b += 'a' - 'A'
			}
			nameBuf[n+i] = b
		}
		n += l
		nameBuf[n] = '.'
		n++
		off += l
	}
	if off+4 > len(pkt) {
		return 0, dnsname.Question{}, 0, false
	}
	q = dnsname.Question{
		Name:   string(nameBuf[:n]),
		Qtype:  binary.BigEndian.Uint16(pkt[off : off+2]),
		Qclass: binary.BigEndian.Uint16(pkt[off+2 : off+4]),
	}
	off += 4

	udpSize = dns.MinMsgSize
	if ar == 0 {
		if off != len(pkt) {
			return 0, dnsname.Question{}, 0, false
		}
		return binary.BigEndian.Uint16(pkt[0:2]), q, udpSize, true
	}

	// Single additional RR: must be root-named OPT (RFC 6891).
	if off+11 > len(pkt) || pkt[off] != 0 || binary.BigEndian.Uint16(pkt[off+1:off+3]) != dns.TypeOPT {
		return 0, dnsname.Question{}, 0, false
	}
	if pkt[off+6] != 0 { // EDNS version != 0 -> BADVERS via full path
		return 0, dnsname.Question{}, 0, false
	}
	rdlen := int(binary.BigEndian.Uint16(pkt[off+9 : off+11]))
	if off+11+rdlen != len(pkt) {
		return 0, dnsname.Question{}, 0, false
	}
	if checkCookie && rdlen > 0 {
		optEnd := off + 11 + rdlen
		for p := off + 11; p < optEnd; {
			if p+4 > optEnd {
				return 0, dnsname.Question{}, 0, false
			}
			code := binary.BigEndian.Uint16(pkt[p : p+2])
			olen := int(binary.BigEndian.Uint16(pkt[p+2 : p+4]))
			if p+4+olen > optEnd {
				return 0, dnsname.Question{}, 0, false
			}
			if code == dns.CodeCOOKIE {
				return 0, dnsname.Question{}, 0, false
			}
			p += 4 + olen
		}
	}
	if sz := int(binary.BigEndian.Uint16(pkt[off+3 : off+5])); sz >= dns.MinMsgSize {
		udpSize = sz
	}
	return binary.BigEndian.Uint16(pkt[0:2]), q, udpSize, true
}

// ServeUDPRaw attempts to answer a UDP datagram directly from the L1/L2 cache
// without unpacking the packet into a *dns.Msg. Returns true if the datagram
// was handled (answered from cache or silently dropped by ACL/rate/flood
// guards); returns false when the caller should fall back to dns.Msg.Unpack
// and ServeDNS.
func (h *Handler) ServeUDPRaw(w dns.ResponseWriter, pkt []byte) bool {
	s := h.settings.Load()
	if s.Cache == nil || s.Geo != nil || s.RepeatGuard != nil || len(s.UpstreamRoutes) > 0 {
		return false
	}
	id, q, udpSize, ok := parseUDPFastQuery(pkt, h.Cookies.Load())
	if !ok || isMetaQuery(q) || q.Qtype == dns.TypeANY {
		return false
	}
	client := clientIPOf(w.RemoteAddr())
	if s.ClientRouter != nil && s.ClientRouter.Resolve(client) != nil {
		return false
	}
	// q.Name is already ASCII-lowercased and trailing-dot-terminated by
	// parseUDPFastQuery, so qname is a zero-alloc slice of q.Name.
	qname := ""
	if len(q.Name) > 1 {
		qname = q.Name[:len(q.Name)-1]
	}
	if qname == "_dns.resolver.arpa" {
		return false
	}
	if s.IPBanner != nil && s.IPBanner.LookupHoneypot(qname) {
		return false
	}
	if s.Rewriter != nil {
		if _, found := s.Rewriter.Lookup(q.Name); found {
			return false
		}
	}
	if h.DHCPHosts != nil {
		if q.Qtype == dns.TypePTR {
			return false
		}
		if _, found := h.DHCPHosts.LookupHost(q.Name); found {
			return false
		}
	}
	if d := h.Engine.DecideCanonical(qname); d.Action != filter.Allow {
		return false
	}

	start := time.Now()
	if (s.ACL != nil && client != "" && !s.ACL.Allowed(client)) ||
		(s.RateLimiter != nil && !s.RateLimiter.AllowAt(client, start)) ||
		(s.NXGuard != nil && !s.NXGuard.AllowAt(clientPrefix(client), start)) {
		h.Stats.Total.Add(1)
		if p, ok := h.Stats.ByProtocol["udp"]; ok {
			p.Add(1)
		}
		h.Stats.Errors.Add(1)
		return true
	}

	hit := s.Cache.LookupAt(q, start)
	if len(hit.Raw) == 0 || hit.Stale {
		return false
	}
	rebaseOK := hit.Negative || len(hit.TTLOffsets) > 0
	if !rebaseOK || len(hit.Raw) > udpSize {
		return false
	}

	sw := getStatsWriter(w, &h.Stats.WriteErrors)
	defer putStatsWriter(sw)

	h.Stats.Total.Add(1)
	if p, ok := h.Stats.ByProtocol["udp"]; ok {
		p.Add(1)
	}
	h.Stats.Cached.Add(1)
	reason := "cache"
	if hit.Negative {
		reason = "cache-negative"
		if s.NXGuard != nil && packedRcode(hit.Raw) == dns.RcodeNameError {
			s.NXGuard.NoteNX(clientPrefix(client))
		}
	}
	h.recordRaw(client, qname, q, "cached", reason, "", start, hit.Raw)
	_ = h.writeRawPacked(sw, hit, id, start.Unix())
	return true
}

// newReply allocates the empty response skeleton used by the error, NODATA
// and DNSSEC-failure paths: the client's ID, RD/CD flags and first question
// copied, Response and RA set. It is allocated lazily — the fast paths (cache
// hit, blocklist, rewrite answer, successful upstream resolution) never pay
// for it, and most queries are served from one of those.
//
// It draws its *dns.Msg from msgPool, which is safe for every caller — Get
// never has a safety concern, only Put does. Whether a given caller may also
// putMsg it back afterward depends on that call site's own lifetime; see the
// safety comment at each one.
func questionOf(rr dns.RR) dnsname.Question {
	h := rr.Header()
	return dnsname.Question{Name: h.Name, Qtype: dns.RRToType(rr), Qclass: h.Class}
}

func newReply(r *dns.Msg) *dns.Msg {
	m := getMsg()
	dnsutil.SetReply(m, r)
	m.RecursionAvailable = true
	return m
}

func answerIPs(m *dns.Msg) []net.IP {
	if m == nil {
		return nil
	}
	var ips []net.IP
	for _, rr := range m.Answer {
		switch v := rr.(type) {
		case *dns.A:
			ips = append(ips, v.A.Addr.AsSlice())
		case *dns.AAAA:
			ips = append(ips, v.AAAA.Addr.AsSlice())
		}
	}
	return ips
}

// cnameCloakCheck evaluates every CNAME hop in an answer against the filter
// engine and returns the first one whose target is blocked (owner name,
// target name, decision). If no hop is blocked, decision.Action is
// filter.Allow.
func cnameCloakCheck(engine *filter.Engine, m *dns.Msg) (owner, target string, decision filter.Decision) {
	if m == nil {
		return "", "", filter.Decision{Action: filter.Allow}
	}
	for _, rr := range m.Answer {
		cname, ok := rr.(*dns.CNAME)
		if !ok {
			continue
		}
		if d := engine.DecideDomain(cname.Target); d.Action == filter.Block {
			return cname.Hdr.Name, cname.Target, d
		}
	}
	return "", "", filter.Decision{Action: filter.Allow}
}
