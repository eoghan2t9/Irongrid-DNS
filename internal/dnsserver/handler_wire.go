package dnsserver

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/eoghan2t9/Irongrid-DNS/internal/cache"
	"github.com/eoghan2t9/Irongrid-DNS/internal/filter"
	"github.com/eoghan2t9/Irongrid-DNS/internal/querylog"
	"github.com/miekg/dns"
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

func (w *statsResponseWriter) WriteMsg(m *dns.Msg) error {
	err := w.ResponseWriter.WriteMsg(m)
	if err != nil {
		w.writeErrors.Add(1)
	}
	return err
}

func (w *statsResponseWriter) Write(b []byte) (int, error) {
	n, err := w.ResponseWriter.Write(b)
	if err != nil {
		w.writeErrors.Add(1)
	}
	return n, err
}

func (h *Handler) record(client, qname string, q dns.Question, action, reason, upstreamName string, start time.Time, m *dns.Msg) {
	rcode, answers := dns.RcodeServerFailure, 0
	if m != nil {
		rcode = m.Rcode
		answers = len(m.Answer)
	}
	h.recordEntry(client, qname, q, action, reason, upstreamName, start, rcode, answers)
}

// recordRaw is record for a cache hit served from packed bytes: the rcode
// and answer count are header fields, read off the wire form without
// decoding the message into a dns.Msg.
func (h *Handler) recordRaw(client, qname string, q dns.Question, action, reason, upstreamName string, start time.Time, raw []byte) {
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

func (h *Handler) recordEntry(client, qname string, q dns.Question, action, reason, upstreamName string, start time.Time, rcode, answers int) {
	h.latency.record(time.Since(start))
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
		Type:           dns.TypeToString[q.Qtype],
		Action:         action,
		Reason:         reason,
		Upstream:       upstreamName,
		ResponseTimeMS: time.Since(start).Milliseconds(),
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
	if r != nil {
		if opt := r.IsEdns0(); opt != nil {
			if s := int(opt.UDPSize()); s >= dns.MinMsgSize {
				return s
			}
		}
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
	opt := r.IsEdns0()
	if opt == nil {
		return ""
	}
	for _, o := range opt.Option {
		if c, ok := o.(*dns.EDNS0_COOKIE); ok {
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
	opt := c.IsEdns0()
	if opt == nil {
		opt = &dns.OPT{Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeOPT}}
		opt.SetUDPSize(udpMaxPacketSize)
		c.Extra = append(c.Extra, opt)
	}
	keep := opt.Option[:0]
	for _, o := range opt.Option {
		if o.Option() != dns.EDNS0COOKIE {
			keep = append(keep, o)
		}
	}
	opt.Option = keep
	opt.Option = append(opt.Option, &dns.EDNS0_COOKIE{Code: dns.EDNS0COOKIE, Cookie: cookie})
	return c
}

// attachEDE returns a copy of m carrying an Extended DNS Error option (RFC
// 8914) with the given info code and human-readable extra text, replacing
// any existing EDE option. Only meaningful for a client that sent its own
// OPT record — callers gate on r.IsEdns0() != nil before calling this, the
// same convention attachCookie's caller uses for the COOKIE option.
func attachEDE(m *dns.Msg, code uint16, extra string) *dns.Msg {
	c := m.Copy()
	opt := c.IsEdns0()
	if opt == nil {
		opt = &dns.OPT{Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeOPT}}
		opt.SetUDPSize(udpMaxPacketSize)
		c.Extra = append(c.Extra, opt)
	}
	keep := opt.Option[:0]
	for _, o := range opt.Option {
		if o.Option() != dns.EDNS0EDE {
			keep = append(keep, o)
		}
	}
	opt.Option = keep
	opt.Option = append(opt.Option, &dns.EDNS0_EDE{InfoCode: code, ExtraText: extra})
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
	c.Compress = true
	opt := c.IsEdns0()
	if opt == nil {
		opt = &dns.OPT{Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeOPT}}
		opt.SetUDPSize(udpMaxPacketSize)
		c.Extra = append(c.Extra, opt)
	}
	keep := opt.Option[:0]
	for _, o := range opt.Option {
		if o.Option() != dns.EDNS0PADDING {
			keep = append(keep, o)
		}
	}
	opt.Option = keep
	// The padding option costs 4 bytes of framing (code + length fields)
	// once added; size its data so the total lands on the boundary.
	base := c.Len() + 4
	if need := block - (base % block); need != block {
		opt.Option = append(opt.Option, &dns.EDNS0_PADDING{Padding: make([]byte, need)})
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
	m.Compress = true
	// Fast path: pack the response once into a pooled buffer and hand the
	// bytes straight to the transport. This is the every-query path — the
	// old code packed once for the m.Len() size check and again inside
	// WriteMsg (and a third time for a UDP truncation). Only the rare
	// per-client transformations below (an oversized datagram for a
	// small-buffer client, RFC 7830 padding, RFC 7873 cookie attachment)
	// fall back to the decoded-message path, which copies the message so
	// the caller's — resp about to be handed to the background cache
	// writer — is never mutated.
	pad := h.Padding.Load() && (proto == "dot" || proto == "doh" || proto == "doh3" || proto == "doq")
	cookie := h.Cookies.Load() && requestClientCookie(r) != ""
	if !pad && !cookie {
		buf := getPackBuf()
		packed, err := m.PackBuffer(buf)
		if err != nil {
			putPackBuf(buf)
			return err
		}
		if proto != "udp" || len(packed) <= clientUDPSize(r) {
			_, werr := w.Write(packed)
			putPackBuf(packed)
			return werr
		}
		putPackBuf(buf)
	}
	// Slow path: a per-client transformation is needed. Padding only helps
	// where the stream is encrypted anyway — on plain UDP the padded
	// datagram length leaks just as much as the unpadded one, and padding
	// must not inflate a datagram toward the client's buffer limit.
	out := m
	if proto == "udp" {
		if limit := clientUDPSize(r); m.Len() > limit {
			c := m.Copy()
			c.Truncate(limit)
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
	return w.WriteMsg(out)
}

// writeRaw serves a cache hit straight from its stored packed bytes,
// skipping the Unpack→re-Pack round trip entirely: the query ID is patched
// (bytes 0-1) and positive-entry answer TTLs are rebased to their remaining
// lifetime at the precomputed byte offsets, all in a private pooled copy
// that is written out and recycled. The stored bytes are never mutated.
//
// The few responses that need a real message fall back to the decoded path
// (write): RFC 7830 padding, RFC 7873 cookie attachment, and a UDP datagram
// that exceeds the client's advertised buffer (truncation needs the RR
// structure). An L2-sourced hit without TTL offsets also decodes — its
// re-warm into L1 records them, so every later hit is raw.
func (h *Handler) writeRaw(w dns.ResponseWriter, res cache.LookupResult, r *dns.Msg, proto string) error {
	raw := res.Raw
	pad := h.Padding.Load() && (proto == "dot" || proto == "doh" || proto == "doh3" || proto == "doq")
	cookie := h.Cookies.Load() && requestClientCookie(r) != ""
	rebaseOK := res.Negative || len(res.TTLOffsets) > 0
	if !rebaseOK || pad || cookie || (proto == "udp" && len(raw) > clientUDPSize(r)) {
		m := res.Msg()
		if m == nil {
			return nil // corrupt entry: answer nothing rather than garbage
		}
		m.Id = r.Id
		return h.write(w, m, r, proto)
	}
	buf := getPackBuf()
	if len(raw) > len(buf) {
		buf = make([]byte, len(raw))
	}
	n := copy(buf, raw)
	// Rebase the query ID to this request's (the stored bytes carry the
	// original query's ID).
	buf[0], buf[1] = byte(r.Id>>8), byte(r.Id)
	if !res.Negative {
		// Rebase every answer TTL to its remaining lifetime, floor 1 so a
		// client never caches a zero-TTL answer as immortal — the same
		// arithmetic unpackEntry performs on the decoded path.
		elapsed := time.Now().Unix() - res.StoredAt
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
	_, err := w.Write(buf[:n])
	putPackBuf(buf)
	return err
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
func newReply(r *dns.Msg) *dns.Msg {
	m := getMsg()
	m.SetReply(r)
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
			ips = append(ips, v.A)
		case *dns.AAAA:
			ips = append(ips, v.AAAA)
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
