package dnsserver

import "sync"

// packBufPool recycles []byte buffers for dns.Msg.PackBuffer on the DoH and
// DoQ response paths. Unlike the UDP/TCP/DoT path (miekg/dns's own
// dns.Server loop), these transports call Pack themselves, so without this
// pool every response would allocate a fresh buffer. Buffers start at
// udpMaxPacketSize and PackBuffer grows past that on its own (allocating a
// bigger buffer) for the rare oversized message — putPackBuf recycles
// whatever buffer was actually used, so the pool self-tunes to the largest
// message seen rather than guessing a fixed cap.
var packBufPool = sync.Pool{
	New: func() any {
		b := make([]byte, udpMaxPacketSize)
		return &b
	},
}

// getPackBuf returns a []byte at its full capacity, ready to pass to
// dns.Msg.PackBuffer.
func getPackBuf() []byte {
	bp := packBufPool.Get().(*[]byte)
	return (*bp)[:cap(*bp)]
}

// putPackBuf returns buf to the pool for reuse. Only call this once nothing
// else can still read buf — see the safety notes at each call site.
func putPackBuf(buf []byte) {
	buf = buf[:0]
	packBufPool.Put(&buf)
}
