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

// packHdrPool recycles the *[]byte slice-header holders that packBufPool
// stores. A sync.Pool can only hold pointers without boxing, but the public
// helpers below traffic in plain []byte: taking &buf of the parameter would
// move a fresh slice header to the heap on every put (one allocation per
// response). Instead putPackBuf borrows a holder from here, and getPackBuf
// hands it back once it has copied the slice out, so steady state allocates
// nothing.
var packHdrPool = sync.Pool{
	New: func() any { return new([]byte) },
}

// getPackBuf returns a []byte at its full capacity, ready to pass to
// dns.Msg.PackBuffer.
func getPackBuf() []byte {
	bp := packBufPool.Get().(*[]byte)
	buf := (*bp)[:cap(*bp)]
	*bp = nil // drop the reference so the idle holder doesn't pin the buffer
	packHdrPool.Put(bp)
	return buf
}

// putPackBuf returns buf to the pool for reuse. Only call this once nothing
// else can still read buf — see the safety notes at each call site.
func putPackBuf(buf []byte) {
	bp := packHdrPool.Get().(*[]byte)
	*bp = buf[:0]
	packBufPool.Put(bp)
}
