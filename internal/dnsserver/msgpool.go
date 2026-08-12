package dnsserver

import (
	"sync"

	"github.com/miekg/dns"
)

// msgPool recycles *dns.Msg for reply construction whose lifetime is
// provably local to serve(): build, maybe h.record (which only reads
// primitive fields synchronously), h.write (packs and sends synchronously
// in every transport), then return — nothing else ever retains the
// pointer. getMsg/putMsg are only ever used at call sites proven safe by
// that lifetime; each call site in handler.go says so.
//
// Deliberately NOT pooled, on purpose: the fresh-upstream-resolution
// response (resp) and the full-resolution-failure SERVFAIL both get handed
// unmodified into a background goroutine that calls cache.Set/SetNegative,
// and serve() returns without waiting for it — pooling either at the point
// serve() returns would race that goroutine. Messages built by
// internal/filter (BuildBlockResponse, BuildAnswer) are also left alone
// here to keep this pool's ownership rules confined to internal/dnsserver.
var msgPool = sync.Pool{
	New: func() any { return new(dns.Msg) },
}

// getMsg returns a zero-value *dns.Msg, either recycled or freshly
// allocated.
func getMsg() *dns.Msg {
	return msgPool.Get().(*dns.Msg)
}

// putMsg returns m to the pool. Only call this once nothing else can
// possibly still read m — see the safety notes on each call site.
func putMsg(m *dns.Msg) {
	if m == nil {
		return
	}
	*m = dns.Msg{}
	msgPool.Put(m)
}
