package cache

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/miekg/dns"
)

// l1onlyCache builds a Cache with only the in-memory L1 layer (nil Redis
// client), so the fast path is fully exercised offline.
func l1onlyCache(ttl, negTTL time.Duration) *Cache {
	return &Cache{client: nil, l1: newL1(512, 0), prefix: "irongrid:dns:", ttl: ttl, negativeTTL: negTTL}
}

func aQuestion() dns.Question {
	return dns.Question{Name: "example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
}

func aResponse(ip string, ttl uint32) *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion("example.com.", dns.TypeA)
	m.Response = true
	m.Answer = append(m.Answer, &dns.A{
		Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: ttl},
		A:   net.ParseIP(ip),
	})
	return m
}

func emptyResponse() *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion("example.com.", dns.TypeA)
	m.Response = true
	return m
}

func TestL1GetSet(t *testing.T) {
	t.Parallel()
	c := l1onlyCache(time.Hour, time.Minute)
	ctx := t.Context()
	c.Set(ctx, aQuestion(), aResponse("1.2.3.4", 3600), 0)
	got := c.Get(ctx, aQuestion())
	if got == nil {
		t.Fatal("expected an L1 hit")
	}
	if len(got.Answer) != 1 {
		t.Fatalf("answers = %d, want 1", len(got.Answer))
	}
	if a, ok := got.Answer[0].(*dns.A); !ok || !a.A.Equal(net.ParseIP("1.2.3.4")) {
		t.Fatalf("unexpected answer: %v", got.Answer[0])
	}
}

// TestL1TTLRebase verifies answer TTLs are reduced by the elapsed time on
// read (the same rebasing the L2 path applies).
func TestL1TTLRebase(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		c := l1onlyCache(time.Hour, time.Minute)
		ctx := t.Context()
		c.Set(ctx, aQuestion(), aResponse("1.2.3.4", 3600), 0)
		time.Sleep(1 * time.Second)
		got := c.Get(ctx, aQuestion())
		if got == nil {
			t.Fatal("expected a hit")
		}
		a := got.Answer[0].(*dns.A)
		if a.Hdr.Ttl >= 3600 {
			t.Fatalf("TTL %d was not rebased down", a.Hdr.Ttl)
		}
		if a.Hdr.Ttl < 3599 {
			t.Fatalf("TTL %d rebased too far after 1s", a.Hdr.Ttl)
		}
	})
}

// TestL1CapExpiry verifies entries expire at the configured TTL cap, even
// when the underlying record TTL is much larger.
func TestL1CapExpiry(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		c := l1onlyCache(300*time.Millisecond, time.Minute)
		ctx := t.Context()
		c.Set(ctx, aQuestion(), aResponse("1.2.3.4", 3600), 0)
		time.Sleep(400 * time.Millisecond)
		if got := c.Get(ctx, aQuestion()); got != nil {
			t.Fatal("entry should have expired at the TTL cap")
		}
	})
}

func TestL1Negative(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		c := l1onlyCache(time.Hour, 50*time.Millisecond)
		ctx := t.Context()
		c.SetNegative(ctx, aQuestion(), emptyResponse(), 0)
		if got := c.GetNegative(ctx, aQuestion()); got == nil {
			t.Fatal("expected a negative hit")
		}
		time.Sleep(80 * time.Millisecond)
		if got := c.GetNegative(ctx, aQuestion()); got != nil {
			t.Fatal("expired negative entry should miss")
		}
	})
}

func TestL1Flush(t *testing.T) {
	t.Parallel()
	c := l1onlyCache(time.Hour, time.Minute)
	ctx := t.Context()
	c.Set(ctx, aQuestion(), aResponse("1.2.3.4", 3600), 0)
	if _, err := c.FlushAll(ctx); err != nil {
		t.Fatalf("FlushAll: %v", err)
	}
	if got := c.Get(ctx, aQuestion()); got != nil {
		t.Fatal("entry should be gone after FlushAll")
	}
}

// TestL1Counters verifies the dashboard's L1 hit/miss counters: a served
// lookup counts as one hit and a missed lookup as one miss, counted once per
// logical query even though Lookup probes two keys.
func TestL1Counters(t *testing.T) {
	t.Parallel()
	c := l1onlyCache(time.Hour, time.Minute)
	ctx := t.Context()

	// A clean miss counts one miss.
	if res := c.Lookup(aQuestion()); res.Msg() != nil {
		t.Fatal("expected a miss before anything is cached")
	}
	if h, m := c.L1Counters(); h != 0 || m != 1 {
		t.Fatalf("after first miss: hits=%d misses=%d, want 0/1", h, m)
	}

	// A served positive lookup counts one hit (Lookup probes pos+neg keys
	// internally, so it must still count once).
	c.Set(ctx, aQuestion(), aResponse("1.2.3.4", 3600), 0)
	if res := c.Lookup(aQuestion()); res.Msg() == nil || res.Negative || res.Stale {
		t.Fatal("expected a fresh positive L1 hit")
	}
	if h, m := c.L1Counters(); h != 1 || m != 1 {
		t.Fatalf("after hit: hits=%d misses=%d, want 1/1", h, m)
	}

	// Get (positive-only path) on an unknown question counts a miss.
	other := dns.Question{Name: "other.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
	if got := c.Get(ctx, other); got != nil {
		t.Fatal("expected a miss")
	}
	if h, m := c.L1Counters(); h != 1 || m != 2 {
		t.Fatalf("after extra miss: hits=%d misses=%d, want 1/2", h, m)
	}
}

// BenchmarkL1Get measures the hot path: a pure in-memory cache hit with no
// Redis round-trip.
func BenchmarkL1Get(b *testing.B) {
	c := l1onlyCache(time.Hour, time.Minute)
	q := aQuestion()
	c.Set(context.Background(), q, aResponse("1.2.3.4", 3600), 0)
	for b.Loop() {
		c.Get(context.Background(), q)
	}
}

// BenchmarkLookupL1Hit measures the handler's actual cache path (Lookup): a
// pure L1 hit — no key-string building, no context, no Redis. The hit path
// returns the stored packed bytes without decoding them into a dns.Msg, so
// it stays allocation-free (the handler writes those bytes straight out).
func BenchmarkLookupL1Hit(b *testing.B) {
	c := l1onlyCache(time.Hour, time.Minute)
	q := aQuestion()
	c.Set(context.Background(), q, aResponse("1.2.3.4", 3600), 0)
	for b.Loop() {
		c.Lookup(q)
	}
}

func TestLookupL1Positive(t *testing.T) {
	t.Parallel()
	c := l1onlyCache(time.Hour, time.Minute)
	ctx := t.Context()
	c.Set(ctx, aQuestion(), aResponse("1.2.3.4", 3600), 0)
	res := c.Lookup(aQuestion())
	if res.Msg() == nil {
		t.Fatal("expected a hit")
	}
	if res.Negative {
		t.Fatal("expected a positive hit, got negative")
	}
	if res.Stale {
		t.Fatal("expected a fresh hit, got stale")
	}
}

func TestLookupL1Negative(t *testing.T) {
	t.Parallel()
	c := l1onlyCache(time.Hour, time.Minute)
	ctx := t.Context()
	c.SetNegative(ctx, aQuestion(), emptyResponse(), 0)
	res := c.Lookup(aQuestion())
	if res.Msg() == nil {
		t.Fatal("expected a hit")
	}
	if !res.Negative {
		t.Fatal("expected a negative hit")
	}
}

// TestLookupMissWithNilClient verifies Lookup degrades to a clean miss (no
// panic) when neither L1 nor L2 (nil Redis client, as in every test in this
// file) has anything — the path a genuinely new domain takes before ever
// reaching upstream.
func TestLookupMissWithNilClient(t *testing.T) {
	t.Parallel()
	c := l1onlyCache(time.Hour, time.Minute)
	res := c.Lookup(aQuestion())
	if res.Msg() != nil || res.Negative {
		t.Fatalf("expected a clean miss, got msg=%v negative=%v", res.Msg(), res.Negative)
	}
}

// TestLookupStale verifies an entry past its cache TTL but inside the
// serve-stale window is reported with Stale=true (still decodable), and is
// reported as a plain miss once the stale window itself passes.
func TestLookupStale(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		c := l1onlyCache(300*time.Millisecond, time.Minute)
		c.l1.staleTTL = 2 * time.Second
		ctx := t.Context()
		c.Set(ctx, aQuestion(), aResponse("1.2.3.4", 3600), 0)

		time.Sleep(400 * time.Millisecond)
		res := c.Lookup(aQuestion())
		if res.Msg() == nil {
			t.Fatal("expected the stale entry to still be servable")
		}
		if !res.Stale {
			t.Fatal("expected Stale=true inside the serve-stale window")
		}
		if res.Negative {
			t.Fatal("stale entry should still be reported as positive")
		}

		// Once the serve-stale window itself passes the entry is evicted, and
		// the next lookup is a plain miss.
		time.Sleep(2200 * time.Millisecond)
		if res := c.Lookup(aQuestion()); res.Msg() != nil {
			t.Fatal("entry should miss once the serve-stale window passes")
		}
	})
}

// TestFresh verifies the cache warmer's quiet probe: fresh positive and
// negative entries report fresh (L1 hits without touching the hit/miss
// counters), a miss and an expired entry report not-fresh, and the counters
// stay untouched by probes.
func TestFresh(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		c := l1onlyCache(300*time.Millisecond, 50*time.Millisecond)
		ctx := t.Context()

		// Empty cache: not fresh, and the probe must not count as a miss.
		if c.Fresh(aQuestion()) {
			t.Fatal("empty cache reported fresh")
		}
		if h, m := c.L1Counters(); h != 0 || m != 0 {
			t.Fatalf("Fresh probe counted: hits=%d misses=%d, want 0/0", h, m)
		}

		// A positive entry is fresh.
		c.Set(ctx, aQuestion(), aResponse("1.2.3.4", 3600), 0)
		if !c.Fresh(aQuestion()) {
			t.Fatal("fresh positive entry not reported fresh")
		}
		// A negative entry is fresh too.
		c.SetNegative(ctx, aQuestion(), emptyResponse(), 0)
		if !c.Fresh(aQuestion()) {
			t.Fatal("fresh negative entry not reported fresh")
		}
		if h, m := c.L1Counters(); h != 0 || m != 0 {
			t.Fatalf("Fresh probe counted: hits=%d misses=%d, want 0/0", h, m)
		}

		// After expiry the entry is no longer fresh.
		time.Sleep(400 * time.Millisecond)
		if c.Fresh(aQuestion()) {
			t.Fatal("expired entry reported fresh")
		}
	})
}

// TestPrefetchNearExpiry verifies a background refresh is scheduled when a
// positive entry is served close to its cache-lifetime end, and that a fresh
// entry with plenty of life left does not trigger one.
func TestPrefetchNearExpiry(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		c := l1onlyCache(5*time.Second, time.Minute) // lead = 1s
		ctx := t.Context()

		prefetched := make(chan dns.Question, 1)
		c.EnablePrefetch(func(cctx context.Context, q dns.Question) {
			prefetched <- q
		})

		// Fresh entry with ~5s of life left: no prefetch.
		c.Set(ctx, aQuestion(), aResponse("1.2.3.4", 3600), 0)
		if res := c.Lookup(aQuestion()); res.Msg() == nil {
			t.Fatal("expected a hit")
		}
		select {
		case q := <-prefetched:
			t.Fatalf("prefetch fired too early for %s", q.Name)
		default:
		}

		// Wait until the entry is within the 1s prefetch lead, then trigger.
		time.Sleep(4200 * time.Millisecond)
		if res := c.Lookup(aQuestion()); res.Msg() == nil {
			t.Fatal("expected a hit")
		}
		select {
		case q := <-prefetched:
			if q.Name != aQuestion().Name {
				t.Fatalf("prefetched %s, want %s", q.Name, aQuestion().Name)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("expected a prefetch once the entry neared expiry")
		}
	})
}

// TestAutoPerShard verifies the L1 auto-sizing policy: unknown memory uses
// the default, a tiny box hits the floor, a huge one is capped, and sizing
// grows monotonically with the machine in between.
func TestAutoPerShard(t *testing.T) {
	t.Parallel()
	if got := AutoPerShard(0, false); got != l1AutoDefault {
		t.Fatalf("unknown memory: AutoPerShard = %d, want default %d", got, l1AutoDefault)
	}
	if got := AutoPerShard(256<<20, true); got != l1AutoFloor {
		t.Errorf("256 MiB: AutoPerShard = %d, want floor %d", got, l1AutoFloor)
	}
	if got := AutoPerShard(256<<30, true); got != l1AutoCap {
		t.Errorf("256 GiB: AutoPerShard = %d, want cap %d", got, l1AutoCap)
	}
	prev := 0
	for _, gb := range []uint64{1, 2, 4, 8, 16, 32, 64} {
		got := AutoPerShard(gb<<30, true)
		if got < l1AutoFloor || got > l1AutoCap {
			t.Fatalf("%d GiB: AutoPerShard = %d outside [%d, %d]", gb, got, l1AutoFloor, l1AutoCap)
		}
		if got < prev {
			t.Errorf("%d GiB: AutoPerShard = %d shrank from %d", gb, got, prev)
		}
		prev = got
	}
}

// TestL1FIFOEviction verifies a full shard evicts the oldest-inserted entry
// rather than an arbitrary one: three keys hashing to the same shard under a
// per-shard cap of two evict the first-inserted key while the later two stay.
func TestL1FIFOEviction(t *testing.T) {
	t.Parallel()
	c := newL1(2, 0) // cap 2 per shard
	now := time.Now()
	// h=0, h=l1Shards and h=2*l1Shards all mask to shard 0.
	hs := []uint64{0, l1Shards, 2 * l1Shards}
	for i, h := range hs {
		c.set(h, false, []byte{byte(i)}, time.Hour, now, nil)
	}
	if _, _, _, _, ok := c.get(hs[0], false, now); ok {
		t.Fatal("oldest-inserted entry should have been evicted first")
	}
	for _, h := range hs[1:] {
		if _, _, _, _, ok := c.get(h, false, now); !ok {
			t.Fatal("newer entry should still be cached")
		}
	}
}

func nxdomainResponse() *dns.Msg {
	m := emptyResponse()
	m.Rcode = dns.RcodeNameError
	return m
}

func servfailResponse() *dns.Msg {
	m := emptyResponse()
	m.Rcode = dns.RcodeServerFailure
	return m
}

// TestNegativePrefetch verifies negative entries near the end of their
// (short) lifetime schedule a background refresh when the cached answer is a
// stable one — NXDOMAIN or NODATA (NOERROR with no answers, the classic
// stale-AAAA-probe case) — but never when it's SERVFAIL: those are
// failure-cache entries written during an upstream outage, and refreshing
// them would re-probe the failing upstream on every query instead of letting
// the failure cache absorb the retries.
func TestNegativePrefetch(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		negTTL := 2 * time.Second // negPrefetchLead = max(2s/5, 1s) = 1s
		c := l1onlyCache(5*time.Second, negTTL)
		ctx := t.Context()

		prefetched := make(chan dns.Question, 2)
		c.EnablePrefetch(func(cctx context.Context, q dns.Question) {
			prefetched <- q
		})

		// SERVFAIL negative near expiry: must NOT prefetch.
		c.SetNegative(ctx, aQuestion(), servfailResponse(), 0)
		time.Sleep(1200 * time.Millisecond) // remaining ~0.8s < 1s lead
		if res := c.Lookup(aQuestion()); res.Msg() == nil || !res.Negative {
			t.Fatal("expected a negative hit")
		}
		select {
		case q := <-prefetched:
			t.Fatalf("SERVFAIL negative prefetched %s — failure entries must absorb retries", q.Name)
		default:
		}

		// NXDOMAIN negative near expiry: must prefetch.
		c.SetNegative(ctx, aQuestion(), nxdomainResponse(), 0)
		time.Sleep(1200 * time.Millisecond)
		if res := c.Lookup(aQuestion()); res.Msg() == nil || !res.Negative {
			t.Fatal("expected a negative hit")
		}
		select {
		case q := <-prefetched:
			if q.Name != aQuestion().Name {
				t.Fatalf("prefetched %s, want %s", q.Name, aQuestion().Name)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("expected a prefetch for the NXDOMAIN negative")
		}

		// NODATA negative (NOERROR, empty answer — e.g. an AAAA probe for an
		// A-only domain) near expiry: must prefetch too.
		c.SetNegative(ctx, aQuestion(), emptyResponse(), 0)
		time.Sleep(1200 * time.Millisecond)
		if res := c.Lookup(aQuestion()); res.Msg() == nil || !res.Negative {
			t.Fatal("expected a negative hit")
		}
		select {
		case q := <-prefetched:
			if q.Name != aQuestion().Name {
				t.Fatalf("prefetched %s, want %s", q.Name, aQuestion().Name)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("expected a prefetch for the NODATA negative")
		}
	})
}

// TestDecodeMGetResult exercises the MGET response parsing in isolation
// (posKey, negKey order, as Lookup calls MGet) without needing a real Redis
// connection — go-redis returns a present key as a string and a missing key
// as nil in the result slice.
func TestDecodeMGetResult(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		vals    []any
		wantPos []byte
		wantNeg []byte
		wantOK  bool
	}{
		{"both missing", []any{nil, nil}, nil, nil, false},
		{"positive present", []any{"pos-bytes", nil}, []byte("pos-bytes"), nil, true},
		{"negative present", []any{nil, "neg-bytes"}, nil, []byte("neg-bytes"), true},
		{"both present positive wins", []any{"pos-bytes", "neg-bytes"}, []byte("pos-bytes"), nil, true},
		{"wrong length", []any{"only-one"}, nil, nil, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			pos, neg, ok := decodeMGetResult(c.vals)
			if ok != c.wantOK {
				t.Fatalf("ok = %v, want %v", ok, c.wantOK)
			}
			if string(pos) != string(c.wantPos) {
				t.Errorf("posRaw = %q, want %q", pos, c.wantPos)
			}
			if string(neg) != string(c.wantNeg) {
				t.Errorf("negRaw = %q, want %q", neg, c.wantNeg)
			}
		})
	}
}

// TestLookupRawPositive verifies a positive L1 hit is returned as raw packed
// bytes with the recorded TTL offsets and store timestamp — the data the
// handler's raw serve path needs — and that Msg() still decodes it into a
// correctly-TTL'd dns.Msg for the fallback paths.
func TestLookupRawPositive(t *testing.T) {
	t.Parallel()
	c := l1onlyCache(time.Hour, time.Minute)
	ctx := t.Context()
	c.Set(ctx, aQuestion(), aResponse("1.2.3.4", 3600), 0)

	res := c.Lookup(aQuestion())
	if res.Raw == nil || res.Negative || res.Stale {
		t.Fatalf("expected a fresh positive raw hit, got %+v", res)
	}
	if res.StoredAt == 0 {
		t.Fatal("StoredAt must be set for a positive entry")
	}
	// One A record -> exactly one TTL offset.
	if len(res.TTLOffsets) != 1 {
		t.Fatalf("TTLOffsets = %v, want one offset", res.TTLOffsets)
	}
	// The raw bytes must be a valid message whose answer matches.
	m := res.Msg()
	if m == nil || len(m.Answer) != 1 {
		t.Fatalf("Msg() = %v, want one answer", m)
	}
	a, ok := m.Answer[0].(*dns.A)
	if !ok || a.A.String() != "1.2.3.4" {
		t.Fatalf("answer = %v, want A 1.2.3.4", m.Answer[0])
	}
}

// TestLookupRawNegative verifies a negative L1 hit is raw too, tagged
// Negative and without TTL offsets (negative TTLs are never rebased).
func TestLookupRawNegative(t *testing.T) {
	t.Parallel()
	c := l1onlyCache(time.Hour, time.Minute)
	ctx := t.Context()
	c.SetNegative(ctx, aQuestion(), emptyResponse(), 0)

	res := c.Lookup(aQuestion())
	if res.Raw == nil || !res.Negative || res.Stale {
		t.Fatalf("expected a fresh negative raw hit, got %+v", res)
	}
	if len(res.TTLOffsets) != 0 {
		t.Fatalf("negative entry must carry no TTL offsets, got %v", res.TTLOffsets)
	}
}

// TestLookupRawMultiAnswerTTLOffsets verifies the packed-message scanner on
// a realistic compressed multi-RR answer (eight distinct-owner TXT records):
// every Answer-section TTL is located and reads its original value.
func TestLookupRawMultiAnswerTTLOffsets(t *testing.T) {
	t.Parallel()
	m := new(dns.Msg)
	m.SetQuestion("example.com.", dns.TypeTXT)
	m.Response = true
	for i := range 8 {
		m.Answer = append(m.Answer, &dns.TXT{
			Hdr: dns.RR_Header{Name: fmt.Sprintf("txt%d.example.com.", i), Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 60},
			// RFC 1035 caps each TXT character-string at 255 bytes, so split
			// 400 chars across two strings (240 + 160) like real records.
			Txt: []string{strings.Repeat("0123456789abcdef", 15), strings.Repeat("0123456789abcdef", 10)},
		})
	}
	m.Compress = true
	packed, err := m.Pack()
	if err != nil {
		t.Fatalf("pack: %v", err)
	}
	off := ttlOffsets(packed)
	if len(off) != 8 {
		t.Fatalf("offsets = %v, want 8", off)
	}
	for _, o := range off {
		if int(o)+4 > len(packed) {
			t.Fatalf("offset %d out of range", o)
		}
		if ttl := binary.BigEndian.Uint32(packed[o : o+4]); ttl != 60 {
			t.Fatalf("offset %d reads TTL %d, want 60", o, ttl)
		}
	}
}

// TestLookupRawMsgRebasesTTL verifies the lazy Msg() path rebases answer
// TTLs to the remaining lifetime, exactly like the pre-raw Lookup did.
func TestLookupRawMsgRebasesTTL(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		c := l1onlyCache(time.Hour, time.Minute)
		ctx := t.Context()
		c.Set(ctx, aQuestion(), aResponse("1.2.3.4", 3600), 0)
		time.Sleep(1100 * time.Millisecond)

		res := c.Lookup(aQuestion())
		if res.Raw == nil {
			t.Fatal("expected a hit")
		}
		m := res.Msg()
		if m == nil || len(m.Answer) != 1 {
			t.Fatalf("Msg() = %v, want one answer", m)
		}
		ttl := m.Answer[0].Header().Ttl
		if ttl >= 3600 || ttl < 3590 {
			t.Fatalf("rebased TTL = %d, want ~3599 (elapsed ~1s)", ttl)
		}
	})
}

// TestLookupRawStaleKeepsRaw verifies an expired-but-stale entry still
// exposes its raw bytes so the handler can answer from it (after decoding)
// when re-resolution fails.
func TestLookupRawStaleKeepsRaw(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		c := l1onlyCache(300*time.Millisecond, time.Minute)
		c.l1.staleTTL = 2 * time.Second
		ctx := t.Context()
		c.Set(ctx, aQuestion(), aResponse("1.2.3.4", 3600), 0)
		time.Sleep(500 * time.Millisecond)

		res := c.Lookup(aQuestion())
		if res.Raw == nil || !res.Stale {
			t.Fatalf("expected a stale raw entry, got %+v", res)
		}
		if m := res.Msg(); m == nil {
			t.Fatal("stale entry must still decode")
		}
	})
}
