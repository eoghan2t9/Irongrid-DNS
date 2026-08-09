package cache

import (
	"context"
	"net"
	"testing"
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
	c := l1onlyCache(time.Hour, time.Minute)
	ctx := context.Background()
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
	c := l1onlyCache(time.Hour, time.Minute)
	ctx := context.Background()
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
}

// TestL1CapExpiry verifies entries expire at the configured TTL cap, even
// when the underlying record TTL is much larger.
func TestL1CapExpiry(t *testing.T) {
	c := l1onlyCache(300*time.Millisecond, time.Minute)
	ctx := context.Background()
	c.Set(ctx, aQuestion(), aResponse("1.2.3.4", 3600), 0)
	time.Sleep(400 * time.Millisecond)
	if got := c.Get(ctx, aQuestion()); got != nil {
		t.Fatal("entry should have expired at the TTL cap")
	}
}

func TestL1Negative(t *testing.T) {
	c := l1onlyCache(time.Hour, 50*time.Millisecond)
	ctx := context.Background()
	c.SetNegative(ctx, aQuestion(), emptyResponse(), 0)
	if got := c.GetNegative(ctx, aQuestion()); got == nil {
		t.Fatal("expected a negative hit")
	}
	time.Sleep(80 * time.Millisecond)
	if got := c.GetNegative(ctx, aQuestion()); got != nil {
		t.Fatal("expired negative entry should miss")
	}
}

func TestL1Flush(t *testing.T) {
	c := l1onlyCache(time.Hour, time.Minute)
	ctx := context.Background()
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
	c := l1onlyCache(time.Hour, time.Minute)
	ctx := context.Background()

	// A clean miss counts one miss.
	if res := c.Lookup(ctx, aQuestion()); res.Msg != nil {
		t.Fatal("expected a miss before anything is cached")
	}
	if h, m := c.L1Counters(); h != 0 || m != 1 {
		t.Fatalf("after first miss: hits=%d misses=%d, want 0/1", h, m)
	}

	// A served positive lookup counts one hit (Lookup probes pos+neg keys
	// internally, so it must still count once).
	c.Set(ctx, aQuestion(), aResponse("1.2.3.4", 3600), 0)
	if res := c.Lookup(ctx, aQuestion()); res.Msg == nil || res.Negative || res.Stale {
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
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c.Get(context.Background(), q)
	}
}

func TestLookupL1Positive(t *testing.T) {
	c := l1onlyCache(time.Hour, time.Minute)
	ctx := context.Background()
	c.Set(ctx, aQuestion(), aResponse("1.2.3.4", 3600), 0)
	res := c.Lookup(ctx, aQuestion())
	if res.Msg == nil {
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
	c := l1onlyCache(time.Hour, time.Minute)
	ctx := context.Background()
	c.SetNegative(ctx, aQuestion(), emptyResponse(), 0)
	res := c.Lookup(ctx, aQuestion())
	if res.Msg == nil {
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
	c := l1onlyCache(time.Hour, time.Minute)
	res := c.Lookup(context.Background(), aQuestion())
	if res.Msg != nil || res.Negative {
		t.Fatalf("expected a clean miss, got msg=%v negative=%v", res.Msg, res.Negative)
	}
}

// TestLookupStale verifies an entry past its cache TTL but inside the
// serve-stale window is reported with Stale=true (still decodable), and is
// reported as a plain miss once the stale window itself passes.
func TestLookupStale(t *testing.T) {
	c := l1onlyCache(300*time.Millisecond, time.Minute)
	c.l1.staleTTL = 2 * time.Second
	ctx := context.Background()
	c.Set(ctx, aQuestion(), aResponse("1.2.3.4", 3600), 0)

	time.Sleep(400 * time.Millisecond)
	res := c.Lookup(ctx, aQuestion())
	if res.Msg == nil {
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
	if res := c.Lookup(ctx, aQuestion()); res.Msg != nil {
		t.Fatal("entry should miss once the serve-stale window passes")
	}
}

// TestPrefetchNearExpiry verifies a background refresh is scheduled when a
// positive entry is served close to its cache-lifetime end, and that a fresh
// entry with plenty of life left does not trigger one.
func TestPrefetchNearExpiry(t *testing.T) {
	c := l1onlyCache(5*time.Second, time.Minute) // lead = 1s
	ctx := context.Background()

	prefetched := make(chan dns.Question, 1)
	c.EnablePrefetch(func(cctx context.Context, q dns.Question) {
		prefetched <- q
	})

	// Fresh entry with ~5s of life left: no prefetch.
	c.Set(ctx, aQuestion(), aResponse("1.2.3.4", 3600), 0)
	if res := c.Lookup(ctx, aQuestion()); res.Msg == nil {
		t.Fatal("expected a hit")
	}
	select {
	case q := <-prefetched:
		t.Fatalf("prefetch fired too early for %s", q.Name)
	default:
	}

	// Wait until the entry is within the 1s prefetch lead, then trigger.
	time.Sleep(4200 * time.Millisecond)
	if res := c.Lookup(ctx, aQuestion()); res.Msg == nil {
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
}

// TestDecodeMGetResult exercises the MGET response parsing in isolation
// (posKey, negKey order, as Lookup calls MGet) without needing a real Redis
// connection — go-redis returns a present key as a string and a missing key
// as nil in the result slice.
func TestDecodeMGetResult(t *testing.T) {
	cases := []struct {
		name    string
		vals    []interface{}
		wantPos []byte
		wantNeg []byte
		wantOK  bool
	}{
		{"both missing", []interface{}{nil, nil}, nil, nil, false},
		{"positive present", []interface{}{"pos-bytes", nil}, []byte("pos-bytes"), nil, true},
		{"negative present", []interface{}{nil, "neg-bytes"}, nil, []byte("neg-bytes"), true},
		{"both present positive wins", []interface{}{"pos-bytes", "neg-bytes"}, []byte("pos-bytes"), nil, true},
		{"wrong length", []interface{}{"only-one"}, nil, nil, false},
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
