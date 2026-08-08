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
	return &Cache{client: nil, l1: newL1(512), prefix: "irongrid:dns:", ttl: ttl, negativeTTL: negTTL}
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
	if msg, _ := c.Lookup(ctx, aQuestion()); msg != nil {
		t.Fatal("expected a miss before anything is cached")
	}
	if h, m := c.L1Counters(); h != 0 || m != 1 {
		t.Fatalf("after first miss: hits=%d misses=%d, want 0/1", h, m)
	}

	// A served positive lookup counts one hit (Lookup probes pos+neg keys
	// internally, so it must still count once).
	c.Set(ctx, aQuestion(), aResponse("1.2.3.4", 3600), 0)
	if msg, negative := c.Lookup(ctx, aQuestion()); msg == nil || negative {
		t.Fatal("expected a positive L1 hit")
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
	msg, negative := c.Lookup(ctx, aQuestion())
	if msg == nil {
		t.Fatal("expected a hit")
	}
	if negative {
		t.Fatal("expected a positive hit, got negative")
	}
}

func TestLookupL1Negative(t *testing.T) {
	c := l1onlyCache(time.Hour, time.Minute)
	ctx := context.Background()
	c.SetNegative(ctx, aQuestion(), emptyResponse(), 0)
	msg, negative := c.Lookup(ctx, aQuestion())
	if msg == nil {
		t.Fatal("expected a hit")
	}
	if !negative {
		t.Fatal("expected a negative hit")
	}
}

// TestLookupMissWithNilClient verifies Lookup degrades to a clean miss (no
// panic) when neither L1 nor L2 (nil Redis client, as in every test in this
// file) has anything — the path a genuinely new domain takes before ever
// reaching upstream.
func TestLookupMissWithNilClient(t *testing.T) {
	c := l1onlyCache(time.Hour, time.Minute)
	msg, negative := c.Lookup(context.Background(), aQuestion())
	if msg != nil || negative {
		t.Fatalf("expected a clean miss, got msg=%v negative=%v", msg, negative)
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
