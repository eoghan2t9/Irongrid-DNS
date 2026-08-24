package dnsserver

import (
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/miekg/dns"

	"github.com/eoghan2t9/Irongrid-DNS/internal/cache"
	"github.com/eoghan2t9/Irongrid-DNS/internal/config"
	"github.com/eoghan2t9/Irongrid-DNS/internal/filter"
	"github.com/eoghan2t9/Irongrid-DNS/internal/querylog"
	"github.com/eoghan2t9/Irongrid-DNS/internal/upstream"
)

// warmLogEntry mirrors the query-log entry shape the DNS handler records
// (domain without a trailing dot, action tag).
func warmLogEntry(domain, action string) querylog.Entry {
	return querylog.Entry{
		Time: time.Now(), Client: "127.0.0.1", Domain: domain,
		Type: "A", Action: action, Upstream: "udp://1.1.1.1:53",
		ResponseTimeMS: 12, Rcode: 0, Answers: 1,
	}
}

// waitLogEntries polls until the async query-log writer has flushed n entries.
func waitLogEntries(t *testing.T, ql *querylog.Log, n int) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		entries, err := ql.Query(t.Context(), n+10, 0, "", "", "", "")
		if err != nil {
			t.Fatalf("query log read: %v", err)
		}
		if len(entries) >= n {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("only %d of %d log entries flushed in time", len(entries), n)
		}
		time.Sleep(25 * time.Millisecond)
	}
}

// newWarmerHarness wires a handler (real upstream DNS server, in-memory
// Dragonfly-compatible query log, local-only cache) plus a warmer over it.
func newWarmerHarness(t *testing.T) (*Handler, *querylog.Log, *Warmer) {
	t.Helper()
	addr := startUDPTestServer(t, "1.1.1.1", 0)
	mr := miniredis.RunT(t)
	ql, err := querylog.New(mr.Addr(), "", 0, 30, 0)
	if err != nil {
		t.Fatalf("querylog: %v", err)
	}
	t.Cleanup(func() { _ = ql.Close() })
	c := cache.NewLocalOnly(time.Hour, time.Minute, 512, 0)
	h := NewHandler(filter.NewEngine(), c, []*upstream.Upstream{{Transport: upstream.UDP, Addr: addr}}, ql, "nxdomain", 600, 5*time.Second)
	w := NewWarmer(h, ql)
	w.SetConfig(config.WarmerConfig{Enabled: true, Interval: time.Hour, Lookback: 24 * time.Hour, MaxDomains: 100, Concurrency: 4})
	return h, ql, w
}

// TestWarmerWarmsActiveDomains runs one warming pass end to end: domains seen
// in the query log get their answers resolved and cached (A + AAAA), while a
// blacklisted domain is skipped entirely, and the snapshot reports the counts.
func TestWarmerWarmsActiveDomains(t *testing.T) {
	h, ql, w := newWarmerHarness(t)
	// Blacklist blocked.com so the warmer must skip it.
	h.Engine.SetUserLists([]string{"blocked.com"}, nil)
	h.Engine.Compile()

	ql.Record(warmLogEntry("warm.com", "allowed"))
	ql.Record(warmLogEntry("warm.com", "cached"))
	ql.Record(warmLogEntry("blocked.com", "allowed"))
	waitLogEntries(t, ql, 3)

	w.run(t.Context())

	// warm.com was resolved and cached for both A and AAAA. The cache lives
	// in the handler's hot-swappable settings snapshot (the Handler.Cache
	// field was removed when settings became an atomic pointer).
	cache := h.settings.Load().Cache
	for _, qt := range []uint16{dns.TypeA, dns.TypeAAAA} {
		q := dns.Question{Name: "warm.com.", Qtype: qt, Qclass: dns.ClassINET}
		if got := cache.Get(t.Context(), q); got == nil || len(got.Answer) == 0 {
			t.Fatalf("warm.com %s not cached after warming: %v", dns.TypeToString[qt], got)
		}
	}
	// The blacklisted domain must never have been resolved/warmed.
	if got := cache.Get(t.Context(), dns.Question{Name: "blocked.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}); got != nil {
		t.Fatalf("blacklisted domain was warmed: %v", got)
	}

	s := w.Snapshot()
	if s.Runs != 1 || s.DomainsConsidered != 2 {
		t.Fatalf("runs/domains = %d/%d, want 1/2", s.Runs, s.DomainsConsidered)
	}
	if s.Warmed != 2 {
		t.Fatalf("warmed = %d, want 2 (A + AAAA for warm.com)", s.Warmed)
	}
	if s.Skipped != 1 {
		t.Fatalf("skipped = %d, want 1 (blocked.com)", s.Skipped)
	}
	if s.Failed != 0 {
		t.Fatalf("failed = %d, want 0", s.Failed)
	}
}

// TestWarmerSkipsFreshEntries verifies a second pass doesn't re-resolve what
// the cache still answers fresh: after the first pass warms both questions,
// the second pass counts them as skipped instead of re-resolving them.
func TestWarmerSkipsFreshEntries(t *testing.T) {
	_, ql, w := newWarmerHarness(t)
	ql.Record(warmLogEntry("warm.com", "allowed"))
	waitLogEntries(t, ql, 1)

	w.run(t.Context())
	if s := w.Snapshot(); s.Warmed != 2 || s.Skipped != 0 {
		t.Fatalf("first pass: warmed=%d skipped=%d, want 2/0", s.Warmed, s.Skipped)
	}

	// Second pass: both questions are now fresh in the cache, so nothing is
	// re-resolved — the skip counters absorb them.
	w.run(t.Context())
	s := w.Snapshot()
	if s.Runs != 2 {
		t.Fatalf("runs = %d, want 2", s.Runs)
	}
	if s.Warmed != 2 {
		t.Fatalf("second pass re-resolved: warmed = %d, want still 2", s.Warmed)
	}
	if s.Skipped != 2 {
		t.Fatalf("skipped = %d, want 2 (fresh A + AAAA)", s.Skipped)
	}
	if s.Failed != 0 {
		t.Fatalf("failed = %d, want 0", s.Failed)
	}
}

// TestWarmerDisabledLogIsNoOp verifies a warmer over a disabled log (no Redis
// backing) completes a pass cleanly with nothing to warm.
func TestWarmerDisabledLogIsNoOp(t *testing.T) {
	addr := startUDPTestServer(t, "1.1.1.1", 0)
	c := cache.NewLocalOnly(time.Hour, time.Minute, 512, 0)
	h := NewHandler(filter.NewEngine(), c, []*upstream.Upstream{{Transport: upstream.UDP, Addr: addr}}, nil, "nxdomain", 600, 5*time.Second)
	w := NewWarmer(h, querylog.NewDisabled(30))
	w.SetConfig(config.WarmerConfig{Enabled: true, Interval: time.Hour, Lookback: 24 * time.Hour, MaxDomains: 100, Concurrency: 4})
	w.run(t.Context())
	s := w.Snapshot()
	if s.Runs != 1 || s.DomainsConsidered != 0 || s.Warmed != 0 || s.Failed != 0 {
		t.Fatalf("disabled-log pass stats = %+v, want runs=1 and zeros", s)
	}
}
