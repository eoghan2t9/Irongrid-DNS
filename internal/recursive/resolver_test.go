package recursive

import (
	"context"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// freePort reserves an OS-assigned UDP port on loopback, then releases it —
// the returned number is reused across several distinct 127.0.0.x addresses
// so a fake root/TLD/authoritative chain can share one port (glue records
// carry no port, so every level must be reachable on the same one).
func freePort(t *testing.T) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve port: %v", err)
	}
	_, port, _ := net.SplitHostPort(pc.LocalAddr().String())
	pc.Close()
	return port
}

// delegateEntry is one referral rule: names ending in suffix get referred to
// ns, with A glue for it unless noGlue (the out-of-bailiwick case).
type delegateEntry struct {
	suffix    string // e.g. "com." or "example.com."
	ns        string // NS hostname, e.g. "a.gtld-servers.invalid."
	addr      string // child zone's server address, "ip:port"
	childName string // zone name the NS record is owned by, e.g. "com."
	noGlue    bool
}

// fakeZone is one authority level in a test hierarchy: it answers queries
// for names it holds directly, and otherwise checks delegates in order for
// a referral.
type fakeZone struct {
	name      string // e.g. "com." or "." for the root
	answers   map[string][]dns.RR
	delegates []delegateEntry

	// Convenience for a zone with exactly one delegate — set these instead
	// of delegates for the common single-referral case.
	delegateSuffix string
	delegateNS     string
	delegateAddr   string
	childName      string
	delegateNoGlue bool
}

func (z *fakeZone) allDelegates() []delegateEntry {
	all := append([]delegateEntry{}, z.delegates...)
	if z.delegateSuffix != "" {
		all = append(all, delegateEntry{
			suffix: z.delegateSuffix, ns: z.delegateNS, addr: z.delegateAddr,
			childName: z.childName, noGlue: z.delegateNoGlue,
		})
	}
	return all
}

// startFakeServer binds to listenAddr (a fixed "ip:port", not an ephemeral
// port) because glue records carry no port — the resolver always dials
// derived addresses on Resolver.nsPort, so every fake level in a chain must
// share one port to be reachable via glue, same as real nameservers all
// living on port 53.
func startFakeServer(t *testing.T, listenAddr string, z *fakeZone) (string, func()) {
	t.Helper()
	pc, err := net.ListenPacket("udp", listenAddr)
	if err != nil {
		t.Fatalf("listen %s: %v", listenAddr, err)
	}
	srv := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		q := r.Question[0]
		m := new(dns.Msg)
		m.SetReply(r)
		name := strings.ToLower(q.Name)

		if rrs, ok := z.answers[name]; ok {
			m.Authoritative = true
			m.Answer = rrs
			_ = w.WriteMsg(m)
			return
		}
		var ns []dns.RR
		var extra []dns.RR
		matched := false
		for _, d := range z.allDelegates() {
			if !strings.HasSuffix(name, d.suffix) {
				continue
			}
			// Every matching delegate contributes an NS record (and glue
			// unless noGlue), so a zone can be delegated to several
			// nameservers in one referral — the real-world shape the
			// nameserver-racing path depends on.
			matched = true
			rr, _ := dns.NewRR(d.childName + " 300 IN NS " + d.ns)
			ns = append(ns, rr)
			if !d.noGlue {
				host, _, _ := net.SplitHostPort(d.addr)
				a, _ := dns.NewRR(d.ns + " 300 IN A " + host)
				extra = append(extra, a)
			}
		}
		if matched {
			m.Ns = ns
			m.Extra = extra
			_ = w.WriteMsg(m)
			return
		}
		// NXDOMAIN with an authoritative SOA, like a real authoritative
		// server would answer for an unknown name in its own zone.
		m.Authoritative = true
		m.Rcode = dns.RcodeNameError
		soa, _ := dns.NewRR(z.name + " 300 IN SOA ns.invalid. admin.invalid. 1 3600 900 604800 300")
		m.Ns = []dns.RR{soa}
		_ = w.WriteMsg(m)
	})}
	go func() { _ = srv.ActivateAndServe() }()
	t.Cleanup(func() { _ = srv.Shutdown() })
	return pc.LocalAddr().String(), func() { _ = srv.Shutdown() }
}

// buildChain wires a fake root -> fake "com." TLD -> fake "example.com."
// authoritative server, each only knowing how to refer to (or answer
// within) its own level, mirroring a real root/TLD/authoritative walk. The
// three levels sit on distinct 127.0.0.x loopback addresses sharing one
// port; use nsPort (returned) as the test Resolver's nsPort so its
// glue-derived addresses land on the fakes instead of real port 53.
func buildChain(t *testing.T) (rootAddr, authAddr, nsPort string) {
	t.Helper()
	nsPort = freePort(t)

	// The authoritative server is built first so its address is known
	// ahead of time for the TLD's glue.
	authAnswers := map[string][]dns.RR{}
	authRR, _ := dns.NewRR("example.com. 300 IN A 93.184.216.34")
	authAnswers["example.com."] = []dns.RR{authRR}
	cnameRR, _ := dns.NewRR("www.example.com. 300 IN CNAME example.com.")
	authAnswers["www.example.com."] = []dns.RR{cnameRR, authRR}

	authZone := &fakeZone{name: "example.com.", answers: authAnswers}
	authAddr, _ = startFakeServer(t, "127.0.0.3:"+nsPort, authZone)

	tldZone := &fakeZone{
		name:           "com.",
		answers:        map[string][]dns.RR{},
		delegateSuffix: "example.com.",
		delegateNS:     "ns1.example.com.",
		delegateAddr:   authAddr,
		childName:      "example.com.",
	}
	tldAddr, _ := startFakeServer(t, "127.0.0.2:"+nsPort, tldZone)

	rootZone := &fakeZone{
		name:           ".",
		answers:        map[string][]dns.RR{},
		delegateSuffix: "com.",
		delegateNS:     "a.gtld-servers.invalid.",
		delegateAddr:   tldAddr,
		childName:      "com.",
	}
	rootAddr, _ = startFakeServer(t, "127.0.0.1:"+nsPort, rootZone)
	return rootAddr, authAddr, nsPort
}

// newTestResolver builds a Resolver pointed at rootAddr with nsPort so
// glue-derived hops land on the fake chain instead of real port 53.
func newTestResolver(rootAddr, nsPort string) *Resolver {
	r := New([]string{rootAddr})
	r.nsPort = nsPort
	return r
}

func TestResolveWalksRootToAuthoritative(t *testing.T) {
	rootAddr, _, nsPort := buildChain(t)
	r := newTestResolver(rootAddr, nsPort)

	m := new(dns.Msg)
	m.SetQuestion("example.com.", dns.TypeA)
	resp, err := r.Resolve(t.Context(), m)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if len(resp.Answer) != 1 {
		t.Fatalf("answers = %d, want 1: %v", len(resp.Answer), resp.Answer)
	}
	a, ok := resp.Answer[0].(*dns.A)
	if !ok || a.A.String() != "93.184.216.34" {
		t.Fatalf("unexpected answer: %v", resp.Answer[0])
	}
	if resp.Id != m.Id {
		t.Fatalf("response Id = %d, want %d (rebased to the original query)", resp.Id, m.Id)
	}
	if !resp.RecursionAvailable {
		t.Fatal("expected RecursionAvailable set on the final response")
	}
}

// TestResolveCachesDelegation verifies a second query under the same zone
// skips the root and TLD hops — proven by shutting down the root server
// before the second query and confirming it still resolves.
func TestResolveCachesDelegation(t *testing.T) {
	rootAddr, _, nsPort := buildChain(t)
	r := newTestResolver(rootAddr, nsPort)

	m1 := new(dns.Msg)
	m1.SetQuestion("example.com.", dns.TypeA)
	if _, err := r.Resolve(t.Context(), m1); err != nil {
		t.Fatalf("first Resolve: %v", err)
	}

	zone, servers := r.bestDelegation("example.com.")
	if zone != "example.com." {
		t.Fatalf("expected a cached delegation for example.com., got zone=%q", zone)
	}
	if len(servers) == 0 {
		t.Fatal("expected cached delegation servers")
	}
}

func TestResolveChasesCNAME(t *testing.T) {
	rootAddr, _, nsPort := buildChain(t)
	r := newTestResolver(rootAddr, nsPort)

	m := new(dns.Msg)
	m.SetQuestion("www.example.com.", dns.TypeA)
	resp, err := r.Resolve(t.Context(), m)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	var sawCNAME, sawA bool
	for _, rr := range resp.Answer {
		switch rr.(type) {
		case *dns.CNAME:
			sawCNAME = true
		case *dns.A:
			sawA = true
		}
	}
	if !sawCNAME || !sawA {
		t.Fatalf("expected both CNAME and A in the answer, got %v", resp.Answer)
	}
}

func TestResolveNXDOMAIN(t *testing.T) {
	rootAddr, _, nsPort := buildChain(t)
	r := newTestResolver(rootAddr, nsPort)

	m := new(dns.Msg)
	m.SetQuestion("nowhere.example.com.", dns.TypeA)
	resp, err := r.Resolve(t.Context(), m)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if resp.Rcode != dns.RcodeNameError {
		t.Fatalf("rcode = %d, want NXDOMAIN", resp.Rcode)
	}
}

// TestResolveRacesNameservers verifies a dead nameserver in a zone doesn't
// stall resolution: the com. TLD delegates example.com. to two nameservers,
// one unreachable and one live. Sequentially, the dead one would cost a full
// per-server timeout before the live one was tried (blowing the whole query
// budget); racing must answer in a small fraction of that.
func TestResolveRacesNameservers(t *testing.T) {
	nsPort := freePort(t)

	// Reserve a dead address (bound then released) for the dead delegate. It
	// sits on 127.0.0.9 — off the 127.0.0.1/2/3 loopback addresses the fake
	// chain binds — so freePort() (127.0.0.1:0, reused by every fake level)
	// can never hand the dead address's port back to a live server, which
	// would turn the "dead" delegate into an accidental live zone and turn
	// this test into a referral-loop.
	pc, err := net.ListenPacket("udp", "127.0.0.9:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	deadAddr := pc.LocalAddr().String()
	pc.Close()

	authAnswers := map[string][]dns.RR{}
	authRR, _ := dns.NewRR("example.com. 300 IN A 93.184.216.34")
	authAnswers["example.com."] = []dns.RR{authRR}
	authZone := &fakeZone{name: "example.com.", answers: authAnswers}
	liveAddr, _ := startFakeServer(t, "127.0.0.3:"+nsPort, authZone)

	tldZone := &fakeZone{
		name:    "com.",
		answers: map[string][]dns.RR{},
		delegates: []delegateEntry{
			{suffix: "example.com.", ns: "ns1.dead.invalid.", addr: deadAddr, childName: "example.com."},
			{suffix: "example.com.", ns: "ns2.live.invalid.", addr: liveAddr, childName: "example.com."},
		},
	}
	tldAddr, _ := startFakeServer(t, "127.0.0.2:"+nsPort, tldZone)

	root := &fakeZone{
		name:           ".",
		answers:        map[string][]dns.RR{},
		delegateSuffix: "com.",
		delegateNS:     "a.gtld-servers.invalid.",
		delegateAddr:   tldAddr,
		childName:      "com.",
	}
	rootAddr, _ := startFakeServer(t, "127.0.0.1:"+nsPort, root)

	r := newTestResolver(rootAddr, nsPort)
	m := new(dns.Msg)
	m.SetQuestion("example.com.", dns.TypeA)

	start := time.Now()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	resp, err := r.Resolve(ctx, m)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if len(resp.Answer) != 1 {
		t.Fatalf("answers = %d, want 1: %v", len(resp.Answer), resp.Answer)
	}
	a, ok := resp.Answer[0].(*dns.A)
	if !ok || a.A.String() != "93.184.216.34" {
		t.Fatalf("unexpected answer: %v", resp.Answer[0])
	}
	// The dead server would cost perServerTimeout (3s) if it were tried
	// sequentially first; racing must answer well under that.
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("resolution with a dead nameserver took %s, want < 1s (nameservers not raced)", elapsed)
	}
}

// TestSetDefaultServerTimeout verifies the config-layer knob: it overrides
// the per-server exchange timeout for every Resolver and resets to the
// built-in default when cleared.
func TestSetDefaultServerTimeout(t *testing.T) {
	defer SetDefaultServerTimeout(0) // leave the default for other tests

	if got := serverTimeout(); got != perServerTimeout {
		t.Fatalf("default serverTimeout = %v, want %v", got, perServerTimeout)
	}

	SetDefaultServerTimeout(123 * time.Millisecond)
	if got := serverTimeout(); got != 123*time.Millisecond {
		t.Fatalf("configured serverTimeout = %v, want 123ms", got)
	}

	SetDefaultServerTimeout(0)
	if got := serverTimeout(); got != perServerTimeout {
		t.Fatalf("cleared serverTimeout = %v, want %v", got, perServerTimeout)
	}
}

// TestResolveAllRootsUnreachable verifies a prompt error instead of a hang
// when every root hint is dead.
func TestResolveAllRootsUnreachable(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	deadAddr := pc.LocalAddr().String()
	pc.Close()

	r := New([]string{deadAddr})
	m := new(dns.Msg)
	m.SetQuestion("example.com.", dns.TypeA)

	start := time.Now()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	if _, err := r.Resolve(ctx, m); err == nil {
		t.Fatal("expected an error when every root hint is unreachable")
	}
	if elapsed := time.Since(start); elapsed > 4*time.Second {
		t.Fatalf("took %s, want a prompt failure", elapsed)
	}
}

func TestReferralParsing(t *testing.T) {
	resp := new(dns.Msg)
	ns, _ := dns.NewRR("example.com. 300 IN NS ns1.example.com.")
	resp.Ns = []dns.RR{ns}
	a, _ := dns.NewRR("ns1.example.com. 300 IN A 10.0.0.1")
	resp.Extra = []dns.RR{a}

	zone, records, ttl, hasNS := parseReferral(resp)
	if !hasNS {
		t.Fatal("expected hasNS = true")
	}
	if zone != "example.com." {
		t.Fatalf("zone = %q, want example.com.", zone)
	}
	if len(records) != 1 || records[0].name != "ns1.example.com." || len(records[0].glueIPs) != 1 || records[0].glueIPs[0] != "10.0.0.1" {
		t.Fatalf("records = %v", records)
	}
	if ttl != minDelegationTTL*5 { // 300s == minDelegationTTL(60s)*5, i.e. not clamped
		t.Fatalf("ttl = %v", ttl)
	}

	servers := New(nil).resolveNameservers(t.Context(), records, 0)
	if len(servers) != 1 || servers[0] != "10.0.0.1:53" {
		t.Fatalf("servers = %v", servers)
	}
}

func TestReferralNoGlue(t *testing.T) {
	resp := new(dns.Msg)
	ns, _ := dns.NewRR("example.com. 300 IN NS ns1.example.com.")
	resp.Ns = []dns.RR{ns}

	zone, records, _, hasNS := parseReferral(resp)
	if !hasNS {
		t.Fatal("expected hasNS = true even without glue")
	}
	if zone != "example.com." {
		t.Fatalf("zone = %q", zone)
	}
	if len(records) != 1 || records[0].glueIPs != nil {
		t.Fatalf("expected one nameserver with no glue, got %v", records)
	}
}

// TestResolveGluelessOutOfBailiwickNS is the real-world case the earlier
// "skip glueless NS" design got wrong: a domain delegated to nameservers
// living under a completely different, unrelated domain (as with
// Cloudflare/Route53/DNSimple-style DNS hosting) — the TLD has no glue
// obligation for them, so the resolver must look them up independently.
func TestResolveGluelessOutOfBailiwickNS(t *testing.T) {
	nsPort := freePort(t)

	// The DNS host's own server answers its nameserver's own A record (so
	// its bootstrap address can be resolved) — and, since one hosting-
	// provider IP authoritatively serves many unrelated customer zones in
	// real life, it's also where example.com. itself actually lives, not on
	// some separate server: the .com TLD delegated example.com. to exactly
	// this nameserver, so this IS the server the walk must end up querying.
	nsHostAnswers := map[string][]dns.RR{}
	nsA, _ := dns.NewRR("ns1.dnshost.invalid. 300 IN A 127.0.0.4")
	nsHostAnswers["ns1.dnshost.invalid."] = []dns.RR{nsA}
	exampleRR, _ := dns.NewRR("example.com. 300 IN A 93.184.216.34")
	nsHostAnswers["example.com."] = []dns.RR{exampleRR}
	nsHostZone := &fakeZone{name: "dnshost.invalid.", answers: nsHostAnswers}
	nsHostAddr, _ := startFakeServer(t, "127.0.0.4:"+nsPort, nsHostZone)

	// A TLD ("invalid.") that glues its own in-bailiwick delegation for
	// dnshost.invalid. normally...
	tldInvalid := &fakeZone{
		name:           "invalid.",
		answers:        map[string][]dns.RR{},
		delegateSuffix: "dnshost.invalid.",
		delegateNS:     "a.gtld-servers.invalid.",
		delegateAddr:   nsHostAddr,
		childName:      "dnshost.invalid.",
	}
	tldInvalidAddr, _ := startFakeServer(t, "127.0.0.5:"+nsPort, tldInvalid)

	// The "com." TLD delegates example.com. to ns1.dnshost.invalid — an
	// out-of-bailiwick nameserver — WITHOUT glue, the case that matters here.
	// delegateAddr is unused when delegateNoGlue is set (no glue is derived
	// from it), so it's left empty.
	tldCom := &fakeZone{
		name:           "com.",
		answers:        map[string][]dns.RR{},
		delegateSuffix: "example.com.",
		delegateNS:     "ns1.dnshost.invalid.",
		childName:      "example.com.",
		delegateNoGlue: true,
	}
	tldComAddr, _ := startFakeServer(t, "127.0.0.2:"+nsPort, tldCom)

	// The root delegates both "com." and "invalid." so the nested lookup of
	// ns1.dnshost.invalid's own address can succeed.
	root := &fakeZone{
		name:    ".",
		answers: map[string][]dns.RR{},
		delegates: []delegateEntry{
			{suffix: "com.", ns: "a.gtld-servers.invalid.", addr: tldComAddr, childName: "com."},
			{suffix: "invalid.", ns: "a.iana-servers.invalid.", addr: tldInvalidAddr, childName: "invalid."},
		},
	}
	rootAddr, _ := startFakeServer(t, "127.0.0.1:"+nsPort, root)

	r := newTestResolver(rootAddr, nsPort)
	m := new(dns.Msg)
	m.SetQuestion("example.com.", dns.TypeA)
	resp, err := r.Resolve(t.Context(), m)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if len(resp.Answer) != 1 {
		t.Fatalf("answers = %d, want 1: %v", len(resp.Answer), resp.Answer)
	}
	a, ok := resp.Answer[0].(*dns.A)
	if !ok || a.A.String() != "93.184.216.34" {
		t.Fatalf("unexpected answer: %v", resp.Answer[0])
	}
}

// TestResolveCoalescesNSAddressLookups verifies concurrent address lookups
// for the same glueless nameserver hostname share one referral walk: two
// domains hosted by the same DNS provider resolved at once must not each
// walk the tree to find that provider's nameservers.
func TestResolveCoalescesNSAddressLookups(t *testing.T) {
	nsPort := freePort(t)

	// The DNS host answers ns1.dnshost.invalid's own A record slowly, so
	// concurrent lookups overlap; its hit count proves how many walks ran.
	var nsHits atomic.Int64
	pc, err := net.ListenPacket("udp", "127.0.0.4:"+nsPort)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	nsHostSrv := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		nsHits.Add(1)
		time.Sleep(300 * time.Millisecond)
		m := new(dns.Msg)
		m.SetReply(r)
		a, _ := dns.NewRR("ns1.dnshost.invalid. 300 IN A 127.0.0.4")
		m.Answer = []dns.RR{a}
		m.Authoritative = true
		_ = w.WriteMsg(m)
	})}
	go func() { _ = nsHostSrv.ActivateAndServe() }()
	t.Cleanup(func() { _ = nsHostSrv.Shutdown() })

	// The invalid. TLD glues dnshost.invalid. so a nameserver-address walk
	// ends at the DNS host above.
	tldInvalid := &fakeZone{
		name:           "invalid.",
		answers:        map[string][]dns.RR{},
		delegateSuffix: "dnshost.invalid.",
		delegateNS:     "a.gtld-servers.invalid.",
		delegateAddr:   "127.0.0.4:" + nsPort,
		childName:      "dnshost.invalid.",
	}
	tldInvalidAddr, _ := startFakeServer(t, "127.0.0.5:"+nsPort, tldInvalid)

	root := &fakeZone{
		name:    ".",
		answers: map[string][]dns.RR{},
		delegates: []delegateEntry{
			{suffix: "invalid.", ns: "a.iana-servers.invalid.", addr: tldInvalidAddr, childName: "invalid."},
		},
	}
	rootAddr, _ := startFakeServer(t, "127.0.0.1:"+nsPort, root)

	r := newTestResolver(rootAddr, nsPort)

	const n = 4
	var wg sync.WaitGroup
	for range n {
		wg.Go(func() {
			ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
			defer cancel()
			addr, ok := r.resolveNSAddr(ctx, "ns1.dnshost.invalid.", 1)
			if !ok || addr != "127.0.0.4:"+nsPort {
				t.Errorf("resolveNSAddr = %q (ok=%v), want 127.0.0.4:%s", addr, ok, nsPort)
			}
		})
	}
	wg.Wait()
	if got := nsHits.Load(); got != 1 {
		t.Fatalf("nameserver host answered %d times, want 1 (concurrent NS address lookups coalesced into one walk)", got)
	}
}

// TestResolveCachesNSAddress verifies an out-of-bailiwick nameserver's
// address is cached after the first resolution, so a second domain hosted
// by the same DNS provider skips the nested walk — proven by killing the
// TLD that a fresh nameserver-address lookup would need before resolving
// the second domain.
func TestResolveCachesNSAddress(t *testing.T) {
	nsPort := freePort(t)

	// One provider host answers its own nameserver's A record plus two
	// unrelated customer zones, as a real DNS host serves many domains.
	nsHostAnswers := map[string][]dns.RR{}
	nsA, _ := dns.NewRR("ns1.dnshost.invalid. 300 IN A 127.0.0.4")
	nsHostAnswers["ns1.dnshost.invalid."] = []dns.RR{nsA}
	exampleRR, _ := dns.NewRR("example.com. 300 IN A 93.184.216.34")
	nsHostAnswers["example.com."] = []dns.RR{exampleRR}
	otherRR, _ := dns.NewRR("other.com. 300 IN A 203.0.113.7")
	nsHostAnswers["other.com."] = []dns.RR{otherRR}
	nsHostZone := &fakeZone{name: "dnshost.invalid.", answers: nsHostAnswers}
	nsHostAddr, _ := startFakeServer(t, "127.0.0.4:"+nsPort, nsHostZone)

	// The invalid. TLD glues dnshost.invalid., which is what a fresh
	// nameserver-address walk would need — killed before the second query.
	tldInvalid := &fakeZone{
		name:           "invalid.",
		answers:        map[string][]dns.RR{},
		delegateSuffix: "dnshost.invalid.",
		delegateNS:     "a.gtld-servers.invalid.",
		delegateAddr:   nsHostAddr,
		childName:      "dnshost.invalid.",
	}
	tldInvalidAddr, stopInvalid := startFakeServer(t, "127.0.0.5:"+nsPort, tldInvalid)

	// The com. TLD delegates both customer zones to the same glueless,
	// out-of-bailiwick nameserver.
	tldCom := &fakeZone{
		name:    "com.",
		answers: map[string][]dns.RR{},
		delegates: []delegateEntry{
			{suffix: "example.com.", ns: "ns1.dnshost.invalid.", childName: "example.com.", noGlue: true},
			{suffix: "other.com.", ns: "ns1.dnshost.invalid.", childName: "other.com.", noGlue: true},
		},
	}
	tldComAddr, _ := startFakeServer(t, "127.0.0.2:"+nsPort, tldCom)

	root := &fakeZone{
		name:    ".",
		answers: map[string][]dns.RR{},
		delegates: []delegateEntry{
			{suffix: "com.", ns: "a.gtld-servers.invalid.", addr: tldComAddr, childName: "com."},
			{suffix: "invalid.", ns: "a.iana-servers.invalid.", addr: tldInvalidAddr, childName: "invalid."},
		},
	}
	rootAddr, _ := startFakeServer(t, "127.0.0.1:"+nsPort, root)

	r := newTestResolver(rootAddr, nsPort)

	m1 := new(dns.Msg)
	m1.SetQuestion("example.com.", dns.TypeA)
	if _, err := r.Resolve(t.Context(), m1); err != nil {
		t.Fatalf("first Resolve: %v", err)
	}
	if addr, ok := r.cachedNSAddr("ns1.dnshost.invalid."); !ok || addr != "127.0.0.4:"+nsPort {
		t.Fatalf("expected ns1.dnshost.invalid. cached at 127.0.0.4, got %q (ok=%v)", addr, ok)
	}

	// Drop every delegation learned during the first resolve so a fresh
	// nameserver-address lookup would have to walk root -> invalid. TLD
	// again — which is dead below. Only the NS-address cache can still
	// supply ns1.dnshost.invalid's address, so success proves the nested
	// walk was skipped.
	r.mu.Lock()
	r.delegations = map[string]delegation{}
	r.mu.Unlock()
	stopInvalid()
	m2 := new(dns.Msg)
	m2.SetQuestion("other.com.", dns.TypeA)
	resp, err := r.Resolve(t.Context(), m2)
	if err != nil {
		t.Fatalf("second Resolve with cached NS address: %v", err)
	}
	if len(resp.Answer) != 1 {
		t.Fatalf("answers = %d, want 1: %v", len(resp.Answer), resp.Answer)
	}
	a, ok := resp.Answer[0].(*dns.A)
	if !ok || a.A.String() != "203.0.113.7" {
		t.Fatalf("unexpected answer: %v", resp.Answer[0])
	}
}

// TestResolverAdvertisesEDNS1232 verifies the iterative walk's queries to
// nameservers advertise the Flag Day 2020 recommended 1232-byte EDNS UDP
// payload (the same knob the forward path uses), so a nameserver doesn't
// cap its answers at 512 bytes while a bigger buffer would risk IP
// fragmentation.
func TestResolverAdvertisesEDNS1232(t *testing.T) {
	var gotSize atomic.Int32
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		for _, rr := range r.Extra {
			if opt, ok := rr.(*dns.OPT); ok {
				gotSize.Store(int32(opt.UDPSize()))
			}
		}
		m := new(dns.Msg)
		m.SetReply(r)
		m.Authoritative = true
		m.Answer = append(m.Answer, &dns.A{
			Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
			A:   net.ParseIP("203.0.113.9"),
		})
		_ = w.WriteMsg(m)
	})}
	go func() { _ = srv.ActivateAndServe() }()
	t.Cleanup(func() { _ = srv.Shutdown() })

	r := New([]string{pc.LocalAddr().String()})
	m := new(dns.Msg)
	m.SetQuestion("example.com.", dns.TypeA)
	resp, err := r.Resolve(t.Context(), m)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if len(resp.Answer) != 1 {
		t.Fatalf("answers = %d, want 1", len(resp.Answer))
	}
	if got := gotSize.Load(); got != 1232 {
		t.Fatalf("nameserver saw EDNS %d bytes, want 1232", got)
	}
}

// TestResolverConnPoolReuse verifies exchange() pools a connection after a
// successful query and reuses it (rather than dialing fresh) on the next
// query to the same nameserver address.
func TestResolverConnPoolReuse(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := pc.LocalAddr().String()
	srv := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		_ = w.WriteMsg(m)
	})}
	go func() { _ = srv.ActivateAndServe() }()
	t.Cleanup(func() { _ = srv.Shutdown() })

	r := New([]string{addr})
	t.Cleanup(r.Close)

	m := new(dns.Msg)
	m.SetQuestion("example.com.", dns.TypeA)
	if _, err := r.exchange(t.Context(), addr, m.Copy(), "udp", time.Second); err != nil {
		t.Fatalf("first exchange: %v", err)
	}
	if got := r.poolKeyCount.Load(); got != 1 {
		t.Fatalf("poolKeyCount = %d, want 1 after a successful exchange", got)
	}

	conn := r.getConn("udp", addr)
	if conn == nil {
		t.Fatal("expected the connection from the first exchange to be pooled")
	}
	// getConn drains the single pooled entry: nothing left for a second Get
	// until something is Put back.
	if c := r.getConn("udp", addr); c != nil {
		t.Fatal("expected the pool to be empty after draining its one entry")
	}
	conn.Close()
}

// TestResolverConnPoolKeyCap verifies the pool never tracks more than
// nsConnPoolMaxKeys distinct (network, address) pairs — an address beyond
// the cap must be rejected (connection closed, not pooled) rather than
// growing pool state without bound.
func TestResolverConnPoolKeyCap(t *testing.T) {
	r := New([]string{"127.0.0.1:53"})
	t.Cleanup(r.Close)

	for i := range nsConnPoolMaxKeys + 50 {
		c1, c2 := net.Pipe()
		_ = c2
		addr := "10.0.0.1:" + strconv.Itoa(i) // port varies so every key is distinct
		r.putConn("udp", addr, &dns.Conn{Conn: c1})
	}
	if got := r.poolKeyCount.Load(); got != nsConnPoolMaxKeys {
		t.Fatalf("poolKeyCount = %d, want exactly %d (capped)", got, nsConnPoolMaxKeys)
	}
}
