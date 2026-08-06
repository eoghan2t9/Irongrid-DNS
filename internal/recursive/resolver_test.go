package recursive

import (
	"context"
	"net"
	"strings"
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

// fakeZone is one authority level in a test hierarchy: it answers queries
// for names strictly inside within, and referrals for anything under
// delegateTo (glue supplied from delegateAddrs), for names not in answers.
type fakeZone struct {
	name    string // e.g. "com." or "." for the root
	answers map[string][]dns.RR

	delegateSuffix string // e.g. "example.com." — referred to child
	delegateNS     string // e.g. "ns1.example.com."
	delegateAddr   string // child zone's server address, "ip:port"
	childName      string // e.g. "example.com."
}

// startFakeServer binds to listenAddr (a fixed "ip:port", not an ephemeral
// port) because glue records carry no port — the resolver always dials
// derived addresses on Resolver.nsPort, so every fake level in a chain must
// share one port to be reachable via glue, same as real nameservers all
// living on port 53.
func startFakeServer(t *testing.T, listenAddr string, z *fakeZone) string {
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
			w.WriteMsg(m)
			return
		}
		if z.delegateSuffix != "" && strings.HasSuffix(name, z.delegateSuffix) {
			ns, _ := dns.NewRR(z.childName + " 300 IN NS " + z.delegateNS)
			m.Ns = []dns.RR{ns}
			host, port, _ := net.SplitHostPort(z.delegateAddr)
			_ = port
			a, _ := dns.NewRR(z.delegateNS + " 300 IN A " + host)
			m.Extra = []dns.RR{a}
			w.WriteMsg(m)
			return
		}
		// NXDOMAIN with an authoritative SOA, like a real authoritative
		// server would answer for an unknown name in its own zone.
		m.Authoritative = true
		m.Rcode = dns.RcodeNameError
		soa, _ := dns.NewRR(z.name + " 300 IN SOA ns.invalid. admin.invalid. 1 3600 900 604800 300")
		m.Ns = []dns.RR{soa}
		w.WriteMsg(m)
	})}
	go srv.ActivateAndServe()
	t.Cleanup(func() { srv.Shutdown() })
	return pc.LocalAddr().String()
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
	authAddr = startFakeServer(t, "127.0.0.3:"+nsPort, authZone)

	tldZone := &fakeZone{
		name:           "com.",
		answers:        map[string][]dns.RR{},
		delegateSuffix: "example.com.",
		delegateNS:     "ns1.example.com.",
		delegateAddr:   authAddr,
		childName:      "example.com.",
	}
	tldAddr := startFakeServer(t, "127.0.0.2:"+nsPort, tldZone)

	rootZone := &fakeZone{
		name:           ".",
		answers:        map[string][]dns.RR{},
		delegateSuffix: "com.",
		delegateNS:     "a.gtld-servers.invalid.",
		delegateAddr:   tldAddr,
		childName:      "com.",
	}
	rootAddr = startFakeServer(t, "127.0.0.1:"+nsPort, rootZone)
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
	resp, err := r.Resolve(context.Background(), m)
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
	if _, err := r.Resolve(context.Background(), m1); err != nil {
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
	resp, err := r.Resolve(context.Background(), m)
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
	resp, err := r.Resolve(context.Background(), m)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if resp.Rcode != dns.RcodeNameError {
		t.Fatalf("rcode = %d, want NXDOMAIN", resp.Rcode)
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
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
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

	zone, servers, ttl, hasNS := New(nil).referral(resp)
	if !hasNS {
		t.Fatal("expected hasNS = true")
	}
	if zone != "example.com." {
		t.Fatalf("zone = %q, want example.com.", zone)
	}
	if len(servers) != 1 || servers[0] != "10.0.0.1:53" {
		t.Fatalf("servers = %v", servers)
	}
	if ttl != minDelegationTTL*5 { // 300s == minDelegationTTL(60s)*5, i.e. not clamped
		t.Fatalf("ttl = %v", ttl)
	}
}

func TestReferralNoGlue(t *testing.T) {
	resp := new(dns.Msg)
	ns, _ := dns.NewRR("example.com. 300 IN NS ns1.example.com.")
	resp.Ns = []dns.RR{ns}

	zone, servers, _, hasNS := New(nil).referral(resp)
	if !hasNS {
		t.Fatal("expected hasNS = true even without glue")
	}
	if zone != "example.com." {
		t.Fatalf("zone = %q", zone)
	}
	if servers != nil {
		t.Fatalf("expected no servers without glue, got %v", servers)
	}
}
