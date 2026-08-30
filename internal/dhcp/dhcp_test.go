package dhcp

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/insomniacslk/dhcp/dhcpv6"
)

// testConfig returns a small LAN config: 192.168.1.0/24 with a /100-/199 pool.
func testConfig(t *testing.T) (Config, string) {
	t.Helper()
	_, subnet, _ := net.ParseCIDR("192.168.1.0/24")
	dir := t.TempDir()
	return Config{
		Enabled:    true,
		Subnet:     subnet,
		RangeStart: net.ParseIP("192.168.1.100"),
		RangeEnd:   net.ParseIP("192.168.1.199"),
		ServerIPv4: net.ParseIP("192.168.1.1"),
		ServerMAC:  net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x01},
		LeaseTime:  time.Hour,
		Domain:     "lan",
		DNS:        []net.IP{net.ParseIP("192.168.1.1")},
		IPv6:       true,
		IPv6Prefix: mustCIDR("fd00::/64"),
		IPv6Start:  net.ParseIP("fd00::100"),
		IPv6End:    net.ParseIP("fd00::199"),
		ServerIPv6: net.ParseIP("fd00::1"),
	}, dir
}

func mustCIDR(s string) *net.IPNet {
	_, n, err := net.ParseCIDR(s)
	if err != nil {
		panic(err)
	}
	return n
}

func newTestServer(t *testing.T, cfg Config, dir string) *Server {
	t.Helper()
	s := New(dir)
	s.SetConfig(cfg)
	return s
}

// ---- pool allocation ----

// TestPoolAtCarriesAcrossOctet verifies poolAt carries into the next octet
// when base's own byte overflows, not just when offset's own digits require
// it — poolAt(10.0.0.250, 10) must land on 10.0.1.4 (250+10=260, one octet-3
// carry plus 4), not wrap back to 10.0.0.4 within the same octet.
func TestPoolAtCarriesAcrossOctet(t *testing.T) {
	t.Parallel()
	base := net.ParseIP("10.0.0.250").To4()
	got := poolAt(base, 10)
	want := net.ParseIP("10.0.1.4").To4()
	if !got.Equal(want) {
		t.Fatalf("poolAt(10.0.0.250, 10) = %v, want %v", got, want)
	}
}

func TestPoolAllocV4RoundRobin(t *testing.T) {
	t.Parallel()
	cfg, dir := testConfig(t)
	s := newTestServer(t, cfg, dir)
	mac1 := net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01}
	mac2 := net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x02}

	ip1, _ := s.allocV4(mac1, nil, "phone")
	if ip1 == nil || !ip1.Equal(net.ParseIP("192.168.1.100")) {
		t.Fatalf("first alloc = %v; want 192.168.1.100", ip1)
	}
	// Second client gets the next address even though the first is only
	// offered (never committed): offers must not block the pool.
	ip2, _ := s.allocV4(mac2, nil, "laptop")
	if ip2 == nil || !ip2.Equal(net.ParseIP("192.168.1.101")) {
		t.Fatalf("second alloc = %v; want 192.168.1.101", ip2)
	}
	// The first client asking again gets the same offered address back.
	ip1b, _ := s.allocV4(mac1, nil, "phone")
	if ip1b == nil || !ip1b.Equal(ip1) {
		t.Fatalf("re-alloc = %v; want same %v", ip1b, ip1)
	}
}

func TestPoolAllocV4StaticWins(t *testing.T) {
	t.Parallel()
	cfg, dir := testConfig(t)
	cfg.Static = []StaticLease{{MAC: "aa:bb:cc:dd:ee:01", IP: net.ParseIP("192.168.1.50"), Hostname: "printer"}}
	s := newTestServer(t, cfg, dir)

	ip, ok := s.allocV4(net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01}, nil, "")
	if !ok || !ip.Equal(net.ParseIP("192.168.1.50")) {
		t.Fatalf("static alloc = %v, ok=%v; want 192.168.1.50", ip, ok)
	}
	if got := s.hosts["printer"]; got == nil {
		t.Fatal("static hostname 'printer' not registered in host index")
	}
}

func TestPoolAllocV4Exhaustion(t *testing.T) {
	t.Parallel()
	cfg, dir := testConfig(t)
	// Tiny pool: 3 addresses.
	cfg.RangeStart = net.ParseIP("192.168.1.100")
	cfg.RangeEnd = net.ParseIP("192.168.1.102")
	s := newTestServer(t, cfg, dir)

	var ips []net.IP
	for i := range 5 {
		ip, _ := s.allocV4(net.HardwareAddr{0xaa, byte(i), 0x01}, nil, "")
		if i < 3 && ip == nil {
			t.Fatalf("alloc %d failed, want success", i)
		}
		if i >= 3 && ip != nil {
			t.Fatalf("alloc %d succeeded, want exhaustion", i)
		}
		ips = append(ips, ip)
	}
	// Exhaustion must not break committed leases: commit the first three.
	for i, ip := range ips[:3] {
		s.commit(&Lease{Key: string(v4Key(net.HardwareAddr{0xaa, byte(i), 0x01})), MAC: net.HardwareAddr{0xaa, byte(i), 0x01}.String(), IP: ip.String()})
	}
	if n := len(s.leases); n != 3 {
		t.Fatalf("committed leases = %d, want 3", n)
	}
}

func TestPoolAllocV6(t *testing.T) {
	t.Parallel()
	cfg, dir := testConfig(t)
	s := newTestServer(t, cfg, dir)
	duid := "000100011234567890abcdef"
	ip, _ := s.allocV6(duid, "nas", nil)
	if ip == nil || !ip.Equal(net.ParseIP("fd00::100")) {
		t.Fatalf("v6 alloc = %v; want fd00::100", ip)
	}
	// A second distinct client moves on.
	ip2, _ := s.allocV6("000100011234567890123456", "nas2", nil)
	if ip2 == nil || !ip2.Equal(net.ParseIP("fd00::101")) {
		t.Fatalf("v6 alloc 2 = %v; want fd00::101", ip2)
	}
	// Requested address is honoured when free, for a third distinct client
	// (not one of the two above: a client with its own still-valid offer
	// takes priority over a requested address, exactly like allocV4's
	// equivalent step 2 — see TestPoolAllocV6RoundRobin).
	ip3, _ := s.allocV6("000100011234567890333333", "printer", net.ParseIP("fd00::150"))
	if ip3 == nil || !ip3.Equal(net.ParseIP("fd00::150")) {
		t.Fatalf("v6 requested alloc = %v; want fd00::150", ip3)
	}
}

// TestPoolAllocV6RoundRobin is the v6 analogue of
// TestPoolAllocV4RoundRobin: an in-flight offer for one client must not
// block the pool for the next, and re-asking returns the same offered
// address (exercises the cursor6 round-robin nextFree6 uses, mirroring
// nextFree4's cursor4).
func TestPoolAllocV6RoundRobin(t *testing.T) {
	t.Parallel()
	cfg, dir := testConfig(t)
	s := newTestServer(t, cfg, dir)
	duid1, duid2 := "000100011234567890111111", "000100011234567890222222"

	ip1, _ := s.allocV6(duid1, "phone", nil)
	if ip1 == nil || !ip1.Equal(net.ParseIP("fd00::100")) {
		t.Fatalf("first v6 alloc = %v; want fd00::100", ip1)
	}
	ip2, _ := s.allocV6(duid2, "laptop", nil)
	if ip2 == nil || !ip2.Equal(net.ParseIP("fd00::101")) {
		t.Fatalf("second v6 alloc = %v; want fd00::101", ip2)
	}
	ip1b, _ := s.allocV6(duid1, "phone", nil)
	if ip1b == nil || !ip1b.Equal(ip1) {
		t.Fatalf("v6 re-alloc = %v; want same %v", ip1b, ip1)
	}
}

// TestPoolAllocV6DoesNotImmediatelyReuseFreedAddress proves nextFree6
// actually continues from cursor6 rather than always rescanning from the
// pool's start: without the cursor, freeing the earliest address would make
// it the very next thing handed out (it's always first in a from-start
// scan), independent of how many other addresses were allocated since.
func TestPoolAllocV6DoesNotImmediatelyReuseFreedAddress(t *testing.T) {
	t.Parallel()
	cfg, dir := testConfig(t)
	s := newTestServer(t, cfg, dir)
	duid1 := "000100011234567890111111"

	ip1, _ := s.allocV6(duid1, "phone", nil)
	if ip1 == nil || !ip1.Equal(net.ParseIP("fd00::100")) {
		t.Fatalf("first v6 alloc = %v; want fd00::100", ip1)
	}
	s.commit(&Lease{Key: string(v6Key(duid1)), DUID: duid1, IP: ip1.String(), Hostname: "phone"})
	if !s.releaseLease(v6Key(duid1), ip1) {
		t.Fatal("release of fd00::100 failed")
	}

	// The cursor has already moved to fd00::101, so the next distinct
	// client must not be handed the just-freed fd00::100 back.
	duid2 := "000100011234567890222222"
	ip2, _ := s.allocV6(duid2, "laptop", nil)
	if ip2 == nil || ip2.Equal(ip1) {
		t.Fatalf("v6 alloc after release = %v; must not immediately reuse the just-freed %v", ip2, ip1)
	}
}

// TestPoolAllocV6Exhaustion is the v6 analogue of TestPoolAllocV4Exhaustion:
// a fully occupied pool returns nil (nextFree6's wraparound-to-first check)
// without disturbing addresses already committed.
func TestPoolAllocV6Exhaustion(t *testing.T) {
	t.Parallel()
	cfg, dir := testConfig(t)
	// Tiny pool: 3 addresses.
	cfg.IPv6Start = net.ParseIP("fd00::100")
	cfg.IPv6End = net.ParseIP("fd00::102")
	s := newTestServer(t, cfg, dir)

	var ips []net.IP
	for i := range 5 {
		duid := fmt.Sprintf("00010001123456789%07x", i)
		ip, _ := s.allocV6(duid, "", nil)
		if i < 3 && ip == nil {
			t.Fatalf("v6 alloc %d failed, want success", i)
		}
		if i >= 3 && ip != nil {
			t.Fatalf("v6 alloc %d succeeded, want exhaustion", i)
		}
		ips = append(ips, ip)
	}
	// Exhaustion must not break committed leases: commit the first three.
	for i, ip := range ips[:3] {
		duid := fmt.Sprintf("00010001123456789%07x", i)
		s.commit(&Lease{Key: string(v6Key(duid)), DUID: duid, IP: ip.String()})
	}
	if n := len(s.leases); n != 3 {
		t.Fatalf("committed v6 leases = %d, want 3", n)
	}
}

// ---- DHCPv4 DORA handshake (in-process, no real sockets) ----

// fakeV4Conn records replies for the handler tests.
type fakeV4Conn struct {
	replies [][]byte
}

func (f *fakeV4Conn) WriteTo(b []byte, _ net.Addr) (int, error) {
	f.replies = append(f.replies, b)
	return len(b), nil
}

func (f *fakeV4Conn) ReadFrom(b []byte) (int, net.Addr, error) { return 0, nil, net.ErrClosed }
func (f *fakeV4Conn) Close() error                             { return nil }
func (f *fakeV4Conn) LocalAddr() net.Addr                      { return &net.UDPAddr{IP: net.IPv4zero, Port: 67} }
func (f *fakeV4Conn) SetDeadline(t time.Time) error            { return nil }
func (f *fakeV4Conn) SetReadDeadline(t time.Time) error        { return nil }
func (f *fakeV4Conn) SetWriteDeadline(t time.Time) error       { return nil }

func TestV4DORA(t *testing.T) {
	t.Parallel()
	cfg, dir := testConfig(t)
	s := newTestServer(t, cfg, dir)

	// DISCOVER
	d, err := dhcpv4.New(
		dhcpv4.WithHwAddr(net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x05}),
		dhcpv4.WithMessageType(dhcpv4.MessageTypeDiscover),
		dhcpv4.WithOption(dhcpv4.OptGeneric(dhcpv4.OptionHostName, []byte("kitchen"))),
	)
	if err != nil {
		t.Fatal(err)
	}
	conn := &fakeV4Conn{}
	s.handleV4(conn, &net.UDPAddr{}, d)
	if len(conn.replies) != 1 {
		t.Fatalf("DISCOVER: %d replies, want 1", len(conn.replies))
	}
	offer, err := dhcpv4.FromBytes(conn.replies[0])
	if err != nil {
		t.Fatalf("parse offer: %v", err)
	}
	if offer.MessageType() != dhcpv4.MessageTypeOffer {
		t.Fatalf("reply type = %v, want OFFER", offer.MessageType())
	}
	offered := offer.YourIPAddr
	if !offered.Equal(net.ParseIP("192.168.1.100")) {
		t.Fatalf("offered = %v, want 192.168.1.100", offered)
	}

	// REQUEST (SELECTING) — a real client repeats its hostname here.
	req, err := dhcpv4.NewRequestFromOffer(offer)
	if err != nil {
		t.Fatal(err)
	}
	req.UpdateOption(dhcpv4.OptGeneric(dhcpv4.OptionHostName, []byte("kitchen")))
	conn.replies = nil
	s.handleV4(conn, &net.UDPAddr{}, req)
	if len(conn.replies) != 1 {
		t.Fatalf("REQUEST: %d replies, want 1", len(conn.replies))
	}
	ack, err := dhcpv4.FromBytes(conn.replies[0])
	if err != nil {
		t.Fatal(err)
	}
	if ack.MessageType() != dhcpv4.MessageTypeAck {
		t.Fatalf("reply type = %v, want ACK", ack.MessageType())
	}
	if !ack.YourIPAddr.Equal(offered) {
		t.Fatalf("ack addr = %v, want offered %v", ack.YourIPAddr, offered)
	}
	// The lease is committed with the hostname registered.
	if got := s.leases[v4Key(net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x05})]; got == nil {
		t.Fatal("no committed lease after DORA")
	}
	if got := s.hosts["kitchen"]; got == nil || !got.Equal(offered) {
		t.Fatalf("hostname 'kitchen' -> %v, want %v", got, offered)
	}
	// Hostname resolves with and without the domain suffix.
	if ips, ok := s.LookupHost("kitchen.lan"); !ok || len(ips) != 1 || !ips[0].Equal(offered) {
		t.Fatalf("LookupHost(kitchen.lan) = %v, %v", ips, ok)
	}
	if ips, ok := s.LookupHost("kitchen"); !ok || !ips[0].Equal(offered) {
		t.Fatalf("LookupHost(kitchen) = %v, %v", ips, ok)
	}
	if _, ok := s.LookupHost("nonexistent.lan"); ok {
		t.Fatal("unknown hostname resolved")
	}
}

// ---- reverse (PTR) lookups ----

func TestLookupPTR(t *testing.T) {
	t.Parallel()
	cfg, dir := testConfig(t)
	s := newTestServer(t, cfg, dir)
	mac := net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x07}

	// A dynamic lease with a registered hostname.
	ip, _ := s.allocV4(mac, nil, "fridge")
	s.commit(&Lease{
		Key: string(v4Key(mac)), MAC: mac.String(), IP: ip.String(),
		Hostname: "fridge", Expires: time.Now().Add(time.Hour),
	})
	// The address resolves back to hostname.domain.
	host, ok := s.LookupPTR(ip.String())
	if !ok || host != "fridge.lan" {
		t.Fatalf("LookupPTR(%s) = %q, %v; want fridge.lan, true", ip, host, ok)
	}
	// Unknown addresses don't resolve.
	if _, ok := s.LookupPTR("192.168.1.99"); ok {
		t.Fatal("unleased address resolved")
	}
	// Garbage input is refused.
	if _, ok := s.LookupPTR("not-an-ip"); ok {
		t.Fatal("non-IP resolved")
	}

	// A static reservation with a hostname answers too (via rebuildHosts).
	staticIP := net.ParseIP("192.168.1.77")
	s.SetConfig(func(cfg Config) Config {
		cfg.Static = append(cfg.Static, StaticLease{MAC: "aa:bb:cc:dd:ee:08", IP: staticIP, Hostname: "nas"})
		return cfg
	}(s.cfg))
	host, ok = s.LookupPTR(staticIP.String())
	if !ok || host != "nas.lan" {
		t.Fatalf("LookupPTR(static) = %q, %v; want nas.lan, true", host, ok)
	}
}

func TestV4RequestRejectsTakenAddress(t *testing.T) {
	t.Parallel()
	cfg, dir := testConfig(t)
	s := newTestServer(t, cfg, dir)
	macA := net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01}
	macB := net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x02}

	// Client A commits 192.168.1.100.
	ip, _ := s.allocV4(macA, nil, "")
	s.commit(&Lease{Key: string(v4Key(macA)), MAC: macA.String(), IP: ip.String()})

	// Client B requests A's address: must be NAK'd.
	req, err := dhcpv4.New(dhcpv4.WithHwAddr(macB), dhcpv4.WithMessageType(dhcpv4.MessageTypeRequest),
		dhcpv4.WithOption(dhcpv4.OptGeneric(dhcpv4.OptionRequestedIPAddress, ip.To4())),
		dhcpv4.WithServerIP(cfg.ServerIPv4))
	if err != nil {
		t.Fatal(err)
	}
	conn := &fakeV4Conn{}
	s.handleV4(conn, &net.UDPAddr{}, req)
	if len(conn.replies) != 1 {
		t.Fatalf("got %d replies, want 1", len(conn.replies))
	}
	nak, err := dhcpv4.FromBytes(conn.replies[0])
	if err != nil {
		t.Fatal(err)
	}
	if nak.MessageType() != dhcpv4.MessageTypeNak {
		t.Fatalf("reply type = %v, want NAK", nak.MessageType())
	}
}

func TestV4ReleaseFreesLease(t *testing.T) {
	t.Parallel()
	cfg, dir := testConfig(t)
	s := newTestServer(t, cfg, dir)
	mac := net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x09}
	ip, _ := s.allocV4(mac, nil, "")
	s.commit(&Lease{Key: string(v4Key(mac)), MAC: mac.String(), IP: ip.String()})

	rel, err := dhcpv4.New(dhcpv4.WithHwAddr(mac), dhcpv4.WithMessageType(dhcpv4.MessageTypeRelease), dhcpv4.WithClientIP(ip))
	if err != nil {
		t.Fatal(err)
	}
	s.handleV4(&fakeV4Conn{}, &net.UDPAddr{}, rel)
	if s.leases[v4Key(mac)] != nil {
		t.Fatal("lease still present after RELEASE")
	}
}

// ---- persistence ----

func TestLeasePersistenceRoundTrip(t *testing.T) {
	t.Parallel()
	cfg, dir := testConfig(t)
	s := newTestServer(t, cfg, dir)
	mac := net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x07}
	ip, _ := s.allocV4(mac, nil, "nas")
	s.commit(&Lease{Key: string(v4Key(mac)), MAC: mac.String(), IP: ip.String(), Hostname: "nas"})
	s.persistNow()

	// Reload from disk with a fresh server.
	s2 := New(dir)
	s2.SetConfig(cfg)
	if s2.leases[v4Key(mac)] == nil {
		t.Fatal("lease not restored from disk")
	}
	if got := s2.hosts["nas"]; got == nil || !got.Equal(ip) {
		t.Fatalf("restored hostname 'nas' -> %v, want %v", got, ip)
	}
}

func TestStaticLeasePersistsOnlyWhileConfigured(t *testing.T) {
	t.Parallel()
	cfg, dir := testConfig(t)
	cfg.Static = []StaticLease{{MAC: "aa:bb:cc:dd:ee:01", IP: net.ParseIP("192.168.1.50"), Hostname: "printer"}}
	s := newTestServer(t, cfg, dir)
	s.allocV4(net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01}, nil, "")
	s.persistNow()

	// New config without the reservation: the static lease must be dropped.
	cfg2, dir2 := testConfig(t)
	_ = dir2
	s2 := New(dir)
	s2.SetConfig(cfg2)
	if s2.leases[v4Key(net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01})] != nil {
		t.Fatal("static lease survived removal from config")
	}
}

// ---- misc ----

func TestHostnameSanitize(t *testing.T) {
	t.Parallel()
	cases := map[string]string{
		"Kitchen-PC":  "kitchen-pc",
		"  cam  ":     "cam",
		"multi.label": "multi",
		"bad!@#chars": "badchars",
		"UPPER":       "upper",
	}
	for in, want := range cases {
		if got := sanitizeHostname(in); got != want {
			t.Errorf("sanitizeHostname(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestDomainPeeling(t *testing.T) {
	t.Parallel()
	cfg, dir := testConfig(t)
	cfg.Domain = "lan"
	s := newTestServer(t, cfg, dir)
	mac := net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x0a}
	ip, _ := s.allocV4(mac, nil, "cam")
	s.commit(&Lease{Key: string(v4Key(mac)), MAC: mac.String(), IP: ip.String(), Hostname: "cam"})

	// Bare name, dotted name, and a non-matching suffix must behave.
	if _, ok := s.LookupHost("cam"); !ok {
		t.Fatal("bare hostname not found")
	}
	if _, ok := s.LookupHost("cam.lan"); !ok {
		t.Fatal("hostname.domain not found")
	}
	if _, ok := s.LookupHost("cam.other"); ok {
		t.Fatal("hostname under foreign suffix resolved")
	}
}

// TestServerLifecycleStartStopRestart ensures the server can be stopped and
// restarted (the config-reload path) without leaking state.
func TestServerLifecycleStartStopRestart(t *testing.T) {
	if os.Getenv("DHCP_SOCKET_TESTS") == "" {
		t.Skip("requires binding UDP 67/547 — set DHCP_SOCKET_TESTS=1 to run")
	}
	cfg, dir := testConfig(t)
	s := newTestServer(t, cfg, dir)
	if !s.Enabled() {
		t.Fatal("server should be enabled")
	}
	if err := s.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	s.Stop()
	// Restart must actually bind again (not be a no-op).
	if err := s.Start(); err != nil {
		t.Fatalf("restart: %v", err)
	}
	s.Stop()
	// Stop is idempotent.
	s.Stop()
}

// ---- DHCPv6 state machine ----

// fakeV6Conn records replies for the v6 handler tests.
type fakeV6Conn struct {
	replies [][]byte
}

func (f *fakeV6Conn) WriteTo(b []byte, _ net.Addr) (int, error) {
	f.replies = append(f.replies, b)
	return len(b), nil
}

func (f *fakeV6Conn) ReadFrom(b []byte) (int, net.Addr, error) { return 0, nil, net.ErrClosed }
func (f *fakeV6Conn) Close() error                             { return nil }
func (f *fakeV6Conn) LocalAddr() net.Addr                      { return &net.UDPAddr{IP: net.ParseIP("fd00::1"), Port: 547} }
func (f *fakeV6Conn) SetDeadline(t time.Time) error            { return nil }
func (f *fakeV6Conn) SetReadDeadline(t time.Time) error        { return nil }
func (f *fakeV6Conn) SetWriteDeadline(t time.Time) error       { return nil }

// clientDUID6 builds a deterministic client DUID-LL for tests.
func clientDUID6(mac byte) dhcpv6.DUID {
	return &dhcpv6.DUIDLL{
		HWType:        1,
		LinkLayerAddr: net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, mac},
	}
}

func TestV6SolicitAdvertiseRequest(t *testing.T) {
	t.Parallel()
	cfg, dir := testConfig(t)
	s := newTestServer(t, cfg, dir)
	conn := &fakeV6Conn{}
	peer := &net.UDPAddr{IP: net.ParseIP("fe80::1"), Port: 546}

	// SOLICIT
	sol, err := dhcpv6.NewSolicit(net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x11},
		dhcpv6.WithClientID(clientDUID6(0x11)),
		dhcpv6.WithIANA(dhcpv6.OptIAAddress{IPv6Addr: net.IPv6zero}),
	)
	if err != nil {
		t.Fatal(err)
	}
	s.handleV6(conn, peer, sol)
	if len(conn.replies) != 1 {
		t.Fatalf("SOLICIT: %d replies, want 1", len(conn.replies))
	}
	raw, err := dhcpv6.FromBytes(conn.replies[0])
	if err != nil {
		t.Fatalf("parse advertise: %v", err)
	}
	adv := raw.(*dhcpv6.Message)
	if adv.Type() != dhcpv6.MessageTypeAdvertise {
		t.Fatalf("reply type = %v, want ADVERTISE", adv.Type())
	}
	advertised := requestedAddr6(adv)
	if advertised == nil || !advertised.Equal(net.ParseIP("fd00::100")) {
		t.Fatalf("advertised = %v, want fd00::100", advertised)
	}
	// No lease committed yet from a SOLICIT alone.
	if n := len(s.leases); n != 0 {
		t.Fatalf("SOLICIT committed %d leases, want 0", n)
	}

	// REQUEST the advertised address.
	req, err := dhcpv6.NewRequestFromAdvertise(adv,
		dhcpv6.WithClientID(clientDUID6(0x11)),
		dhcpv6.WithIANA(dhcpv6.OptIAAddress{IPv6Addr: advertised}),
	)
	if err != nil {
		t.Fatal(err)
	}
	conn.replies = nil
	s.handleV6(conn, peer, req)
	if len(conn.replies) != 1 {
		t.Fatalf("REQUEST: %d replies, want 1", len(conn.replies))
	}
	raw2, err := dhcpv6.FromBytes(conn.replies[0])
	if err != nil {
		t.Fatal(err)
	}
	reply := raw2.(*dhcpv6.Message)
	if reply.Type() != dhcpv6.MessageTypeReply {
		t.Fatalf("reply type = %v, want REPLY", reply.Type())
	}
	if got := requestedAddr6(reply); !got.Equal(advertised) {
		t.Fatalf("reply addr = %v, want %v", got, advertised)
	}
	// Committed with the hostname registered for DNS resolution.
	key := v6Key(duidHex(clientDUID6(0x11)))
	if s.leases[key] == nil {
		t.Fatal("no committed v6 lease after REQUEST")
	}

	// A second client must get a different address.
	sol2, err := dhcpv6.NewSolicit(net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x12},
		dhcpv6.WithClientID(clientDUID6(0x12)),
		dhcpv6.WithIANA(dhcpv6.OptIAAddress{IPv6Addr: net.IPv6zero}),
	)
	if err != nil {
		t.Fatal(err)
	}
	conn.replies = nil
	s.handleV6(conn, peer, sol2)
	raw3, err := dhcpv6.FromBytes(conn.replies[0])
	if err != nil {
		t.Fatal(err)
	}
	adv2 := raw3.(*dhcpv6.Message)
	if got := requestedAddr6(adv2); got.Equal(advertised) {
		t.Fatalf("second client got the first client's address %v", got)
	}
}

func TestV6RapidCommit(t *testing.T) {
	t.Parallel()
	cfg, dir := testConfig(t)
	s := newTestServer(t, cfg, dir)
	conn := &fakeV6Conn{}
	peer := &net.UDPAddr{IP: net.ParseIP("fe80::1"), Port: 546}

	sol, err := dhcpv6.NewSolicit(net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x13},
		dhcpv6.WithClientID(clientDUID6(0x13)),
		dhcpv6.WithOption(&dhcpv6.OptionGeneric{OptionCode: dhcpv6.OptionRapidCommit}),
		dhcpv6.WithIANA(dhcpv6.OptIAAddress{IPv6Addr: net.IPv6zero}),
	)
	if err != nil {
		t.Fatal(err)
	}
	s.handleV6(conn, peer, sol)
	if len(conn.replies) != 1 {
		t.Fatalf("rapid-commit SOLICIT: %d replies, want 1", len(conn.replies))
	}
	raw, err := dhcpv6.FromBytes(conn.replies[0])
	if err != nil {
		t.Fatal(err)
	}
	reply := raw.(*dhcpv6.Message)
	if reply.Type() != dhcpv6.MessageTypeReply {
		t.Fatalf("rapid-commit reply type = %v, want REPLY (not ADVERTISE)", reply.Type())
	}
	// Rapid commit commits the lease immediately.
	if n := len(s.leases); n != 1 {
		t.Fatalf("rapid commit left %d leases, want 1", n)
	}
}

func TestV6Release(t *testing.T) {
	t.Parallel()
	cfg, dir := testConfig(t)
	s := newTestServer(t, cfg, dir)
	conn := &fakeV6Conn{}
	peer := &net.UDPAddr{IP: net.ParseIP("fe80::1"), Port: 546}
	duid := clientDUID6(0x14)
	hexID := duidHex(duid)

	// Commit a lease directly.
	ip, _ := s.allocV6(hexID, "printer", nil)
	s.commit(&Lease{Key: string(v6Key(hexID)), DUID: hexID, IP: ip.String(), Hostname: "printer"})

	rel, err := dhcpv6.NewMessage(
		dhcpv6.WithClientID(duid),
		dhcpv6.WithIANA(dhcpv6.OptIAAddress{IPv6Addr: ip}),
	)
	if err != nil {
		t.Fatal(err)
	}
	rel.MessageType = dhcpv6.MessageTypeRelease
	s.handleV6(conn, peer, rel)
	if s.leases[v6Key(hexID)] != nil {
		t.Fatal("v6 lease still present after RELEASE")
	}
}

func TestV6RequestUnavailableNoAddrs(t *testing.T) {
	t.Parallel()
	cfg, dir := testConfig(t)
	s := newTestServer(t, cfg, dir)
	conn := &fakeV6Conn{}
	peer := &net.UDPAddr{IP: net.ParseIP("fe80::1"), Port: 546}

	// REQUEST an address from a different (unrelated) network.
	req, err := dhcpv6.NewMessage(
		dhcpv6.WithClientID(clientDUID6(0x15)),
		dhcpv6.WithIANA(dhcpv6.OptIAAddress{IPv6Addr: net.ParseIP("2001:db8::99")}),
	)
	if err != nil {
		t.Fatal(err)
	}
	req.MessageType = dhcpv6.MessageTypeRequest
	s.handleV6(conn, peer, req)
	if len(conn.replies) != 1 {
		t.Fatalf("got %d replies, want 1", len(conn.replies))
	}
	raw, err := dhcpv6.FromBytes(conn.replies[0])
	if err != nil {
		t.Fatal(err)
	}
	reply := raw.(*dhcpv6.Message)
	// The reply must carry a polite NoAddrsAvail, not an assignment.
	if got := requestedAddr6(reply); got != nil {
		t.Fatalf("unavailable request answered with address %v", got)
	}
}

var _ = filepath.Join // keep import if tests change
