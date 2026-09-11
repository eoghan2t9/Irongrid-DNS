package vpn

import (
	"context"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeRunner records every command instead of executing it, and lets a test
// fail specific commands by prefix.
type fakeRunner struct {
	mu       sync.Mutex
	commands []string
	fail     map[string]bool // command prefix -> return an error
}

func (f *fakeRunner) key(name string, args ...string) string {
	return name + " " + strings.Join(args, " ")
}

func (f *fakeRunner) record(cmd string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.commands = append(f.commands, cmd)
	for prefix := range f.fail {
		if strings.HasPrefix(cmd, prefix) {
			return errFake
		}
	}
	return nil
}

func (f *fakeRunner) LookPath(name string) (string, error) { return "/usr/bin/" + name, nil }

func (f *fakeRunner) Run(name string, args ...string) error {
	return f.record(f.key(name, args...))
}

func (f *fakeRunner) RunStdin(name string, args []string, stdin []byte) error {
	return f.record(f.key(name, args...) + " <<< " + string(stdin))
}

func (f *fakeRunner) has(substr string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, c := range f.commands {
		if strings.Contains(c, substr) {
			return true
		}
	}
	return false
}

var errFake = fakeError("fake failure")

type fakeError string

func (e fakeError) Error() string { return string(e) }

// stubProvider satisfies Provider without any network access.
type stubProvider struct {
	name string
	peer PeerConfig
	err  error
}

func (s *stubProvider) Name() string { return s.name }
func (s *stubProvider) Connect(ctx context.Context, region string) (PeerConfig, error) {
	if s.err != nil {
		return PeerConfig{}, s.err
	}
	return s.peer, nil
}

func newTestManager(t *testing.T) (*Manager, *fakeRunner) {
	t.Helper()
	r := &fakeRunner{fail: map[string]bool{}}
	m := &Manager{
		runner: r,
		active: make(map[string]*activeProfile),
		work:   make(chan workItem, 64),
		closed: make(chan struct{}),
	}
	m.snap.Store(&snapshot{})
	m.workers.Add(1)
	go m.worker()
	t.Cleanup(m.Close)
	return m, r
}

func TestMatchRoute_LongestSuffixWins(t *testing.T) {
	routes := []route{
		{profile: "general", domains: []string{"example.com"}},
		{profile: "uk", domains: []string{"bbc.co.uk", "iplayer.bbc.co.uk"}},
	}
	tests := []struct {
		name string
		want string // profile, or "" for no match
	}{
		{"bbc.co.uk", "uk"},
		{"www.bbc.co.uk", "uk"},
		{"iplayer.bbc.co.uk", "uk"},      // exact match on the more specific route
		{"live.iplayer.bbc.co.uk", "uk"}, // longest-suffix still wins the same profile
		{"example.com", "general"},
		{"sub.example.com", "general"},
		{"unrelated.org", ""},
		{"notbbc.co.uk", ""}, // must not match as a suffix of bbc.co.uk
	}
	for _, tt := range tests {
		got := matchRoute(routes, tt.name)
		gotProfile := ""
		if got != nil {
			gotProfile = got.profile
		}
		if gotProfile != tt.want {
			t.Errorf("matchRoute(%q) = %q, want %q", tt.name, gotProfile, tt.want)
		}
	}
}

func TestReconcile_BringsUpConfiguredProfile(t *testing.T) {
	m, r := newTestManager(t)
	orig := providerFactory
	providerFactory = func(kind string, creds Credentials) (Provider, error) {
		return &stubProvider{name: kind, peer: PeerConfig{
			PrivateKey: "cHJpdg==", PeerPublicKey: "cHVi", Endpoint: "203.0.113.1:51820",
			AllowedIPs: []string{"0.0.0.0/0"},
		}}, nil
	}
	t.Cleanup(func() { providerFactory = orig })

	profiles := []ProfileSpec{{ID: "uk-iplayer", Provider: "pia", Region: "uk_london"}}
	routes := []RouteSpec{{Profile: "uk-iplayer", Domains: []string{"bbc.co.uk"}}}
	if err := m.Reconcile(context.Background(), profiles, routes, Credentials{}); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}

	if !r.has("ip link add dev igvpn") {
		t.Errorf("expected a WireGuard interface to be created, commands: %v", r.commands)
	}
	if !r.has("wg set igvpn") {
		t.Errorf("expected the WireGuard peer to be configured, commands: %v", r.commands)
	}
	if !r.has("ip rule add fwmark") {
		t.Errorf("expected a policy-routing rule, commands: %v", r.commands)
	}
	if !r.has("nft -f -") {
		t.Errorf("expected the nftables marking table to be programmed, commands: %v", r.commands)
	}
	status := m.Status()
	if len(status) != 1 || status[0].ID != "uk-iplayer" {
		t.Fatalf("Status() = %+v, want one profile uk-iplayer", status)
	}
}

func TestReconcile_UnchangedProfileIsNotReconnected(t *testing.T) {
	m, r := newTestManager(t)
	orig := providerFactory
	connectCalls := 0
	providerFactory = func(kind string, creds Credentials) (Provider, error) {
		return &stubProvider{name: kind, peer: PeerConfig{
			PrivateKey: "cHJpdg==", PeerPublicKey: "cHVi", Endpoint: "203.0.113.1:51820",
			AllowedIPs: []string{"0.0.0.0/0"},
		}}, nil
	}
	t.Cleanup(func() { providerFactory = orig })

	profiles := []ProfileSpec{{ID: "p1", Provider: "pia", Region: "uk_london"}}
	if err := m.Reconcile(context.Background(), profiles, nil, Credentials{}); err != nil {
		t.Fatalf("first Reconcile: %v", err)
	}
	before := len(r.commands)
	_ = connectCalls

	// Reconcile again with the exact same profile — must not tear down or
	// recreate the interface.
	if err := m.Reconcile(context.Background(), profiles, nil, Credentials{}); err != nil {
		t.Fatalf("second Reconcile: %v", err)
	}
	if r.has("ip link del") {
		t.Errorf("unchanged profile should not have been torn down, commands: %v", r.commands[before:])
	}
	addCount := 0
	for _, c := range r.commands[before:] {
		if strings.HasPrefix(c, "ip link add dev "+status(m)[0].Iface) {
			addCount++
		}
	}
	if addCount != 0 {
		t.Errorf("unchanged profile should not have recreated its interface, commands: %v", r.commands[before:])
	}
}

func status(m *Manager) []ProfileStatus { return m.Status() }

func TestObserve_RoutesMatchedDomainIPs(t *testing.T) {
	m, r := newTestManager(t)
	orig := providerFactory
	providerFactory = func(kind string, creds Credentials) (Provider, error) {
		return &stubProvider{name: kind, peer: PeerConfig{
			PrivateKey: "cHJpdg==", PeerPublicKey: "cHVi", Endpoint: "203.0.113.1:51820",
			AllowedIPs: []string{"0.0.0.0/0"},
		}}, nil
	}
	t.Cleanup(func() { providerFactory = orig })

	profiles := []ProfileSpec{{ID: "uk-iplayer", Provider: "pia", Region: "uk_london"}}
	routes := []RouteSpec{{Profile: "uk-iplayer", Domains: []string{"bbc.co.uk"}}}
	if err := m.Reconcile(context.Background(), profiles, routes, Credentials{}); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}

	m.Observe(Answer{Name: "www.bbc.co.uk", IPs: []net.IP{net.ParseIP("151.101.0.81")}, TTL: 5 * time.Minute})

	deadline := time.Now().Add(2 * time.Second)
	for !r.has("add element") && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if !r.has("add element") {
		t.Errorf("expected the resolved IP to be added to an nft set, commands: %v", r.commands)
	}
	if !r.has("151.101.0.81") {
		t.Errorf("expected the specific resolved IP in the nft element command, commands: %v", r.commands)
	}
}

func TestProxyAnswer_ReturnsPublicIPOnlyForConnectedProxyRoute(t *testing.T) {
	m, _ := newTestManager(t)
	orig := providerFactory
	providerFactory = func(kind string, creds Credentials) (Provider, error) {
		return &stubProvider{name: kind, peer: PeerConfig{PrivateKey: "cHJpdg==", PeerPublicKey: "cHVi", Endpoint: "1.2.3.4:51820"}}, nil
	}
	t.Cleanup(func() { providerFactory = orig })
	m.SetPublicIP(net.ParseIP("203.0.113.5"))

	profiles := []ProfileSpec{
		{ID: "proxied", Provider: "pia", Region: "uk_london"},
		{ID: "marking-only", Provider: "pia", Region: "us_new_york_city"},
	}
	routes := []RouteSpec{
		{Profile: "proxied", Domains: []string{"imgur.com"}, Proxy: true},
		{Profile: "marking-only", Domains: []string{"example.com"}, Proxy: false},
	}
	if err := m.Reconcile(context.Background(), profiles, routes, Credentials{}); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}

	if ip, ok := m.ProxyAnswer("www.imgur.com"); !ok || !ip.Equal(net.ParseIP("203.0.113.5")) {
		t.Errorf("ProxyAnswer(www.imgur.com) = %v, %v; want 203.0.113.5, true", ip, ok)
	}
	if _, ok := m.ProxyAnswer("example.com"); ok {
		t.Error("ProxyAnswer(example.com) should be false — that route has Proxy:false")
	}
	if _, ok := m.ProxyAnswer("unrelated.org"); ok {
		t.Error("ProxyAnswer(unrelated.org) should be false — no matching route")
	}
}

func TestProxyAnswer_FalseWhenProfileNotConnected(t *testing.T) {
	m, _ := newTestManager(t)
	orig := providerFactory
	providerFactory = func(kind string, creds Credentials) (Provider, error) {
		return &stubProvider{err: errFake}, nil
	}
	t.Cleanup(func() { providerFactory = orig })
	m.SetPublicIP(net.ParseIP("203.0.113.5"))

	profiles := []ProfileSpec{{ID: "proxied", Provider: "pia", Region: "uk_london"}}
	routes := []RouteSpec{{Profile: "proxied", Domains: []string{"imgur.com"}, Proxy: true}}
	// Reconcile returns an error (the profile fails to connect via the
	// stub's forced error) but must not panic — ProxyAnswer must then
	// report no match rather than pointing traffic at a dead tunnel.
	_ = m.Reconcile(context.Background(), profiles, routes, Credentials{})

	if _, ok := m.ProxyAnswer("imgur.com"); ok {
		t.Error("ProxyAnswer should be false when the matching profile failed to connect")
	}
}

func TestMatchProxyRoute_MirrorsProxyAnswer(t *testing.T) {
	m, _ := newTestManager(t)
	orig := providerFactory
	providerFactory = func(kind string, creds Credentials) (Provider, error) {
		return &stubProvider{name: kind, peer: PeerConfig{PrivateKey: "cHJpdg==", PeerPublicKey: "cHVi", Endpoint: "1.2.3.4:51820"}}, nil
	}
	t.Cleanup(func() { providerFactory = orig })

	profiles := []ProfileSpec{{ID: "proxied", Provider: "nordvpn", Region: "gb"}}
	routes := []RouteSpec{{Profile: "proxied", Domains: []string{"imgur.com"}, Proxy: true}}
	if err := m.Reconcile(context.Background(), profiles, routes, Credentials{}); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}

	id, ok := m.MatchProxyRoute("i.imgur.com")
	if !ok || id != "proxied" {
		t.Errorf("MatchProxyRoute(i.imgur.com) = %q, %v; want proxied, true", id, ok)
	}
	if _, ok := m.MatchProxyRoute("other.com"); ok {
		t.Error("MatchProxyRoute(other.com) should be false")
	}
}

func TestObserve_UnmatchedDomainDoesNothing(t *testing.T) {
	m, r := newTestManager(t)
	orig := providerFactory
	providerFactory = func(kind string, creds Credentials) (Provider, error) {
		return &stubProvider{name: kind, peer: PeerConfig{PrivateKey: "cHJpdg==", PeerPublicKey: "cHVi", Endpoint: "1.2.3.4:51820"}}, nil
	}
	t.Cleanup(func() { providerFactory = orig })

	profiles := []ProfileSpec{{ID: "uk-iplayer", Provider: "pia", Region: "uk_london"}}
	routes := []RouteSpec{{Profile: "uk-iplayer", Domains: []string{"bbc.co.uk"}}}
	if err := m.Reconcile(context.Background(), profiles, routes, Credentials{}); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	before := len(r.commands)

	m.Observe(Answer{Name: "example.com", IPs: []net.IP{net.ParseIP("93.184.216.34")}, TTL: time.Minute})
	time.Sleep(50 * time.Millisecond)

	if len(r.commands) != before {
		t.Errorf("unmatched domain should not have issued any commands, got: %v", r.commands[before:])
	}
}
