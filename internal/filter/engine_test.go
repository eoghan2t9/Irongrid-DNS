package filter

import (
	"net"
	"testing"
)

func TestSplitRule(t *testing.T) {
	cases := []struct {
		in         string
		want       string
		exact, exc bool
		ok         bool
	}{
		{"example.com", "example.com", false, false, true},
		{"*.example.com", "example.com", false, false, true},
		{".example.com", "example.com", false, false, true},
		{"=example.com", "example.com", true, false, true},
		{"||ads.example.com^", "ads.example.com", false, false, true},
		{"@@||allow.com^", "allow.com", false, true, true},
		{"0.0.0.0 foo", "", false, false, false}, // hosts line handled elsewhere
		{"// comment", "", false, false, false},
		{"single", "", false, false, false}, // single label skipped
	}
	for _, c := range cases {
		got, exact, exc, ok := splitRule(c.in)
		if ok != c.ok || got != c.want || exact != c.exact || exc != c.exc {
			t.Errorf("splitRule(%q) = (%q, %v, %v, %v), want (%q, %v, %v, %v)",
				c.in, got, exact, exc, ok, c.want, c.exact, c.exc, c.ok)
		}
	}
}

func TestBlockAndWhitelist(t *testing.T) {
	e := NewEngine()
	// hosts format + adblock format + plain
	_, err := e.LoadList("test", "test list", []byte("0.0.0.0 blocked.net\n||ads.example.com^\nplain.org\n"))
	if err != nil {
		t.Fatal(err)
	}
	e.SetUserLists(nil, []string{"ads.example.com"}) // whitelist overrides adblock entry
	e.Compile()

	cases := []struct {
		qname   string
		blocked bool
	}{
		{"blocked.net.", true},
		{"www.blocked.net.", true},        // subdomain blocked
		{"ads.example.com.", false},       // whitelisted overrides
		{"sub.ads.example.com.", false},   // whitelist subtree overrides
		{"plain.org.", true},
		{"other.org.", false},
	}
	for _, c := range cases {
		d := e.DecideDomain(c.qname)
		if (d.Action == Block) != c.blocked {
			t.Errorf("DecideDomain(%q) = %v (%s), want blocked=%v", c.qname, d.Action, d.Reason, c.blocked)
		}
	}
}

func TestAdblockExceptionFromList(t *testing.T) {
	e := NewEngine()
	_, err := e.LoadList("ad", "ad", []byte("||tracker.com^\n@@||good.tracker.com^\n"))
	if err != nil {
		t.Fatal(err)
	}
	e.Compile()
	if d := e.DecideDomain("tracker.com."); d.Action != Block {
		t.Errorf("tracker.com should be blocked")
	}
	if d := e.DecideDomain("good.tracker.com."); d.Action != Allow {
		t.Errorf("good.tracker.com should be allowed by inline exception")
	}
}

func TestIPRules(t *testing.T) {
	e := NewEngine()
	_, err := e.LoadList("ip", "ip", []byte("1.2.3.4\n"))
	if err != nil {
		t.Fatal(err)
	}
	e.Compile()
	blocked, reason := e.CheckIPs([]net.IP{net.ParseIP("1.2.3.4")})
	if !blocked || reason == "" {
		t.Errorf("expected IP 1.2.3.4 to be blocked, got %v %q", blocked, reason)
	}
	blocked, _ = e.CheckIPs([]net.IP{net.ParseIP("9.9.9.9")})
	if blocked {
		t.Errorf("9.9.9.9 should not be blocked")
	}
}

func TestWhitelistAlwaysWins(t *testing.T) {
	e := NewEngine()
	if _, err := e.LoadList("test", "test", []byte("manual.org\n")); err != nil {
		t.Fatal(err)
	}
	e.SetUserLists(nil, []string{"manual.org"}) // whitelisted despite blocklist
	e.Compile()
	if d := e.DecideDomain("manual.org."); d.Action != Allow {
		t.Errorf("whitelisted domain must never be blocked, got %v (%s)", d.Action, d.Reason)
	}
}
