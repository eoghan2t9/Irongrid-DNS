package filter

import (
	"strings"
	"testing"
)

// TestRegexBlocklistRules verifies AdGuard-style /pattern/ rules: anchoring,
// the /i flag, per-list attribution, classic rules coexisting, and broken
// patterns being skipped without failing the list.
func TestRegexBlocklistRules(t *testing.T) {
	e := NewEngine()
	res, err := e.LoadList("re1", "Regex list", []byte(strings.Join([]string{
		"/^ads\\./",                  // first label is "ads"
		"/\\.trackers\\./i",          // any label, case-insensitive
		"/this pattern is [unclosed", // invalid -> skipped
		"plain.example.com",          // classic rule still works alongside
	}, "\n")))
	if err != nil {
		t.Fatal(err)
	}
	if res.Regexes != 2 {
		t.Fatalf("regexes parsed = %d, want 2 (one rule is invalid)", res.Regexes)
	}
	e.Compile()

	cases := []struct {
		name string
		want Action
	}{
		{"ads.example.com.", Block},    // ^ads\. matches the first label
		{"x.ads.example.com.", Allow},  // ^ads\. anchors to the start — no match
		{"c.ads.trackers.com.", Block}, // .trackers. matches any label
		{"c.ads.TRACKERS.com.", Block}, // /i flag makes it case-insensitive
		{"plain.example.com.", Block},  // classic rule next to the regexes
		{"example.com.", Allow},
	}
	for _, c := range cases {
		d := e.DecideDomain(c.name)
		if d.Action != c.want {
			t.Errorf("DecideDomain(%s) = %v (%s), want %v", c.name, d.Action, d.Reason, c.want)
		}
	}

	// A regex block carries the list name for the dashboard's blocked-by row.
	d := e.DecideDomain("ads.example.com.")
	if d.Action != Block || d.ListName != "Regex list" {
		t.Fatalf("regex block reason = %q / list %q, want blocklist:regex / Regex list", d.Reason, d.ListName)
	}
}

// TestRegexExceptions verifies @@/pattern/ rules override block rules (both
// regex and classic domain rules) — matching AdGuard's exception semantics.
func TestRegexExceptions(t *testing.T) {
	e := NewEngine()
	if _, err := e.LoadList("re2", "Regex list", []byte(strings.Join([]string{
		"/ads\\./",         // blocks any name containing "ads."
		"@@/^allowed\\./",  // whitelists names starting with "allowed."
		"@@/^keep\\./",     // whitelist regex that beats a classic block rule
		"keep.example.com", // classic subtree block
	}, "\n"))); err != nil {
		t.Fatal(err)
	}
	e.Compile()

	cases := []struct {
		name string
		want Action
	}{
		{"ads.example.com.", Block},         // matches /ads\./
		{"blocked.ads.example.com.", Block}, // matches /ads\./
		{"allowed.example.com.", Allow},     // allow regex
		{"allowed.ads.example.com.", Allow}, // allow regex beats the block regex
		{"keep.example.com.", Allow},        // allow regex beats the classic block
		{"x.keep.example.com.", Block},      // classic subtree rule still blocks
	}
	for _, c := range cases {
		d := e.DecideDomain(c.name)
		if d.Action != c.want {
			t.Errorf("DecideDomain(%s) = %v (%s), want %v", c.name, d.Action, d.Reason, c.want)
		}
	}
}

// TestRegexUserLists verifies /pattern/ entries in the manual blacklist and
// whitelist fields (SetUserLists) compile and take precedence like domain
// entries do.
func TestRegexUserLists(t *testing.T) {
	e := NewEngine()
	e.SetUserLists([]string{"/^track\\./", "blocked.example.com"}, []string{"/^keep\\./"})
	e.Compile()

	if d := e.DecideDomain("track.example.com."); d.Action != Block {
		t.Fatalf("user regex block: got %v (%s), want Block", d.Action, d.Reason)
	}
	if d := e.DecideDomain("blocked.example.com."); d.Action != Block {
		t.Fatalf("user domain block: got %v, want Block", d.Action)
	}
	if d := e.DecideDomain("keep.example.com."); d.Action != Allow {
		t.Fatalf("user regex allow: got %v (%s), want Allow", d.Action, d.Reason)
	}
	// A whitelist regex overrides a blocklist regex for the same name.
	e2 := NewEngine()
	if _, err := e2.LoadList("l", "L", []byte("/^keep\\./")); err != nil {
		t.Fatal(err)
	}
	e2.SetUserLists(nil, []string{"/^keep\\./"})
	e2.Compile()
	if d := e2.DecideDomain("keep.example.com."); d.Action != Allow {
		t.Fatalf("whitelist regex should override block regex: got %v (%s)", d.Action, d.Reason)
	}
	// Stats counts compiled regex rules.
	if st := e.Stats(); st["regex_rules"] < 1 {
		t.Fatalf("stats regex_rules = %d, want >= 1", st["regex_rules"])
	}
	// Compile is idempotent: calling it again without an intervening Reset
	// must not duplicate rules (domain entries dedupe via maps; regexes need
	// explicit rebuilds).
	e.Compile()
	e.Compile()
	if st := e.Stats(); st["regex_rules"] != 1 {
		t.Fatalf("stats regex_rules after repeated Compile = %d, want 1 (no duplication)", st["regex_rules"])
	}
	if d := e.DecideDomain("track.example.com."); d.Action != Block {
		t.Fatalf("user regex block after repeated Compile: got %v (%s), want Block", d.Action, d.Reason)
	}
}
