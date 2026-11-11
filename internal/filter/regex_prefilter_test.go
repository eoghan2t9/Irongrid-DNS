package filter

import (
	"math/rand/v2"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// The pre-check may only ever rule a name OUT: whenever mayMatch is false the
// regex itself must not match. This property is what keeps decisions identical.
func assertNeverSkipsAMatch(t *testing.T, rr *RegexRule, names []string) {
	t.Helper()
	for _, n := range names {
		if rr.Re.MatchString(n) && !rr.mayMatch(n) {
			t.Fatalf("pattern %q matches %q but the pre-check (minLen=%d lits=%q fold=%q) skipped it", rr.Re.String(), n, rr.minLen, rr.lits, rr.foldLits)
		}
	}
}

func TestAnalyzeRegexDerivedConditions(t *testing.T) {
	cases := []struct {
		pattern  string
		minLen   int
		lits     []string // must all be present (order-insensitive)
		foldLits []string
	}{
		{`^139\.45\.197\.2(4[0-9]|5[0-4]):`, 15, []string{"139.45.197.2", ":"}, nil},
		{`(https?:\/\/)213\.32\.115\..{100,}`, 7 + 11 + 100, []string{"213.32.115.", "://", "http"}, nil},
		{`^(a|c)\.[0-9a-f]{56}\.com$`, 1 + 1 + 56 + 4, []string{".com", "."}, nil},
		{`(?i)fcp/v1`, 6, nil, []string{"fcp/v1"}},
		{`(?i)ask`, 3, nil, nil}, // k and s have non-ASCII case-fold partners: no fold literal
		{`(a|bb)c`, 2, []string{"c"}, nil},
		{`x*y?`, 0, nil, nil},
		{`\.(gif|jpe?g)#(\/?.+)?(\/(ad)s?\/|\/ad-)`, 9, []string{"#", "."}, nil},
	}
	for _, c := range cases {
		minLen, lits, fold := analyzeRegex(c.pattern)
		if minLen != c.minLen {
			t.Errorf("%s: minLen %d want %d", c.pattern, minLen, c.minLen)
		}
		for _, want := range c.lits {
			if !slices.Contains(lits, want) {
				t.Errorf("%s: lits %q missing %q", c.pattern, lits, want)
			}
		}
		if len(c.lits) == 0 && len(lits) != 0 {
			t.Errorf("%s: unexpected lits %q", c.pattern, lits)
		}
		if !slices.Equal(fold, c.foldLits) {
			t.Errorf("%s: foldLits %q want %q", c.pattern, fold, c.foldLits)
		}
	}
}

func TestPrefilterNeverSkipsAMatch(t *testing.T) {
	patterns := []string{
		`^139\.45\.197\.2(4[0-9]|5[0-4]):`, `^88\.208\.22\.[1234]$`, `62.76.25.2(7|8)`,
		`^(a|c)\.[0-9a-f]{56}\.com$`, `^anon1.gt\d{6}.com$`, `(?i)fcp/v1`, `(?i)ads?\.`,
		`(https?:\/\/)104\.154\..{100,}`, `^(mon|tue|wed)\d{1,2}\.\w{2}\d{1,6}\w{4}\.com$`,
		`ad[sz]?\.example\.com`, `(foo|bar)+baz`, `^x{3,5}y$`, `a.*b.*c`, `(?s)a.b`, `é+`, `(?i)k`,
		`^$`, `.*`, `a|b|c`, `\bads\b`, `[a-c]{2}d`, `(ab)*c`, `^(?:ab){2,}$`, `ü.com$`, `(?m)^x`,
	}
	alphabet := []string{"a", "b", "c", "d", "x", "y", "k", "K", "é", "ü", ".", "-", "1", "2", "9", "ads", "foo", "baz", "com", "example", "K"}
	rng := rand.New(rand.NewPCG(7, 11))
	var names []string
	for range 20000 {
		var sb strings.Builder
		for range 1 + rng.IntN(10) {
			sb.WriteString(alphabet[rng.IntN(len(alphabet))])
		}
		names = append(names, sb.String())
	}
	// names built to actually match several patterns
	names = append(names, "139.45.197.245:", "88.208.22.3", "62.76.25.27", "mon1.ab123456abcd.com", "ads.example.com",
		"adz.example.com", "foobarbaz", "xxxy", "a-b-c", "aXb", "fcp/v1", "FCP/V1", "ads.", "ADS.", "kk", "K",
		"a.com", "anon1xgt123456xcom", "https://104.154.1.1/"+strings.Repeat("a", 100))
	for _, p := range patterns {
		rr := parseRegexRule("/"+strings.ReplaceAll(p, "/", `\/`)+"/", "t")
		if rr == nil {
			t.Fatalf("pattern %q did not compile", p)
		}
		assertNeverSkipsAMatch(t, rr, names)
	}
}

// Real regex rules from the cached lists, against real listed domains,
// subdomains and absent names: the pre-check must never skip a match, and
// should skip nearly all of them on a normal name.
func TestPrefilterOnRealListRegexes(t *testing.T) {
	files, _ := filepath.Glob("/home/ubuntu/data/lists/*.txt")
	if len(files) == 0 {
		t.Skip("no cached blocklists on this machine")
	}
	e := NewEngine()
	var domains []string
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		id := strings.TrimSuffix(filepath.Base(f), ".txt")
		if _, err := e.LoadList(id, id, b); err != nil {
			t.Fatal(err)
		}
		bd, be := map[string]struct{}{}, map[string]struct{}{}
		var rb, ra []RegexRule
		parseContent(string(b), id, bd, be, map[string]struct{}{}, map[string]struct{}{}, map[string]struct{}{}, map[string]struct{}{}, nil, &rb, &ra)
		for d := range bd {
			domains = append(domains, d, "www."+d)
			if len(domains) > 400000 {
				break
			}
		}
	}
	e.Compile()
	rs := e.rs.Load()
	rules := append(append([]RegexRule{}, rs.blockRegex...), rs.allowRegex...)
	if len(rules) == 0 {
		t.Skip("no regex rules in the cached lists")
	}
	names := append([]string{"example.com", "www.google.com", "mon1.ab123456abcd.com", "anon1xgt123456xcom"}, domains...)
	var checks, skipped int
	for i := range rules {
		assertNeverSkipsAMatch(t, &rules[i], names)
	}
	for _, n := range names[:5000] {
		for i := range rules {
			checks++
			if !rules[i].mayMatch(n) {
				skipped++
			}
		}
	}
	t.Logf("%d regex rules; pre-check skipped %d of %d (%.1f%%) rule evaluations on real names", len(rules), skipped, checks, 100*float64(skipped)/float64(checks))
	if float64(skipped)/float64(checks) < 0.8 {
		t.Errorf("pre-check skips only %.1f%% — expected most rule evaluations to be avoided", 100*float64(skipped)/float64(checks))
	}
}
