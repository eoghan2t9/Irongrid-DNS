package filter

import (
	"fmt"
	"math/rand/v2"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// refDecide is the pre-compaction block logic, kept as an oracle: plain maps,
// exact check, then the ancestor walk (the allow side is empty in this test).
func refDecide(blockDomains, blockExact map[string]struct{}, qname string) bool {
	qname = normalizeDomain(qname)
	if qname == "" {
		return false
	}
	if _, ok := blockExact[qname]; ok {
		return true
	}
	if _, ok := blockDomains[qname]; ok {
		return true
	}
	lastDot := strings.LastIndexByte(qname, '.')
	for i := range lastDot {
		if qname[i] != '.' {
			continue
		}
		if _, ok := blockDomains[qname[i+1:]]; ok {
			return true
		}
	}
	return false
}

// TestCompactEngineMatchesMapOracle loads the real cached blocklists (when
// present on this machine) through the compact engine and checks every
// decision against a plain-map oracle built with the original parser.
func TestCompactEngineMatchesMapOracle(t *testing.T) {
	files, _ := filepath.Glob("/home/ubuntu/data/lists/*.txt")
	if len(files) == 0 {
		t.Skip("no cached blocklists on this machine")
	}
	e := NewEngine()
	refDomains, refExact := map[string]struct{}{}, map[string]struct{}{}
	ips, allow, allowExact, allowIPs := map[string]struct{}{}, map[string]struct{}{}, map[string]struct{}{}, map[string]struct{}{}
	var rb, ra []RegexRule
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		id := strings.TrimSuffix(filepath.Base(f), ".txt")
		if _, err := e.LoadList(id, id, b); err != nil {
			t.Fatal(err)
		}
		parseContent(string(b), id, refDomains, refExact, ips, allow, allowExact, allowIPs, nil, &rb, &ra)
	}
	e.Compile()
	// This test isolates the domain tables: wipe the allow side and regexes on
	// the engine too, so only block-table behaviour is compared.
	e.mu.Lock()
	e.allowDomains, e.allowExact = map[string]struct{}{}, map[string]struct{}{}
	e.allowRegex, e.blockRegex = nil, nil
	e.publishLocked()
	e.mu.Unlock()

	var names []string
	for d := range refDomains {
		names = append(names, d)
	}
	for d := range refExact {
		names = append(names, d)
	}
	rng := rand.New(rand.NewPCG(1, 2))
	rng.Shuffle(len(names), func(i, j int) { names[i], names[j] = names[j], names[i] })
	names = names[:min(len(names), 120_000)]

	var queries []string
	for _, d := range names {
		queries = append(queries, d+".", "www."+d+".", "a.b."+d+".")
	}
	for i := range 100_000 {
		queries = append(queries, fmt.Sprintf("absent-%d.example-%d.test.", i, i%977))
	}
	var blocked, mismatches int
	for _, q := range queries {
		want := refDecide(refDomains, refExact, q)
		got := e.DecideDomain(q).Action == Block
		if want {
			blocked++
		}
		if got != want {
			mismatches++
			if mismatches <= 10 {
				t.Errorf("%q: compact=%v oracle=%v", q, got, want)
			}
		}
	}
	t.Logf("%d queries (%d blocked) compared against map oracle, %d mismatches; table entries: domains=%d exact=%d",
		len(queries), blocked, mismatches, e.rs.Load().blockDomains.Len(), e.rs.Load().blockExact.Len())
	if mismatches > 0 {
		t.Fatalf("%d mismatches", mismatches)
	}
}
