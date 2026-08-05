package filter

import (
	"testing"

	"github.com/miekg/dns"
)

func TestRewriterExactAndWildcard(t *testing.T) {
	rw := NewRewriter()
	rw.Set([]RewriteSpec{
		{Domain: "nas.home", Type: "A", Value: "192.168.1.10", TTL: 300},
		{Domain: "*.internal.example.com", Type: "A", Value: "10.0.0.5", TTL: 60},
	})

	if _, ok := rw.Lookup("nas.home."); !ok {
		t.Fatal("expected exact match for nas.home")
	}
	if _, ok := rw.Lookup("other.home."); ok {
		t.Fatal("did not expect a match for other.home")
	}
	if _, ok := rw.Lookup("svc.internal.example.com."); !ok {
		t.Fatal("expected wildcard subtree match for svc.internal.example.com")
	}
	if _, ok := rw.Lookup("internal.example.com."); ok {
		t.Fatal("wildcard *.internal.example.com should not match the bare suffix itself")
	}
}

func TestRewriterExactWinsOverWildcard(t *testing.T) {
	rw := NewRewriter()
	rw.Set([]RewriteSpec{
		{Domain: "*.example.com", Type: "A", Value: "10.0.0.1", TTL: 60},
		{Domain: "special.example.com", Type: "A", Value: "10.0.0.2", TTL: 60},
	})
	rules, ok := rw.Lookup("special.example.com.")
	if !ok || len(rules) != 1 || rules[0].Value != "10.0.0.2" {
		t.Fatalf("expected exact rule to win, got %v ok=%v", rules, ok)
	}
}

func TestRewriterBuildAnswerTypeMismatchIsNoMatch(t *testing.T) {
	rw := NewRewriter()
	rw.Set([]RewriteSpec{{Domain: "nas.home", Type: "A", Value: "192.168.1.10", TTL: 300}})
	rules, ok := rw.Lookup("nas.home.")
	if !ok {
		t.Fatal("expected a match")
	}
	r := new(dns.Msg)
	r.SetQuestion("nas.home.", dns.TypeAAAA)
	ans := BuildAnswer(r, rules, "nas.home.", dns.TypeAAAA)
	if ans != nil {
		t.Fatalf("querying AAAA against an A-only rule should yield no answer (NODATA), got %v", ans)
	}
}

func TestRewriterBuildAnswerA(t *testing.T) {
	rw := NewRewriter()
	rw.Set([]RewriteSpec{{Domain: "nas.home", Type: "A", Value: "192.168.1.10", TTL: 300}})
	rules, _ := rw.Lookup("nas.home.")
	r := new(dns.Msg)
	r.SetQuestion("nas.home.", dns.TypeA)
	ans := BuildAnswer(r, rules, "nas.home.", dns.TypeA)
	if ans == nil || len(ans.Answer) != 1 {
		t.Fatalf("expected one answer, got %v", ans)
	}
	a, ok := ans.Answer[0].(*dns.A)
	if !ok || a.A.String() != "192.168.1.10" {
		t.Fatalf("unexpected answer: %v", ans.Answer[0])
	}
}

func TestRewriterCNAMEAnswersAnyQtype(t *testing.T) {
	rw := NewRewriter()
	rw.Set([]RewriteSpec{{Domain: "web.home", Type: "CNAME", Value: "nas.home", TTL: 300}})
	rules, ok := rw.Lookup("web.home.")
	if !ok {
		t.Fatal("expected a match")
	}
	r := new(dns.Msg)
	r.SetQuestion("web.home.", dns.TypeA)
	ans := BuildAnswer(r, rules, "web.home.", dns.TypeA)
	if ans == nil || len(ans.Answer) != 1 {
		t.Fatalf("expected a CNAME answer even for an A query, got %v", ans)
	}
	if _, ok := ans.Answer[0].(*dns.CNAME); !ok {
		t.Fatalf("expected a CNAME record, got %T", ans.Answer[0])
	}
}

func TestRewriterSetReplacesWholeTable(t *testing.T) {
	rw := NewRewriter()
	rw.Set([]RewriteSpec{{Domain: "a.home", Type: "A", Value: "1.1.1.1", TTL: 60}})
	rw.Set([]RewriteSpec{{Domain: "b.home", Type: "A", Value: "2.2.2.2", TTL: 60}})
	if _, ok := rw.Lookup("a.home."); ok {
		t.Fatal("a.home should be gone after Set replaced the table")
	}
	if _, ok := rw.Lookup("b.home."); !ok {
		t.Fatal("b.home should be present after Set")
	}
}

func TestRewriterInvalidSpecsAreSkipped(t *testing.T) {
	rw := NewRewriter()
	rw.Set([]RewriteSpec{
		{Domain: "", Type: "A", Value: "1.1.1.1"},
		{Domain: "bad.home", Type: "MX", Value: "1.1.1.1"},
		{Domain: "novalue.home", Type: "A", Value: ""},
		{Domain: "good.home", Type: "A", Value: "1.1.1.1"},
	})
	if _, ok := rw.Lookup("good.home."); !ok {
		t.Fatal("the one valid spec should still be present")
	}
	if _, ok := rw.Lookup("bad.home."); ok {
		t.Fatal("an unsupported record type should have been skipped")
	}
}
