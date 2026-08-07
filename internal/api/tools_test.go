package api

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/eoghan2t9/Irongrid-DNS/internal/filter"
	"github.com/eoghan2t9/Irongrid-DNS/internal/upstream"
)

// startUDPDNS runs a one-shot DNS server answering from a name|qtype -> RR map
// and returns its udp address.
func startUDPDNS(t *testing.T, rrs map[string][]dns.RR) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &dns.Server{PacketConn: pc, Handler: zoneHandler(rrs)}
	go func() { _ = srv.ActivateAndServe() }()
	t.Cleanup(func() { _ = pc.Close() })
	return pc.LocalAddr().String()
}

func zoneHandler(rrs map[string][]dns.RR) dns.Handler {
	return dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(req)
		q := req.Question[0]
		key := strings.ToLower(q.Name) + "|" + dns.TypeToString[q.Qtype]
		if got, ok := rrs[key]; ok {
			m.Answer = got
		} else {
			m.Rcode = dns.RcodeNameError
		}
		_ = w.WriteMsg(m)
	})
}

func txtRR(name, s string) *dns.TXT {
	return &dns.TXT{Hdr: dns.RR_Header{Name: dns.Fqdn(name), Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 300}, Txt: []string{s}}
}

// handlerFor sets h.Upstreams to a single upstream dialing addr, so the tools
// resolve through a local test server instead of the network.
func handlerFor(t *testing.T, addr string) *Handler {
	t.Helper()
	up, err := upstream.Parse("udp://" + addr)
	if err != nil {
		t.Fatal(err)
	}
	return &Handler{Upstreams: []*upstream.Upstream{up}}
}

func postTools(t *testing.T, h *Handler, path, body string) (int, []byte) {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	rr := httptest.NewRecorder()
	switch path {
	case "/api/tools/resolve":
		h.toolsResolve(context.Background(), rr, req)
	case "/api/tools/mail":
		h.toolsMail(context.Background(), rr, req)
	case "/api/tools/rbl":
		h.toolsRBL(context.Background(), rr, req)
	case "/api/tools/axfr":
		h.toolsAXFR(context.Background(), rr, req)
	case "/api/tools/subdomains":
		h.toolsSubdomains(context.Background(), rr, req)
	}
	return rr.Code, rr.Body.Bytes()
}

func TestToolsResolve(t *testing.T) {
	addr := startUDPDNS(t, map[string][]dns.RR{
		"test.example.|A": {&dns.A{Hdr: dns.RR_Header{Name: "test.example.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300}, A: net.ParseIP("1.2.3.4")}},
	})
	h := handlerFor(t, addr)

	code, body := postTools(t, h, "/api/tools/resolve", `{"name": "test.example", "type": "A", "rd": true, "sources": ["local"]}`)
	if code != http.StatusOK {
		t.Fatalf("status %d: %s", code, body)
	}
	var res struct {
		Results []resolveResult `json:"results"`
	}
	if err := json.Unmarshal(body, &res); err != nil {
		t.Fatal(err)
	}
	if len(res.Results) != 1 {
		t.Fatalf("results = %d, want 1", len(res.Results))
	}
	r := res.Results[0]
	if r.Error != "" {
		t.Fatalf("error: %s", r.Error)
	}
	if r.Rcode != "NOERROR" {
		t.Errorf("rcode = %s, want NOERROR", r.Rcode)
	}
	if len(r.Answers) != 1 || !strings.Contains(r.Answers[0], "1.2.3.4") {
		t.Errorf("answers = %v, want A 1.2.3.4", r.Answers)
	}
}

// TestToolsResolveNXDOMAINAnswersNotNull guards the JSON contract the
// dashboard depends on: a lookup that returns no records (NXDOMAIN, NODATA)
// must serialize answers as [] — not null — because the frontend reads
// res.answers.length and null.length throws, blanking the whole page.
func TestToolsResolveNXDOMAINAnswersNotNull(t *testing.T) {
	addr := startUDPDNS(t, map[string][]dns.RR{}) // nothing answers -> NXDOMAIN
	h := handlerFor(t, addr)

	code, body := postTools(t, h, "/api/tools/resolve", `{"name": "nx.test", "type": "A", "rd": true, "sources": ["local"]}`)
	if code != http.StatusOK {
		t.Fatalf("status %d: %s", code, body)
	}
	// The raw JSON must contain "answers":[] — a nil Go slice would emit
	// "answers":null. Match structurally so field order doesn't matter.
	var raw map[string]any
	if err := json.Unmarshal(body, &raw); err != nil {
		t.Fatal(err)
	}
	results, ok := raw["results"].([]any)
	if !ok || len(results) != 1 {
		t.Fatalf("results = %v, want 1", raw["results"])
	}
	first, ok := results[0].(map[string]any)
	if !ok {
		t.Fatal("first result not an object")
	}
	ans, ok := first["answers"]
	if !ok {
		t.Fatal("missing answers field")
	}
	arr, isSlice := ans.([]any)
	if !isSlice {
		t.Fatalf("answers = %v (%T), want a JSON array ([]), not null — the dashboard crashes on null.length", ans, ans)
	}
	if len(arr) != 0 {
		t.Fatalf("answers = %v, want empty array", arr)
	}
}

func TestToolsResolveBadSource(t *testing.T) {
	h := &Handler{} // no local upstreams at all
	code, body := postTools(t, h, "/api/tools/resolve", `{"name": "x.com", "sources": ["local"]}`)
	if code != http.StatusOK {
		t.Fatalf("status %d", code)
	}
	var res struct {
		Results []resolveResult `json:"results"`
	}
	_ = json.Unmarshal(body, &res)
	if len(res.Results) != 1 || res.Results[0].Error == "" {
		t.Errorf("expected a per-source error for missing local upstreams, got %+v", res.Results)
	}
}

func TestToolsMail(t *testing.T) {
	addr := startUDPDNS(t, map[string][]dns.RR{
		"example.com.|MX":                     {&dns.MX{Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeMX, Class: dns.ClassINET, Ttl: 300}, Preference: 10, Mx: "mail.example.com."}},
		"example.com.|TXT":                    {txtRR("example.com.", "v=spf1 include:spf.example.net -all")},
		"default._domainkey.example.com.|TXT": {txtRR("default._domainkey.example.com.", "v=DKIM1; k=rsa; p=abc")},
		"_dmarc.example.com.|TXT":             {txtRR("_dmarc.example.com.", "v=DMARC1; p=reject")},
		"example.com.|CAA":                    {&dns.CAA{Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeCAA, Class: dns.ClassINET, Ttl: 300}, Tag: "issue", Value: "letsencrypt.org"}},
	})
	h := handlerFor(t, addr)

	code, body := postTools(t, h, "/api/tools/mail", `{"domain": "example.com"}`)
	if code != http.StatusOK {
		t.Fatalf("status %d: %s", code, body)
	}
	var res mailCheckResult
	if err := json.Unmarshal(body, &res); err != nil {
		t.Fatal(err)
	}
	if len(res.MX) != 1 {
		t.Errorf("mx = %v, want 1 record", res.MX)
	}
	if !res.SPFOK || len(res.SPFIssues) != 0 {
		t.Errorf("spf = %q ok=%v issues=%v, want OK", res.SPF, res.SPFOK, res.SPFIssues)
	}
	if !res.DKIMOK {
		t.Errorf("dkim = %q, want present", res.DKIM)
	}
	if res.DMARCPolicy != "reject" {
		t.Errorf("dmarc_policy = %q, want reject", res.DMARCPolicy)
	}
	if len(res.CAA) != 1 {
		t.Errorf("caa = %v, want 1 record", res.CAA)
	}
}

func TestSpfIssues(t *testing.T) {
	if issues := spfIssues("v=spf1 include:ok.example -all"); len(issues) != 0 {
		t.Errorf("clean spf flagged: %v", issues)
	}
	// Missing fail term.
	if issues := spfIssues("v=spf1 mx"); len(issues) == 0 {
		t.Error("missing -all/~all not flagged")
	}
	// Over the lookup limit.
	many := "v=spf1 " + strings.Repeat("a ", 11) + "-all"
	if issues := spfIssues(many); len(issues) == 0 {
		t.Error(">10 lookups not flagged")
	}
}

func TestToolsRBL(t *testing.T) {
	addr := startUDPDNS(t, map[string][]dns.RR{
		"4.3.2.1.zen.spamhaus.org.|A":   {&dns.A{Hdr: dns.RR_Header{Name: "4.3.2.1.zen.spamhaus.org.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300}, A: net.ParseIP("127.0.0.2")}},
		"4.3.2.1.zen.spamhaus.org.|TXT": {txtRR("4.3.2.1.zen.spamhaus.org.", "Spam from this IP")},
	})
	h := handlerFor(t, addr)

	code, body := postTools(t, h, "/api/tools/rbl", `{"ip": "1.2.3.4"}`)
	if code != http.StatusOK {
		t.Fatalf("status %d: %s", code, body)
	}
	var res struct {
		Checks []rblResult `json:"checks"`
	}
	if err := json.Unmarshal(body, &res); err != nil {
		t.Fatal(err)
	}
	if len(res.Checks) != len(rblZones) {
		t.Fatalf("checks = %d, want %d", len(res.Checks), len(rblZones))
	}
	listed := false
	for _, c := range res.Checks {
		if c.Zone == "zen.spamhaus.org" {
			listed = c.Listed
			if c.Code != "127.0.0.2" {
				t.Errorf("code = %q, want 127.0.0.2", c.Code)
			}
			if !strings.Contains(c.Reason, "Spam") {
				t.Errorf("reason = %q, want Spam text", c.Reason)
			}
		} else if c.Listed {
			t.Errorf("%s listed unexpectedly", c.Zone)
		}
	}
	if !listed {
		t.Error("zen.spamhaus.org not flagged as listed")
	}
}

func TestToolsRBLBadIP(t *testing.T) {
	code, _ := postTools(t, &Handler{}, "/api/tools/rbl", `{"ip": "not-an-ip"}`)
	if code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", code)
	}
}

// startAXFRSrv runs a TCP DNS server that either serves or refuses AXFR for
// zone, returning its address.
func startAXFRSrv(t *testing.T, zone string, records []dns.RR, refuse bool) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	h := dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
		if req.Question[0].Qtype != dns.TypeAXFR || refuse {
			m := new(dns.Msg)
			m.SetRcode(req, dns.RcodeRefused)
			_ = w.WriteMsg(m)
			return
		}
		for _, rr := range records {
			m := new(dns.Msg)
			m.SetReply(req)
			m.Authoritative = true
			m.Answer = []dns.RR{rr}
			_ = w.WriteMsg(m)
		}
	})
	srv := &dns.Server{Listener: ln, Handler: h}
	go func() { _ = srv.ActivateAndServe() }()
	t.Cleanup(func() { _ = ln.Close() })
	return ln.Addr().String()
}

func TestToolsAXFR(t *testing.T) {
	zoneRRs := []dns.RR{
		&dns.SOA{Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 300}, Ns: "ns1.example.com.", Mbox: "hostmaster.example.com."},
		&dns.A{Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300}, A: net.ParseIP("1.2.3.4")},
		&dns.SOA{Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 300}, Ns: "ns1.example.com.", Mbox: "hostmaster.example.com."},
	}
	axfrAddr := startAXFRSrv(t, "example.com.", zoneRRs, false)

	// Resolution server: NS for the zone points at a nameserver resolving to
	// 127.0.0.1 (the AXFR server is reached via the swappable axfrPort).
	addr := startUDPDNS(t, map[string][]dns.RR{
		"example.com.|NS":       {&dns.NS{Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 300}, Ns: "ns1.example.com."}},
		"ns1.example.com.|A":    {&dns.A{Hdr: dns.RR_Header{Name: "ns1.example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300}, A: net.ParseIP("127.0.0.1")}},
		"ns1.example.com.|AAAA": {},
	})
	h := handlerFor(t, addr)

	_, port, _ := net.SplitHostPort(axfrAddr)
	old := axfrPort
	axfrPort = port
	defer func() { axfrPort = old }()

	code, body := postTools(t, h, "/api/tools/axfr", `{"domain": "example.com"}`)
	if code != http.StatusOK {
		t.Fatalf("status %d: %s", code, body)
	}
	var res struct {
		Nameservers []axfrNSResult `json:"nameservers"`
	}
	if err := json.Unmarshal(body, &res); err != nil {
		t.Fatal(err)
	}
	if len(res.Nameservers) == 0 {
		t.Fatal("no nameservers reported")
	}
	ns := res.Nameservers[0]
	if !ns.AXFR {
		t.Errorf("axfr = false for %s (%+v), want true (records %d)", ns.Host, ns, ns.Records)
	}
	if ns.Records != 3 {
		t.Errorf("records = %d, want 3", ns.Records)
	}
}

func TestToolsAXFRRefused(t *testing.T) {
	axfrAddr := startAXFRSrv(t, "example.com.", nil, true)
	addr := startUDPDNS(t, map[string][]dns.RR{
		"example.com.|NS":       {&dns.NS{Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 300}, Ns: "ns1.example.com."}},
		"ns1.example.com.|A":    {&dns.A{Hdr: dns.RR_Header{Name: "ns1.example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300}, A: net.ParseIP("127.0.0.1")}},
		"ns1.example.com.|AAAA": {},
	})
	h := handlerFor(t, addr)

	_, port, _ := net.SplitHostPort(axfrAddr)
	old := axfrPort
	axfrPort = port
	defer func() { axfrPort = old }()

	code, body := postTools(t, h, "/api/tools/axfr", `{"domain": "example.com"}`)
	if code != http.StatusOK {
		t.Fatalf("status %d: %s", code, body)
	}
	var res struct {
		Nameservers []axfrNSResult `json:"nameservers"`
	}
	if err := json.Unmarshal(body, &res); err != nil {
		t.Fatal(err)
	}
	if len(res.Nameservers) == 0 || res.Nameservers[0].AXFR {
		t.Errorf("expected refused transfer, got %+v", res.Nameservers)
	}
}

func TestToolsSubdomains(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		payload := `[{"name_value": "www.example.com\napi.example.com", "common_name": "example.com"}]`
		_, _ = w.Write([]byte(payload))
	}))
	defer srv.Close()

	oldBase, oldClient := crtShBase, crtShClient
	crtShBase = srv.URL
	crtShClient = &http.Client{Timeout: 5 * time.Second}
	defer func() { crtShBase, crtShClient = oldBase, oldClient }()

	eng := filter.NewEngine()
	if _, err := eng.LoadList("test", "Test Ads", []byte("api.example.com\n")); err != nil {
		t.Fatal(err)
	}
	eng.Compile()

	h := &Handler{Engine: eng}
	code, body := postTools(t, h, "/api/tools/subdomains", `{"domain": "example.com"}`)
	if code != http.StatusOK {
		t.Fatalf("status %d: %s", code, body)
	}
	var res struct {
		Total   int               `json:"total"`
		Blocked int               `json:"blocked"`
		Domains []subdomainResult `json:"domains"`
	}
	if err := json.Unmarshal(body, &res); err != nil {
		t.Fatal(err)
	}
	if res.Total != 3 {
		t.Errorf("total = %d, want 3 (example.com + www + api)", res.Total)
	}
	if res.Blocked != 1 {
		t.Errorf("blocked = %d, want 1", res.Blocked)
	}
	found := false
	for _, d := range res.Domains {
		if d.Domain == "api.example.com" && d.Blocked && d.List == "Test Ads" {
			found = true
		}
	}
	if !found {
		t.Errorf("api.example.com not flagged as blocked: %+v", res.Domains)
	}
}

func TestToolsSubdomainsTimeoutStyle(t *testing.T) {
	// Unreachable crt.sh base must produce a clean error, not a hang.
	oldBase, oldClient := crtShBase, crtShClient
	crtShBase = "http://127.0.0.1:1"
	crtShClient = &http.Client{Timeout: 200 * time.Millisecond}
	defer func() { crtShBase, crtShClient = oldBase, oldClient }()

	code, body := postTools(t, &Handler{}, "/api/tools/subdomains", `{"domain": "example.com"}`)
	if code != http.StatusBadGateway {
		t.Errorf("status = %d, want 502", code)
	}
	if !strings.Contains(string(body), "fetch failed") {
		t.Errorf("body = %s, want fetch failure message", body)
	}
}
