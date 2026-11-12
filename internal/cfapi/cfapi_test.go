package cfapi

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strconv"
	"testing"

	"github.com/eoghan2t9/Irongrid-DNS/internal/cfapi/cfapitest"
)

func newClient(s *cfapitest.Server) *Client {
	return &Client{Token: cfapitest.Token, BaseURL: s.URL, HTTP: s.Client()}
}

func TestParseTunnelToken(t *testing.T) {
	t.Parallel()
	doc, _ := json.Marshal(map[string]string{"a": "acct123", "t": "tun456", "s": "c2VjcmV0"})
	for name, tok := range map[string]string{
		"padded":   base64.StdEncoding.EncodeToString(doc),
		"unpadded": base64.RawStdEncoding.EncodeToString(doc),
	} {
		a, tn, err := ParseTunnelToken(tok)
		if err != nil || a != "acct123" || tn != "tun456" {
			t.Errorf("%s: ParseTunnelToken = %q, %q, %v", name, a, tn, err)
		}
	}
	for _, bad := range []string{"", "definitely-not-a-valid-tunnel-token", base64.StdEncoding.EncodeToString([]byte(`{"a":"x"}`))} {
		if _, _, err := ParseTunnelToken(bad); err == nil {
			t.Errorf("ParseTunnelToken(%q) accepted garbage", bad)
		}
	}
}

func TestPermissionErrorsAreRecognised(t *testing.T) {
	t.Parallel()
	s := cfapitest.New(t)
	c := &Client{Token: "wrong", BaseURL: s.URL, HTTP: s.Client()}
	_, err := c.ListAccounts(context.Background())
	if !IsPermission(err) {
		t.Fatalf("ListAccounts with a bad token = %v, want a permission error", err)
	}
	var ae *APIError
	if !errors.As(err, &ae) || ae.Status != 403 || ae.Code != 10000 {
		t.Errorf("error = %#v, want status 403 code 10000", err)
	}
	if _, err := newClient(s).GetTunnel(context.Background(), cfapitest.Account, "missing"); err == nil || IsPermission(err) {
		t.Errorf("GetTunnel(missing) = %v, want a non-permission error", err)
	}
}

func TestListsWalkEveryPage(t *testing.T) {
	t.Parallel()
	s := cfapitest.New(t)
	s.PerPage = 2
	for i := range 5 {
		s.AddZone("zone" + strconv.Itoa(i) + ".example")
		s.AddTunnel("t"+strconv.Itoa(i), "healthy", 1)
	}
	c := newClient(s)
	zones, err := c.ListZones(context.Background())
	if err != nil || len(zones) != 5 {
		t.Fatalf("ListZones = %d zones, %v; want 5 across pages", len(zones), err)
	}
	tunnels, err := c.ListTunnels(context.Background(), cfapitest.Account)
	if err != nil || len(tunnels) != 5 {
		t.Fatalf("ListTunnels = %d tunnels, %v; want 5 across pages", len(tunnels), err)
	}
}

func TestTunnelLifecycleAndToken(t *testing.T) {
	t.Parallel()
	s := cfapitest.New(t)
	c := newClient(s)
	ctx := context.Background()

	tn, err := c.CreateTunnel(ctx, cfapitest.Account, "irongrid")
	if err != nil || tn.Name != "irongrid" || tn.ConfigSrc != "cloudflare" {
		t.Fatalf("CreateTunnel = %+v, %v", tn, err)
	}
	tok, err := c.TunnelToken(ctx, cfapitest.Account, tn.ID)
	if err != nil {
		t.Fatal(err)
	}
	if a, id, perr := ParseTunnelToken(tok); perr != nil || a != cfapitest.Account || id != tn.ID {
		t.Errorf("token carries account %q tunnel %q (%v), want %q / %q", a, id, perr, cfapitest.Account, tn.ID)
	}
	if err := c.DeleteTunnel(ctx, cfapitest.Account, tn.ID); err != nil {
		t.Fatalf("DeleteTunnel: %v", err)
	}
	if _, err := c.GetTunnel(ctx, cfapitest.Account, tn.ID); err == nil {
		t.Error("a deleted tunnel is still readable")
	}

	busy := s.AddTunnel("in-use", "healthy", 2)
	err = c.DeleteTunnel(ctx, cfapitest.Account, busy.ID)
	var ae *APIError
	if !errors.As(err, &ae) || ae.Status != 400 {
		t.Errorf("deleting a tunnel with connectors = %v, want Cloudflare's 400 refusal passed through", err)
	}
}

// A tunnel's configuration is replaced wholesale on every PUT, so anything we
// do not edit must come back exactly as it was.
func TestConfigEditsPreserveEverythingElse(t *testing.T) {
	t.Parallel()
	s := cfapitest.New(t)
	tn := s.AddTunnel("main", "healthy", 1)
	s.SetConfig(tn.ID, `{
	  "warp-routing": {"enabled": true},
	  "originRequest": {"connectTimeout": "30s"},
	  "ingress": [
	    {"hostname": "a.example.com", "service": "http://localhost:8080", "originRequest": {"connectTimeout": "5s", "noTLSVerify": true}, "futureField": 7},
	    {"service": "http_status:503"}
	  ]
	}`)
	c := newClient(s)
	ctx := context.Background()

	cfg, err := c.GetConfig(ctx, cfapitest.Account, tn.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got := cfg.CatchAll(); got != "http_status:503" {
		t.Errorf("catch-all = %q, want the configured http_status:503", got)
	}
	cfg.Upsert(NewRule("b.example.com", "https://localhost:443", "", true))
	if err := c.PutConfig(ctx, cfapitest.Account, tn.ID, cfg); err != nil {
		t.Fatal(err)
	}

	stored := s.Config(tn.ID)
	if string(stored["warp-routing"]) != `{"enabled":true}` && string(stored["warp-routing"]) != `{"enabled": true}` {
		t.Errorf("warp-routing was not preserved: %s", stored["warp-routing"])
	}
	if _, ok := stored["originRequest"]; !ok {
		t.Error("the tunnel-wide originRequest was dropped")
	}
	var rules []map[string]any
	if err := json.Unmarshal(stored["ingress"], &rules); err != nil {
		t.Fatal(err)
	}
	if len(rules) != 3 {
		t.Fatalf("ingress has %d rules, want a, b and the catch-all: %v", len(rules), rules)
	}
	if rules[0]["hostname"] != "a.example.com" || rules[0]["futureField"] != float64(7) {
		t.Errorf("the untouched rule changed: %v", rules[0])
	}
	if rules[1]["hostname"] != "b.example.com" {
		t.Errorf("new rule not inserted before the catch-all: %v", rules)
	}
	if rules[2]["hostname"] != nil || rules[2]["service"] != "http_status:503" {
		t.Errorf("the catch-all is not last and unchanged: %v", rules[2])
	}
}

func TestUpsertReplaceKeepsOtherOriginSettings(t *testing.T) {
	t.Parallel()
	cfg := &TunnelConfig{Other: map[string]json.RawMessage{}}
	old := NewRule("a.example.com", "http://localhost:1", "", true)
	old["originRequest"] = json.RawMessage(`{"connectTimeout":"5s","noTLSVerify":true}`)
	old["futureField"] = json.RawMessage(`7`)
	cfg.Rules = []Rule{old}

	// The user unticks "skip TLS verification" and changes the origin.
	if !cfg.Upsert(NewRule("A.example.com", "http://localhost:2", "", false)) {
		t.Fatal("Upsert did not treat a case-different hostname as the same rule")
	}
	got := cfg.Hostnames()
	if len(got) != 1 || got[0].Service() != "http://localhost:2" {
		t.Fatalf("rules = %v", got)
	}
	if got[0].NoTLSVerify() {
		t.Error("noTLSVerify stayed on after being turned off")
	}
	var o map[string]any
	_ = json.Unmarshal(got[0]["originRequest"], &o)
	if o["connectTimeout"] != "5s" {
		t.Errorf("another originRequest setting was lost: %v", o)
	}
	if string(got[0]["futureField"]) != "7" {
		t.Error("an unmodelled field of the replaced rule was lost")
	}
}

// Regression: editing an existing hostname dropped the TLS settings chosen in
// the edit (they were deleted before being merged), so a rule that needed
// "skip verification" or a server name lost it on every save and the tunnel
// answered 502.
func TestUpsertReplaceAppliesTheNewTLSSettings(t *testing.T) {
	t.Parallel()
	cfg := &TunnelConfig{Other: map[string]json.RawMessage{}}
	old := NewRule("a.example.com", "https://localhost:443", "", false)
	old["originRequest"] = json.RawMessage(`{"connectTimeout":"5s"}`)
	cfg.Rules = []Rule{old}

	// Turn verification off on an existing rule.
	cfg.Upsert(NewRuleOrigin("a.example.com", "https://localhost:443", "", true, ""))
	got := cfg.Hostnames()[0]
	if !got.NoTLSVerify() {
		t.Fatal("editing a rule to skip TLS verification did not stick")
	}
	var o map[string]any
	_ = json.Unmarshal(got["originRequest"], &o)
	if o["connectTimeout"] != "5s" {
		t.Errorf("another origin setting was lost: %v", o)
	}

	// Switch to verifying as a specific name instead.
	cfg.Upsert(NewRuleOrigin("a.example.com", "https://localhost:443", "", false, "dns.example.com"))
	got = cfg.Hostnames()[0]
	if got.NoTLSVerify() || got.OriginServerName() != "dns.example.com" {
		t.Errorf("after switching to a server name: noTLSVerify=%v name=%q", got.NoTLSVerify(), got.OriginServerName())
	}

	// And back to plain verification: both settings are removed, others kept.
	cfg.Upsert(NewRuleOrigin("a.example.com", "https://localhost:443", "", false, ""))
	got = cfg.Hostnames()[0]
	_ = json.Unmarshal(got["originRequest"], &o)
	if got.NoTLSVerify() || got.OriginServerName() != "" || o["connectTimeout"] != "5s" {
		t.Errorf("after clearing: %v", o)
	}
}

func TestConfigRemoveAndMissingCatchAll(t *testing.T) {
	t.Parallel()
	s := cfapitest.New(t)
	tn := s.AddTunnel("main", "healthy", 1)
	// A tunnel that has never been configured returns a null config.
	c := newClient(s)
	cfg, err := c.GetConfig(context.Background(), cfapitest.Account, tn.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Hostnames()) != 0 || cfg.CatchAll() != "http_status:404" {
		t.Fatalf("empty config = %v / %q, want no hostnames and a 404 catch-all", cfg.Hostnames(), cfg.CatchAll())
	}
	cfg.Upsert(NewRule("a.example.com", "http://localhost:1", "", false))
	cfg.Upsert(NewRule("b.example.com", "http://localhost:2", "", false))
	if !cfg.Remove("A.EXAMPLE.COM") || cfg.Remove("nope.example.com") {
		t.Error("Remove did not report existence correctly")
	}
	if h := cfg.Hostnames(); len(h) != 1 || h[0].Hostname() != "b.example.com" {
		t.Errorf("after Remove: %v", h)
	}
	if last := cfg.Rules[len(cfg.Rules)-1]; last.Hostname() != "" {
		t.Error("the catch-all is no longer last")
	}
}

func TestZoneForPrefersTheLongestSuffix(t *testing.T) {
	t.Parallel()
	zones := []Zone{{ID: "1", Name: "example.com"}, {ID: "2", Name: "sub.example.com"}, {ID: "3", Name: "other.net"}}
	for host, want := range map[string]string{
		"dns.example.com":       "1",
		"example.com":           "1",
		"a.sub.example.com":     "2",
		"*.sub.example.com":     "2",
		"DNS.Example.COM":       "1",
		"notexample.com":        "",
		"dns.example.com.evil":  "",
		"x.other.net":           "3",
		"example.com.other.net": "3",
	} {
		z := ZoneFor(zones, host)
		got := ""
		if z != nil {
			got = z.ID
		}
		if got != want {
			t.Errorf("ZoneFor(%q) = %q, want %q", host, got, want)
		}
	}
}

func TestDNSRecordsForATunnel(t *testing.T) {
	t.Parallel()
	s := cfapitest.New(t)
	zone := s.AddZone("example.com")
	tn := s.AddTunnel("main", "healthy", 1)
	other := s.AddTunnel("other", "healthy", 1)
	s.AddRecord(zone, "mine.example.com", "CNAME", TunnelTarget(tn.ID), true)
	s.AddRecord(zone, "theirs.example.com", "CNAME", TunnelTarget(other.ID), true)
	s.AddRecord(zone, "www.example.com", "A", "192.0.2.1", false)
	c := newClient(s)
	ctx := context.Background()

	mine, err := c.RecordsPointingAt(ctx, zone, tn.ID)
	if err != nil || len(mine) != 1 || mine[0].Name != "mine.example.com" {
		t.Fatalf("RecordsPointingAt = %v, %v; want only this tunnel's record", mine, err)
	}
	named, err := c.RecordsNamed(ctx, zone, "www.example.com")
	if err != nil || len(named) != 1 || named[0].Type != "A" {
		t.Fatalf("RecordsNamed = %v, %v", named, err)
	}

	rec, err := c.CreateTunnelCNAME(ctx, zone, "new.example.com", tn.ID)
	if err != nil || rec.Content != TunnelTarget(tn.ID) || !rec.Proxied {
		t.Fatalf("CreateTunnelCNAME = %+v, %v; want a proxied CNAME to the tunnel", rec, err)
	}
	if _, err := c.CreateTunnelCNAME(ctx, zone, "new.example.com", tn.ID); err == nil {
		t.Error("creating a duplicate CNAME succeeded; Cloudflare refuses it")
	}
	up, err := c.UpdateTunnelCNAME(ctx, zone, rec.ID, "new.example.com", other.ID)
	if err != nil || up.Content != TunnelTarget(other.ID) {
		t.Fatalf("UpdateTunnelCNAME = %+v, %v", up, err)
	}
	if err := c.DeleteRecord(ctx, zone, rec.ID); err != nil {
		t.Fatalf("DeleteRecord: %v", err)
	}
	if err := c.DeleteRecord(ctx, zone, rec.ID); err == nil {
		t.Error("deleting a missing record succeeded")
	}
}
