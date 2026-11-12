package api

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/eoghan2t9/Irongrid-DNS/internal/cfapi"
	"github.com/eoghan2t9/Irongrid-DNS/internal/cfapi/cfapitest"
	"github.com/eoghan2t9/Irongrid-DNS/internal/config"
)

// useIPs fixes the "detected public address" for a test. The detector is a
// package variable, so these tests are deliberately not parallel.
func useIPs(t *testing.T, v4, v6 string) {
	t.Helper()
	old := detectPublicIPs
	detectPublicIPs = func() (string, string) { return v4, v6 }
	t.Cleanup(func() { detectPublicIPs = old })
}

func setIPs(v4, v6 string) { detectPublicIPs = func() (string, string) { return v4, v6 } }

// dnsFixture is a cfFixture whose server listens for DoH, DoT and DoQ and
// publishes under dns.example.com (a zone the fake owns).
func dnsFixture(t *testing.T) *cfFixture {
	t.Helper()
	f := newCFFixture(t)
	f.cfg.Server.ListenDoT, f.cfg.Server.ListenDoQ, f.cfg.Server.ListenDoH = ":853", ":853", ":443"
	f.cfg.Server.DoHPath = "/dns-query"
	f.cfg.TLS.ACME.Domains = []string{"dns.example.com"}
	return f
}

func items(out map[string]any) []map[string]any {
	var res []map[string]any
	list, _ := out["items"].([]any)
	for _, it := range list {
		res = append(res, it.(map[string]any))
	}
	return res
}

func counts(out map[string]any) map[string]float64 {
	m := map[string]float64{}
	c, _ := out["counts"].(map[string]any)
	for k, v := range c {
		m[k] = v.(float64)
	}
	return m
}

func TestCFDNSPlanIsBuiltFromTheLiveListeners(t *testing.T) {
	f := dnsFixture(t)
	useIPs(t, "192.0.2.10", "2001:db8::10")

	code, out := f.do(http.MethodGet, "/api/tunnel/cf/dns-plan", nil)
	if code != http.StatusOK {
		t.Fatalf("= %d %v", code, out)
	}
	if out["host"] != "dns.example.com" || out["host_default"] != "dns.example.com" || out["zone"] != "example.com" {
		t.Errorf("host/zone = %v / %v / %v; the default host should come from the ACME domain", out["host"], out["host_default"], out["zone"])
	}
	protos, _ := out["protocols"].([]any)
	if len(protos) != 3 {
		t.Errorf("protocols = %v, want DoH, DoT and DoQ", out["protocols"])
	}
	types := map[string]int{}
	for _, it := range items(out) {
		types[it["type"].(string)]++
		if it["state"] != "missing" || it["action"] != "create" {
			t.Errorf("%v %v = %v/%v on an empty zone, want missing/create", it["type"], it["name"], it["state"], it["action"])
		}
	}
	if types["A"] != 1 || types["AAAA"] != 1 || types["SVCB"] != 3 || types["HTTPS"] != 1 {
		t.Errorf("planned record types = %v", types)
	}
	if c := counts(out); c["create"] != 6 || out["in_sync"] != false {
		t.Errorf("counts = %v in_sync = %v", c, out["in_sync"])
	}
	if n := f.fake.CallCount("POST") + f.fake.CallCount("PUT") + f.fake.CallCount("DELETE"); n != 0 {
		t.Errorf("planning made %d writes to Cloudflare", n)
	}
}

func TestCFDNSApplyCreatesTheRecordsThenIsInSync(t *testing.T) {
	f := dnsFixture(t)
	useIPs(t, "192.0.2.10", "2001:db8::10")

	code, out := f.do(http.MethodPost, "/api/tunnel/cf/dns-plan/apply", map[string]any{})
	if code != http.StatusOK {
		t.Fatalf("apply = %d %v", code, out)
	}
	for _, r := range out["results"].([]any) {
		if m := r.(map[string]any); m["ok"] != true {
			t.Errorf("a record failed: %v", m)
		}
	}

	byKey := map[string]cfapitest.Record{}
	for _, r := range f.fake.RecordsFor() {
		byKey[r.Type+" "+r.Name+" "+r.Content] = r
		if r.Proxied {
			t.Errorf("%s %s was created proxied; DoT/DoQ cannot go through Cloudflare's proxy", r.Type, r.Name)
		}
		if r.TTL != dnsRecordTTL {
			t.Errorf("%s %s ttl = %d, want %d", r.Type, r.Name, r.TTL, dnsRecordTTL)
		}
	}
	for _, want := range []string{
		"A dns.example.com 192.0.2.10",
		"AAAA dns.example.com 2001:db8::10",
		`SVCB _dns.dns.example.com 1 dns.example.com. alpn="h2" ipv4hint="192.0.2.10" ipv6hint="2001:db8::10" dohpath="/dns-query{?dns}"`,
		`SVCB _dns.dns.example.com 2 dns.example.com. alpn="dot" ipv4hint="192.0.2.10" ipv6hint="2001:db8::10"`,
		`SVCB _dns.dns.example.com 3 dns.example.com. alpn="doq" ipv4hint="192.0.2.10" ipv6hint="2001:db8::10"`,
		`HTTPS dns.example.com 1 . alpn="h2" ipv4hint="192.0.2.10" ipv6hint="2001:db8::10"`,
	} {
		if _, ok := byKey[want]; !ok {
			t.Errorf("record missing: %s\nhave: %v", want, keys(byKey))
		}
	}

	// What Cloudflare stored must read back as "already right": the plan is a
	// no-op, so nothing is rewritten on the next apply or sync.
	code, out = f.do(http.MethodGet, "/api/tunnel/cf/dns-plan", nil)
	if code != http.StatusOK || out["in_sync"] != true || counts(out)["create"] != 0 || counts(out)["update"] != 0 {
		t.Fatalf("after apply: in_sync=%v counts=%v items=%v", out["in_sync"], counts(out), items(out))
	}
	before := len(f.fake.RecordsFor())
	f.do(http.MethodPost, "/api/tunnel/cf/dns-plan/apply", map[string]any{})
	if len(f.fake.RecordsFor()) != before {
		t.Error("applying an already-correct plan changed the zone")
	}
}

func keys(m map[string]cfapitest.Record) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}

func TestCFDNSAnAddressChangeUpdatesRecordsInPlace(t *testing.T) {
	f := dnsFixture(t)
	useIPs(t, "192.0.2.10", "")
	f.do(http.MethodPost, "/api/tunnel/cf/dns-plan/apply", map[string]any{})
	before := len(f.fake.RecordsFor())

	setIPs("198.51.100.7", "") // the server moved
	_, out := f.do(http.MethodGet, "/api/tunnel/cf/dns-plan", nil)
	c := counts(out)
	// The A record plus the three SVCB records and the HTTPS record carry the address.
	if c["update"] != 5 || c["create"] != 0 || c["delete"] != 0 || out["in_sync"] != false {
		t.Fatalf("counts after an IP change = %v, want 5 in-place updates", c)
	}
	f.do(http.MethodPost, "/api/tunnel/cf/dns-plan/apply", map[string]any{})
	if got := len(f.fake.RecordsFor()); got != before {
		t.Errorf("record count %d -> %d: an address change must update, not duplicate or delete", before, got)
	}
	for _, r := range f.fake.RecordsFor() {
		if (r.Type == "A" && r.Content != "198.51.100.7") || (r.Type != "A" && !strings.Contains(r.Content, "198.51.100.7")) {
			t.Errorf("%s %s still carries the old address: %s", r.Type, r.Name, r.Content)
		}
	}
	if _, out = f.do(http.MethodGet, "/api/tunnel/cf/dns-plan", nil); out["in_sync"] != true {
		t.Errorf("not in sync after the update: %v", counts(out))
	}
}

// Deleting is the one destructive step: it only happens when asked for.
func TestCFDNSNeverDeletesUnlessPruneIsSet(t *testing.T) {
	f := dnsFixture(t)
	useIPs(t, "192.0.2.10", "")
	f.do(http.MethodPost, "/api/tunnel/cf/dns-plan/apply", map[string]any{})
	f.fake.AddRecord(f.zone, "dns.example.com", "A", "203.0.113.9", false)                          // an extra address
	f.fake.AddRecord(f.zone, "_dns.dns.example.com", "SVCB", `9 dns.example.com. alpn="h3"`, false) // a stale priority

	_, out := f.do(http.MethodGet, "/api/tunnel/cf/dns-plan", nil)
	if counts(out)["delete"] != 2 || out["in_sync"] != true {
		t.Fatalf("counts = %v in_sync = %v; extras should be reported without making the plan out of date", counts(out), out["in_sync"])
	}
	before := len(f.fake.RecordsFor())
	f.do(http.MethodPost, "/api/tunnel/cf/dns-plan/apply", map[string]any{})
	if len(f.fake.RecordsFor()) != before {
		t.Fatal("a plain apply deleted records")
	}
	f.do(http.MethodPost, "/api/tunnel/cf/dns-plan/apply", map[string]any{"prune": true})
	if got := len(f.fake.RecordsFor()); got != before-2 {
		t.Errorf("prune left %d records, want %d", got, before-2)
	}
	for _, r := range f.fake.RecordsFor() {
		if r.Content == "203.0.113.9" || strings.HasPrefix(r.Content, "9 ") {
			t.Errorf("a pruned record is still there: %+v", r)
		}
	}
}

// The tunnel's own hostname is a proxied CNAME. Publishing address records
// there would take the tunnel down, so it is reported as a conflict and left
// exactly as it is.
func TestCFDNSLeavesAHostnameThatHasACNAMEAlone(t *testing.T) {
	f := dnsFixture(t)
	useIPs(t, "192.0.2.10", "2001:db8::10")
	cname := f.fake.AddRecord(f.zone, "dns.example.com", "CNAME", cfapi.TunnelTarget(f.tunnel.ID), true)

	_, out := f.do(http.MethodPost, "/api/tunnel/cf/dns-plan/apply", map[string]any{})
	for _, r := range f.fake.RecordsFor() {
		if r.ID == cname.ID && (r.Content != cfapi.TunnelTarget(f.tunnel.ID) || !r.Proxied) {
			t.Fatalf("the tunnel's CNAME was modified: %+v", r)
		}
		if r.Name == "dns.example.com" && r.Type != "CNAME" {
			t.Errorf("a %s record was created next to a CNAME", r.Type)
		}
	}
	plan := out["plan"].(map[string]any)
	if c := counts(plan); c["conflict"] != 3 || plan["in_sync"] != false {
		t.Errorf("counts = %v, want A, AAAA and HTTPS reported as conflicts", c)
	}
	svcb := 0
	for _, r := range f.fake.RecordsFor() {
		if r.Type == "SVCB" {
			svcb++
		}
	}
	if svcb != 3 {
		t.Errorf("%d SVCB records, want the discovery records still published under _dns", svcb)
	}
}

func TestCFDNSSettingsAreValidatedSavedAndShapeThePlan(t *testing.T) {
	f := dnsFixture(t)
	useIPs(t, "192.0.2.10", "2001:db8::10")

	for name, body := range map[string]map[string]any{
		"bad host":   {"host": "no_dot"},
		"bad ipv4":   {"ipv4": "not-an-ip"},
		"v6 as v4":   {"ipv4": "2001:db8::1"},
		"v4 as v6":   {"ipv6": "192.0.2.1"},
		"loopback":   {"ipv4": "127.0.0.1"},
		"link-local": {"ipv6": "fe80::1"},
	} {
		if code, out := f.do(http.MethodPut, "/api/tunnel/cf/dns-settings", body); code != http.StatusBadRequest {
			t.Errorf("%s = %d %v, want 400", name, code, out)
		}
	}
	if f.cfg.CloudflareDNS != (config.CloudflareDNSConfig{}) {
		t.Errorf("invalid settings were saved: %+v", f.cfg.CloudflareDNS)
	}

	code, out := f.do(http.MethodPut, "/api/tunnel/cf/dns-settings", map[string]any{
		"host": "Other.Example.com.", "auto_sync": true, "ipv4": "198.51.100.5", "ipv6": "off", "skip_https": true,
	})
	if code != http.StatusOK {
		t.Fatalf("save = %d %v", code, out)
	}
	if got := f.cfg.CloudflareDNS; got.Host != "other.example.com" || !got.AutoSync || got.IPv4 != "198.51.100.5" || got.IPv6 != "off" || !got.SkipHTTPS {
		t.Errorf("saved = %+v", got)
	}
	if out["host"] != "other.example.com" || len(out["ipv6"].([]any)) != 0 || out["ipv4"].([]any)[0] != "198.51.100.5" {
		t.Errorf("plan ignores the settings: host=%v ipv4=%v ipv6=%v", out["host"], out["ipv4"], out["ipv6"])
	}
	for _, it := range items(out) {
		if it["type"] == "AAAA" || it["type"] == "HTTPS" {
			t.Errorf("a %v record is planned although it was switched off", it["type"])
		}
	}

	// A normal settings save rebuilds the config from the dashboard payload and
	// must not drop these.
	fresh := &config.Config{}
	carryOverUneditable(fresh, f.cfg)
	if fresh.CloudflareDNS != f.cfg.CloudflareDNS {
		t.Errorf("settings lost across a config save: %+v", fresh.CloudflareDNS)
	}
}

func TestCFDNSNeedsAHostnameAndAProtocolAndAZone(t *testing.T) {
	f := dnsFixture(t)
	useIPs(t, "192.0.2.10", "")

	f.cfg.TLS.ACME.Domains, f.cfg.Server.DiscoveryHost = nil, ""
	code, out := f.do(http.MethodGet, "/api/tunnel/cf/dns-plan", nil)
	if code != http.StatusOK || out["needs_host"] != true || f.fake.CallsBy(cfapitest.Token) != 0 {
		t.Errorf("no host = %d %v, want needs_host and no Cloudflare calls", code, out)
	}
	if code, _ := f.do(http.MethodPost, "/api/tunnel/cf/dns-plan/apply", map[string]any{}); code != http.StatusBadRequest {
		t.Errorf("apply without a host = %d, want 400", code)
	}

	f.cfg.CloudflareDNS.Host = "dns.nowhere.invalid"
	_, out = f.do(http.MethodGet, "/api/tunnel/cf/dns-plan", nil)
	if e, _ := out["error"].(string); !strings.Contains(e, "No Cloudflare zone") {
		t.Errorf("unknown zone: error = %v", out["error"])
	}

	f.cfg.Server.ListenDoT, f.cfg.Server.ListenDoQ, f.cfg.Server.ListenDoH = "", "", ""
	f.cfg.CloudflareDNS.Host = "dns.example.com"
	_, out = f.do(http.MethodGet, "/api/tunnel/cf/dns-plan", nil)
	if notes, _ := out["notes"].([]any); len(notes) == 0 || len(items(out)) != 0 {
		t.Errorf("no protocols: notes=%v items=%v, want an explanation and nothing planned", out["notes"], items(out))
	}
}

func TestCFDNSWarnsWhenNoPublicAddressIsFound(t *testing.T) {
	f := dnsFixture(t)
	useIPs(t, "", "")
	_, out := f.do(http.MethodGet, "/api/tunnel/cf/dns-plan", nil)
	notes, _ := out["notes"].([]any)
	if len(notes) == 0 || !strings.Contains(notes[0].(string), "NAT") {
		t.Errorf("notes = %v, want a hint about NAT / entering the address", notes)
	}
	for _, it := range items(out) {
		if it["type"] == "A" {
			t.Error("an A record was planned with no address")
		}
	}
}

func TestCFDNSPermissionDenialIsReportedWithTheZone(t *testing.T) {
	f := dnsFixture(t)
	useIPs(t, "192.0.2.10", "")
	f.fake.Deny(cfapitest.Token, true, false)
	code, out := f.do(http.MethodGet, "/api/tunnel/cf/dns-plan", nil)
	if e, _ := out["error"].(string); code != http.StatusBadGateway || out["permission"] != true || !strings.Contains(e, "example.com") {
		t.Errorf("= %d %v, want 502 + permission naming the zone", code, out)
	}
	// The ACME token, when there is one, makes it work.
	f.cfg.TLS.ACME.DNS01.CloudflareToken = cfapitest.DNSToken
	if code, out := f.do(http.MethodGet, "/api/tunnel/cf/dns-plan", nil); code != http.StatusOK {
		t.Errorf("with the ACME fallback = %d %v", code, out)
	}
}

// ---- background sync ----

func TestDNSSyncDoesNothingUnlessSwitchedOn(t *testing.T) {
	f := dnsFixture(t)
	useIPs(t, "192.0.2.10", "")
	f.h.dnsSyncOnce(context.Background())
	if f.fake.CallsBy(cfapitest.Token) != 0 || len(f.fake.RecordsFor()) != 0 {
		t.Error("the sync ran although auto-sync is off")
	}
}

func TestDNSSyncCreatesThenIdlesThenFollowsAnAddressChange(t *testing.T) {
	f := dnsFixture(t)
	useIPs(t, "192.0.2.10", "")
	f.cfg.CloudflareDNS.AutoSync = true
	ctx := context.Background()

	f.h.dnsSyncOnce(ctx)
	if f.h.cfSyncLast == nil || f.h.cfSyncLast.Applied != 5 || f.h.cfSyncLast.Error != "" || !f.h.cfSyncLast.Changed {
		t.Fatalf("first sync = %+v, want 5 records created", f.h.cfSyncLast)
	}

	// Nothing changed: it must not even ask Cloudflare.
	calls := f.fake.CallsBy(cfapitest.Token)
	f.h.dnsSyncOnce(ctx)
	if f.fake.CallsBy(cfapitest.Token) != calls {
		t.Error("an unchanged sync still called Cloudflare")
	}

	// The address changes: records are updated in place, nothing is deleted.
	setIPs("198.51.100.7", "")
	f.fake.AddRecord(f.zone, "dns.example.com", "A", "203.0.113.9", false) // somebody's extra record
	n := len(f.fake.RecordsFor())
	f.h.dnsSyncOnce(ctx)
	if f.h.cfSyncLast.Applied == 0 || len(f.fake.RecordsFor()) != n {
		t.Errorf("after an address change: %+v, records %d -> %d; want updates and no deletions", f.h.cfSyncLast, n, len(f.fake.RecordsFor()))
	}
	found := false
	for _, r := range f.fake.RecordsFor() {
		found = found || (r.Type == "A" && r.Content == "203.0.113.9")
		if r.Type == "A" && r.Content == "192.0.2.10" {
			t.Error("the old address record was not updated")
		}
	}
	if !found {
		t.Error("the sync deleted a record it does not own")
	}
}

func TestDNSSyncReportsFailuresAndRetries(t *testing.T) {
	f := dnsFixture(t)
	useIPs(t, "192.0.2.10", "")
	f.cfg.CloudflareDNS.AutoSync = true
	f.fake.Deny(cfapitest.Token, true, false)

	f.h.dnsSyncOnce(context.Background())
	if f.h.cfSyncLast == nil || f.h.cfSyncLast.Error == "" || f.h.cfSyncLast.Changed {
		t.Fatalf("sync under a denial = %+v, want an error and no change", f.h.cfSyncLast)
	}
	if f.h.cfSyncKey != "" {
		t.Error("a failed sync was remembered as done, so it would not be retried")
	}
	// The plan endpoint surfaces the last run.
	f.fake.Deny(cfapitest.Token, false, false)
	_, out := f.do(http.MethodGet, "/api/tunnel/cf/dns-plan", nil)
	if s, _ := out["sync"].(map[string]any); s == nil || s["error"] == nil {
		t.Errorf("plan.sync = %v, want the failed run", out["sync"])
	}
	f.h.dnsSyncOnce(context.Background())
	if f.h.cfSyncLast.Error != "" || f.h.cfSyncLast.Applied == 0 {
		t.Errorf("retry after the denial cleared = %+v", f.h.cfSyncLast)
	}
}
