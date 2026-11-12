package api

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/eoghan2t9/Irongrid-DNS/internal/cfapi"
	"github.com/eoghan2t9/Irongrid-DNS/internal/cfapi/cfapitest"
	"github.com/eoghan2t9/Irongrid-DNS/internal/config"
	"github.com/eoghan2t9/Irongrid-DNS/internal/tunnel"
)

// cfFixture is a Handler wired to a fake Cloudflare with one remotely-managed
// tunnel, one zone and a configured API token.
type cfFixture struct {
	h      *Handler
	cfg    *config.Config
	fake   *cfapitest.Server
	tunnel *cfapitest.Tunnel
	zone   string
	saves  *int
}

func tunnelTokenFor(id string) string {
	doc, _ := json.Marshal(map[string]string{"a": cfapitest.Account, "t": id, "s": "c2VjcmV0"})
	return base64.StdEncoding.EncodeToString(doc)
}

func newCFFixture(t *testing.T) *cfFixture {
	t.Helper()
	h, cfg, _, _ := newTunnelTestHandler(t)
	fake := cfapitest.New(t)
	tn := fake.AddTunnel("irongrid", "healthy", 2)
	zone := fake.AddZone("example.com")
	saves := 0
	prev := h.SaveConfig
	h.SaveConfig = func() error { saves++; return prev() }
	h.CloudflareBaseURL = fake.URL
	cfg.Tunnel.CloudflareAPIToken = cfapitest.Token
	cfg.Tunnel.Token = tunnelTokenFor(tn.ID)
	return &cfFixture{h: h, cfg: cfg, fake: fake, tunnel: tn, zone: zone, saves: &saves}
}

// do sends a request through the router and decodes the JSON answer.
func (f *cfFixture) do(method, path string, body any) (int, map[string]any) {
	var rdr *bytes.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rdr = bytes.NewReader(b)
	} else {
		rdr = bytes.NewReader(nil)
	}
	rr := httptest.NewRecorder()
	f.h.HandleAPI(rr, httptest.NewRequest(method, path, rdr))
	var out map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &out)
	if out == nil {
		out = map[string]any{"_raw": rr.Body.String()}
	}
	return rr.Code, out
}

func hostnames(t *testing.T, out map[string]any) map[string]map[string]any {
	t.Helper()
	list, _ := out["hostnames"].([]any)
	m := map[string]map[string]any{}
	for _, it := range list {
		row := it.(map[string]any)
		m[row["hostname"].(string)] = row
	}
	return m
}

func dnsState(row map[string]any) string {
	d, _ := row["dns"].(map[string]any)
	s, _ := d["state"].(string)
	return s
}

func TestCFNeedsAnAPITokenFirst(t *testing.T) {
	t.Parallel()
	f := newCFFixture(t)
	f.cfg.Tunnel.CloudflareAPIToken = ""
	code, out := f.do(http.MethodGet, "/api/tunnel/cf/hostnames", nil)
	if code != http.StatusBadRequest || out["needs"] != "api_token" {
		t.Fatalf("hostnames without a token = %d %v, want 400 needs api_token", code, out)
	}
	if n := f.fake.CallCount(""); n != 0 {
		t.Errorf("%d Cloudflare calls were made without a token", n)
	}
}

// The credentials are verified against Cloudflare before they are saved, and
// they are never echoed back.
func TestCFCredentialsAreVerifiedSavedAndNeverEchoed(t *testing.T) {
	t.Parallel()
	f := newCFFixture(t)
	f.cfg.Tunnel.CloudflareAPIToken = ""

	code, out := f.do(http.MethodPut, "/api/tunnel/cf/credentials", map[string]string{"api_token": "wrong-token"})
	if code != http.StatusBadGateway || out["permission"] != true {
		t.Fatalf("bad token = %d %v, want 502 with permission=true (never 401/403, which means session-expired)", code, out)
	}
	if f.cfg.Tunnel.CloudflareAPIToken != "" || *f.saves != 0 {
		t.Fatal("a token Cloudflare rejected was saved")
	}

	code, out = f.do(http.MethodPut, "/api/tunnel/cf/credentials", map[string]string{"api_token": cfapitest.Token})
	if code != http.StatusOK || out["api_token_set"] != true || out["account_id"] != cfapitest.Account {
		t.Fatalf("good token = %d %v", code, out)
	}
	if f.cfg.Tunnel.CloudflareAPIToken != cfapitest.Token || f.cfg.Tunnel.CloudflareAccountID != cfapitest.Account {
		t.Errorf("credentials not stored: %+v", f.cfg.Tunnel)
	}
	if tun, _ := out["tunnel"].(map[string]any); tun == nil || tun["name"] != "irongrid" {
		t.Errorf("status did not report the tunnel: %v", out["tunnel"])
	}

	_, body := f.do(http.MethodGet, "/api/tunnel/cf/status", nil)
	raw, _ := json.Marshal(body)
	if strings.Contains(string(raw), cfapitest.Token) {
		t.Error("the API token appears in the status response")
	}

	code, out = f.do(http.MethodPut, "/api/tunnel/cf/credentials", map[string]string{"api_token": ""})
	if code != http.StatusOK || out["api_token_set"] != false || f.cfg.Tunnel.CloudflareAPIToken != "" {
		t.Errorf("disconnect = %d %v, token %q", code, out, f.cfg.Tunnel.CloudflareAPIToken)
	}
}

func TestCFAccountIsDiscoveredWhenNoTunnelTokenIsSaved(t *testing.T) {
	t.Parallel()
	f := newCFFixture(t)
	f.cfg.Tunnel.CloudflareAPIToken, f.cfg.Tunnel.Token = "", ""
	code, out := f.do(http.MethodPut, "/api/tunnel/cf/credentials", map[string]string{"api_token": cfapitest.Token})
	if code != http.StatusOK || f.cfg.Tunnel.CloudflareAccountID != cfapitest.Account {
		t.Fatalf("= %d %v, account %q; want the only visible account to be picked", code, out, f.cfg.Tunnel.CloudflareAccountID)
	}
}

// A plain settings save rebuilds the tunnel config from the dashboard's
// payload, which has no Cloudflare fields; it must not disconnect the account.
func TestSettingsSaveKeepsTheCloudflareCredentials(t *testing.T) {
	t.Parallel()
	running := &config.Config{}
	running.Tunnel.CloudflareAPIToken = "tok"
	running.Tunnel.CloudflareAccountID = "acct"
	fresh := &config.Config{} // what a payload rebuild produces
	carryOverUneditable(fresh, running)
	if fresh.Tunnel.CloudflareAPIToken != "tok" || fresh.Tunnel.CloudflareAccountID != "acct" {
		t.Errorf("credentials lost across a settings save: %+v", fresh.Tunnel)
	}
	// ...and the settings payload must not carry the token out to the browser.
	raw, _ := json.Marshal(payloadFromConfig(running))
	if strings.Contains(string(raw), "tok\"") && strings.Contains(string(raw), "cloudflare") {
		t.Errorf("the settings payload exposes Cloudflare credentials: %s", raw)
	}
}

func TestCFHostnamesListShowsDNSAndOriginState(t *testing.T) {
	t.Parallel()
	f := newCFFixture(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	up := strconv.Itoa(ln.Addr().(*net.TCPAddr).Port)
	closed, _ := net.Listen("tcp", "127.0.0.1:0")
	down := strconv.Itoa(closed.Addr().(*net.TCPAddr).Port)
	closed.Close()

	f.fake.SetConfig(f.tunnel.ID, `{"ingress":[
	  {"hostname":"ok.example.com","service":"http://localhost:`+up+`"},
	  {"hostname":"missing.example.com","service":"http://localhost:`+down+`"},
	  {"hostname":"dnsonly.example.com","service":"https://remote.internal:8443"},
	  {"hostname":"clash.example.com","service":"http://localhost:`+up+`"},
	  {"hostname":"elsewhere.other.org","service":"http://localhost:`+up+`"},
	  {"service":"http_status:404"}]}`)
	target := cfapi.TunnelTarget(f.tunnel.ID)
	f.fake.AddRecord(f.zone, "ok.example.com", "CNAME", target, true)
	f.fake.AddRecord(f.zone, "dnsonly.example.com", "CNAME", target, false)
	f.fake.AddRecord(f.zone, "clash.example.com", "A", "192.0.2.9", false)

	code, out := f.do(http.MethodGet, "/api/tunnel/cf/hostnames", nil)
	if code != http.StatusOK {
		t.Fatalf("= %d %v", code, out)
	}
	rows := hostnames(t, out)
	for host, want := range map[string]string{
		"ok.example.com": "ok", "missing.example.com": "missing", "dnsonly.example.com": "proxy_off",
		"clash.example.com": "conflict", "elsewhere.other.org": "no_zone",
	} {
		if got := dnsState(rows[host]); got != want {
			t.Errorf("%s DNS state = %q, want %q (%v)", host, got, want, rows[host]["dns"])
		}
	}
	if rows["ok.example.com"]["origin_reachable"] != true {
		t.Error("a listening loopback origin was not reported reachable")
	}
	if rows["missing.example.com"]["origin_reachable"] != false {
		t.Error("a closed loopback origin was not reported unreachable")
	}
	if rows["dnsonly.example.com"]["origin_reachable"] != nil {
		t.Error("a non-loopback origin must not be probed from this host")
	}
	if out["catch_all"] != "http_status:404" {
		t.Errorf("catch_all = %v", out["catch_all"])
	}
}

func TestCFHostnamesListIsBrieflyCachedAndClearedByWrites(t *testing.T) {
	t.Parallel()
	f := newCFFixture(t)
	f.do(http.MethodGet, "/api/tunnel/cf/hostnames", nil)
	f.do(http.MethodGet, "/api/tunnel/cf/hostnames", nil)
	if n := f.fake.CallCount("GET /accounts/acc1/cfd_tunnel/" + f.tunnel.ID + "/configurations"); n != 1 {
		t.Errorf("two listings cost %d configuration reads, want 1 (cached)", n)
	}
	f.do(http.MethodPost, "/api/tunnel/cf/hostnames", map[string]any{"hostname": "new.example.com", "service": "http://localhost:80", "create_dns": false})
	f.do(http.MethodGet, "/api/tunnel/cf/hostnames", nil)
	if n := f.fake.CallCount("GET /accounts/acc1/cfd_tunnel/" + f.tunnel.ID + "/configurations"); n < 3 {
		t.Errorf("a write did not invalidate the cache (%d reads)", n)
	}
}

func TestCFAddHostnameWritesIngressAndDNS(t *testing.T) {
	t.Parallel()
	f := newCFFixture(t)
	f.fake.SetConfig(f.tunnel.ID, `{"warp-routing":{"enabled":true},"ingress":[{"hostname":"old.example.com","service":"http://localhost:1"},{"service":"http_status:404"}]}`)

	code, out := f.do(http.MethodPost, "/api/tunnel/cf/hostnames", map[string]any{
		"hostname": "DNS.Example.com.", "service": "https://localhost:443", "no_tls_verify": true,
	})
	if code != http.StatusOK || out["saved"] != true || out["replaced"] != false {
		t.Fatalf("add = %d %v", code, out)
	}
	if d, _ := out["dns"].(map[string]any); d["state"] != "ok" {
		t.Errorf("dns = %v, want ok", out["dns"])
	}
	cfg := f.fake.Config(f.tunnel.ID)
	if _, ok := cfg["warp-routing"]; !ok {
		t.Error("an unrelated tunnel setting was dropped by the write")
	}
	var rules []map[string]any
	_ = json.Unmarshal(cfg["ingress"], &rules)
	if len(rules) != 3 || rules[0]["hostname"] != "old.example.com" || rules[1]["hostname"] != "dns.example.com" || rules[2]["hostname"] != nil {
		t.Fatalf("ingress = %v, want old, dns (normalised), catch-all last", rules)
	}
	if o, _ := rules[1]["originRequest"].(map[string]any); o["noTLSVerify"] != true {
		t.Errorf("noTLSVerify not stored: %v", rules[1])
	}
	recs := f.fake.RecordsFor()
	if len(recs) != 1 || recs[0].Name != "dns.example.com" || recs[0].Content != cfapi.TunnelTarget(f.tunnel.ID) || !recs[0].Proxied {
		t.Fatalf("records = %+v, want one proxied CNAME to the tunnel", recs)
	}

	// Saving it again is an edit, not a duplicate, and creates no second record.
	code, out = f.do(http.MethodPut, "/api/tunnel/cf/hostnames", map[string]any{"hostname": "dns.example.com", "service": "http://localhost:8080"})
	if code != http.StatusOK || out["replaced"] != true {
		t.Fatalf("edit = %d %v", code, out)
	}
	if len(f.fake.RecordsFor()) != 1 {
		t.Errorf("editing created a second DNS record: %+v", f.fake.RecordsFor())
	}
	_ = json.Unmarshal(f.fake.Config(f.tunnel.ID)["ingress"], &rules)
	if len(rules) != 3 || rules[1]["service"] != "http://localhost:8080" {
		t.Errorf("ingress after edit = %v", rules)
	}
}

func TestCFEditingAnUnknownHostnameIs404(t *testing.T) {
	t.Parallel()
	f := newCFFixture(t)
	code, _ := f.do(http.MethodPut, "/api/tunnel/cf/hostnames", map[string]any{"hostname": "nope.example.com", "service": "http://localhost:1"})
	if code != http.StatusNotFound {
		t.Errorf("PUT of a missing hostname = %d, want 404", code)
	}
}

// DNS must never clobber another service: an existing A record, or a CNAME
// elsewhere, is reported as a conflict and left exactly as it was unless the
// user explicitly overwrites a CNAME.
func TestCFDNSConflictsAreReportedNotOverwritten(t *testing.T) {
	t.Parallel()
	f := newCFFixture(t)
	f.fake.AddRecord(f.zone, "a.example.com", "A", "192.0.2.1", false)
	f.fake.AddRecord(f.zone, "c.example.com", "CNAME", "elsewhere.net", true)

	code, out := f.do(http.MethodPost, "/api/tunnel/cf/hostnames", map[string]any{"hostname": "a.example.com", "service": "http://localhost:1"})
	if d, _ := out["dns"].(map[string]any); code != http.StatusOK || d["state"] != "conflict" || out["saved"] != true {
		t.Fatalf("A-record clash = %d %v, want saved with a conflict", code, out)
	}
	code, out = f.do(http.MethodPost, "/api/tunnel/cf/hostnames", map[string]any{"hostname": "c.example.com", "service": "http://localhost:1"})
	if d, _ := out["dns"].(map[string]any); d["state"] != "conflict" {
		t.Fatalf("CNAME clash = %d %v", code, out)
	}
	for _, r := range f.fake.RecordsFor() {
		if r.Name == "a.example.com" && r.Content != "192.0.2.1" || r.Name == "c.example.com" && r.Content != "elsewhere.net" {
			t.Errorf("a conflicting record was modified: %+v", r)
		}
	}

	code, out = f.do(http.MethodPost, "/api/tunnel/cf/hostnames/sync-dns", map[string]any{"hostname": "c.example.com", "overwrite": true})
	if d, _ := out["dns"].(map[string]any); code != http.StatusOK || d["state"] != "ok" {
		t.Fatalf("explicit overwrite = %d %v", code, out)
	}
}

func TestCFHostnameInputIsValidatedBeforeAnythingIsWritten(t *testing.T) {
	t.Parallel()
	f := newCFFixture(t)
	for name, body := range map[string]map[string]any{
		"no dot":        {"hostname": "localhost", "service": "http://localhost:1"},
		"bad chars":     {"hostname": "a b.example.com", "service": "http://localhost:1"},
		"leading dash":  {"hostname": "-a.example.com", "service": "http://localhost:1"},
		"file scheme":   {"hostname": "a.example.com", "service": "file:///etc/passwd"},
		"tcp w/o port":  {"hostname": "a.example.com", "service": "tcp://localhost"},
		"with path":     {"hostname": "a.example.com", "service": "http://localhost:80/x"},
		"credentials":   {"hostname": "a.example.com", "service": "http://u:p@localhost:80"},
		"bad port":      {"hostname": "a.example.com", "service": "http://localhost:99999"},
		"empty service": {"hostname": "a.example.com", "service": ""},
		"bad status":    {"hostname": "a.example.com", "service": "http_status:99"},
		"spaced path":   {"hostname": "a.example.com", "service": "http://localhost:1", "path": "/a b"},
	} {
		if code, out := f.do(http.MethodPost, "/api/tunnel/cf/hostnames", body); code != http.StatusBadRequest {
			t.Errorf("%s: = %d %v, want 400", name, code, out)
		}
	}
	if n := f.fake.CallCount("PUT"); n != 0 {
		t.Errorf("%d writes reached Cloudflare for invalid input", n)
	}
	for _, ok := range []string{"http://localhost:8080", "https://127.0.0.1", "tcp://localhost:5432", "ssh://localhost", "http_status:404", "hello_world"} {
		if msg := validCFService(ok); msg != "" {
			t.Errorf("validCFService(%q) rejected a valid origin: %s", ok, msg)
		}
	}
}

func TestCFRemoveHostnameAndOnlyItsOwnDNS(t *testing.T) {
	t.Parallel()
	f := newCFFixture(t)
	target := cfapi.TunnelTarget(f.tunnel.ID)
	f.fake.SetConfig(f.tunnel.ID, `{"ingress":[{"hostname":"a.example.com","service":"http://localhost:1"},{"hostname":"b.example.com","service":"http://localhost:2"},{"service":"http_status:404"}]}`)
	f.fake.AddRecord(f.zone, "a.example.com", "CNAME", target, true)
	f.fake.AddRecord(f.zone, "b.example.com", "CNAME", "someone-elses.net", true)

	code, out := f.do(http.MethodDelete, "/api/tunnel/cf/hostnames?hostname=a.example.com&dns=1", nil)
	if code != http.StatusOK || out["removed"] != true || out["dns_removed"] != float64(1) {
		t.Fatalf("remove a = %d %v", code, out)
	}
	// b's CNAME points elsewhere, so removing b from the tunnel must leave it.
	code, out = f.do(http.MethodDelete, "/api/tunnel/cf/hostnames?hostname=b.example.com&dns=1", nil)
	if code != http.StatusOK || out["dns_removed"] != float64(0) {
		t.Fatalf("remove b = %d %v, want its foreign CNAME left alone", code, out)
	}
	recs := f.fake.RecordsFor()
	if len(recs) != 1 || recs[0].Name != "b.example.com" {
		t.Errorf("records = %+v, want only the foreign b CNAME left", recs)
	}
	var rules []map[string]any
	_ = json.Unmarshal(f.fake.Config(f.tunnel.ID)["ingress"], &rules)
	if len(rules) != 1 || rules[0]["service"] != "http_status:404" {
		t.Errorf("ingress = %v, want just the catch-all", rules)
	}
	if code, _ := f.do(http.MethodDelete, "/api/tunnel/cf/hostnames?hostname=a.example.com", nil); code != http.StatusNotFound {
		t.Errorf("removing it again = %d, want 404", code)
	}
}

func TestCFLocallyConfiguredTunnelCannotBeEditedHere(t *testing.T) {
	t.Parallel()
	f := newCFFixture(t)
	f.tunnel.ConfigSrc = "local"
	code, out := f.do(http.MethodPost, "/api/tunnel/cf/hostnames", map[string]any{"hostname": "a.example.com", "service": "http://localhost:1"})
	if code != http.StatusBadRequest || !strings.Contains(out["error"].(string), "local config file") {
		t.Errorf("= %d %v, want a clear refusal", code, out)
	}
	if f.fake.CallCount("PUT") != 0 {
		t.Error("a write was attempted on a locally-configured tunnel")
	}
}

func TestCFTunnelCreateSelectAndDelete(t *testing.T) {
	t.Parallel()
	f := newCFFixture(t)
	other := f.fake.AddTunnel("spare", "inactive", 0)

	code, out := f.do(http.MethodPost, "/api/tunnel/cf/tunnels", map[string]any{"name": "bad/name"})
	if code != http.StatusBadRequest {
		t.Errorf("a bad tunnel name = %d %v, want 400", code, out)
	}
	code, out = f.do(http.MethodPost, "/api/tunnel/cf/tunnels", map[string]any{"name": "fresh", "select": true})
	if code != http.StatusOK || out["selected"] != true {
		t.Fatalf("create+select = %d %v", code, out)
	}
	id := out["tunnel"].(map[string]any)["id"].(string)
	if _, tid, err := cfapi.ParseTunnelToken(f.cfg.Tunnel.Token); err != nil || tid != id {
		t.Fatalf("the new tunnel's token was not saved (tunnel %q, %v), want %q", tid, err, id)
	}
	if f.cfg.Tunnel.QuickTunnel || f.cfg.Tunnel.ConfigFile != "" {
		t.Error("selecting a named tunnel left quick-tunnel / config-file mode on")
	}

	code, out = f.do(http.MethodGet, "/api/tunnel/cf/tunnels", nil)
	if code != http.StatusOK || out["selected"] != id || len(out["tunnels"].([]any)) != 3 {
		t.Fatalf("list = %d %v", code, out)
	}

	// The selected tunnel cannot be deleted; an idle one can; a busy one is refused by Cloudflare.
	if code, _ := f.do(http.MethodDelete, "/api/tunnel/cf/tunnels/"+id, nil); code != http.StatusConflict {
		t.Errorf("deleting the selected tunnel = %d, want 409", code)
	}
	if code, out := f.do(http.MethodDelete, "/api/tunnel/cf/tunnels/"+other.ID, nil); code != http.StatusOK {
		t.Errorf("deleting an idle tunnel = %d %v", code, out)
	}
	busy := f.fake.AddTunnel("busy", "healthy", 1)
	if code, _ := f.do(http.MethodDelete, "/api/tunnel/cf/tunnels/"+busy.ID, nil); code != http.StatusBadGateway {
		t.Errorf("deleting a tunnel with live connectors = %d, want Cloudflare's refusal as 502", code)
	}
}

// Switching tunnels while one is running would leave the live process on the
// old one, so it is refused.
func TestCFSwitchingTunnelsIsRefusedWhileRunning(t *testing.T) {
	t.Parallel()
	f := newCFFixture(t)
	fakeCloudflared(t, f.h, "2026.11.1")
	if err := f.h.Tunnel.Start(tunnel.ModeQuick, "", "", "http://localhost:8080", ""); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(f.h.Tunnel.Stop)
	other := f.fake.AddTunnel("spare", "inactive", 0)
	before := f.cfg.Tunnel.Token

	code, out := f.do(http.MethodPost, "/api/tunnel/cf/tunnels/select", map[string]string{"tunnel_id": other.ID})
	if code != http.StatusConflict || f.cfg.Tunnel.Token != before {
		t.Errorf("select while running = %d %v, token changed: %v", code, out, f.cfg.Tunnel.Token != before)
	}
}

func TestCFPermissionFailuresAre502NotSessionExpiry(t *testing.T) {
	t.Parallel()
	f := newCFFixture(t)
	f.cfg.Tunnel.CloudflareAPIToken = "revoked"
	code, out := f.do(http.MethodGet, "/api/tunnel/cf/hostnames", nil)
	if code != http.StatusBadGateway || out["permission"] != true {
		t.Errorf("= %d %v, want 502 + permission (a 401/403 would log the user out of the dashboard)", code, out)
	}
	code, out = f.do(http.MethodGet, "/api/tunnel/cf/status", nil)
	if code != http.StatusOK || out["permission"] != true || out["error"] == nil {
		t.Errorf("status = %d %v, want 200 carrying the permission problem", code, out)
	}
}

func TestCFSuggestedOriginsFollowTheListeners(t *testing.T) {
	t.Parallel()
	f := newCFFixture(t)
	f.cfg.Server.WebListen, f.cfg.Server.WebTLS, f.cfg.Server.ListenDoH = "0.0.0.0:443", true, "0.0.0.0:443"
	got := f.h.suggestedOrigins()
	if len(got) != 1 || got[0].Service != "https://localhost:443" || !got[0].NoTLSVerify || !strings.Contains(got[0].Label, "shared") {
		t.Errorf("shared port: %+v", got)
	}
	f.cfg.Server.WebListen, f.cfg.Server.WebTLS, f.cfg.Server.ListenDoH = "0.0.0.0:8080", false, "0.0.0.0:8443"
	got = f.h.suggestedOrigins()
	if len(got) != 2 || got[0].Service != "http://localhost:8080" || got[0].NoTLSVerify || got[1].Service != "https://localhost:8443" {
		t.Errorf("separate ports: %+v", got)
	}
}

func (f *cfFixture) seedDNSHosts() {
	f.fake.SetConfig(f.tunnel.ID, `{"ingress":[
	  {"hostname":"ok.example.com","service":"http://localhost:1"},
	  {"hostname":"missing.example.com","service":"http://localhost:2"},
	  {"service":"http_status:404"}]}`)
	f.fake.AddRecord(f.zone, "ok.example.com", "CNAME", cfapi.TunnelTarget(f.tunnel.ID), true)
}

// The token can see the zone but has no DNS permission on it. Cloudflare only
// says "Authentication error"; the page must say which zone, so the fix is
// obvious.
func TestCFDNSDenialNamesTheZone(t *testing.T) {
	t.Parallel()
	f := newCFFixture(t)
	f.seedDNSHosts()
	f.fake.Deny(cfapitest.Token, true, false)

	code, out := f.do(http.MethodGet, "/api/tunnel/cf/hostnames", nil)
	if code != http.StatusOK {
		t.Fatalf("= %d %v", code, out)
	}
	if z, _ := out["dns_denied_zones"].([]any); len(z) != 1 || z[0] != "example.com" {
		t.Errorf("dns_denied_zones = %v, want [example.com]", out["dns_denied_zones"])
	}
	if out["dns_error"] != nil {
		t.Errorf("a permission denial was reported as a generic error: %v", out["dns_error"])
	}
	row := hostnames(t, out)["ok.example.com"]
	d, _ := row["dns"].(map[string]any)
	if d["state"] != "unknown" || !strings.Contains(d["detail"].(string), "example.com") {
		t.Errorf("row dns = %v, want unknown naming the zone", d)
	}

	// Writing reports the same cause, and still saves the hostname itself.
	code, out = f.do(http.MethodPost, "/api/tunnel/cf/hostnames", map[string]any{"hostname": "new.example.com", "service": "http://localhost:3"})
	msg, _ := out["dns_error"].(string)
	if code != http.StatusOK || out["saved"] != true || !strings.Contains(msg, "DNS records in example.com") {
		t.Errorf("add under a DNS denial = %d %v", code, out)
	}
}

// The certificate settings hold a second Cloudflare token. It stands in for DNS
// records only when the tunnel token is refused, and never otherwise.
func TestCFDNSFallsBackToTheACMETokenOnlyWhenRefused(t *testing.T) {
	t.Parallel()
	f := newCFFixture(t)
	f.seedDNSHosts()
	f.cfg.TLS.ACME.DNS01.CloudflareToken = cfapitest.DNSToken
	f.fake.Deny(cfapitest.Token, true, false)

	_, out := f.do(http.MethodGet, "/api/tunnel/cf/hostnames", nil)
	rows := hostnames(t, out)
	if dnsState(rows["ok.example.com"]) != "ok" || dnsState(rows["missing.example.com"]) != "missing" {
		t.Fatalf("states with the fallback = %v / %v", rows["ok.example.com"]["dns"], rows["missing.example.com"]["dns"])
	}
	if out["dns_via_acme"] != true || out["dns_denied_zones"] != nil {
		t.Errorf("dns_via_acme=%v denied=%v, want the fallback reported and nothing denied", out["dns_via_acme"], out["dns_denied_zones"])
	}

	code, out := f.do(http.MethodPost, "/api/tunnel/cf/hostnames", map[string]any{"hostname": "new.example.com", "service": "http://localhost:3"})
	if d, _ := out["dns"].(map[string]any); code != http.StatusOK || d["state"] != "ok" || out["dns_via_acme"] != true {
		t.Fatalf("add via the fallback = %d %v", code, out)
	}
	created := false
	for _, r := range f.fake.RecordsFor() {
		created = created || r.Name == "new.example.com"
	}
	if !created {
		t.Error("the fallback token did not create the DNS record")
	}

	// Once the tunnel token has DNS permission the fallback is not touched.
	f.fake.Deny(cfapitest.Token, false, false)
	f.h.cfCacheClear()
	before := f.fake.CallsBy(cfapitest.DNSToken)
	_, out = f.do(http.MethodGet, "/api/tunnel/cf/hostnames", nil)
	if f.fake.CallsBy(cfapitest.DNSToken) != before || out["dns_via_acme"] != nil {
		t.Errorf("the ACME token was used although the tunnel token works (via_acme=%v)", out["dns_via_acme"])
	}
}

func TestCFFallbackAlsoRefusedStillNamesTheZone(t *testing.T) {
	t.Parallel()
	f := newCFFixture(t)
	f.seedDNSHosts()
	f.cfg.TLS.ACME.DNS01.CloudflareToken = cfapitest.DNSToken
	f.fake.Deny(cfapitest.Token, true, false)
	f.fake.Deny(cfapitest.DNSToken, true, false)

	_, out := f.do(http.MethodGet, "/api/tunnel/cf/hostnames", nil)
	if z, _ := out["dns_denied_zones"].([]any); len(z) != 1 || out["dns_via_acme"] != nil {
		t.Errorf("denied=%v via_acme=%v, want the zone named and no claim the fallback helped", out["dns_denied_zones"], out["dns_via_acme"])
	}
}

// A token without Zone › Zone › Read cannot list zones at all; the fallback
// token may.
func TestCFZoneListFallsBackToo(t *testing.T) {
	t.Parallel()
	f := newCFFixture(t)
	f.seedDNSHosts()
	f.cfg.TLS.ACME.DNS01.CloudflareToken = cfapitest.DNSToken
	f.fake.Deny(cfapitest.Token, true, true)

	code, out := f.do(http.MethodGet, "/api/tunnel/cf/zones", nil)
	if zs, _ := out["zones"].([]any); code != http.StatusOK || len(zs) != 1 {
		t.Fatalf("zones = %d %v", code, out)
	}
	_, out = f.do(http.MethodGet, "/api/tunnel/cf/hostnames", nil)
	if dnsState(hostnames(t, out)["ok.example.com"]) != "ok" {
		t.Errorf("states did not resolve through the fallback: %v", out)
	}
}

func TestCFStatusReportsWhetherAFallbackExists(t *testing.T) {
	t.Parallel()
	f := newCFFixture(t)
	if _, out := f.do(http.MethodGet, "/api/tunnel/cf/status", nil); out["dns_fallback"] != nil {
		t.Errorf("dns_fallback = %v with no ACME token", out["dns_fallback"])
	}
	f.cfg.TLS.ACME.DNS01.CloudflareToken = cfapitest.Token // the very same token adds nothing
	if _, out := f.do(http.MethodGet, "/api/tunnel/cf/status", nil); out["dns_fallback"] != nil {
		t.Errorf("dns_fallback = %v for the identical token", out["dns_fallback"])
	}
	f.cfg.TLS.ACME.DNS01.CloudflareToken = cfapitest.DNSToken
	if _, out := f.do(http.MethodGet, "/api/tunnel/cf/status", nil); out["dns_fallback"] != true {
		t.Errorf("dns_fallback = %v, want true with a distinct ACME token", out["dns_fallback"])
	}
}
