//go:build smoke

// Boot smoke test: runs the real irongrid binary end to end against an isolated
// Dragonfly and fake upstreams, and checks what an operator depends on —
// plain DNS, DoT, DoH over HTTP/2, the dashboard + API, filtering, an
// in-process config reload that rebinds listeners, and clean shutdown.
//
// It exists to make refactors of main() (which has no unit tests) safe, so it
// is behind a build tag and run on demand:
//
//	go test -tags smoke -count=1 -run TestSmoke ./cmd/irongrid/
//
// Needs a `dragonfly` binary (PATH, or IRONGRID_SMOKE_DRAGONFLY); skips without
// one. IRONGRID_SMOKE_BIN reuses a prebuilt binary instead of building one;
// IRONGRID_SMOKE_PPROF=1 enables /debug/pprof on the test instance.
// Nothing here touches a running production instance: every port is an
// ephemeral loopback port and Dragonfly is a private throwaway process.
package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
	"codeberg.org/miekg/dns/rdata"
	"codeberg.org/miekg/dns/svcb"

	"github.com/eoghan2t9/Irongrid-DNS/internal/config"
)

// ---------- helpers ----------

func freeTCPPort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

// freePort returns a port free for both TCP and UDP.
func freePort(t *testing.T) int {
	t.Helper()
	for range 50 {
		p := freeTCPPort(t)
		if l, err := net.ListenPacket("udp", fmt.Sprintf("127.0.0.1:%d", p)); err == nil {
			l.Close()
			return p
		}
	}
	t.Fatal("no port free for tcp+udp")
	return 0
}

func waitFor(t *testing.T, what string, d time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("timed out after %s waiting for %s", d, what)
}

type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// fakeUpstream answers every A query with ip, over UDP and TCP.
func fakeUpstream(t *testing.T, ip string) int {
	t.Helper()
	port := freePort(t)
	h := dns.HandlerFunc(func(_ context.Context, w dns.ResponseWriter, r *dns.Msg) {
		_ = r.Unpack()
		m := new(dns.Msg)
		dnsutil.SetReply(m, r)
		if len(r.Question) > 0 && dns.RRToType(r.Question[0]) == dns.TypeA {
			m.Answer = append(m.Answer, &dns.A{
				Hdr: dns.Header{Name: r.Question[0].Header().Name, Class: dns.ClassINET, TTL: 60},
				A:   rdata.A{Addr: netip.MustParseAddr(ip)},
			})
		}
		_ = m.Pack()
		_, _ = m.WriteTo(w)
	})
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	for _, netw := range []string{"udp", "tcp"} {
		started := make(chan struct{})
		srv := &dns.Server{
			Addr:              addr,
			Net:               netw,
			Handler:           h,
			NotifyStartedFunc: func(context.Context) { close(started) },
		}
		go func() { _ = srv.ListenAndServe() }()
		<-started
		t.Cleanup(func() { srv.Shutdown(context.Background()) })
	}
	return port
}

func startDragonfly(t *testing.T) string {
	t.Helper()
	bin := os.Getenv("IRONGRID_SMOKE_DRAGONFLY")
	if bin == "" {
		var err error
		if bin, err = exec.LookPath("dragonfly"); err != nil {
			t.Skip("no dragonfly binary (set IRONGRID_SMOKE_DRAGONFLY)")
		}
	}
	port := freeTCPPort(t)
	dir := t.TempDir()
	cmd := exec.Command(bin, fmt.Sprintf("--port=%d", port), "--bind=127.0.0.1",
		"--dir="+dir, "--proactor_threads=1", "--maxmemory=256mb", "--cache_mode=true",
		"--logtostderr=false", "--alsologtostderr=false", "--log_dir="+dir)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	waitFor(t, "dragonfly", 15*time.Second, func() bool {
		c, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err == nil {
			c.Close()
			return true
		}
		return false
	})
	return addr
}

func buildBinary(t *testing.T) string {
	t.Helper()
	if b := os.Getenv("IRONGRID_SMOKE_BIN"); b != "" {
		return b
	}
	out := filepath.Join(t.TempDir(), "irongrid")
	cmd := exec.Command("go", "build", "-o", out, ".")
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build failed: %v\n%s", err, b)
	}
	return out
}

func query(t *testing.T, netw, addr, name string, qtype uint16) (*dns.Msg, error) {
	t.Helper()
	c := dns.NewClient()
	c.Transport.ReadTimeout = 3 * time.Second
	c.Transport.Dialer.Timeout = 3 * time.Second
	if netw == "tcp-tls" {
		c.TLSConfig = &tls.Config{InsecureSkipVerify: true}
		netw = "tcp"
	}
	m := dns.NewMsg(dnsutil.Fqdn(name), qtype)
	r, _, err := c.Exchange(context.Background(), m, netw, addr)
	return r, err
}

func firstA(r *dns.Msg) string {
	if r == nil {
		return ""
	}
	for _, rr := range r.Answer {
		if a, ok := rr.(*dns.A); ok {
			return a.A.String()
		}
	}
	return ""
}

// ---------- the test ----------

type smokeEnv struct {
	t                       *testing.T
	cmd                     *exec.Cmd
	log                     *syncBuf
	udp, tcp, dot, doh, web int
	webScheme               string
	upA, upB                int
	api                     *http.Client
	exited                  chan error
	curUDP                  int // UDP port after the reload test rebinds it
}

const smokePassword = "smoke-pass"

func bootSmoke(t *testing.T, shared bool) *smokeEnv {
	t.Helper()
	dflyAddr := startDragonfly(t)
	bin := buildBinary(t)
	work := t.TempDir()

	env := &smokeEnv{t: t, log: &syncBuf{}, exited: make(chan error, 1)}
	env.upA = fakeUpstream(t, "198.51.100.10")
	env.upB = fakeUpstream(t, "198.51.100.20")
	env.udp, env.tcp, env.dot, env.doh = freePort(t), freePort(t), freePort(t), freePort(t)
	env.web = freeTCPPort(t)

	listPath := filepath.Join(work, "blocklist.txt")
	if err := os.WriteFile(listPath, []byte("0.0.0.0 blocked.smoke.test\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg := config.Default()
	cfg.Server.ListenUDP = fmt.Sprintf("127.0.0.1:%d", env.udp)
	cfg.Server.ListenTCP = fmt.Sprintf("127.0.0.1:%d", env.tcp)
	cfg.Server.ListenDoT = fmt.Sprintf("127.0.0.1:%d", env.dot)
	cfg.Server.ListenDoH = fmt.Sprintf("127.0.0.1:%d", env.doh)
	cfg.Server.ListenDoQ = ""
	cfg.Server.DiscoveryHost = "dns.smoke.test"                     // advertised via DDR (RFC 9462)
	cfg.Server.DebugPprof = os.Getenv("IRONGRID_SMOKE_PPROF") != "" // opt-in: expose /debug/pprof (test credentials only)
	cfg.Server.WebListen = fmt.Sprintf("127.0.0.1:%d", env.web)
	env.webScheme = "http"
	if shared {
		// Dashboard and DoH on one HTTPS port: the case that needs h2 on the
		// dashboard listener.
		cfg.Server.WebListen = cfg.Server.ListenDoH
		cfg.Server.WebTLS = true
		env.web = env.doh
		env.webScheme = "https"
	}
	cfg.Upstreams = []string{fmt.Sprintf("udp://127.0.0.1:%d", env.upA)}
	cfg.Cache.Addr = dflyAddr
	cfg.TLS.CertDir = filepath.Join(work, "certs")
	cfg.TLS.SelfSignedHosts = []string{"localhost", "127.0.0.1"}
	cfg.Web.Username = "admin"
	cfg.Web.Password = smokePassword
	cfg.Filter.AutoUpdate = 0
	cfg.Filter.Blocklists = []config.BlocklistSpec{{ID: "smoke", Name: "smoke", URL: "file://" + listPath, Enabled: true}}
	cfgPath := filepath.Join(work, "irongrid.yaml")
	if err := cfg.Save(cfgPath); err != nil {
		t.Fatal(err)
	}

	env.cmd = exec.Command(bin, "-config", cfgPath, "-data", filepath.Join(work, "data"))
	env.cmd.Dir = work
	env.cmd.Stdout, env.cmd.Stderr = env.log, env.log
	if err := env.cmd.Start(); err != nil {
		t.Fatal(err)
	}
	go func() { env.exited <- env.cmd.Wait() }()
	t.Cleanup(func() {
		if env.cmd.ProcessState == nil {
			_ = env.cmd.Process.Kill()
		}
		if t.Failed() {
			t.Logf("---- irongrid log ----\n%s", env.log.String())
		}
	})

	env.api = &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, ForceAttemptHTTP2: true,
	}}
	waitFor(t, "DNS to answer", 40*time.Second, func() bool {
		r, err := query(t, "udp", fmt.Sprintf("127.0.0.1:%d", env.udp), "ready.smoke.test", dns.TypeA)
		return err == nil && r != nil && r.Rcode == dns.RcodeSuccess
	})
	return env
}

func (e *smokeEnv) url(path string) string {
	return fmt.Sprintf("%s://127.0.0.1:%d%s", e.webScheme, e.web, path)
}

func (e *smokeEnv) apiDo(method, path string, body any) (*http.Response, []byte) {
	e.t.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, _ := http.NewRequestWithContext(context.Background(), method, e.url(path), rd)
	req.SetBasicAuth("admin", smokePassword)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := e.api.Do(req)
	if err != nil {
		e.t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp, b
}

func (e *smokeEnv) getConfig() map[string]any {
	e.t.Helper()
	_, body := e.apiDo(http.MethodGet, "/api/config", nil)
	var cfg map[string]any
	if err := json.Unmarshal(body, &cfg); err != nil {
		e.t.Fatal(err)
	}
	return cfg
}

func TestSmokeStandalone(t *testing.T)   { runSmoke(t, false) }
func TestSmokeSharedDoHWeb(t *testing.T) { runSmoke(t, true) }

func runSmoke(t *testing.T, shared bool) {
	e := bootSmoke(t, shared)
	udpAddr := fmt.Sprintf("127.0.0.1:%d", e.udp)

	t.Run("dns-udp-tcp", func(t *testing.T) {
		for _, netw := range []string{"udp", "tcp"} {
			addr := udpAddr
			if netw == "tcp" {
				addr = fmt.Sprintf("127.0.0.1:%d", e.tcp)
			}
			r, err := query(t, netw, addr, "ok-"+netw+".smoke.test", dns.TypeA)
			if err != nil || firstA(r) != "198.51.100.10" {
				t.Fatalf("%s: got %q err=%v, want 198.51.100.10 from upstream A", netw, firstA(r), err)
			}
		}
	})

	t.Run("filtering", func(t *testing.T) {
		for _, name := range []string{"blocked.smoke.test", "sub.blocked.smoke.test"} {
			r, err := query(t, "udp", udpAddr, name, dns.TypeA)
			if err != nil || r.Rcode != dns.RcodeNameError {
				t.Fatalf("%s: rcode=%v err=%v, want NXDOMAIN", name, r, err)
			}
		}
	})

	t.Run("dot", func(t *testing.T) {
		r, err := query(t, "tcp-tls", fmt.Sprintf("127.0.0.1:%d", e.dot), "ok-dot.smoke.test", dns.TypeA)
		if err != nil || firstA(r) != "198.51.100.10" {
			t.Fatalf("DoT: got %q err=%v", firstA(r), err)
		}
	})

	// DDR (RFC 9462): the real binary answers _dns.resolver.arpa locally with
	// the configured DoH and DoT endpoints — not forwarded to the (fake)
	// upstream, which would answer it with an A record.
	t.Run("ddr", func(t *testing.T) {
		r, err := query(t, "udp", fmt.Sprintf("127.0.0.1:%d", e.udp), "_dns.resolver.arpa", dns.TypeSVCB)
		if err != nil || r == nil || r.Rcode != dns.RcodeSuccess {
			t.Fatalf("DDR query: %v err=%v", r, err)
		}
		var sawDoH, sawDoT bool
		for _, rr := range r.Answer {
			s, ok := rr.(*dns.SVCB)
			if !ok {
				t.Fatalf("DDR answer is %T, want SVCB (forwarded upstream?)", rr)
			}
			if s.Target != "dns.smoke.test." {
				t.Errorf("DDR target = %q", s.Target)
			}
			for _, kv := range s.Value {
				if a, ok := kv.(*svcb.ALPN); ok {
					switch strings.Join(a.Alpn, ",") {
					case "h2":
						sawDoH = true
					case "dot":
						sawDoT = true
					}
				}
			}
		}
		if !sawDoH || !sawDoT {
			t.Fatalf("DDR missing endpoints (doh=%v dot=%v): %v", sawDoH, sawDoT, r.Answer)
		}
	})

	t.Run("doh-over-http2", func(t *testing.T) {
		m := dns.NewMsg("ok-doh.smoke.test.", dns.TypeA)
		_ = m.Pack()
		wire := m.Data
		req, _ := http.NewRequest(http.MethodPost, fmt.Sprintf("https://127.0.0.1:%d/dns-query", e.doh), bytes.NewReader(wire))
		req.Header.Set("Content-Type", "application/dns-message")
		req.Header.Set("Accept", "application/dns-message")
		resp, err := e.api.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if resp.ProtoMajor != 2 {
			t.Fatalf("DoH negotiated %s, want HTTP/2", resp.Proto)
		}
		body, _ := io.ReadAll(resp.Body)
		var ans dns.Msg
		ans.Data = body
		if err := ans.Unpack(); err != nil || firstA(&ans) != "198.51.100.10" {
			t.Fatalf("DoH answer %q err=%v status=%d", firstA(&ans), err, resp.StatusCode)
		}
	})

	t.Run("dashboard-and-api", func(t *testing.T) {
		resp, body := e.apiDo(http.MethodGet, "/", nil)
		if resp.StatusCode != 200 || !strings.Contains(strings.ToLower(string(body)), "<html") {
			t.Fatalf("dashboard: status %d, %d bytes", resp.StatusCode, len(body))
		}
		if shared && resp.ProtoMajor != 2 {
			t.Fatalf("shared dashboard negotiated %s, want HTTP/2", resp.Proto)
		}
		for _, p := range []string{"/api/status", "/api/stats", "/api/config", "/api/lists", "/api/log?limit=5"} {
			resp, body := e.apiDo(http.MethodGet, p, nil)
			if resp.StatusCode != 200 || !json.Valid(body) {
				t.Fatalf("GET %s: status %d body %.120s", p, resp.StatusCode, body)
			}
		}
		req, _ := http.NewRequest(http.MethodGet, e.url("/api/config"), nil)
		resp2, err := e.api.Do(req)
		if err != nil || resp2.StatusCode != http.StatusUnauthorized {
			t.Fatalf("unauthenticated /api/config: %v %v, want 401", resp2, err)
		}
		resp2.Body.Close()
	})

	t.Run("reload-rebinds-listeners-and-swaps-upstreams", func(t *testing.T) {
		cfg := e.getConfig()
		newUDP, newTCP := freePort(t), freePort(t)
		srv := cfg["server"].(map[string]any)
		srv["listen_udp"] = fmt.Sprintf("127.0.0.1:%d", newUDP)
		srv["listen_tcp"] = fmt.Sprintf("127.0.0.1:%d", newTCP)
		cfg["upstreams"] = []string{fmt.Sprintf("udp://127.0.0.1:%d", e.upB)}
		if resp, b := e.apiDo(http.MethodPut, "/api/config", cfg); resp.StatusCode != 200 {
			t.Fatalf("PUT config: %d %s", resp.StatusCode, b)
		}
		if resp, b := e.apiDo(http.MethodPost, "/api/config/reload", nil); resp.StatusCode != 200 {
			t.Fatalf("reload: %d %s", resp.StatusCode, b)
		}
		e.curUDP = newUDP
		newUDPAddr := fmt.Sprintf("127.0.0.1:%d", newUDP)
		waitFor(t, "new UDP listener", 15*time.Second, func() bool {
			r, err := query(t, "udp", newUDPAddr, "after-reload.smoke.test", dns.TypeA)
			return err == nil && firstA(r) == "198.51.100.20"
		})
		if r, err := query(t, "tcp", fmt.Sprintf("127.0.0.1:%d", newTCP), "after-reload-tcp.smoke.test", dns.TypeA); err != nil || firstA(r) != "198.51.100.20" {
			t.Fatalf("new TCP listener after reload: %q err=%v", firstA(r), err)
		}
		c := dns.NewClient()
		c.Transport.ReadTimeout = 800 * time.Millisecond
		c.Transport.Dialer.Timeout = 800 * time.Millisecond
		m := dns.NewMsg("old-port.smoke.test.", dns.TypeA)
		if r, _, err := c.Exchange(context.Background(), m, "udp", udpAddr); err == nil && r != nil {
			t.Fatalf("old UDP listener still answering after reload")
		}
		if r, err := query(t, "udp", newUDPAddr, "blocked.smoke.test", dns.TypeA); err != nil || r.Rcode != dns.RcodeNameError {
			t.Fatalf("blocked name after reload: %v err=%v", r, err)
		}
		if r, err := query(t, "tcp-tls", fmt.Sprintf("127.0.0.1:%d", e.dot), "dot-after-reload.smoke.test", dns.TypeA); err != nil || firstA(r) != "198.51.100.20" {
			t.Fatalf("DoT after reload: %q err=%v", firstA(r), err)
		}
	})

	t.Run("reload-applies-rewrites", func(t *testing.T) {
		cfg := e.getConfig()
		cfg["rewrites"] = []map[string]any{{"domain": "rewritten.smoke.test", "type": "A", "value": "203.0.113.7", "ttl": 30}}
		if resp, b := e.apiDo(http.MethodPut, "/api/config", cfg); resp.StatusCode != 200 {
			t.Fatalf("PUT config: %d %s", resp.StatusCode, b)
		}
		if resp, b := e.apiDo(http.MethodPost, "/api/config/reload", nil); resp.StatusCode != 200 {
			t.Fatalf("reload: %d %s", resp.StatusCode, b)
		}
		addr := fmt.Sprintf("127.0.0.1:%d", e.curUDP)
		waitFor(t, "rewrite to take effect", 10*time.Second, func() bool {
			r, err := query(t, "udp", addr, "rewritten.smoke.test", dns.TypeA)
			return err == nil && firstA(r) == "203.0.113.7"
		})
	})

	t.Run("reload-moves-web-listener", func(t *testing.T) {
		if shared {
			t.Skip("web shares the DoH port in this mode")
		}
		cfg := e.getConfig()
		newWeb := freeTCPPort(t)
		cfg["server"].(map[string]any)["web_listen"] = fmt.Sprintf("127.0.0.1:%d", newWeb)
		if resp, b := e.apiDo(http.MethodPut, "/api/config", cfg); resp.StatusCode != 200 {
			t.Fatalf("PUT config: %d %s", resp.StatusCode, b)
		}
		// The reload response may be cut off as the old server shuts down.
		req, _ := http.NewRequest(http.MethodPost, e.url("/api/config/reload"), nil)
		req.SetBasicAuth("admin", smokePassword)
		if resp, err := e.api.Do(req); err == nil {
			resp.Body.Close()
		}
		e.web = newWeb
		waitFor(t, "dashboard on the new port", 15*time.Second, func() bool {
			req, _ := http.NewRequest(http.MethodGet, e.url("/api/status"), nil)
			req.SetBasicAuth("admin", smokePassword)
			resp, err := e.api.Do(req)
			if err != nil {
				return false
			}
			resp.Body.Close()
			return resp.StatusCode == 200
		})
	})

	t.Run("reload-applies-rate-limit", func(t *testing.T) {
		cfg := e.getConfig()
		cfg["rate_limit"].(map[string]any)["enabled"] = true
		cfg["rate_limit"].(map[string]any)["qps"] = 1
		cfg["rate_limit"].(map[string]any)["burst"] = 1
		if resp, b := e.apiDo(http.MethodPut, "/api/config", cfg); resp.StatusCode != 200 {
			t.Fatalf("PUT config: %d %s", resp.StatusCode, b)
		}
		if resp, b := e.apiDo(http.MethodPost, "/api/config/reload", nil); resp.StatusCode != 200 {
			t.Fatalf("reload: %d %s", resp.StatusCode, b)
		}
		addr := fmt.Sprintf("127.0.0.1:%d", e.curUDP)
		limited := 0
		for i := range 12 {
			c := dns.NewClient()
			c.Transport.ReadTimeout = 300 * time.Millisecond
			c.Transport.Dialer.Timeout = 300 * time.Millisecond
			m := dns.NewMsg(fmt.Sprintf("rl-%d.smoke.test.", i), dns.TypeA)
			r, _, err := c.Exchange(context.Background(), m, "udp", addr)
			if err != nil || r.Rcode == dns.RcodeRefused {
				limited++
			}
		}
		if limited == 0 {
			t.Fatal("12 rapid queries at qps=1/burst=1 were never rate limited after reload")
		}
	})

	t.Run("graceful-shutdown", func(t *testing.T) {
		before := e.log.String()
		for _, bad := range []string{"panic", "fatal error", "level=ERROR"} {
			if i := strings.Index(before, bad); i >= 0 {
				lo := max(0, i-120)
				t.Errorf("unexpected %q in log before shutdown: …%s", bad, before[lo:min(len(before), i+300)])
			}
		}
		if err := e.cmd.Process.Signal(syscall.SIGTERM); err != nil {
			t.Fatal(err)
		}
		select {
		case err := <-e.exited:
			if err != nil {
				t.Fatalf("exit after SIGTERM: %v", err)
			}
		case <-time.After(20 * time.Second):
			t.Fatal("did not exit within 20s of SIGTERM")
		}
		if strings.Contains(e.log.String(), "panic") {
			t.Errorf("panic during shutdown:\n%s", e.log.String())
		}
	})
}
