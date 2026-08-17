// Command dnsload is a small, dependency-light load tester for Irongrid (or
// any DNS server): it floods the configured address with A queries over UDP,
// TCP or DoH for a fixed duration and reports throughput plus latency
// percentiles, so a performance change (e.g. server.udp_sockets) can be
// measured before and after.
//
// Usage:
//
//	make bench              # UDP, 10s, 127.0.0.1:53
//	make bench-tcp
//	make bench-doh
//	go run ./bench/dnsload -addr 10.0.0.5:53 -proto udp -dur 30 -qps 20000
package main

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"math/rand"
	"net"
	"net/http"
	"os"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
)

// qnames is the default query mix — a handful of real, cacheable domains.
var qnames = []string{
	"example.com.", "google.com.", "cloudflare.com.", "github.com.",
	"wikipedia.org.", "reddit.com.", "amazon.com.", "netflix.com.",
	"apple.com.", "microsoft.com.", "python.org.", "archlinux.org.",
}

func main() {
	addr := flag.String("addr", "127.0.0.1:53", "server address (host:port)")
	proto := flag.String("proto", "udp", "transport: udp | tcp | doh")
	dur := flag.Duration("dur", 10*time.Second, "how long to run")
	qps := flag.Int("qps", 0, "target send rate per second (0 = as fast as possible)")
	names := flag.String("names", "", "comma-separated query names (defaults to a built-in mix)")
	dohPath := flag.String("doh-path", "/dns-query", "HTTP path for DoH")
	workers := flag.Int("workers", 32, "concurrent query goroutines")
	flag.Parse()

	switch *proto {
	case "udp", "tcp", "doh":
	default:
		fmt.Fprintf(os.Stderr, "proto must be udp, tcp or doh\n")
		os.Exit(2)
	}
	mix := qnames
	if *names != "" {
		mix = splitNames(*names)
	}
	if len(mix) == 0 {
		fmt.Fprintln(os.Stderr, "no query names")
		os.Exit(2)
	}

	var (
		sent, ok, failed atomic.Int64
		latMu            sync.Mutex
		lats             []time.Duration
	)
	record := func(el time.Duration, err error) {
		sent.Add(1)
		if err != nil {
			failed.Add(1)
		} else {
			ok.Add(1)
		}
		latMu.Lock()
		lats = append(lats, el)
		latMu.Unlock()
	}

	ctx, cancel := context.WithTimeout(context.Background(), *dur)
	defer cancel()

	// Per-worker pacing: total target / workers per second. qps=0 skips the
	// sleep and runs flat out. Clamp so qps < workers can't divide by zero.
	pace := time.Duration(0)
	if *qps > 0 && *workers > 0 {
		perWorker := max(*qps / *workers, 1)
		pace = time.Second / time.Duration(perWorker)
	}

	var dohClient *http.Client
	var dohURL string
	if *proto == "doh" {
		dohClient = &http.Client{Timeout: 3 * time.Second}
		scheme := "http"
		if host, _, err := net.SplitHostPort(*addr); err == nil && host == "localhost" {
			// localhost DoH often runs behind the self-signed dashboard cert.
			scheme = "https"
		}
		dohURL = scheme + "://" + *addr + *dohPath
	}
	client := &dns.Client{Net: *proto, Timeout: 3 * time.Second}

	var wg sync.WaitGroup
	for i := 0; i < *workers; i++ {
		wg.Add(1)
		go func(seed int64) {
			defer wg.Done()
			rnd := rand.New(rand.NewSource(time.Now().UnixNano() + seed))
			for {
				select {
				case <-ctx.Done():
					return
				default:
				}
				if pace > 0 {
					time.Sleep(pace)
				}
				m := new(dns.Msg)
				m.SetQuestion(mix[rnd.Intn(len(mix))], dns.TypeA)
				start := time.Now()
				var err error
				if *proto == "doh" {
					err = dohExchange(dohClient, dohURL, m)
				} else {
					_, _, err = client.Exchange(m, *addr)
				}
				record(time.Since(start), err)
			}
		}(int64(i))
	}
	wg.Wait()

	latMu.Lock()
	slices.Sort(lats)
	n := len(lats)
	pct := func(p float64) time.Duration {
		if n == 0 {
			return 0
		}
		return lats[int(float64(n-1)*p)]
	}
	total := sent.Load()
	secs := dur.Seconds()
	fmt.Printf("proto=%s addr=%s duration=%s workers=%d qps=%d\n", *proto, *addr, *dur, *workers, *qps)
	fmt.Printf("queries sent:  %d\n", total)
	fmt.Printf("responses:     %d ok, %d failed (%.2f%%)\n", ok.Load(), failed.Load(), pctFailed(ok.Load(), total))
	fmt.Printf("throughput:    %.0f qps\n", float64(total)/secs)
	if n > 0 {
		fmt.Printf("latency:       avg %s | p50 %s | p95 %s | p99 %s | max %s\n",
			avg(lats), pct(0.50), pct(0.95), pct(0.99), lats[n-1])
	}
	latMu.Unlock()
}

func pctFailed(ok, total int64) float64 {
	if total == 0 {
		return 0
	}
	return 100 * float64(total-ok) / float64(total)
}

func avg(l []time.Duration) time.Duration {
	if len(l) == 0 {
		return 0
	}
	var s time.Duration
	for _, d := range l {
		s += d
	}
	return s / time.Duration(len(l))
}

func splitNames(s string) []string {
	var out []string
	for n := range bytes.SplitSeq([]byte(s), []byte(",")) {
		if v := string(bytes.TrimSpace(n)); v != "" {
			out = append(out, v)
		}
	}
	return out
}

// dohExchange sends one RFC 8484 DoH POST (application/dns-message) and
// returns an error if the response isn't a parseable DNS message.
func dohExchange(c *http.Client, url string, m *dns.Msg) error {
	raw, err := m.Pack()
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(raw))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")
	resp, err := c.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("doh status %d", resp.StatusCode)
	}
	buf := new(bytes.Buffer)
	if _, err := buf.ReadFrom(resp.Body); err != nil {
		return err
	}
	r := new(dns.Msg)
	if err := r.Unpack(buf.Bytes()); err != nil {
		return fmt.Errorf("doh decode: %w", err)
	}
	return nil
}
