// Command udpsockets measures what server.udp_sockets actually buys: DNS
// query throughput on a loopback address with 1 SO_REUSEPORT socket vs N,
// using the same building blocks as the real listener (reuseport binds via
// tuning.ReuseportControl, tuned socket buffers, one miekg/dns server per
// socket). Each configuration runs back to back and a comparison table is
// printed, so the socket count can be picked from measured numbers instead
// of guesswork.
//
// Usage:
//
//	make bench-udp-sockets          # 1 vs 8 sockets, 5s each
//	go run ./bench/udpsockets -sockets 1,4,8 -dur 10s
package main

import (
	"context"
	"flag"
	"fmt"
	"math/rand"
	"net"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"

	"github.com/eoghan2t9/Irongrid-DNS/internal/tuning"
)

// names is the query mix the client floods with.
var names = []string{"example.com.", "google.com.", "github.com.", "wikipedia.org."}

// canned answers every A query with one fixed record. The reply path is real
// (pack + write), but there's no cache/upstream/blocklist work — the measured
// cost is the listen path: read, unpack, dispatch, pack, write. That is
// exactly the part server.udp_sockets changes.
type canned struct{}

func (canned) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Answer = append(m.Answer, &dns.A{
		Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
		A:   net.ParseIP("192.0.2.1"),
	})
	_ = w.WriteMsg(m)
}

// bindSockets mirrors dnsserver.newUDPListeners: n SO_REUSEPORT sockets on a
// loopback ephemeral port (each with tuned buffers), or a single plain socket
// when the platform lacks reuseport, so the baseline still runs everywhere.
func bindSockets(n int) ([]net.PacketConn, net.Addr, error) {
	if n > 1 {
		lc := &net.ListenConfig{Control: tuning.ReuseportControl}
		first, err := lc.ListenPacket(context.Background(), "udp", "127.0.0.1:0")
		if err == nil {
			addr := first.LocalAddr()
			pcs := []net.PacketConn{first}
			for i := 1; i < n; i++ {
				pc, err := lc.ListenPacket(context.Background(), "udp", addr.String())
				if err != nil {
					for _, p := range pcs {
						_ = p.Close()
					}
					return nil, nil, err
				}
				pcs = append(pcs, pc)
			}
			for _, pc := range pcs {
				tuning.SetPacketBuffers(pc)
			}
			return pcs, addr, nil
		}
		fmt.Printf("  reuseport unavailable (%v) — falling back to a single socket\n", err)
	}
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		return nil, nil, err
	}
	tuning.SetPacketBuffers(pc)
	return []net.PacketConn{pc}, pc.LocalAddr(), nil
}

type result struct {
	sockets int
	qps     float64
	p50     time.Duration
	p95     time.Duration
	failPct float64
}

func run(sockets int, dur time.Duration, workers int) result {
	pcs, addr, err := bindSockets(sockets)
	if err != nil {
		fmt.Fprintf(os.Stderr, "  bind: %v\n", err)
		os.Exit(1)
	}
	defer func() {
		for _, pc := range pcs {
			_ = pc.Close()
		}
	}()

	// One dns.Server per socket, like the production listener.
	for _, pc := range pcs {
		srv := &dns.Server{Net: "udp", PacketConn: pc, UDPSize: 4096, Handler: canned{}}
		go func() {
			_ = srv.ActivateAndServe()
		}()
	}
	time.Sleep(200 * time.Millisecond) // let the servers come up

	var sent, ok atomic.Int64
	var latMu sync.Mutex
	var lats []time.Duration
	ctx, cancel := context.WithTimeout(context.Background(), dur)
	defer cancel()

	client := &dns.Client{Net: "udp", Timeout: 2 * time.Second}
	var wg sync.WaitGroup
	for i := range workers {
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
				m := new(dns.Msg)
				m.SetQuestion(names[rnd.Intn(len(names))], dns.TypeA)
				start := time.Now()
				_, _, err := client.Exchange(m, addr.String())
				sent.Add(1)
				if err == nil {
					ok.Add(1)
				}
				latMu.Lock()
				lats = append(lats, time.Since(start))
				latMu.Unlock()
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
	p50, p95 := pct(0.50), pct(0.95)
	total := sent.Load()
	latMu.Unlock()

	qps := float64(total) / dur.Seconds()
	failPct := 0.0
	if total > 0 {
		failPct = 100 * float64(total-ok.Load()) / float64(total)
	}
	// Report the count actually bound (len(pcs)), not the request: on a
	// platform without reuseport the fallback is one plain socket, and the
	// comparison must not label it as N.
	return result{sockets: len(pcs), qps: qps, p50: p50, p95: p95, failPct: failPct}
}

func main() {
	socketsFlag := flag.String("sockets", "1,8", "comma-separated socket counts to compare")
	dur := flag.Duration("dur", 5*time.Second, "run time per socket count")
	workers := flag.Int("workers", 64, "concurrent client goroutines")
	flag.Parse()

	var counts []int
	for s := range strings.SplitSeq(*socketsFlag, ",") {
		n, err := strconv.Atoi(strings.TrimSpace(s))
		if err != nil || n < 1 {
			fmt.Fprintf(os.Stderr, "invalid socket count %q\n", s)
			os.Exit(2)
		}
		counts = append(counts, n)
	}

	fmt.Printf("UDP listen-path benchmark: %d client workers, %s per socket count\n\n", *workers, *dur)
	results := make([]result, 0, len(counts))
	for _, n := range counts {
		fmt.Printf("=== udp_sockets=%d ===\n", n)
		r := run(n, *dur, *workers)
		fmt.Printf("bound %d socket(s) on loopback · %.0f qps · p50 %s · p95 %s · %.2f%% failed\n\n",
			r.sockets, r.qps, r.p50, r.p95, r.failPct)
		results = append(results, r)
	}

	fmt.Println("=== comparison ===")
	fmt.Printf("%-8s %12s %10s %10s %10s\n", "sockets", "qps", "p50", "p95", "fail%")
	base := results[0].qps
	for _, r := range results {
		delta := ""
		if r.sockets != results[0].sockets {
			pct := 100 * (r.qps - base) / base
			delta = fmt.Sprintf("  (%s%.1f%% vs %d)", plus(pct), pct, results[0].sockets)
		}
		fmt.Printf("%-8d %12.0f %10s %10s %10.2f%s\n", r.sockets, r.qps, r.p50, r.p95, r.failPct, delta)
	}
}

func plus(p float64) string {
	if p >= 0 {
		return "+"
	}
	return ""
}
