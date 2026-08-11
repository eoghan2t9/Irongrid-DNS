// Command reuseport measures raw UDP receive throughput on a loopback
// address with N SO_REUSEPORT sockets (the mechanism behind
// server.udp_sockets) vs a single socket. It floods datagrams from a set of
// sender goroutines and counts how many the listener sockets pick up, so a
// box can be checked for whether splitting receive queues across sockets
// actually buys throughput before raising the socket count.
//
// Run `make bench-reuseport` for the 1-vs-8 comparison, or pass -sockets
// directly:
//
//	go run ./bench/reuseport -sockets 1 -dur 5
//	go run ./bench/reuseport -sockets 8 -dur 5
package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/eoghan2t9/Irongrid-DNS/internal/tuning"
)

func main() {
	sockets := flag.Int("sockets", 1, "number of SO_REUSEPORT listener sockets")
	dur := flag.Duration("dur", 5*time.Second, "how long to run")
	senders := flag.Int("senders", 8, "concurrent sender goroutines")
	size := flag.Int("size", 64, "payload bytes per datagram")
	flag.Parse()
	if *sockets < 1 {
		fmt.Fprintln(os.Stderr, "sockets must be >= 1")
		os.Exit(2)
	}

	// Bind the first socket on :0 with SO_REUSEPORT, then share that exact
	// address with the rest — the same layout the DNS listener uses. On a
	// platform without reuseport (Windows) the first bind fails, so fall
	// back to a single plain socket: the 1-socket baseline still runs, and
	// the multi-socket comparison is skipped with a note.
	lc := &net.ListenConfig{Control: tuning.ReuseportControl}
	first, err := lc.ListenPacket(context.Background(), "udp", "127.0.0.1:0")
	if err != nil {
		fmt.Printf("SO_REUSEPORT unavailable (%v) — falling back to a single plain socket\n", err)
		first, err = net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			fmt.Fprintf(os.Stderr, "plain bind: %v\n", err)
			os.Exit(1)
		}
		*sockets = 1
	}
	addr := first.LocalAddr().String()
	all := []net.PacketConn{first}
	for i := 1; i < *sockets; i++ {
		pc, err := lc.ListenPacket(context.Background(), "udp", addr)
		if err != nil {
			for _, p := range all {
				_ = p.Close()
			}
			fmt.Fprintf(os.Stderr, "reuseport bind %d on %s: %v\n", i, addr, err)
			os.Exit(1)
		}
		all = append(all, pc)
	}
	var received atomic.Int64
	ctx, cancel := context.WithTimeout(context.Background(), *dur)
	defer cancel()

	var wg sync.WaitGroup
	for _, pc := range all {
		wg.Add(1)
		go func(pc net.PacketConn) {
			defer wg.Done()
			buf := make([]byte, 1500)
			for {
				n, _, err := pc.ReadFrom(buf)
				if err != nil {
					return
				}
				if n > 0 {
					received.Add(1)
				}
			}
		}(pc)
	}

	// Senders: each opens its own source socket (so every flow has a unique
	// 4-tuple for the kernel's reuseport hash) and floods as fast as it can.
	payload := make([]byte, *size)
	var sent atomic.Int64
	for i := 0; i < *senders; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			src, err := net.Dial("udp", addr)
			if err != nil {
				return
			}
			defer src.Close()
			for {
				select {
				case <-ctx.Done():
					return
				default:
				}
				if _, err := src.Write(payload); err != nil {
					return
				}
				sent.Add(1)
			}
		}()
	}

	time.Sleep(*dur)
	cancel()
	// Closing the sockets makes the blocked ReadFrom calls error out so the
	// reader goroutines can return; without this wg.Wait would hang forever.
	for _, pc := range all {
		_ = pc.Close()
	}
	wg.Wait()

	total := sent.Load()
	got := received.Load()
	secs := dur.Seconds()
	fmt.Printf("sockets=%d senders=%d size=%dB duration=%s\n", *sockets, *senders, *size, *dur)
	fmt.Printf("sent:      %d (%.0f pps)\n", total, float64(total)/secs)
	fmt.Printf("received:  %d (%.0f pps)\n", got, float64(got)/secs)
	if total > 0 {
		fmt.Printf("delivered: %.2f%%\n", 100*float64(got)/float64(total))
	}
	if *sockets > 1 {
		fmt.Println("note: on Linux < 6.6 a busy hash bucket can drop while siblings idle (SO_REUSEPORT_LOAD_BALANCE needs 6.6+); this measures the net win.")
	}
}
