// Package tuning auto-tunes the Go runtime (GOMAXPROCS, GOGC, GOMEMLIMIT) to
// whatever hardware or container limits the process is actually given, so a
// Raspberry Pi and a 32-core server both end up with a runtime configuration
// matched to what they have — no per-deployment GOGC/GOMEMLIMIT env vars to
// hand-tune. It re-checks periodically so a live container resize
// (`docker update --memory`, a cgroup edit) is picked up without a restart.
package tuning

import (
	"fmt"
	"log"
	"math"
	"os"
	"runtime"
	"runtime/debug"
	"time"
)

const (
	// memoryFraction is the share of the detected memory ceiling the Go heap
	// is allowed to grow into before GOMEMLIMIT-triggered GC kicks in. The
	// rest is headroom for the OS page cache, SQLite's query log, network
	// buffers and — outside a container, where the "ceiling" is the whole
	// machine's RAM — every other process on the box.
	memoryFraction = 0.75

	// recheckInterval controls how often limits are re-read.
	recheckInterval = 5 * time.Minute
)

// Start applies GOMAXPROCS/GOGC/GOMEMLIMIT once immediately, logs what it
// found, and then re-applies every recheckInterval. Any of the three the
// operator has already pinned via its standard Go environment variable
// (GOMAXPROCS, GOGC, GOMEMLIMIT — including "off") is left untouched.
// Returns a stop function for clean shutdown.
func Start() (stop func()) {
	last := apply()
	logResult(last, "")
	done := make(chan struct{})
	go func() {
		t := time.NewTicker(recheckInterval)
		defer t.Stop()
		for {
			select {
			case <-t.C:
				cur := apply()
				if cur.changedFrom(last) {
					logResult(cur, " (re-detected)")
				}
				last = cur
			case <-done:
				return
			}
		}
	}()
	return func() { close(done) }
}

// result summarizes what one detection pass found and applied.
type result struct {
	cpuDetected bool
	cpuQuota    float64
	gomaxprocs  int

	memDetected bool
	memBytes    uint64
	memLimitSet uint64 // 0 when GOMEMLIMIT was left to the operator/default
	gogcSet     int    // 0 when GOGC was left to the operator/default
}

func (r result) changedFrom(prev result) bool {
	return r.gomaxprocs != prev.gomaxprocs || r.memLimitSet != prev.memLimitSet || r.gogcSet != prev.gogcSet
}

func apply() result {
	var r result

	if os.Getenv("GOMAXPROCS") == "" {
		if quota, ok := detectCPUQuota(); ok {
			r.cpuDetected = true
			r.cpuQuota = quota
			procs := int(math.Floor(quota))
			if procs < 1 {
				procs = 1
			}
			if n := runtime.NumCPU(); procs > n {
				procs = n
			}
			runtime.GOMAXPROCS(procs)
			r.gomaxprocs = procs
		} else {
			r.gomaxprocs = runtime.GOMAXPROCS(0)
		}
	} else {
		r.gomaxprocs = runtime.GOMAXPROCS(0)
	}

	memPinned := os.Getenv("GOMEMLIMIT") != ""
	gcPinned := os.Getenv("GOGC") != ""
	if !memPinned || !gcPinned {
		if mem, ok := detectMemoryLimitBytes(); ok {
			r.memDetected = true
			r.memBytes = mem
			if !memPinned {
				limit := uint64(float64(mem) * memoryFraction)
				debug.SetMemoryLimit(int64(limit))
				r.memLimitSet = limit
			}
			if !gcPinned {
				gogc := gogcFor(mem)
				debug.SetGCPercent(gogc)
				r.gogcSet = gogc
			}
		}
	}
	return r
}

// gogcFor scales GOGC to how much memory is actually available. GOMEMLIMIT
// is the hard backstop against OOM regardless of this value, but on a tight
// budget a high GOGC still wastes CPU: the heap grows close to the limit
// before every collection, so each cycle does more work, and per the Go
// runtime/debug docs, repeated near-limit collections can thrash instead of
// making progress. A lower GOGC on constrained boxes collects earlier and
// cheaper; a generous one on well-resourced boxes trades that memory for
// fewer, cheaper collections overall.
func gogcFor(memBytes uint64) int {
	const (
		mib = 1 << 20
		gib = 1 << 30
	)
	switch {
	case memBytes <= 256*mib:
		return 40
	case memBytes <= 512*mib:
		return 60
	case memBytes <= 1*gib:
		return 100
	case memBytes <= 4*gib:
		return 150
	default:
		return 200
	}
}

func logResult(r result, suffix string) {
	cpuDesc := "default"
	if r.cpuDetected {
		cpuDesc = fmt.Sprintf("%.1f (cgroup quota)", r.cpuQuota)
	}
	memDesc := "default (no GOMEMLIMIT set)"
	if r.memLimitSet > 0 {
		memDesc = fmt.Sprintf("%s of %s detected", formatBytes(r.memLimitSet), formatBytes(r.memBytes))
	} else if r.memDetected {
		memDesc = fmt.Sprintf("%s detected, GOMEMLIMIT pinned by operator", formatBytes(r.memBytes))
	}
	gogcDesc := "operator-pinned"
	if r.gogcSet > 0 {
		gogcDesc = fmt.Sprintf("%d", r.gogcSet)
	}
	log.Printf("[tune] cpus=%s GOMAXPROCS=%d memlimit=%s GOGC=%s%s",
		cpuDesc, r.gomaxprocs, memDesc, gogcDesc, suffix)
}

func formatBytes(b uint64) string {
	const (
		mib = 1 << 20
		gib = 1 << 30
	)
	if b >= gib {
		return fmt.Sprintf("%.1fGiB", float64(b)/gib)
	}
	return fmt.Sprintf("%.0fMiB", float64(b)/mib)
}
