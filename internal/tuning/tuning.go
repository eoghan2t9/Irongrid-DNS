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
	"net"
	"os"
	"runtime"
	"runtime/debug"
	"runtime/metrics"
	"sync"
	"syscall"
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

	// SocketBufferSize is the SO_RCVBUF/SO_SNDBUF size requested for every DNS
	// listener socket (plain UDP/TCP, DoT, DoH, DoQ and the HTTPS web
	// listener). Under bursts the kernel's default buffer drops datagrams and
	// the client pays a retransmit round trip — the biggest avoidable latency
	// cost on a busy LAN. On Linux the request is clamped to net.core.rmem_max
	// unless that ceiling has been raised (applySysctls does this when running
	// as root; docker-compose.yml does it for containers).
	SocketBufferSize = 2 << 20 // 2 MiB
)

// MemoryLimitBytes returns the effective memory ceiling for this process:
// the cgroup limit when one is set (and it's tighter than the host's total
// RAM), otherwise the host's total RAM. On platforms where neither can be
// read (non-Linux) it returns (0, false). This is the same cgroup-aware
// detection the runtime auto-tuning uses, exported so other components —
// e.g. the cache's auto-sized L1 — can size themselves to what the process
// is actually allowed to use.
func MemoryLimitBytes() (uint64, bool) {
	return detectMemoryLimitBytes()
}

// ApplySystem applies the OS-level tweaks that are separate from the Go
// runtime: the file-descriptor soft limit is raised to the hard limit (Unix;
// a no-op on Windows), and on Linux running as root the kernel socket-buffer
// ceilings are raised so the per-socket buffer sizes actually take effect.
// Every step is best-effort and never fatal — inside an unprivileged Docker
// container the sysctl writes are skipped with a log line, and the container
// can get the same effect from docker-compose's sysctls instead. Call it once
// at boot, before any DNS listeners are created.
func ApplySystem() {
	raiseFileLimit()
	applySysctls()
}

// ListenConfig returns a net.ListenConfig whose sockets get SocketBufferSize
// send/receive buffers, for listeners that are created via the standard net
// package (TCP, TLS and HTTP servers). Accepted connections inherit the
// listener's buffer settings on every supported OS.
func ListenConfig() *net.ListenConfig {
	return &net.ListenConfig{Control: SocketControl}
}

// SetPacketBuffers raises the receive/send buffers of a packet socket (the
// UDP DNS listener and the DoQ QUIC socket) to SocketBufferSize. Best-effort:
// a kernel that refuses (e.g. a macOS sockbuf ceiling) keeps the OS default
// and is logged rather than failing the listener.
func SetPacketBuffers(pc net.PacketConn) {
	uc, ok := pc.(*net.UDPConn)
	if !ok {
		return
	}
	if err := uc.SetReadBuffer(SocketBufferSize); err != nil {
		log.Printf("[tune] SO_RCVBUF: %v", err)
	}
	if err := uc.SetWriteBuffer(SocketBufferSize); err != nil {
		log.Printf("[tune] SO_SNDBUF: %v", err)
	}
}

// SocketControl is a net.ListenConfig.Control / net.Dialer.Control hook: it
// applies the SocketBufferSize receive/send buffers to the raw socket, for
// listener sockets (via ListenConfig) and outbound sockets (upstream DNS
// clients and the DoH HTTP transport, via Dialer). A failure only logs — a
// buffer that couldn't be raised must never take a listener or a dial down.
func SocketControl(network, address string, c syscall.RawConn) error {
	var err error
	if cerr := c.Control(func(fd uintptr) { err = setSocketBufferSizes(fd) }); cerr != nil {
		log.Printf("[tune] socket buffers for %s %s: %v", network, address, cerr)
		return nil
	}
	if err != nil {
		log.Printf("[tune] socket buffers for %s %s: %v", network, address, err)
	}
	return nil
}

// ---- status snapshot (dashboard) ----

// SystemTuning is the state ApplySystem set up at boot, reported through
// Status(). Sysctls carry the live value at query time plus the note recorded
// when ApplySystem tried each knob.
type SystemTuning struct {
	OS           string        `json:"os"`
	SocketBuffer int           `json:"socket_buffer"`
	FDSoft       *uint64       `json:"fd_soft"` // nil where there is no fd limit (Windows)
	FDHard       *uint64       `json:"fd_hard"`
	FDRaised     bool          `json:"fd_raised"`
	FDRaisedFrom *uint64       `json:"fd_raised_from,omitempty"`
	Sysctls      []SysctlState `json:"sysctls"`
	GOMAXPROCS   int           `json:"gomaxprocs"`
	GOMEMLIMIT   int64         `json:"gomemlimit"`
	GOGC         int           `json:"gogc"`
}

// SysctlState describes one kernel socket knob Irongrid tunes (Linux only).
type SysctlState struct {
	Key    string `json:"key"`
	Value  uint64 `json:"value"` // live value as of Status()
	Target uint64 `json:"target"`
	Note   string `json:"note"` // what ApplySystem recorded at boot
}

// statusMu guards the package-level tuning state recorded at boot.
var (
	statusMu     sync.Mutex
	fdRaised     bool
	fdRaisedFrom uint64
	sysctlNotes  []SysctlState
)

func recordFDRaised(from uint64) {
	statusMu.Lock()
	fdRaised = true
	fdRaisedFrom = from
	statusMu.Unlock()
}

func recordSysctl(s SysctlState) {
	statusMu.Lock()
	sysctlNotes = append(sysctlNotes, s)
	statusMu.Unlock()
}

// Status returns a snapshot of the current system-tuning state for the
// dashboard: the file-descriptor limit (live), every Linux socket sysctl
// (live value + the boot-time note), the per-socket buffer size and the Go
// runtime settings ApplySystem/Start arrived at.
func Status() SystemTuning {
	st := SystemTuning{
		OS:           runtime.GOOS,
		SocketBuffer: SocketBufferSize,
		GOMAXPROCS:   runtime.GOMAXPROCS(0),
		GOMEMLIMIT:   debug.SetMemoryLimit(-1), // -1 is a documented query for SetMemoryLimit
		GOGC:         currentGCPercent(),
	}

	statusMu.Lock()
	st.FDRaised = fdRaised
	if fdRaised {
		from := fdRaisedFrom
		st.FDRaisedFrom = &from
	}
	st.Sysctls = make([]SysctlState, len(sysctlNotes))
	copy(st.Sysctls, sysctlNotes)
	statusMu.Unlock()

	if soft, hard, ok := readFileLimit(); ok {
		st.FDSoft = &soft
		st.FDHard = &hard
	}
	for i := range st.Sysctls {
		if v, ok := currentSysctlValue(st.Sysctls[i].Key); ok {
			st.Sysctls[i].Value = v
		}
	}
	return st
}

// currentGCPercent reads the live GOGC setting via the read-only
// /gc/gogc:percent runtime metric. debug.SetGCPercent cannot be used to
// query the current value: unlike SetMemoryLimit it has no negative-input
// query mode — a negative argument disables the GC-percentage heuristic
// outright — so calling it with -1 on every status poll would silently switch
// the runtime to memory-limit-only collection.
func currentGCPercent() int {
	samples := []metrics.Sample{{Name: "/gc/gogc:percent"}}
	metrics.Read(samples)
	for _, s := range samples {
		if s.Value.Kind() != metrics.KindUint64 {
			continue
		}
		// The runtime stores GOGC as a signed int32 but reports it as an
		// uint64, so a negative setting (GOGC=off) surfaces as a huge number;
		// reinterpret it so "off" is reported truthfully.
		v := s.Value.Uint64()
		if v <= math.MaxInt32 {
			return int(v)
		}
		return int(int32(v))
	}
	return 0
}

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
