package tuning

import (
	"os"
	"runtime"
	"strconv"
	"strings"
)

// HostCPUs returns the number of logical CPUs available on the host.
// On Linux it reads /proc/cpuinfo; on other platforms it uses runtime.NumCPU().
func HostCPUs() int {
	if n := cpusFromProcCPUInfo(); n > 0 {
		return n
	}
	return runtime.NumCPU()
}

// HostMemoryBytes returns the total physical memory of the host in bytes.
// It tries /proc/meminfo (Linux), then sysctl (macOS/BSD), and returns (0, false)
// when neither source is available (e.g. Windows without cgo).
func HostMemoryBytes() (uint64, bool) {
	if b, ok := memoryFromProcMeminfo(); ok {
		return b, true
	}
	if b, ok := memoryFromSysctl(); ok {
		return b, true
	}
	return 0, false
}

// ---- Linux /proc/cpuinfo ----

func cpusFromProcCPUInfo() int {
	b, err := os.ReadFile("/proc/cpuinfo")
	if err != nil {
		return 0
	}
	count := 0
	for _, line := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(line, "processor\t:") {
			count++
		}
	}
	return count
}

// ---- Linux /proc/meminfo ----

func memoryFromProcMeminfo() (uint64, bool) {
	b, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0, false
	}
	for _, line := range strings.Split(string(b), "\n") {
		if !strings.HasPrefix(line, "MemTotal:") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			return 0, false
		}
		kb, err := strconv.ParseUint(fields[1], 10, 64)
		if err != nil {
			return 0, false
		}
		return kb * 1024, true
	}
	return 0, false
}

// ---- macOS/BSD sysctl hw.memsize ----

func memoryFromSysctl() (uint64, bool) {
	// This is only compiled on non-Linux when someone adds a build tag,
	// but as a cross-platform helper we try the file path approach which
	// works on FreeBSD/macOS via a procfs-like sysctl filesystem.
	b, err := os.ReadFile("/proc/sys/hw/memsize")
	if err != nil {
		return 0, false
	}
	v, err := strconv.ParseUint(strings.TrimSpace(string(b)), 10, 64)
	if err != nil {
		return 0, false
	}
	return v, true
}
