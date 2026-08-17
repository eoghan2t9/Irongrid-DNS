//go:build linux

package tuning

import (
	"bufio"
	"os"
	"runtime"
	"strconv"
	"strings"
)

// Paths are package vars (not consts) so tests can point them at a fixture
// directory instead of the real /sys and /proc.
var (
	cgroupV2MemoryMaxPath   = "/sys/fs/cgroup/memory.max"
	cgroupV1MemoryLimitPath = "/sys/fs/cgroup/memory/memory.limit_in_bytes"
	cgroupV2CPUMaxPath      = "/sys/fs/cgroup/cpu.max"
	cgroupV1CPUQuotaPath    = "/sys/fs/cgroup/cpu/cpu.cfs_quota_us"
	cgroupV1CPUPeriodPath   = "/sys/fs/cgroup/cpu/cpu.cfs_period_us"
	procMeminfoPath         = "/proc/meminfo"
)

// detectMemoryLimit returns the effective memory ceiling for this process
// and whether it came from a cgroup limit rather than the host's total RAM:
// the cgroup limit when one is set and it's tighter than the host's total
// RAM, otherwise the host's total RAM. The fromCgroup flag lets the runtime
// tuner pick a different GOMEMLIMIT fraction for a container (where the
// cgroup limit is the process's own budget) vs bare metal (where the host's
// RAM is shared with every other process on the box).
func detectMemoryLimit() (bytes uint64, fromCgroup bool, ok bool) {
	sys, sysOK := systemMemoryTotal()

	if limit, ok := cgroupV2MemoryMax(); ok {
		if sysOK && limit > sys {
			return sys, false, true
		}
		return limit, true, true
	}
	if limit, ok := cgroupV1MemoryLimit(); ok {
		if sysOK && limit > sys {
			return sys, false, true
		}
		return limit, true, true
	}
	return sys, false, sysOK
}

// detectMemoryLimitBytes returns the effective memory ceiling for this
// process: the cgroup limit if one is set and it's tighter than the host's
// total RAM, otherwise the host's total RAM.
func detectMemoryLimitBytes() (uint64, bool) {
	b, _, ok := detectMemoryLimit()
	return b, ok
}

func cgroupV2MemoryMax() (uint64, bool) {
	b, err := os.ReadFile(cgroupV2MemoryMaxPath)
	if err != nil {
		return 0, false
	}
	s := strings.TrimSpace(string(b))
	if s == "max" || s == "" {
		return 0, false
	}
	v, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return 0, false
	}
	return v, true
}

func cgroupV1MemoryLimit() (uint64, bool) {
	b, err := os.ReadFile(cgroupV1MemoryLimitPath)
	if err != nil {
		return 0, false
	}
	v, err := strconv.ParseUint(strings.TrimSpace(string(b)), 10, 64)
	if err != nil {
		return 0, false
	}
	// cgroup v1 signals "no limit" with a huge page-aligned sentinel
	// (~2^63) instead of a keyword.
	const noLimitThreshold = 1 << 62
	if v > noLimitThreshold {
		return 0, false
	}
	return v, true
}

func systemMemoryTotal() (uint64, bool) {
	f, err := os.Open(procMeminfoPath)
	if err != nil {
		return 0, false
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
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

// detectCPUQuota returns the number of CPUs this process is actually
// allowed to use: the cgroup CPU quota if one is set, otherwise false (the
// caller falls back to runtime.NumCPU(), which is already what Go's default
// GOMAXPROCS uses).
func detectCPUQuota() (float64, bool) {
	if q, ok := cgroupV2CPUMax(); ok {
		return q, true
	}
	if q, ok := cgroupV1CPUQuota(); ok {
		return q, true
	}
	return float64(runtime.NumCPU()), false
}

func cgroupV2CPUMax() (float64, bool) {
	b, err := os.ReadFile(cgroupV2CPUMaxPath)
	if err != nil {
		return 0, false
	}
	fields := strings.Fields(strings.TrimSpace(string(b)))
	if len(fields) != 2 || fields[0] == "max" {
		return 0, false
	}
	quota, err1 := strconv.ParseFloat(fields[0], 64)
	period, err2 := strconv.ParseFloat(fields[1], 64)
	if err1 != nil || err2 != nil || period <= 0 || quota <= 0 {
		return 0, false
	}
	return quota / period, true
}

func cgroupV1CPUQuota() (float64, bool) {
	quotaB, err := os.ReadFile(cgroupV1CPUQuotaPath)
	if err != nil {
		return 0, false
	}
	periodB, err := os.ReadFile(cgroupV1CPUPeriodPath)
	if err != nil {
		return 0, false
	}
	quota, err1 := strconv.ParseFloat(strings.TrimSpace(string(quotaB)), 64)
	period, err2 := strconv.ParseFloat(strings.TrimSpace(string(periodB)), 64)
	// -1 quota is cgroup v1's "unlimited".
	if err1 != nil || err2 != nil || quota <= 0 || period <= 0 {
		return 0, false
	}
	return quota / period, true
}
