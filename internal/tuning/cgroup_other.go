//go:build !linux

package tuning

import "runtime"

// Irongrid ships and runs as a Linux service/container (see docker-compose.yml,
// install.sh); on other platforms (dev builds on macOS/Windows) there's no
// cgroup to read and no cheap dependency-free way to get total system RAM,
// so auto-tuning leaves GOMEMLIMIT/GOGC at Go's defaults and only reports
// the CPU count Go already uses by default.
func detectMemoryLimitBytes() (uint64, bool) { return 0, false }

func detectCPUQuota() (float64, bool) { return float64(runtime.NumCPU()), false }
