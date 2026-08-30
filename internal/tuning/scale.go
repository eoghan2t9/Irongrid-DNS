// Package tuning: shared sizing formulas for hot-path pools/queues/workers.
package tuning

import "runtime"

// ScaleByCores returns perCore × the tuned GOMAXPROCS, clamped to
// [floor, ceil]. Every pool or queue whose right size tracks concurrent
// CPU-bound or blocking-I/O fan-out (worker counts, connection pools,
// write-queue depths) should call this instead of hand-rolling its own
// clamp, so the floor/ceil policy for a Raspberry Pi vs. a big box lives in
// one place and every ceiling moves together when the formula is retuned.
func ScaleByCores(perCore, floor, ceil int) int {
	n := runtime.GOMAXPROCS(0) * perCore
	return clampInt(n, floor, ceil)
}

// ScaleByMemory returns how many avgItemBytes-sized items fit in fraction of
// the detected memory ceiling (see MemoryLimitBytes), clamped to
// [floor, ceil]. Returns fallback when the memory ceiling can't be detected
// (non-Linux, no cgroup, no /proc/meminfo) or avgItemBytes is 0.
func ScaleByMemory(fraction float64, avgItemBytes uint64, floor, ceil, fallback int) int {
	mem, ok := MemoryLimitBytes()
	if !ok || avgItemBytes == 0 {
		return fallback
	}
	n := int(uint64(float64(mem)*fraction) / avgItemBytes)
	return clampInt(n, floor, ceil)
}

func clampInt(n, floor, ceil int) int {
	if n < floor {
		return floor
	}
	if n > ceil {
		return ceil
	}
	return n
}
