package tuning

import "fmt"

// DragonflyFlags holds the auto-computed Dragonfly startup flags.
type DragonflyFlags struct {
	MaxMemory       string // e.g. "2gb"
	ProactorThreads int    // e.g. 4
}

// DragonflyFlagsForSystem computes optimal Dragonfly flags for the given
// host CPU count and total memory bytes. The allocator leaves enough RAM
// for the OS, Irongrid's Go process (~500 MiB peak), and other services.
//
// Rules:
//   - maxmemory = 25% of host RAM, clamped to [256mb, 32gb]
//   - proactor_threads = min(CPUs, 8), floor 2 (Dragonfly needs ≥256 MiB per thread)
//   - maxmemory must be ≥ 256 MiB × proactor_threads (Dragonfly startup requirement)
func DragonflyFlagsForSystem(cpus int, memBytes uint64) DragonflyFlags {
	const (
		mib = 1 << 20
		gib = 1 << 30

		dflyShare    = 0.25 // fraction of host RAM for Dragonfly
		minMemory    = 256 * mib
		maxMemory    = 32 * gib
		minProactors = 2
		maxProactors = 8
		memPerThread = 256 * mib // Dragonfly requires ≥256 MiB per proactor thread
	)

	// --- proactor threads ---
	threads := max(min(cpus, maxProactors), minProactors)

	// --- maxmemory ---
	var mem uint64
	if memBytes > 0 {
		mem = uint64(float64(memBytes) * dflyShare)
	} else {
		// No memory info available — use a safe default.
		mem = 512 * mib
	}
	if mem < minMemory {
		mem = minMemory
	}
	if mem > maxMemory {
		mem = maxMemory
	}

	// Ensure maxmemory ≥ 256 MiB × proactor_threads (Dragonfly requirement).
	minForThreads := uint64(threads) * memPerThread
	if mem < minForThreads {
		mem = minForThreads
	}

	return DragonflyFlags{
		MaxMemory:       formatDflyMemory(mem),
		ProactorThreads: threads,
	}
}

// AutoDragonflyFlags is a convenience wrapper that detects the host's
// CPU count and memory and returns the optimal Dragonfly flags.
func AutoDragonflyFlags() DragonflyFlags {
	return DragonflyFlagsForSystem(HostCPUs(), func() uint64 {
		b, _ := HostMemoryBytes()
		return b
	}())
}

// formatDflyMemory formats bytes into Dragonfly's expected memory string
// (e.g. "512mb", "2gb").
func formatDflyMemory(b uint64) string {
	const gib = 1 << 30
	if b >= gib && b%gib == 0 {
		return fmt.Sprintf("%dgb", b/gib)
	}
	const mib = 1 << 20
	if b >= mib && b%mib == 0 {
		return fmt.Sprintf("%dmb", b/mib)
	}
	return fmt.Sprintf("%dmb", b/mib)
}
