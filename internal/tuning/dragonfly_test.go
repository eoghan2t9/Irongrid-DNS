package tuning

import "testing"

func TestDragonflyFlagsForSystem(t *testing.T) {
	t.Parallel()
	const gib = 1 << 30
	const mib = 1 << 20

	cases := []struct {
		name      string
		cpus      int
		memBytes  uint64
		wantMem   string
		wantThrd  int
	}{
		{
			name:     "tiny VM (1 CPU, 512 MiB)",
			cpus:     1,
			memBytes: 512 * mib,
			wantMem:  "512mb", // 25% of 512 MiB = 128 MiB, clamped to min 256 MiB; 2 threads × 256 MiB = 512 MiB > 256, so bumped to 512mb
			wantThrd: 2,
		},
		{
			name:     "small server (2 CPU, 2 GiB)",
			cpus:     2,
			memBytes: 2 * gib,
			wantMem:  "512mb", // 25% of 2 GiB = 512 MiB; 2 threads × 256 MiB = 512 MiB — exactly fits
			wantThrd: 2,
		},
		{
			name:     "medium server (4 CPU, 8 GiB)",
			cpus:     4,
			memBytes: 8 * gib,
			wantMem:  "2gb", // 25% of 8 GiB = 2 GiB; 4 threads × 256 MiB = 1 GiB < 2 GiB — fine
			wantThrd: 4,
		},
		{
			name:     "this server (6 CPU, 11 GiB)",
			cpus:     6,
			memBytes: 11 * gib,
			wantMem:  "2816mb", // 25% of 11 GiB = 2816 MiB (not exact GiB, so stays as mb)
			wantThrd: 6,
		},
		{
			name:     "large server (16 CPU, 64 GiB)",
			cpus:     16,
			memBytes: 64 * gib,
			wantMem:  "16gb", // 25% of 64 GiB = 16 GiB (within 256mb–32gb range)
			wantThrd: 8,     // capped at maxProactors
		},
		{
			name:     "no memory info (0 bytes)",
			cpus:     4,
			memBytes: 0,
			wantMem:  "1gb", // fallback 512 MiB; 4 × 256 = 1024 MiB = 1 GiB (exact, formats as "1gb")
			wantThrd: 4,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := DragonflyFlagsForSystem(tc.cpus, tc.memBytes)
			if got.ProactorThreads != tc.wantThrd {
				t.Errorf("ProactorThreads = %d, want %d", got.ProactorThreads, tc.wantThrd)
			}
			if got.MaxMemory != tc.wantMem {
				t.Errorf("MaxMemory = %q, want %q", got.MaxMemory, tc.wantMem)
			}
		})
	}
}

func TestFormatDflyMemory(t *testing.T) {
	t.Parallel()
	const gib = 1 << 30
	const mib = 1 << 20

	cases := []struct {
		b    uint64
		want string
	}{
		{256 * mib, "256mb"},
		{512 * mib, "512mb"},
		{1 * gib, "1gb"},
		{2 * gib, "2gb"},
		{1536 * mib, "1536mb"},
	}
	for _, c := range cases {
		if got := formatDflyMemory(c.b); got != c.want {
			t.Errorf("formatDflyMemory(%d) = %q, want %q", c.b, got, c.want)
		}
	}
}
