package tuning

import "testing"

func TestGogcForScalesWithMemory(t *testing.T) {
	cases := []struct {
		mem  uint64
		want int
	}{
		{128 << 20, 40},
		{256 << 20, 40},
		{512 << 20, 60},
		{1 << 30, 100},
		{2 << 30, 150},
		{4 << 30, 150},
		{16 << 30, 200},
	}
	for _, c := range cases {
		if got := gogcFor(c.mem); got != c.want {
			t.Errorf("gogcFor(%d) = %d, want %d", c.mem, got, c.want)
		}
	}
}

func TestMemLimitFor(t *testing.T) {
	const host = 16 << 30 // 16 GiB
	wantHost := uint64(float64(host) * memoryFraction)
	if got := memLimitFor(host, false); got != wantHost {
		t.Errorf("memLimitFor(host) = %d, want %d (%.0f%% of ceiling)", got, wantHost, memoryFraction*100)
	}
	// A var (not a const) so the float product isn't constant-folded into a
	// non-integer constant, which Go rejects on conversion to uint64.
	cgroup := uint64(4 << 30) // 4 GiB container limit
	wantCgroup := uint64(float64(cgroup) * containerFraction)
	if got := memLimitFor(cgroup, true); got != wantCgroup {
		t.Errorf("memLimitFor(cgroup) = %d, want %d (%.0f%% of ceiling)", got, wantCgroup, containerFraction*100)
	}
	// The container *fraction* must be larger than the host fraction: an
	// explicit cgroup limit is the process's own budget, so the heap gets a
	// bigger share of it. (Absolute limits differ because the ceilings
	// differ — the share is the point.)
	if containerFraction <= memoryFraction {
		t.Errorf("container fraction %.2f not above host fraction %.2f", containerFraction, memoryFraction)
	}
	// Sanity: the share of a 4 GiB container stays within the cgroup limit.
	if wantCgroup >= cgroup {
		t.Errorf("container limit %d not below ceiling %d", wantCgroup, cgroup)
	}
}

func TestFormatBytes(t *testing.T) {
	cases := []struct {
		b    uint64
		want string
	}{
		{384 << 20, "384MiB"},
		{1 << 30, "1.0GiB"},
		{1536 << 20, "1.5GiB"},
	}
	for _, c := range cases {
		if got := formatBytes(c.b); got != c.want {
			t.Errorf("formatBytes(%d) = %q, want %q", c.b, got, c.want)
		}
	}
}

func TestResultChangedFrom(t *testing.T) {
	a := result{gomaxprocs: 2, memLimitSet: 100, gogcSet: 60}
	b := a
	if a.changedFrom(b) {
		t.Fatal("identical results reported as changed")
	}
	b.gomaxprocs = 4
	if !a.changedFrom(b) {
		t.Fatal("differing GOMAXPROCS not reported as changed")
	}
}
