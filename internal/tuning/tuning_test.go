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
