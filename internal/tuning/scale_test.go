package tuning

import (
	"runtime"
	"testing"
)

func TestScaleByCoresClampsFloor(t *testing.T) {
	if got := ScaleByCores(1, 1_000_000, 2_000_000); got != 1_000_000 {
		t.Errorf("ScaleByCores floor clamp = %d, want 1000000", got)
	}
}

func TestScaleByCoresClampsCeil(t *testing.T) {
	if got := ScaleByCores(1_000_000, 1, 10); got != 10 {
		t.Errorf("ScaleByCores ceil clamp = %d, want 10", got)
	}
}

func TestScaleByCoresInRange(t *testing.T) {
	want := runtime.GOMAXPROCS(0) * 4
	if got := ScaleByCores(4, 1, want+1000); got != want {
		t.Errorf("ScaleByCores(4, 1, %d) = %d, want %d", want+1000, got, want)
	}
}

func TestScaleByMemoryFallbackOnZeroAvgItem(t *testing.T) {
	if got := ScaleByMemory(0.1, 0, 10, 1000, 42); got != 42 {
		t.Errorf("ScaleByMemory with avgItemBytes=0 = %d, want fallback 42", got)
	}
}

func TestScaleByMemoryClamps(t *testing.T) {
	mem, ok := MemoryLimitBytes()
	if !ok {
		t.Skip("memory ceiling not detectable on this platform")
	}
	if got := ScaleByMemory(1.0, mem*1000+1, 5, 1000, 42); got != 5 {
		t.Errorf("ScaleByMemory floor clamp = %d, want 5", got)
	}
	if got := ScaleByMemory(1.0, 1, 5, 10, 42); got != 10 {
		t.Errorf("ScaleByMemory ceil clamp = %d, want 10", got)
	}
}

func TestClampInt(t *testing.T) {
	cases := []struct{ n, floor, ceil, want int }{
		{5, 1, 10, 5},
		{-5, 1, 10, 1},
		{50, 1, 10, 10},
	}
	for _, tc := range cases {
		if got := clampInt(tc.n, tc.floor, tc.ceil); got != tc.want {
			t.Errorf("clampInt(%d, %d, %d) = %d, want %d", tc.n, tc.floor, tc.ceil, got, tc.want)
		}
	}
}
