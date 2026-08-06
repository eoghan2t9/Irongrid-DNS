//go:build linux

package tuning

import (
	"os"
	"path/filepath"
	"testing"
)

// withFixture writes content to a temp file and points the given path var at
// it for the duration of the test, restoring the original afterwards.
func withFixture(t *testing.T, pathVar *string, content string) {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "fixture")
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	orig := *pathVar
	*pathVar = p
	t.Cleanup(func() { *pathVar = orig })
}

func missing(t *testing.T, pathVar *string) {
	t.Helper()
	orig := *pathVar
	*pathVar = filepath.Join(t.TempDir(), "does-not-exist")
	t.Cleanup(func() { *pathVar = orig })
}

func TestCgroupV2MemoryMax(t *testing.T) {
	withFixture(t, &cgroupV2MemoryMaxPath, "536870912\n")
	v, ok := cgroupV2MemoryMax()
	if !ok || v != 536870912 {
		t.Fatalf("got (%d, %v), want (536870912, true)", v, ok)
	}
}

func TestCgroupV2MemoryMaxUnbounded(t *testing.T) {
	withFixture(t, &cgroupV2MemoryMaxPath, "max\n")
	if _, ok := cgroupV2MemoryMax(); ok {
		t.Fatal("expected ok=false for \"max\"")
	}
}

func TestCgroupV1MemoryLimitSentinelIgnored(t *testing.T) {
	// The classic cgroup v1 "no limit" sentinel.
	withFixture(t, &cgroupV1MemoryLimitPath, "9223372036854771712\n")
	if _, ok := cgroupV1MemoryLimit(); ok {
		t.Fatal("expected ok=false for the no-limit sentinel")
	}
}

func TestCgroupV1MemoryLimitReal(t *testing.T) {
	withFixture(t, &cgroupV1MemoryLimitPath, "268435456\n")
	v, ok := cgroupV1MemoryLimit()
	if !ok || v != 268435456 {
		t.Fatalf("got (%d, %v), want (268435456, true)", v, ok)
	}
}

func TestSystemMemoryTotal(t *testing.T) {
	withFixture(t, &procMeminfoPath, "MemTotal:        1048576 kB\nMemFree:          204800 kB\n")
	v, ok := systemMemoryTotal()
	if !ok || v != 1048576*1024 {
		t.Fatalf("got (%d, %v), want (%d, true)", v, ok, uint64(1048576*1024))
	}
}

func TestDetectMemoryLimitBytesPrefersTighterCgroup(t *testing.T) {
	withFixture(t, &procMeminfoPath, "MemTotal:        4194304 kB\n") // 4GiB host
	withFixture(t, &cgroupV2MemoryMaxPath, "536870912\n")             // 512MiB cgroup cap
	v, ok := detectMemoryLimitBytes()
	if !ok || v != 536870912 {
		t.Fatalf("got (%d, %v), want (536870912, true)", v, ok)
	}
}

func TestDetectMemoryLimitBytesFallsBackToHost(t *testing.T) {
	missing(t, &cgroupV2MemoryMaxPath)
	missing(t, &cgroupV1MemoryLimitPath)
	withFixture(t, &procMeminfoPath, "MemTotal:        2097152 kB\n")
	v, ok := detectMemoryLimitBytes()
	if !ok || v != 2097152*1024 {
		t.Fatalf("got (%d, %v), want (%d, true)", v, ok, uint64(2097152*1024))
	}
}

func TestCgroupV2CPUMax(t *testing.T) {
	withFixture(t, &cgroupV2CPUMaxPath, "150000 100000\n")
	q, ok := cgroupV2CPUMax()
	if !ok || q != 1.5 {
		t.Fatalf("got (%v, %v), want (1.5, true)", q, ok)
	}
}

func TestCgroupV2CPUMaxUnbounded(t *testing.T) {
	withFixture(t, &cgroupV2CPUMaxPath, "max 100000\n")
	if _, ok := cgroupV2CPUMax(); ok {
		t.Fatal("expected ok=false for \"max\"")
	}
}

func TestCgroupV1CPUQuota(t *testing.T) {
	withFixture(t, &cgroupV1CPUQuotaPath, "200000\n")
	withFixture(t, &cgroupV1CPUPeriodPath, "100000\n")
	q, ok := cgroupV1CPUQuota()
	if !ok || q != 2.0 {
		t.Fatalf("got (%v, %v), want (2.0, true)", q, ok)
	}
}

func TestCgroupV1CPUQuotaUnlimited(t *testing.T) {
	withFixture(t, &cgroupV1CPUQuotaPath, "-1\n")
	withFixture(t, &cgroupV1CPUPeriodPath, "100000\n")
	if _, ok := cgroupV1CPUQuota(); ok {
		t.Fatal("expected ok=false for quota=-1 (unlimited)")
	}
}
