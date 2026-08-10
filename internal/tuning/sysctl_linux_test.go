//go:build linux

package tuning

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

// TestApplySysctlsRaisesWhenLower points the sysctl paths at a fixture
// directory, seeds low values, and verifies they are raised to the targets.
func TestApplySysctlsRaisesWhenLower(t *testing.T) {
	dir := t.TempDir()
	orig := sysctlCoreDir
	sysctlCoreDir = dir
	defer func() { sysctlCoreDir = orig }()

	for _, tt := range sysctlTunings {
		if err := os.WriteFile(filepath.Join(dir, tt.key), []byte("1"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	applySysctls()
	for _, tt := range sysctlTunings {
		b, err := os.ReadFile(filepath.Join(dir, tt.key))
		if err != nil {
			t.Fatalf("%s: %v", tt.key, err)
		}
		if got := string(b); got != strconv.FormatUint(tt.value, 10) {
			t.Errorf("%s = %q, want %d", tt.key, got, tt.value)
		}
	}
}

// TestApplySysctlsNeverLowers guards against a future edit that could shrink
// an operator's explicitly configured knob.
func TestApplySysctlsNeverLowers(t *testing.T) {
	dir := t.TempDir()
	orig := sysctlCoreDir
	sysctlCoreDir = dir
	defer func() { sysctlCoreDir = orig }()

	if err := os.WriteFile(filepath.Join(dir, "rmem_max"), []byte("99999999"), 0o644); err != nil {
		t.Fatal(err)
	}
	applySysctls()
	b, err := os.ReadFile(filepath.Join(dir, "rmem_max"))
	if err != nil {
		t.Fatal(err)
	}
	if got := string(b); got != "99999999" {
		t.Errorf("rmem_max changed from a higher configured value to %q", got)
	}
}

// TestApplySysctlsMissingDirNoError: a read-only /proc/sys (default Docker)
// or a missing path must be a silent no-op, never a crash or a fatal error.
func TestApplySysctlsMissingDirNoError(t *testing.T) {
	orig := sysctlCoreDir
	sysctlCoreDir = filepath.Join(t.TempDir(), "does-not-exist")
	defer func() { sysctlCoreDir = orig }()
	applySysctls()
}

// TestStatusIncludesSysctls verifies applySysctls records a per-knob note
// that Status surfaces with the live (fixture) value — the data the
// dashboard's System tuning card renders.
func TestStatusIncludesSysctls(t *testing.T) {
	// Other tests in this package append notes; start from a clean slate so
	// the assertion is order-independent.
	statusMu.Lock()
	sysctlNotes = nil
	statusMu.Unlock()

	dir := t.TempDir()
	orig := sysctlCoreDir
	sysctlCoreDir = dir
	defer func() { sysctlCoreDir = orig }()

	for _, tt := range sysctlTunings {
		if err := os.WriteFile(filepath.Join(dir, tt.key), []byte("1"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	applySysctls()
	st := Status()
	if len(st.Sysctls) != len(sysctlTunings) {
		t.Fatalf("sysctl notes = %d, want %d", len(st.Sysctls), len(sysctlTunings))
	}
	for _, s := range st.Sysctls {
		if s.Value != s.Target {
			t.Errorf("%s live value = %d, want %d", s.Key, s.Value, s.Target)
		}
		if s.Note == "" {
			t.Errorf("%s has an empty note", s.Key)
		}
	}
}
