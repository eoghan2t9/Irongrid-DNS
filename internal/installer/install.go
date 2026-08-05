package installer

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// ensureBinaryInstalled copies the running binary to the canonical install
// location referenced by the generated service files, so `irongrid install`
// is complete on its own. Best-effort: failures print the manual command and
// never fail the wizard. Skipped entirely when IRONGRID_SKIP_PRIVILEGED=1
// (used by the test suite) or when the running binary is not an irongrid
// binary (so tests can never clobber a real install).
func ensureBinaryInstalled(out io.Writer) {
	if os.Getenv("IRONGRID_SKIP_PRIVILEGED") == "1" {
		return
	}
	exe, err := os.Executable()
	if err != nil {
		fmt.Fprintf(out, "  ⚠ could not locate the running binary: %v\n", err)
		return
	}
	if !strings.Contains(strings.ToLower(filepath.Base(exe)), "irongrid") {
		return
	}
	target := binaryPath()
	if samePath(exe, target) {
		fmt.Fprintf(out, "  ✓ binary already installed at %s\n", target)
		return
	}
	if err := copyBinaryPrivileged(exe, target); err != nil {
		fmt.Fprintf(out, "  ⚠ could not install the binary to %s: %v\n", target, err)
		fmt.Fprintf(out, "    do it manually: sudo cp %s %s && sudo chmod 755 %s\n", exe, target, target)
		return
	}
	fmt.Fprintf(out, "  ✓ binary installed to %s\n", target)
}

// copyFile copies src to dst (mode 0755), creating parent directories.
func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
	if err != nil {
		return err
	}
	_, cerr := io.Copy(out, in)
	_ = out.Close()
	return cerr
}

// samePath reports whether two paths resolve to the same file location.
func samePath(a, b string) bool {
	aa, err1 := filepath.Abs(a)
	bb, err2 := filepath.Abs(b)
	if err1 != nil || err2 != nil {
		return a == b
	}
	return filepath.Clean(aa) == filepath.Clean(bb)
}
