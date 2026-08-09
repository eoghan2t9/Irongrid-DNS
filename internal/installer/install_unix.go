//go:build !windows

package installer

import (
	"fmt"
	"os"
	"os/exec"

	"golang.org/x/term"
)

// runPrivileged executes a command as root — directly when already root,
// otherwise via sudo (non-interactive first, then prompting when stdin is a
// terminal so `curl | bash` installs never hang on a password prompt).
// never user input; exec runs them without a shell.
//
//nolint:gosec // G204: args are package-literal commands (systemctl etc.),
func runPrivileged(args ...string) error {
	if os.Geteuid() == 0 {
		return exec.Command(args[0], args[1:]...).Run()
	}
	// Note: a slice spread must be the only argument filling the variadic
	// parameter, so prefix arguments are folded into the slice first.
	sudoN := append([]string{"sudo", "-n"}, args...)
	if err := exec.Command(sudoN[0], sudoN[1:]...).Run(); err == nil {
		return nil
	}
	if term.IsTerminal(int(os.Stdin.Fd())) {
		sudo := append([]string{"sudo"}, args...)
		cmd := exec.Command(sudo[0], sudo[1:]...)
		cmd.Stdin = os.Stdin
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		return cmd.Run()
	}
	return fmt.Errorf("sudo -n failed and there is no interactive terminal for a password prompt")
}

// copyBinaryPrivileged installs src at dst, trying a plain copy first and
// falling back to sudo.
func copyBinaryPrivileged(src, dst string) error {
	if err := copyFile(src, dst); err == nil {
		_ = os.Chmod(dst, 0o755)
		return nil
	}
	return runPrivileged("cp", src, dst)
}
