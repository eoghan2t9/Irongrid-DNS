//go:build windows

package installer

import (
	"context"
	"os/exec"
	"time"
)

// runPrivileged runs the command directly. Windows installs need an elevated
// prompt; callers detect the failure and print the manual command.
func runPrivileged(args ...string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	return exec.CommandContext(ctx, args[0], args[1:]...).Run()
}

// copyBinaryPrivileged installs src at dst. A Go binary can be copied while
// it is running on Windows, so a plain copy is enough when the destination
// directory is writable.
func copyBinaryPrivileged(src, dst string) error {
	return copyFile(src, dst)
}
