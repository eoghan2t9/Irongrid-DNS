//go:build !windows

package installer

import (
	"os"
	"os/exec"
	"syscall"
)

// startDragonflyProcess launches Dragonfly detached (its own process group)
// so it keeps running after the wizard exits.
func startDragonflyProcess(bin string, args []string, logFile *os.File) error {
	cmd := exec.Command(bin, args...)
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	return cmd.Start()
}
