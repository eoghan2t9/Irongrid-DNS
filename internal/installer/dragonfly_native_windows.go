//go:build windows

package installer

import (
	"fmt"
	"os"
)

// startDragonflyProcess is unreachable on Windows (EnsureDragonfly uses Docker
// there) but keeps the package compiling on every platform.
func startDragonflyProcess(bin string, args []string, logFile *os.File) error {
	return fmt.Errorf("native Dragonfly is not supported on Windows")
}
