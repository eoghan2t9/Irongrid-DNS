package installer

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// Older Irongrid versions kept the response cache and query log in a separate
// DragonflyDB service that the installer set up. The cache is embedded now, so
// an upgrade should stop and remove that service rather than leave it running
// (and eating memory) for nothing. Only what Irongrid's own installers created
// is touched: the systemd unit is matched by its Description, and containers by
// both name and image. Dragonfly data directories are always left in place —
// the old query-log history lives there and is not migrated, so the user
// decides when to delete it.

const (
	legacyUnitName   = "dragonfly.service"
	legacyUnitPath   = "/etc/systemd/system/" + legacyUnitName
	legacyUnitMarker = "DragonflyDB - Redis-compatible cache for Irongrid DNS"
	legacyBinary     = "/usr/local/bin/dragonfly"
	legacyDataDir    = "/var/lib/dragonfly"
)

// legacyContainers are the container names the old installers and compose
// files used for the cache.
var legacyContainers = []string{"irongrid-dragonfly", "dragonfly"}

// legacyEnv isolates everything RemoveLegacyDragonfly touches on the host so the
// logic can be tested without root, systemd or Docker.
type legacyEnv struct {
	unitPath string
	binaries []string
	// userDataDir is where the old wizard's detached (non-root) Dragonfly kept
	// its data; its --dir flag identifies that process.
	userDataDir string
	isRoot      bool
	run         func(ctx context.Context, name string, args ...string) ([]byte, error)
	lookPath    func(string) (string, error)
}

func defaultLegacyEnv() legacyEnv {
	home, _ := os.UserHomeDir()
	env := legacyEnv{
		unitPath: legacyUnitPath,
		binaries: []string{legacyBinary, legacyBinary + ".prev"},
		isRoot:   os.Geteuid() == 0,
		run: func(ctx context.Context, name string, args ...string) ([]byte, error) {
			//nolint:gosec // fixed command names with literal / validated arguments, no shell
			return exec.CommandContext(ctx, name, args...).CombinedOutput()
		},
		lookPath: exec.LookPath,
	}
	if home != "" {
		env.userDataDir = filepath.Join(home, ".local", "share", "irongrid", "dragonfly")
	}
	return env
}

// RemoveLegacyDragonfly stops and removes a Dragonfly cache left behind by an
// older Irongrid install: the systemd service and binary on Linux, the
// detached process the wizard used to start for non-root users, and Docker
// containers. It is best-effort and quiet when there is nothing to remove; it
// never returns an error because a failed cleanup must not fail the install.
func RemoveLegacyDragonfly(out io.Writer) {
	removeLegacyDragonfly(defaultLegacyEnv(), out)
}

func removeLegacyDragonfly(env legacyEnv, out io.Writer) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	var removed []string
	var manual []string

	// systemd unit written by install.sh (matched by its Description so an
	// unrelated Redis/KeyDB/Dragonfly service of the operator's is never
	// touched).
	if data, err := os.ReadFile(env.unitPath); err == nil && strings.Contains(string(data), legacyUnitMarker) {
		if !env.isRoot {
			manual = append(manual, "sudo systemctl disable --now "+legacyUnitName+" && sudo rm "+env.unitPath+" && sudo systemctl daemon-reload")
		} else {
			_, _ = env.run(ctx, "systemctl", "disable", "--now", legacyUnitName)
			if err := os.Remove(env.unitPath); err == nil || os.IsNotExist(err) {
				_, _ = env.run(ctx, "systemctl", "daemon-reload")
				_, _ = env.run(ctx, "systemctl", "reset-failed", legacyUnitName)
				removed = append(removed, "systemd service "+legacyUnitName)
				for _, bin := range env.binaries {
					if err := os.Remove(bin); err == nil {
						removed = append(removed, bin)
					}
				}
			} else {
				manual = append(manual, "sudo rm "+env.unitPath)
			}
		}
	}

	// The detached process the wizard started for non-root installs. Matching
	// on the exact --dir flag keeps this from touching anyone else's Dragonfly.
	if env.userDataDir != "" {
		if _, err := os.Stat(env.userDataDir); err == nil {
			if _, err := env.run(ctx, "pkill", "-f", "--", "--dir="+env.userDataDir); err == nil {
				removed = append(removed, "background Dragonfly process")
			}
		}
	}

	// Containers from the old compose file / macOS+Windows installers.
	if _, err := env.lookPath("docker"); err == nil {
		for _, name := range legacyContainers {
			img, err := env.run(ctx, "docker", "inspect", "-f", "{{.Config.Image}}", name)
			if err != nil || !strings.Contains(strings.ToLower(string(img)), "dragonfly") {
				continue
			}
			if _, err := env.run(ctx, "docker", "rm", "-f", name); err == nil {
				removed = append(removed, "container "+name)
			}
		}
	}

	if len(removed) == 0 && len(manual) == 0 {
		return
	}
	fmt.Fprintln(out)
	if len(removed) > 0 {
		fmt.Fprintln(out, "  ✓ Removed the old Dragonfly cache (the cache is built in now):")
		for _, r := range removed {
			fmt.Fprintf(out, "      - %s\n", r)
		}
		fmt.Fprintf(out, "    Its data was left in place and is not migrated — delete %s (and any dragonfly-data Docker volume) when you no longer need it.\n", legacyDataDir)
	}
	for _, m := range manual {
		fmt.Fprintf(out, "  ⚠ The old Dragonfly service needs root to remove — run:\n      %s\n", m)
	}
}
