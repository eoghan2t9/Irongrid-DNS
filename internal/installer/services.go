package installer

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

// writeServiceFiles emits the platform service definition chosen during the
// wizard, next to the config file in a deploy/ directory. It never installs
// the service itself — it prints the exact command to do so, because that
// typically requires root/admin privileges and a manual confirmation.
func writeServiceFiles(w *wizard, configPath, dataDir string) ([]string, error) {
	deployDir := filepath.Join(filepath.Dir(configPath), "deploy")
	if err := os.MkdirAll(deployDir, 0o755); err != nil {
		return nil, fmt.Errorf("create deploy dir: %w", err)
	}

	var (
		files []string
		err   error
	)
	switch w.a.service {
	case "systemd":
		files, err = writeSystemd(w, deployDir, configPath, dataDir)
	case "launchd":
		files, err = writeLaunchd(w, deployDir, configPath, dataDir)
	case "windows":
		files, err = writeWindowsService(w, deployDir, configPath, dataDir)
	case "docker":
		files, err = writeDockerCompose(w, deployDir, configPath)
	}
	if err != nil {
		return nil, err
	}
	return files, nil
}

// installService installs and starts the startup service chosen during the
// wizard, using the files already written to deploy/ by writeServiceFiles.
// Best-effort: failures print the manual commands and never fail the wizard.
func installService(w *wizard, configPath, dataDir string) {
	a := w.a
	if a.service == "none" || a.service == "docker" {
		return
	}
	deployDir := filepath.Join(filepath.Dir(configPath), "deploy")
	switch a.service {
	case "systemd":
		installSystemd(w, deployDir)
	case "launchd":
		installLaunchd(w, deployDir)
	case "windows":
		installWindowsService(w, deployDir)
	}
}

// installSystemd copies the unit into place, reloads and enables+starts it.
func installSystemd(w *wizard, deployDir string) {
	src := filepath.Join(deployDir, "irongrid.service")
	if _, err := os.Stat(src); err != nil {
		fmt.Fprintf(w.out, "  ⚠ systemd unit missing (%s)\n", src)
		return
	}
	fmt.Fprintln(w.out)
	fmt.Fprintln(w.out, "  Installing the systemd service …")
	steps := [][]string{
		{"cp", src, "/etc/systemd/system/"},
		{"systemctl", "daemon-reload"},
		{"systemctl", "enable", "--now", "irongrid"},
	}
	for _, s := range steps {
		if err := runPrivileged(s...); err != nil {
			fmt.Fprintf(w.out, "  ⚠ %s failed: %v\n", strings.Join(s, " "), err)
			fmt.Fprintln(w.out, "    run the deploy/ commands manually:")
			fmt.Fprintf(w.out, "      sudo cp %s /etc/systemd/system/\n", src)
			fmt.Fprintln(w.out, "      sudo systemctl daemon-reload && sudo systemctl enable --now irongrid")
			return
		}
	}
	fmt.Fprintln(w.out, "  ✓ systemd service installed and started (systemctl status irongrid)")
}

// installLaunchd copies the plist into ~/Library/LaunchAgents and loads it.
func installLaunchd(w *wizard, deployDir string) {
	src := filepath.Join(deployDir, "com.irongrid.dns.plist")
	if _, err := os.Stat(src); err != nil {
		fmt.Fprintf(w.out, "  ⚠ launchd plist missing (%s)\n", src)
		return
	}
	home, err := os.UserHomeDir()
	if err != nil {
		home = "."
	}
	dst := filepath.Join(home, "Library", "LaunchAgents", "com.irongrid.dns.plist")
	if err := copyFile(src, dst); err != nil {
		fmt.Fprintf(w.out, "  ⚠ could not copy the launchd plist: %v\n", err)
		fmt.Fprintf(w.out, "    do it manually: cp %s %s && launchctl load %s\n", src, dst, dst)
		return
	}
	_ = exec.Command("launchctl", "unload", dst).Run() // ignore if not loaded yet
	if err := exec.Command("launchctl", "load", dst).Run(); err != nil {
		fmt.Fprintf(w.out, "  ⚠ launchctl load failed: %v\n", err)
		fmt.Fprintf(w.out, "    do it manually: launchctl load %s\n", dst)
		return
	}
	fmt.Fprintln(w.out, "  ✓ launchd agent installed and loaded (com.irongrid.dns)")
}

// installWindowsService runs the generated schtasks .bat (needs Administrator;
// failures fall back to printing the path).
func installWindowsService(w *wizard, deployDir string) {
	bat := filepath.Join(deployDir, "install-irongrid-service.bat")
	if _, err := os.Stat(bat); err != nil {
		fmt.Fprintf(w.out, "  ⚠ service script missing (%s)\n", bat)
		return
	}
	fmt.Fprintln(w.out)
	fmt.Fprintln(w.out, "  Installing the Windows startup task (needs Administrator) …")
	cmd := exec.Command("cmd", "/c", bat)
	cmd.Stdout = w.out
	cmd.Stderr = w.out
	if err := cmd.Run(); err != nil {
		fmt.Fprintf(w.out, "  ⚠ task install failed: %v\n", err)
		fmt.Fprintf(w.out, "    re-run as Administrator: %s\n", bat)
		return
	}
	fmt.Fprintln(w.out, "  ✓ Windows startup task installed and started")
}

// binaryPath is where the installer expects the irongrid binary to land.
// The printed install commands reference it.
func binaryPath() string {
	switch runtime.GOOS {
	case "windows":
		return `C:\Program Files\Irongrid\irongrid.exe`
	default:
		return "/usr/local/bin/irongrid"
	}
}

func writeSystemd(w *wizard, dir, configPath, dataDir string) ([]string, error) {
	// ProtectSystem=full makes /usr (and thus the binary's directory) read-only
	// even to root, which breaks the in-place self-updater. ReadWritePaths
	// punches a hole just for that directory so the rest of /usr stays protected.
	binDir := filepath.Dir(binaryPath())
	unit := fmt.Sprintf(`[Unit]
Description=Irongrid DNS — ad-blocking DNS server
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=%s -config %s -data %s
WorkingDirectory=%s
# WorkingDirectory resolves relative paths in the config (data/certs, data/querylog.db)
Restart=on-failure
RestartSec=3
# Hardening
NoNewPrivileges=true
ProtectSystem=full
ReadWritePaths=%s
PrivateTmp=true
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
`, binaryPath(), configPath, dataDir, dataDir, binDir)
	f := filepath.Join(dir, "irongrid.service")
	if err := os.WriteFile(f, []byte(unit), 0o644); err != nil {
		return nil, err
	}
	fmt.Fprintln(w.out)
	fmt.Fprintln(w.out, "  systemd unit written. To install it:")
	fmt.Fprintf(w.out, "    sudo cp %s /etc/systemd/system/\n", f)
	fmt.Fprintln(w.out, "    sudo systemctl daemon-reload")
	fmt.Fprintln(w.out, "    sudo systemctl enable --now irongrid")
	return []string{f}, nil
}

func writeLaunchd(w *wizard, dir, configPath, dataDir string) ([]string, error) {
	label := "com.irongrid.dns"
	plist := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>%s</string>
	<key>ProgramArguments</key>
	<array>
		<string>%s</string>
		<string>-config</string>
		<string>%s</string>
		<string>-data</string>
		<string>%s</string>
	</array>
	<key>RunAtLoad</key>
	<true/>
	<key>KeepAlive</key>
	<true/>
	<key>WorkingDirectory</key>
	<string>%s</string>
	<key>StandardOutPath</key>
	<string>%s</string>
	<key>StandardErrorPath</key>
	<string>%s</string>
</dict>
</plist>
`, label, binaryPath(), configPath, dataDir, dataDir,
		filepath.Join(dataDir, "irongrid.log"), filepath.Join(dataDir, "irongrid.log"))
	f := filepath.Join(dir, label+".plist")
	if err := os.WriteFile(f, []byte(plist), 0o644); err != nil {
		return nil, err
	}
	fmt.Fprintln(w.out)
	fmt.Fprintln(w.out, "  launchd plist written. To install it:")
	fmt.Fprintln(w.out, "    mkdir -p ~/Library/LaunchAgents")
	fmt.Fprintf(w.out, "    cp %s ~/Library/LaunchAgents/\n", f)
	fmt.Fprintln(w.out, "    launchctl load ~/Library/LaunchAgents/"+label+".plist")
	return []string{f}, nil
}

func writeWindowsService(w *wizard, dir, configPath, dataDir string) ([]string, error) {
	script := fmt.Sprintf(`@echo off
REM Irongrid DNS — install as a startup task (run as Administrator)
REM A plain Go binary does not speak the SCM protocol, so a scheduled task
REM at logon is used instead of sc.exe (which would leave the service stuck
REM in START_PENDING and get killed after ~30s).
REM /RL HIGHEST is required: the default config binds 0.0.0.0:53, which a
REM LIMITED (filtered-token) task cannot do.
schtasks /Create /TN IrongridDNS /TR "\"%s\" -config \"%s\" -data \"%s\"" /SC ONLOGON /RL HIGHEST /F
schtasks /Run /TN IrongridDNS
`, binaryPath(), configPath, dataDir)
	f := filepath.Join(dir, "install-irongrid-service.bat")
	if err := os.WriteFile(f, []byte(script), 0o644); err != nil {
		return nil, err
	}
	fmt.Fprintln(w.out)
	fmt.Fprintln(w.out, "  Windows service script written. To install it (as Administrator):")
	fmt.Fprintf(w.out, "    %s\n", f)
	return []string{f}, nil
}

func writeDockerCompose(w *wizard, dir, configPath string) ([]string, error) {
	// The compose file lives in deploy/ while the config is one level up,
	// so the mount path is relative (../<config>).
	cfgName := filepath.Base(configPath)
	compose := fmt.Sprintf(`services:
  irongrid-dns:
    image: irongrid:latest
    container_name: irongrid-dns
    restart: unless-stopped
    ports:
      - "53:53/udp"      # plain DNS over UDP
      - "53:53/tcp"      # plain DNS over TCP
      - "853:853/tcp"    # DNS over TLS
      - "853:853/udp"    # DNS over QUIC
      - "443:443/tcp"    # DNS over HTTPS
      - "8080:8080/tcp"  # web dashboard + API
    volumes:
      - ../%s:/app/%s:ro
      - irongrid-data:/data
    depends_on:
      - dragonfly
    cap_add:
      - NET_BIND_SERVICE   # allow binding to port 53 as non-root

  dragonfly:
    image: docker.dragonflydb.io/dragonfly/dragonfly
    container_name: irongrid-dragonfly
    restart: unless-stopped
    # --proactor_threads=2 keeps 2 x 256MiB <= the 512mb maxmemory cap
    # (Dragonfly requires >= 256MiB per proactor thread on startup).
    command: --cache_mode=true --maxmemory=512mb --proactor_threads=2 --port=6379
    ports:
      - "127.0.0.1:6379:6379"
    volumes:
      - dragonfly-data:/data

volumes:
  irongrid-data:
  dragonfly-data:
`, cfgName, cfgName)
	f := filepath.Join(dir, "docker-compose.yml")
	if err := os.WriteFile(f, []byte(compose), 0o644); err != nil {
		return nil, err
	}
	fmt.Fprintln(w.out)
	fmt.Fprintln(w.out, "  Docker Compose file written. To start:")
	fmt.Fprintf(w.out, "    cd %s && docker compose up -d\n", dir)
	return []string{f}, nil
}

// printNextSteps shows the final instructions, adjusting for deployment mode.
func (w *wizard) printNextSteps(configPath, dataDir string) {
	a := w.a
	fmt.Fprintln(w.out)
	fmt.Fprintln(w.out, "  ───────────────────────────────────────────────")
	fmt.Fprintln(w.out, "  Next steps")
	fmt.Fprintln(w.out, "  ───────────────────────────────────────────────")

	if a.deploy == "docker" {
		fmt.Fprintln(w.out, "  1. Build the image:  docker build -t irongrid .")
		fmt.Fprintf(w.out, "  2. Start:            cd %s && docker compose up -d\n", filepath.Join(filepath.Dir(configPath), "deploy"))
		if a.webOnDoHPort {
			fmt.Fprintln(w.out, "  3. Dashboard:       https://host  (port 443, shared with DoH — login with the credentials you chose)")
		} else {
			fmt.Fprintln(w.out, "  3. Dashboard:       http://localhost:8080  (login with the credentials you chose)")
		}
		return
	}

	switch runtime.GOOS {
	case "windows":
		fmt.Fprintf(w.out, "  1. Binary: %s\n", binaryPath())
		if a.service == "windows" {
			fmt.Fprintln(w.out, "  2. Startup task attempted (re-run install-irongrid-service.bat as Administrator if it failed)")
		} else {
			fmt.Fprintf(w.out, "  2. Run it manually: %s -config %s -data %s\n", binaryPath(), configPath, dataDir)
		}
	default:
		if w.dflyStarted {
			fmt.Fprintf(w.out, "  1. ✓ Dragonfly cache running at %s\n", a.cacheAddr)
		} else if a.deploy == "native" && a.installDragonfly {
			fmt.Fprintln(w.out, "  1. Dragonfly did not start automatically — run:")
			fmt.Fprintln(w.out, "       docker run -d --name dragonfly -p 6379:6379 docker.dragonflydb.io/dragonfly/dragonfly")
		} else {
			fmt.Fprintf(w.out, "  1. Make sure a Redis-compatible server (e.g. Dragonfly) answers at %s\n", a.cacheAddr)
		}
		if a.service != "none" {
			fmt.Fprintf(w.out, "  2. Service install attempted (see deploy/ for manual steps if it did not start)\n")
		} else {
			fmt.Fprintf(w.out, "  2. Run it manually: %s -config %s -data %s\n", binaryPath(), configPath, dataDir)
		}
	}

	if len(a.protos) > 0 {
		fmt.Fprintln(w.out, "  3. Point your router at this machine's port 53 (UDP/TCP)")
	}
	if a.webOnDoHPort {
		fmt.Fprintln(w.out, "  4. Dashboard:       https://<this-host>  (port 443 shared with DoH — login with the credentials you chose)")
	} else {
		fmt.Fprintln(w.out, "  4. Dashboard:       http://<this-host>:8080  (login with the credentials you chose)")
	}
	fmt.Fprintln(w.out)

	// Sanity note about what was configured.
	var notes []string
	if len(a.blocklists) > 0 {
		notes = append(notes, fmt.Sprintf("%d blocklists enabled", len(a.blocklists)))
	}
	if len(a.whitelists) > 0 {
		notes = append(notes, fmt.Sprintf("%d whitelist presets applied", len(a.whitelists)))
	}
	if len(notes) > 0 {
		fmt.Fprintln(w.out, "  "+strings.Join(notes, " · ")+" — the dashboard can adjust these anytime.")
	}
}
