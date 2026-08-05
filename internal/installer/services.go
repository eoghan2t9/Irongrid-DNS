package installer

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// writeServiceFiles emits the platform service definition chosen during the
// wizard, next to the config file in a deploy/ directory. It never installs
// the service itself — it prints the exact command to do so, because that
// typically requires root/admin privileges and a manual confirmation.
func writeServiceFiles(a *answers, configPath, dataDir string) ([]string, error) {
	deployDir := filepath.Join(filepath.Dir(configPath), "deploy")
	if err := os.MkdirAll(deployDir, 0o755); err != nil {
		return nil, fmt.Errorf("create deploy dir: %w", err)
	}

	var (
		files []string
		err   error
	)
	switch a.service {
	case "systemd":
		files, err = writeSystemd(deployDir, configPath, dataDir)
	case "launchd":
		files, err = writeLaunchd(deployDir, configPath, dataDir)
	case "windows":
		files, err = writeWindowsService(deployDir, configPath, dataDir)
	case "docker":
		files, err = writeDockerCompose(deployDir, configPath)
	}
	if err != nil {
		return nil, err
	}
	return files, nil
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

func writeSystemd(dir, configPath, dataDir string) ([]string, error) {
	unit := fmt.Sprintf(`[Unit]
Description=Irongrid DNS — ad-blocking DNS server
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=%s -config %s -data %s
Restart=on-failure
RestartSec=3
# Hardening
NoNewPrivileges=true
ProtectSystem=full
PrivateTmp=true
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
`, binaryPath(), configPath, dataDir)
	f := filepath.Join(dir, "irongrid.service")
	if err := os.WriteFile(f, []byte(unit), 0o644); err != nil {
		return nil, err
	}
	fmt.Println()
	fmt.Println("  systemd unit written. To install it:")
	fmt.Printf("    sudo cp %s /etc/systemd/system/\n", f)
	fmt.Println("    sudo systemctl daemon-reload")
	fmt.Println("    sudo systemctl enable --now irongrid")
	return []string{f}, nil
}

func writeLaunchd(dir, configPath, dataDir string) ([]string, error) {
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
	<key>StandardOutPath</key>
	<string>%s</string>
	<key>StandardErrorPath</key>
	<string>%s</string>
</dict>
</plist>
`, label, binaryPath(), configPath, dataDir,
		filepath.Join(dataDir, "irongrid.log"), filepath.Join(dataDir, "irongrid.log"))
	f := filepath.Join(dir, label+".plist")
	if err := os.WriteFile(f, []byte(plist), 0o644); err != nil {
		return nil, err
	}
	fmt.Println()
	fmt.Println("  launchd plist written. To install it:")
	fmt.Printf("    mkdir -p ~/Library/LaunchAgents\n")
	fmt.Printf("    cp %s ~/Library/LaunchAgents/\n", f)
	fmt.Println("    launchctl load ~/Library/LaunchAgents/" + label + ".plist")
	return []string{f}, nil
}

func writeWindowsService(dir, configPath, dataDir string) ([]string, error) {
	script := fmt.Sprintf(`@echo off
REM Irongrid DNS — install as a Windows service (run as Administrator)
sc create IrongridDNS binPath= "\"%s\" -config \"%s\" -data \"%s\"" start= auto
sc description IrongridDNS "Irongrid DNS — ad-blocking DNS server"
sc start IrongridDNS
`, binaryPath(), configPath, dataDir)
	f := filepath.Join(dir, "install-irongrid-service.bat")
	if err := os.WriteFile(f, []byte(script), 0o644); err != nil {
		return nil, err
	}
	fmt.Println()
	fmt.Println("  Windows service script written. To install it (as Administrator):")
	fmt.Printf("    %s\n", f)
	return []string{f}, nil
}

func writeDockerCompose(dir, configPath string) ([]string, error) {
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
      - "8080:8080/tcp"  # web dashboard + API	    volumes:
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
    command: --cache_mode=true --maxmemory=512mb --port=6379
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
	fmt.Println()
	fmt.Println("  Docker Compose file written. To start:")
	fmt.Printf("    cd %s && docker compose up -d\n", dir)
	return []string{f}, nil
}

// printNextSteps shows the final instructions, adjusting for deployment mode.
func printNextSteps(a *answers, configPath, dataDir string) {
	fmt.Println()
	fmt.Println("  ───────────────────────────────────────────────")
	fmt.Println("  Next steps")
	fmt.Println("  ───────────────────────────────────────────────")

	if a.deploy == "docker" {
		fmt.Printf("  1. Build the image:  docker build -t irongrid .\n")
		fmt.Printf("  2. Start:            cd %s && docker compose up -d\n", filepath.Join(filepath.Dir(configPath), "deploy"))
		fmt.Println("  3. Dashboard:       http://localhost:8080  (login with the credentials you chose)")
		return
	}

	switch runtime.GOOS {
	case "windows":
		fmt.Printf("  1. Copy the binary to %s\n", binaryPath())
		fmt.Println("  2. Run install-irongrid-service.bat as Administrator")
	default:
		fmt.Printf("  1. Copy the binary: sudo cp irongrid %s\n", binaryPath())
		fmt.Println("  2. Start Dragonfly: docker run -d --name dragonfly -p 6379:6379 docker.dragonflydb.io/dragonfly/dragonfly")
	}

	if a.service != "none" && a.service != "docker" {
		fmt.Printf("  3. Install the service (see deploy/ above)\n")
	} else {
		fmt.Printf("  3. Run it manually: %s -config %s -data %s\n", binaryPath(), configPath, dataDir)
	}
	if len(a.protos) > 0 {
		fmt.Printf("  4. Point your router at this machine's port 53 (UDP/TCP)\n")
	}
	fmt.Println()

	// Sanity note about what was configured.
	var notes []string
	if len(a.blocklists) > 0 {
		notes = append(notes, fmt.Sprintf("%d blocklists enabled", len(a.blocklists)))
	}
	if len(a.whitelists) > 0 {
		notes = append(notes, fmt.Sprintf("%d whitelist presets applied", len(a.whitelists)))
	}
	if len(notes) > 0 {
		fmt.Println("  " + strings.Join(notes, " · ") + " — the dashboard can adjust these anytime.")
	}
}
