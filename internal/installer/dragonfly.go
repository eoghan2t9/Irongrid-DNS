// Dragonfly support for the wizard: `irongrid install --with-dragonfly`
// detects whether a Redis-compatible server answers at the configured cache
// address and, if not, starts Dragonfly — a native binary + background
// process on Linux, or a Docker container on macOS/Windows (Dragonfly
// publishes no native builds for those platforms).
package installer

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/eoghan2t9/Irongrid-DNS/internal/tuning"
)

const (
	dflyRepo  = "dragonflydb/dragonfly"
	dflyImage = "docker.dragonflydb.io/dragonfly/dragonfly"
)

// redisPing reports whether addr answers a Redis PING with "+PONG".
func redisPing(addr string) bool {
	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		return false
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := conn.Write([]byte("PING\r\n")); err != nil {
		return false
	}
	buf := make([]byte, 16)
	n, err := conn.Read(buf)
	return err == nil && strings.HasPrefix(string(buf[:n]), "+PONG")
}

// EnsureDragonfly makes sure a Redis-compatible server answers at addr,
// starting Dragonfly when it does not. The cache address must be local
// (localhost / 127.0.0.1) for an automatic start; a non-local address is
// left alone (e.g. Docker Compose's internal "dragonfly" hostname).
func EnsureDragonfly(addr string, out io.Writer) error {
	addr = strings.TrimPrefix(strings.TrimSpace(addr), "redis://")
	if addr == "" {
		addr = "localhost:6379"
	}
	if redisPing(addr) {
		fmt.Fprintf(out, "  ✓ Dragonfly cache already running at %s\n", addr)
		return nil
	}
	host, _ := splitHostPort(addr)
	if host != "localhost" && host != "127.0.0.1" && host != "::1" && host != "" {
		fmt.Fprintf(out, "  … cache addr %s is not local — skipping automatic Dragonfly start\n", addr)
		return nil
	}
	fmt.Fprintf(out, "  … no cache answering at %s — starting Dragonfly\n", addr)
	switch runtime.GOOS {
	case "linux":
		return ensureDragonflyNative(addr, out)
	case "darwin", "windows":
		return ensureDragonflyDocker(addr, out)
	default:
		return fmt.Errorf("starting Dragonfly on %s is not supported", runtime.GOOS)
	}
}

func splitHostPort(addr string) (host, port string) {
	if h, p, err := net.SplitHostPort(addr); err == nil {
		return h, p
	}
	return addr, "6379"
}

func latestDragonflyVersion(ctx context.Context) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		"https://api.github.com/repos/"+dflyRepo+"/releases/latest", nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "irongrid-installer")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("releases API: %s", resp.Status)
	}
	var rel struct {
		TagName string `json:"tag_name"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&rel); err != nil {
		return "", err
	}
	if rel.TagName == "" {
		return "", fmt.Errorf("latest release has no tag")
	}
	return rel.TagName, nil
}

// ensureDragonflyNative downloads the Dragonfly tarball for this architecture,
// installs the binary, and runs it as a detached background process.
func ensureDragonflyNative(addr string, out io.Writer) error {
	_, port := splitHostPort(addr)
	arch := "x86_64"
	if runtime.GOARCH == "arm64" {
		arch = "aarch64"
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	ver, err := latestDragonflyVersion(ctx)
	if err != nil {
		return fmt.Errorf("resolve Dragonfly release: %w", err)
	}
	url := fmt.Sprintf("https://github.com/%s/releases/download/%s/dragonfly-%s.tar.gz",
		dflyRepo, ver, arch)
	fmt.Fprintf(out, "  … downloading Dragonfly %s (%s)\n", ver, arch)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("download Dragonfly: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download Dragonfly: %s", resp.Status)
	}

	bin, err := extractDragonflyBinary(resp.Body, arch)
	if err != nil {
		return err
	}

	home, err := os.UserHomeDir()
	if err != nil {
		home = "."
	}
	binDir := filepath.Join(home, ".local", "bin")
	if os.Geteuid() == 0 {
		binDir = "/usr/local/bin"
	}
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		return err
	}
	dst := filepath.Join(binDir, "dragonfly")
	//nolint:gosec // the installed binary must be executable (0o755)
	if err := os.WriteFile(dst, bin, 0o755); err != nil {
		return fmt.Errorf("install dragonfly binary: %w", err)
	}

	dataDir := filepath.Join(home, ".local", "share", "irongrid", "dragonfly")
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		return err
	}
	logPath := filepath.Join(dataDir, "dragonfly.log")
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return err
	}
	defer logFile.Close()

	dfly := tuning.AutoDragonflyFlags()
	args := []string{
		"--port=" + port, "--bind=127.0.0.1",
		"--cache_mode=true",
		"--maxmemory=" + dfly.MaxMemory,
		"--proactor_threads=" + fmt.Sprintf("%d", dfly.ProactorThreads),
		"--dir=" + dataDir,
	}
	if err := startDragonflyProcess(dst, args, logFile); err != nil {
		return fmt.Errorf("start dragonfly: %w", err)
	}
	fmt.Fprintf(out, "  … Dragonfly %s starting (%s) — maxmemory=%s proactor_threads=%d\n",
		ver, dst, dfly.MaxMemory, dfly.ProactorThreads)

	if waitForRedis(addr, 30*time.Second) {
		fmt.Fprintf(out, "  ✓ Dragonfly running at %s (log: %s)\n", addr, logPath)
		return nil
	}
	return fmt.Errorf("dragonfly started but did not answer at %s — see %s", addr, logPath)
}

// extractDragonflyBinary pulls the "dragonfly-<arch>" file out of the release
// tarball (the tarball also contains a LICENSE).
func extractDragonflyBinary(r io.Reader, arch string) ([]byte, error) {
	gz, err := gzip.NewReader(r)
	if err != nil {
		return nil, fmt.Errorf("read tarball: %w", err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	want := "dragonfly-" + arch
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil, fmt.Errorf("binary %s not found in tarball", want)
		}
		if err != nil {
			return nil, err
		}
		if hdr.Typeflag == tar.TypeReg && hdr.Name == want {
			bin, err := io.ReadAll(tr)
			if err != nil {
				return nil, err
			}
			if len(bin) == 0 {
				return nil, fmt.Errorf("extracted %s is empty", want)
			}
			return bin, nil
		}
	}
}

// ensureDragonflyDocker runs Dragonfly as a container, publishing the cache
// port on 127.0.0.1.
func ensureDragonflyDocker(addr string, out io.Writer) error {
	_, port := splitHostPort(addr)
	if _, err := exec.LookPath("docker"); err != nil {
		return fmt.Errorf("docker is required on %s — install Docker Desktop, then run:\n"+
			"    docker run -d --name dragonfly --restart unless-stopped -p 127.0.0.1:%s:6379 %s",
			runtime.GOOS, port, dflyImage)
	}
	_ = exec.Command("docker", "rm", "-f", "dragonfly").Run()
	fmt.Fprintf(out, "  … starting Dragonfly in Docker (port %s)\n", port)
	dfly := tuning.AutoDragonflyFlags()
	//nolint:gosec // fixed docker command, literal args, no shell interpolation
	cmd := exec.Command("docker", "run", "-d", "--name", "dragonfly", "--restart", "unless-stopped",
		"-p", "127.0.0.1:"+port+":6379", dflyImage,
		"--cache_mode=true",
		"--maxmemory="+dfly.MaxMemory,
		"--proactor_threads="+fmt.Sprintf("%d", dfly.ProactorThreads),
		"--port=6379")
	cmd.Stdout = out
	cmd.Stderr = out
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("docker run failed: %w", err)
	}
	if waitForRedis(addr, 60*time.Second) {
		fmt.Fprintf(out, "  ✓ Dragonfly running at %s (container: dragonfly) — maxmemory=%s proactor_threads=%d\n",
			addr, dfly.MaxMemory, dfly.ProactorThreads)
		return nil
	}
	return fmt.Errorf("dragonfly container started but did not answer at %s", addr)
}

// waitForRedis polls addr until it answers PING or the deadline passes.
func waitForRedis(addr string, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if redisPing(addr) {
			return true
		}
		time.Sleep(500 * time.Millisecond)
	}
	return false
}
