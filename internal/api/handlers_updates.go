package api

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/eoghan2t9/Irongrid-DNS/internal/cfupdate"
	"github.com/eoghan2t9/Irongrid-DNS/internal/dflyupdate"
	"github.com/eoghan2t9/Irongrid-DNS/internal/update"
	"github.com/eoghan2t9/Irongrid-DNS/internal/version"
)

// ---- updates page: one status view over every tool Irongrid depends on ----

// dragonflyUnit is the systemd unit the install script creates for the cache.
const dragonflyUnit = "dragonfly.service"

// defaultDragonflyBin is where the installer puts the binary when it is not
// on PATH (the service runs with a minimal environment).
const defaultDragonflyBin = "/usr/local/bin/dragonfly"

// toolStatus is one row of the updates page. Irongrid and cloudflared are
// installed through their existing endpoints (/api/update/install and
// /api/tunnel/cloudflared-update); Dragonfly through /api/updates/dragonfly.
type toolStatus struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Purpose string `json:"purpose"`
	// Current is the version on disk; Running is the version of the live
	// process when that can differ from it (Dragonfly after a swap that has
	// not been restarted yet).
	Current        string `json:"current_version"`
	Running        string `json:"running_version,omitempty"`
	Latest         string `json:"latest_version"`
	Available      bool   `json:"update_available"`
	RestartPending bool   `json:"restart_pending,omitempty"`
	// Installable is false when an update cannot be applied from here
	// (externally managed install, unsupported platform, no download).
	Installable bool   `json:"installable"`
	Error       string `json:"error,omitempty"`
	Note        string `json:"note,omitempty"`
	ReleaseURL  string `json:"release_url,omitempty"`
}

// getUpdates checks every managed tool against its upstream releases
// concurrently. Per-tool failures (offline, rate limit) land in that tool's
// error field so one bad upstream never hides the others.
func (h *Handler) getUpdates(ctx context.Context, w http.ResponseWriter) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	checks := []func(context.Context) *toolStatus{h.irongridStatus, h.dragonflyStatus, h.cloudflaredStatus}
	out := make([]*toolStatus, len(checks))
	var wg sync.WaitGroup
	for i, check := range checks {
		wg.Go(func() { out[i] = check(ctx) })
	}
	wg.Wait()

	tools := make([]*toolStatus, 0, len(out))
	for _, t := range out {
		if t != nil {
			tools = append(tools, t)
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"tools": tools, "checked_at": time.Now().UTC()})
}

func (h *Handler) irongridStatus(ctx context.Context) *toolStatus {
	cur := h.Version
	if cur == "" {
		cur = version.Version
	}
	info := (&update.Client{Repo: update.DefaultRepo, Current: cur}).Check(ctx)
	t := &toolStatus{
		ID:          "irongrid",
		Name:        "Irongrid DNS",
		Purpose:     "This server — the DNS resolver and dashboard",
		Current:     info.CurrentVersion,
		Latest:      info.LatestVersion,
		Available:   info.Available,
		Installable: info.DownloadURL != "",
		Error:       info.Error,
		ReleaseURL:  info.ReleaseURL,
	}
	if h.lastInstalledVersion != "" {
		t.Note = h.lastInstalledVersion + " is installed and waiting for a restart"
	}
	return t
}

func (h *Handler) cloudflaredStatus(ctx context.Context) *toolStatus {
	if h.Tunnel == nil {
		return nil
	}
	info := (&cfupdate.Client{}).Check(ctx, h.Tunnel.BinaryPath())
	t := &toolStatus{
		ID:          "cloudflared",
		Name:        "cloudflared",
		Purpose:     "Cloudflare tunnel client for reaching the dashboard remotely",
		Current:     info.CurrentVersion,
		Latest:      info.LatestVersion,
		Available:   info.Available,
		Installable: info.AssetName != "",
		Error:       info.Error,
		ReleaseURL:  "https://github.com/" + cfupdate.DefaultRepo + "/releases/latest",
	}
	switch {
	case info.CurrentVersion == "":
		t.Note = "Not installed yet — it is downloaded the first time the tunnel starts"
	case info.Available && h.Tunnel.Status().Running:
		t.Note = "The running tunnel keeps the old version until it is restarted"
	}
	return t
}

func (h *Handler) dragonflyStatus(ctx context.Context) *toolStatus {
	t := &toolStatus{
		ID:         "dragonfly",
		Name:       "Dragonfly",
		Purpose:    "Redis-compatible cache that holds DNS answers and the query log",
		ReleaseURL: "https://github.com/" + dflyupdate.DefaultRepo + "/releases/latest",
	}
	if h.Cache != nil {
		if v, err := h.Cache.ServerVersion(ctx); err == nil {
			t.Running = v
		}
	}
	bin, why := h.managedDragonflyBin()
	if bin == "" {
		t.Current = t.Running
		t.Note = why
		return t
	}
	info := (&dflyupdate.Client{}).Check(ctx, bin)
	t.Current = info.CurrentVersion
	t.Latest = info.LatestVersion
	t.Available = info.Available
	t.Error = info.Error
	t.Installable = info.AssetName != ""
	if t.Running != "" && t.Current != "" && t.Running != t.Current {
		t.RestartPending = true
		t.Note = "Version " + t.Current + " is installed but " + t.Running + " is still running — restart Dragonfly to apply it"
	}
	return t
}

// managedDragonflyBin returns the Dragonfly binary this host runs, or "" and a
// reason when Irongrid must not touch it (remote or containerised cache, or no
// binary found).
func (h *Handler) managedDragonflyBin() (bin, reason string) {
	h.cfgMu.Lock()
	addr := h.Cfg.Cache.Addr
	h.cfgMu.Unlock()
	addr = strings.TrimPrefix(strings.TrimSpace(addr), "redis://")
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	switch host {
	case "", "localhost", "127.0.0.1", "::1":
	default:
		return "", "The cache runs at " + addr + ", which is not this machine — update it where it runs"
	}
	if p, err := exec.LookPath("dragonfly"); err == nil {
		return p, ""
	}
	if _, err := os.Stat(defaultDragonflyBin); err == nil {
		return defaultDragonflyBin, ""
	}
	return "", "No Dragonfly binary found on this machine (is it running in Docker?) — update it where it runs"
}

// dragonflyMu serialises Dragonfly installs and restarts so two tabs can't race.
var dragonflyMu sync.Mutex

// installDragonflyUpdate downloads and verifies the latest Dragonfly release,
// swaps the binary, and restarts the service so the new version takes effect.
func (h *Handler) installDragonflyUpdate(ctx context.Context, w http.ResponseWriter) {
	dragonflyMu.Lock()
	defer dragonflyMu.Unlock()

	bin, why := h.managedDragonflyBin()
	if bin == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": why})
		return
	}

	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	// The server's 30s WriteTimeout would otherwise cut a slow download+verify
	// off from under a perfectly good install (see installUpdate).
	_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(6 * time.Minute))

	res, err := (&dflyupdate.Client{}).Install(ctx, bin)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	payload := map[string]any{
		"installed":        res.Installed,
		"previous_version": res.PreviousVersion,
		"new_version":      res.NewVersion,
		"asset_name":       res.AssetName,
		"asset_size":       res.AssetSize,
		"rollback_path":    bin + ".prev",
	}
	if !res.Installed {
		payload["note"] = "Dragonfly is already up to date"
		writeJSON(w, http.StatusOK, payload)
		return
	}
	h.restartDragonfly(ctx, res.NewVersion, payload)
	writeJSON(w, http.StatusOK, payload)
}

// restartDragonflyHandler restarts Dragonfly without installing anything — for
// a binary that was swapped earlier (or by hand) but is not yet running.
func (h *Handler) restartDragonflyHandler(ctx context.Context, w http.ResponseWriter) {
	dragonflyMu.Lock()
	defer dragonflyMu.Unlock()

	bin, why := h.managedDragonflyBin()
	if bin == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": why})
		return
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	payload := map[string]any{}
	h.restartDragonfly(ctx, dflyupdate.InstalledVersion(ctx, bin), payload)
	writeJSON(w, http.StatusOK, payload)
}

// restartDragonfly snapshots the dataset, restarts the systemd unit and waits
// for the new version to answer, recording the outcome in payload. Failures
// are reported there rather than as errors: the binary swap already succeeded,
// so the caller still wants a 200 with a "restart it yourself" note.
func (h *Handler) restartDragonfly(ctx context.Context, want string, payload map[string]any) {
	if _, err := os.Stat("/run/systemd/system"); err != nil || !dragonflyUnitExists(ctx) {
		payload["restarting"] = false
		payload["note"] = "Binary updated. Restart Dragonfly manually to run the new version."
		return
	}
	if h.Cache != nil {
		// A fresh snapshot lets the new process reload everything it held.
		if err := h.Cache.Snapshot(ctx); err != nil {
			slog.Warn("dragonfly update: pre-restart snapshot failed", "error", err)
		}
	}
	if out, err := exec.CommandContext(ctx, "systemctl", "restart", dragonflyUnit).CombinedOutput(); err != nil {
		slog.Error("dragonfly update: restart failed", "error", err, "output", string(out))
		payload["restarting"] = false
		payload["note"] = "Binary updated, but restarting Dragonfly failed (" + strings.TrimSpace(string(out)) + "). Restart it manually."
		return
	}
	payload["restarting"] = true

	// The cache client reconnects on its own; wait for the new process to
	// report the version we installed so the page can show the real outcome.
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) && h.Cache != nil {
		if v, err := h.Cache.ServerVersion(ctx); err == nil && v != "" {
			payload["running_version"] = v
			if want == "" || v == want {
				return
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(500 * time.Millisecond):
		}
	}
	payload["note"] = fmt.Sprintf("Dragonfly was restarted but did not report %s within 30s — check its logs", want)
}

func dragonflyUnitExists(ctx context.Context) bool {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	return exec.CommandContext(ctx, "systemctl", "cat", dragonflyUnit).Run() == nil
}
