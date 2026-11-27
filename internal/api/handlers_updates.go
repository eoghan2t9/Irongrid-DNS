package api

import (
	"context"
	"net/http"
	"sync"
	"time"

	"github.com/eoghan2t9/Irongrid-DNS/internal/cfupdate"
	"github.com/eoghan2t9/Irongrid-DNS/internal/update"
	"github.com/eoghan2t9/Irongrid-DNS/internal/version"
)

// ---- updates page: one status view over every tool Irongrid depends on ----

// toolStatus is one row of the updates page. Irongrid and cloudflared are
// installed through their existing endpoints (/api/update/install and
// /api/tunnel/cloudflared-update).
type toolStatus struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Purpose string `json:"purpose"`
	// Current is the version on disk; Running is the version of the live
	// process when that can differ from it (cloudflared after a swap that has
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

	checks := []func(context.Context) *toolStatus{h.irongridStatus, h.cloudflaredStatus}
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
	installUpdateMu.Lock()
	installedVer := h.lastInstalledVersion
	installUpdateMu.Unlock()
	if installedVer != "" {
		t.Note = installedVer + " is installed and waiting for a restart"
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
	// The live tunnel can lag the installed binary: an update swaps the file
	// but the running process keeps what it was started from.
	ts := h.Tunnel.Status()
	if ts.Running {
		t.Running = ts.RunningVersion
		if ts.RunningVersion != "" && info.CurrentVersion != "" && ts.RunningVersion != info.CurrentVersion {
			t.RestartPending = true
		}
	}
	switch {
	case info.CurrentVersion == "":
		t.Note = "Not installed yet — it is downloaded the first time the tunnel starts"
	case t.RestartPending:
		t.Note = "Version " + t.Current + " is installed but " + t.Running + " is still running — restart the tunnel to apply it"
	case info.Available && ts.Running:
		t.Note = "The running tunnel keeps the old version until it is restarted"
	}
	return t
}
