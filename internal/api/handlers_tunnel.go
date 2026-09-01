package api

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/eoghan2t9/Irongrid-DNS/internal/cfupdate"
	"github.com/eoghan2t9/Irongrid-DNS/internal/tunnel"
)

// ---- tunnel ----

type tunnelStartPayload struct {
	Mode       string `json:"mode"` // quick | token | config
	Token      string `json:"token"`
	ConfigFile string `json:"config_file"`
	Origin     string `json:"origin"`
	Hostname   string `json:"hostname"`
}

func (h *Handler) tunnelStatus(w http.ResponseWriter) {
	writeJSON(w, http.StatusOK, h.Tunnel.Status())
}

func (h *Handler) tunnelStart(w http.ResponseWriter, r *http.Request) {
	var p tunnelStartPayload
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad body"})
		return
	}
	mode := tunnel.Mode(p.Mode)
	if mode == "" {
		mode = tunnel.ModeQuick
	}
	// Validate mode-specific inputs here so we never persist a broken
	// configuration (empty token, missing config file) as auto-start-enabled.
	switch mode {
	case tunnel.ModeToken:
		if strings.TrimSpace(p.Token) == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "tunnel token required"})
			return
		}
	case tunnel.ModeConfig:
		if strings.TrimSpace(p.ConfigFile) == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "cloudflared config file required"})
			return
		}
		if _, err := os.Stat(p.ConfigFile); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "config file not readable: " + p.ConfigFile})
			return
		}
	case tunnel.ModeQuick:
	default:
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "unknown tunnel mode"})
		return
	}

	if err := h.Tunnel.Start(mode, p.Token, p.ConfigFile, p.Origin, p.Hostname); err != nil {
		// The settings are still saved so the form is pre-filled on the next
		// visit, but a tunnel that failed to start must NOT be marked
		// auto-start-enabled — otherwise a bad token would retry on every boot.
		// Enabled mirrors the manager's actual state: a failure while another
		// start already succeeded ("tunnel already running") must not clobber
		// that tunnel's enabled flag.
		if perr := h.persistTunnelSettings(mode, p, h.Tunnel.Status().Running); perr != nil {
			slog.Error("tunnel settings not saved after failed start", "error", perr)
		}
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	// Started: persist the settings (token/config path/origin) to the config
	// file so the tunnel comes back automatically after a restart or reboot.
	// main's auto-start block reads these fields at boot.
	if err := h.persistTunnelSettings(mode, p, true); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "tunnel started but settings not saved: " + err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, h.Tunnel.Status())
}

// persistTunnelSettings writes the tunnel settings into the in-memory config
// and saves it to disk so they survive a restart. enabled controls whether
// the tunnel auto-starts at boot (true once a start succeeds, false when a
// start failed or the tunnel was stopped).
func (h *Handler) persistTunnelSettings(mode tunnel.Mode, p tunnelStartPayload, enabled bool) error {
	h.cfgMu.Lock()
	defer h.cfgMu.Unlock()
	h.Cfg.Tunnel.Enabled = enabled
	h.Cfg.Tunnel.Token = p.Token
	h.Cfg.Tunnel.ConfigFile = p.ConfigFile
	h.Cfg.Tunnel.QuickTunnel = mode == tunnel.ModeQuick
	h.Cfg.Tunnel.QuickTunnelURL = p.Origin
	h.Cfg.Tunnel.Hostname = p.Hostname
	return h.SaveConfig()
}

func (h *Handler) tunnelStop(w http.ResponseWriter) {
	h.Tunnel.Stop()
	// Stopping means "I don't want the tunnel anymore": disable auto-start
	// on the next boot. The token/config path is kept so the form is still
	// pre-filled if the user starts it again.
	h.cfgMu.Lock()
	h.Cfg.Tunnel.Enabled = false
	saveErr := h.SaveConfig()
	h.cfgMu.Unlock()
	if saveErr != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "tunnel settings not saved: " + saveErr.Error()})
		return
	}
	writeJSON(w, http.StatusOK, h.Tunnel.Status())
}

func (h *Handler) tunnelLog(w http.ResponseWriter) {
	writeJSON(w, http.StatusOK, map[string]any{"lines": h.Tunnel.TailLog(50)})
}

// installCloudflaredUpdate checks cloudflare/cloudflared's GitHub releases
// and installs a newer managed binary if one exists. Unlike installUpdate
// (Irongrid's own self-update), no restart is needed afterward: the swap
// only affects the *next* tunnel Start(), not the running Irongrid process.
func (h *Handler) installCloudflaredUpdate(ctx context.Context, w http.ResponseWriter) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()

	client := &cfupdate.Client{}
	res, err := client.Install(ctx, h.Tunnel.BinaryPath())
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	h.Tunnel.SetBinaryStatus(tunnel.BinaryStatus{
		Version:       res.NewVersion,
		LatestVersion: res.NewVersion,
		LastChecked:   time.Now(),
	})

	payload := map[string]any{
		"installed":        res.Installed,
		"previous_version": res.PreviousVersion,
		"new_version":      res.NewVersion,
		"asset_name":       res.AssetName,
		"asset_size":       res.AssetSize,
	}
	if !res.Installed {
		payload["note"] = "cloudflared is already up to date"
	} else if h.Tunnel.Status().Running {
		payload["note"] = "cloudflared updated; the running tunnel keeps using the old binary until it is next restarted"
	}
	writeJSON(w, http.StatusOK, payload)
}
