package api

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/eoghan2t9/Irongrid-DNS/internal/acme"
	"github.com/eoghan2t9/Irongrid-DNS/internal/cert"
)

// ---- TLS & certificates ----

// tlsStatus is the shape returned by GET /api/tls.
type tlsStatus struct {
	// Listeners that currently use the certificate.
	Listeners map[string]bool `json:"listeners"`
	// Config knobs the UI reflects.
	CertFile           string   `json:"cert_file"`
	KeyFile            string   `json:"key_file"`
	CertDir            string   `json:"cert_dir"`
	GenerateSelfSigned bool     `json:"generate_self_signed"`
	SelfSignedHosts    []string `json:"self_signed_hosts"`
	WebTLS             bool     `json:"web_tls"`
	// Info is nil when no certificate exists yet.
	Info *cert.Info `json:"info"`
	// ACME status; nil when disabled.
	ACME *acme.Status `json:"acme,omitempty"`
}

func (h *Handler) tlsStatus() tlsStatus {
	s := h.Cfg.Server
	info, _ := cert.Inspect(h.Cfg.TLS.CertDir, h.Cfg.TLS.CertFile, h.Cfg.TLS.KeyFile)
	if info != nil && !info.Present {
		info = nil
	}
	ts := tlsStatus{
		Listeners: map[string]bool{
			"dot": s.ListenDoT != "",
			"doh": s.ListenDoH != "",
			"doq": s.ListenDoQ != "",
		},
		CertFile:           h.Cfg.TLS.CertFile,
		KeyFile:            h.Cfg.TLS.KeyFile,
		CertDir:            h.Cfg.TLS.CertDir,
		GenerateSelfSigned: h.Cfg.TLS.GenerateSelfSigned,
		SelfSignedHosts:    h.Cfg.TLS.SelfSignedHosts,
		WebTLS:             h.Cfg.Server.WebTLS,
		Info:               info,
	}
	if h.ACME != nil {
		st := h.ACME.GetStatus()
		ts.ACME = &st
	}
	return ts
}

func (h *Handler) getTLS(w http.ResponseWriter) {
	h.cfgMu.Lock()
	defer h.cfgMu.Unlock()
	writeJSON(w, http.StatusOK, h.tlsStatus())
}

type tlsGeneratePayload struct {
	Hosts   []string `json:"hosts"`
	KeyType string   `json:"key_type"` // "ecdsa" (default) | "rsa"
	KeyBits int      `json:"key_bits"` // RSA size: 2048 or 4096
	Days    int      `json:"days"`     // validity; <=0 = default (825)
}

// generateTLS creates a fresh self-signed certificate, updates the config so
// it is used, and rebinds the listeners. Returns the new status.
func (h *Handler) generateTLS(w http.ResponseWriter, r *http.Request) {
	h.cfgMu.Lock()
	defer h.cfgMu.Unlock()
	var p tlsGeneratePayload
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad body"})
		return
	}
	hosts := make([]string, 0, len(p.Hosts))
	for _, s := range p.Hosts {
		if t := strings.TrimSpace(s); t != "" {
			hosts = append(hosts, t)
		}
	}
	if len(hosts) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "at least one host (DNS name or IP) is required"})
		return
	}
	keyType := strings.ToLower(p.KeyType)
	if keyType != "rsa" && keyType != "ecdsa" {
		keyType = "ecdsa"
	}

	info, err := cert.Generate(h.Cfg.TLS.CertDir, hosts, keyType, p.KeyBits, p.Days)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "generate certificate: " + err.Error()})
		return
	}

	// Point the config at the freshly generated pair and persist.
	h.Cfg.TLS.CertFile = ""
	h.Cfg.TLS.KeyFile = ""
	h.Cfg.TLS.GenerateSelfSigned = true
	h.Cfg.TLS.SelfSignedHosts = hosts
	if err := h.SaveConfig(); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "save config: " + err.Error()})
		return
	}
	applied, applyErr := h.applyTLSReload()
	st := h.tlsStatus()
	st.Info = info
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "applied": applied, "apply_error": applyErr, "status": st})
}

type tlsUploadPayload struct {
	CertPEM string `json:"cert_pem"`
	KeyPEM  string `json:"key_pem"`
}

// uploadTLS stores a CA-signed certificate + key, points the config at it and
// rebinds the listeners. The pair is validated before anything is written.
func (h *Handler) uploadTLS(w http.ResponseWriter, r *http.Request) {
	h.cfgMu.Lock()
	defer h.cfgMu.Unlock()
	var p tlsUploadPayload
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad body"})
		return
	}
	if strings.TrimSpace(p.CertPEM) == "" || strings.TrimSpace(p.KeyPEM) == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "certificate and private key are both required"})
		return
	}
	// Validate the pair (matches, parses, private key fits the cert) before
	// touching the config or any file.
	if _, err := tls.X509KeyPair([]byte(p.CertPEM), []byte(p.KeyPEM)); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid certificate/key pair: " + err.Error()})
		return
	}

	dir := h.Cfg.TLS.CertDir
	if dir == "" {
		dir = "data/certs"
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	certPath := filepath.Join(dir, "custom-cert.pem")
	keyPath := filepath.Join(dir, "custom-key.pem")
	if err := os.WriteFile(certPath, []byte(p.CertPEM), 0o600); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if err := os.WriteFile(keyPath, []byte(p.KeyPEM), 0o600); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	h.Cfg.TLS.CertFile = certPath
	h.Cfg.TLS.KeyFile = keyPath
	h.Cfg.TLS.GenerateSelfSigned = false
	if err := h.SaveConfig(); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "save config: " + err.Error()})
		return
	}
	applied, applyErr := h.applyTLSReload()
	writeJSON(w, http.StatusOK, map[string]any{
		"ok": true, "applied": applied, "apply_error": applyErr,
		"status": h.tlsStatus(),
	})
}

// issueACME triggers an immediate Let's Encrypt issuance/renewal.
func (h *Handler) issueACME(ctx context.Context, w http.ResponseWriter) {
	if h.ACME == nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "ACME is not enabled — set tls.acme in the config"})
		return
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	// Same fix as installUpdate: the web server's 30s WriteTimeout is fixed
	// at connection-accept time, before this handler runs. DNS-01 issuance
	// waits propagation_wait_sec (60s by default) before even checking the
	// TXT record, so it already exceeds 30s out of the box — without this
	// the browser would see "Failed to fetch" on a run that's still
	// succeeding server-side.
	_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(6 * time.Minute))
	if err := h.ACME.ForceIssue(ctx); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	// New cert on disk: rebind listeners and the web server with it.
	h.cfgMu.Lock()
	applied, applyErr := h.applyTLSReload()
	h.cfgMu.Unlock()
	st := h.ACME.GetStatus()
	writeJSON(w, http.StatusOK, map[string]any{
		"ok": true, "applied": applied, "apply_error": applyErr,
		"status": h.tlsStatus(), "acme": st,
	})
}

// applyTLSReload rebinds the DNS listeners with the new certificate via the
// ReloadTLS hook (wired in main). Returns applied=false when the hook is nil.
func (h *Handler) applyTLSReload() (bool, string) {
	if h.ReloadTLS == nil {
		return false, ""
	}
	if err := h.ReloadTLS(); err != nil {
		return false, err.Error()
	}
	return true, ""
}

// downloadCert serves the currently active certificate so clients (e.g.
// Android Private DNS) can install it as a trusted root.
func (h *Handler) downloadCert(w http.ResponseWriter) {
	h.cfgMu.Lock()
	defer h.cfgMu.Unlock()
	info, err := cert.Inspect(h.Cfg.TLS.CertDir, h.Cfg.TLS.CertFile, h.Cfg.TLS.KeyFile)
	if err != nil || info == nil || !info.Present {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "no certificate available yet"})
		return
	}
	data, err := os.ReadFile(info.CertPath)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Header().Set("Content-Disposition", `attachment; filename="irongrid-cert.pem"`)
	_, _ = w.Write(data)
}
