package api

import (
	"archive/zip"
	"bytes"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/eoghan2t9/Irongrid-DNS/internal/config"
	"github.com/eoghan2t9/Irongrid-DNS/internal/dnsserver"
	"github.com/eoghan2t9/Irongrid-DNS/internal/upstream"
)

const (
	// maxRestoreSize caps a restore upload. A config plus certs rarely
	// exceed a few hundred KB, so 20 MB is generous while bounding how much
	// memory a single request can consume.
	maxRestoreSize = 20 << 20
)

// backupCertExts are the only file types accepted from a backup archive's
// certs/ directory, so a crafted archive can never overwrite arbitrary
// files outside the certificate store.
var backupCertExts = map[string]bool{
	".pem": true, ".crt": true, ".key": true, ".cer": true,
}

// backupConfig serves a downloadable archive of the config file and the
// TLS certificate directory — everything needed to move the server to a new
// host or roll back a bad change. The archive contains the TLS private key
// and the bcrypt password hash, so it must be handled with the same care as
// a private key.
func (h *Handler) backupConfig(w http.ResponseWriter) {
	h.cfgMu.Lock()
	cfgPath := h.ConfigPath
	certDir := h.Cfg.TLS.CertDir
	h.cfgMu.Unlock()

	data, err := buildBackup(cfgPath, certDir)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="irongrid-backup-%s.zip"`, time.Now().Format("20060102-150405")))
	_, _ = w.Write(data)
}

// buildBackup zips the config file as "irongrid.yaml" and every regular
// file directly under certDir as "certs/<name>" (no recursion — the ACME
// account key and the served cert/key all live at the top level).
func buildBackup(configPath, certDir string) ([]byte, error) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)

	cfgData, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	if err := addZipFile(zw, "irongrid.yaml", cfgData); err != nil {
		return nil, err
	}

	entries, err := os.ReadDir(certDir)
	if err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("read cert dir: %w", err)
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		data, err := os.ReadFile(filepath.Join(certDir, e.Name()))
		if err != nil {
			continue // skip an unreadable file rather than failing the backup
		}
		if err := addZipFile(zw, "certs/"+e.Name(), data); err != nil {
			return nil, err
		}
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func addZipFile(zw *zip.Writer, name string, data []byte) error {
	fw, err := zw.Create(name)
	if err != nil {
		return err
	}
	_, err = fw.Write(data)
	return err
}

// restoreConfig replaces the config file and TLS certificates from an
// uploaded backup archive, then live-applies the restored config exactly
// like a PUT /api/config and reports which sections still need a restart.
// Nothing is touched until the archive has fully passed validation.
func (h *Handler) restoreConfig(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRestoreSize)
	if err := r.ParseMultipartForm(maxRestoreSize); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "upload the backup archive as multipart field 'file': " + err.Error()})
		return
	}
	defer func() {
		if r.MultipartForm != nil {
			_ = r.MultipartForm.RemoveAll()
		}
	}()
	f, _, err := r.FormFile("file")
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing 'file' upload"})
		return
	}
	defer f.Close()
	zipData, err := io.ReadAll(io.LimitReader(f, maxRestoreSize))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	h.cfgMu.Lock()
	certDir := h.Cfg.TLS.CertDir
	h.cfgMu.Unlock()

	restored, err := restoreFromZip(zipData, certDir)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	// Live-apply the restored config through the normal save path (applyPayload
	// takes cfgMu itself, validates, hot-swaps, writes the file and reports
	// what needs a restart). The payload carries no password, so applyPayload
	// keeps the current credentials — the auth override below restores the
	// backup's own.
	restart, err := h.applyPayload(payloadFromConfig(restored))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	// Restore the backup's own admin credentials. The secret only swaps when
	// the password actually changes: a same-server backup carries the same
	// hash and secret (nothing changes, sessions survive), and a backup
	// without a session_secret gets a freshly generated one from config.Load
	// that must NOT be installed — that would needlessly log every session
	// out. Only a genuinely foreign password brings its secret in, which
	// invalidates sessions exactly as a password change should.
	authChanged := false
	h.cfgMu.Lock()
	if restored.Web.Password != "" && restored.Web.Password != h.Cfg.Web.Password {
		h.Cfg.Web.Password = restored.Web.Password
		if restored.Web.SessionSecret != "" {
			h.Cfg.Web.SessionSecret = restored.Web.SessionSecret
		}
		authChanged = true
		err = h.SaveConfig()
	}
	h.cfgMu.Unlock()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "saving restored config: " + err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"ok":               true,
		"restore_complete": true,
		"auth_restored":    authChanged,
		"restart_required": restart,
	})
}

// restoreFromZip validates and extracts a backup archive: it writes the
// config and cert files to their real locations and returns the loaded,
// validated config. Every path is checked against the archive root (zip-slip
// guard) and symlinks are refused; cert files must carry a known extension.
func restoreFromZip(zipData []byte, certDir string) (*config.Config, error) {
	zr, err := zip.NewReader(bytes.NewReader(zipData), int64(len(zipData)))
	if err != nil {
		return nil, fmt.Errorf("not a valid zip archive: %w", err)
	}

	// Extract into a temp dir first, so a later validation failure never
	// leaves partially written files behind in the real locations.
	tmp, err := os.MkdirTemp("", "irongrid-restore-*")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tmp)

	// maxExtracted caps the total decompressed size: a 20 MB archive of
	// zeros can expand to gigabytes, so without a total cap a malicious
	// upload could fill the disk (the per-entry limit below only bounds a
	// single file).
	const maxExtracted = 4 * maxRestoreSize
	var extracted int64
	var cfgPath string
	for _, f := range zr.File {
		name := filepath.Clean(f.Name)
		if name == "." || filepath.IsAbs(name) || strings.HasPrefix(name, "../") {
			return nil, fmt.Errorf("archive contains an unsafe path %q", f.Name)
		}
		if f.FileInfo().Mode()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("archive contains a symlink %q", f.Name)
		}
		if name == "irongrid.yaml" || name == "config.yaml" {
			cfgPath = filepath.Join(tmp, name)
		}
		dst := filepath.Join(tmp, name)
		if !strings.HasPrefix(dst, tmp+string(os.PathSeparator)) {
			return nil, fmt.Errorf("archive path escapes the restore root: %q", f.Name)
		}
		if f.FileInfo().IsDir() {
			if err := os.MkdirAll(dst, 0o755); err != nil {
				return nil, err
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			return nil, err
		}
		data, err := readZipEntry(f)
		if err != nil {
			return nil, err
		}
		extracted += int64(len(data))
		if extracted > maxExtracted {
			return nil, fmt.Errorf("archive expands beyond %d bytes — refusing", maxExtracted)
		}
		if err := os.WriteFile(dst, data, 0o600); err != nil {
			return nil, err
		}
	}
	if cfgPath == "" {
		return nil, fmt.Errorf("backup archive has no irongrid.yaml (or config.yaml)")
	}
	// config.Load validates the restored document (and generates a session
	// secret if the backup predates one).
	restored, err := config.Load(cfgPath)
	if err != nil {
		return nil, fmt.Errorf("restored config is invalid: %w", err)
	}
	// Validate the upstream specs applyPayload would parse, before anything
	// is written to the real locations: config.Validate only checks
	// non-empty strings, so a restored config with an unparseable spec
	// (e.g. ftp://) must fail here rather than leaving new certs next to the
	// old config.
	for _, spec := range restored.Upstreams {
		if _, err := upstream.Parse(spec); err != nil {
			return nil, fmt.Errorf("restored upstream %q: %w", spec, err)
		}
	}
	if _, err := dnsserver.ParseRoutes(routeSpecs(restored.UpstreamRoutes)); err != nil {
		return nil, fmt.Errorf("restored upstream routes: %w", err)
	}

	// Certs: only known file types, written flat into the configured cert
	// dir. Unknown entries are skipped rather than failing the restore, so
	// an archive made by a newer build still restores cleanly.
	if err := os.MkdirAll(certDir, 0o700); err != nil {
		return nil, err
	}
	for _, f := range zr.File {
		name := filepath.Clean(f.Name)
		if !strings.HasPrefix(name, "certs/") || f.FileInfo().IsDir() {
			continue
		}
		base := filepath.Base(name)
		if !backupCertExts[strings.ToLower(filepath.Ext(base))] {
			continue
		}
		data, err := readZipEntry(f)
		if err != nil {
			return nil, err
		}
		if err := os.WriteFile(filepath.Join(certDir, base), data, 0o600); err != nil {
			return nil, err
		}
	}
	return restored, nil
}

func readZipEntry(f *zip.File) ([]byte, error) {
	rc, err := f.Open()
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	// One byte past the limit so an oversized entry errors instead of being
	// silently truncated and written.
	data, err := io.ReadAll(io.LimitReader(rc, maxRestoreSize+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maxRestoreSize {
		return nil, fmt.Errorf("archive entry %s exceeds the %d-byte limit", f.Name, maxRestoreSize)
	}
	return data, nil
}
