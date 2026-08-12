package api

import (
	"archive/zip"
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/eoghan2t9/Irongrid-DNS/internal/config"
)

// TestBackupRestoreRoundTrip verifies that a backup archive restores the
// config (including the newer conditional-route section) and the cert files.
func TestBackupRestoreRoundTrip(t *testing.T) {
	dir := t.TempDir()
	cfg := config.Default()
	cfg.Upstreams = []string{"udp://1.1.1.1", "tls://8.8.8.8:853"}
	cfg.UpstreamRoutes = []config.UpstreamRoute{{Domain: "lan", Upstreams: []string{"udp://192.168.1.1"}}}
	cfgPath := filepath.Join(dir, "irongrid.yaml")
	if err := cfg.Save(cfgPath); err != nil {
		t.Fatal(err)
	}
	certDir := filepath.Join(dir, "certs")
	if err := os.MkdirAll(certDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(certDir, "cert.pem"), []byte("CERT"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(certDir, "key.pem"), []byte("KEY"), 0o600); err != nil {
		t.Fatal(err)
	}

	zipData, err := buildBackup(cfgPath, certDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(zipData) == 0 {
		t.Fatal("empty backup")
	}

	restoreCertDir := filepath.Join(dir, "restored-certs")
	restored, err := restoreFromZip(zipData, restoreCertDir)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(restored.Upstreams, cfg.Upstreams) {
		t.Fatalf("restored upstreams = %v, want %v", restored.Upstreams, cfg.Upstreams)
	}
	if !reflect.DeepEqual(restored.UpstreamRoutes, cfg.UpstreamRoutes) {
		t.Fatalf("restored routes = %v, want %v", restored.UpstreamRoutes, cfg.UpstreamRoutes)
	}
	// Certs landed in the restore's cert dir with their content intact.
	for name, want := range map[string]string{"cert.pem": "CERT", "key.pem": "KEY"} {
		got, err := os.ReadFile(filepath.Join(restoreCertDir, name))
		if err != nil {
			t.Fatalf("restored %s: %v", name, err)
		}
		if string(got) != want {
			t.Fatalf("restored %s = %q, want %q", name, got, want)
		}
	}
}

// TestRestoreRejectsZipSlip verifies that an archive whose entries escape
// the extraction root is refused outright.
func TestRestoreRejectsZipSlip(t *testing.T) {
	zipData := zipWith(t, map[string]string{"../evil.txt": "x"})
	if _, err := restoreFromZip(zipData, t.TempDir()); err == nil {
		t.Fatal("zip-slip archive accepted")
	}
}

// TestRestoreRejectsAbsolutePath verifies absolute paths in the archive are
// refused.
func TestRestoreRejectsAbsolutePath(t *testing.T) {
	zipData := zipWith(t, map[string]string{"/etc/irongrid.yaml": "x"})
	if _, err := restoreFromZip(zipData, t.TempDir()); err == nil {
		t.Fatal("absolute-path archive accepted")
	}
}

// TestRestoreRejectsSymlink verifies symlink entries are refused (they could
// otherwise redirect the extraction write).
func TestRestoreRejectsSymlink(t *testing.T) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	fh := &zip.FileHeader{Name: "certs/link"}
	fh.SetMode(os.ModeSymlink)
	if _, err := zw.CreateHeader(fh); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := restoreFromZip(buf.Bytes(), t.TempDir()); err == nil {
		t.Fatal("symlink archive accepted")
	}
}

// TestRestoreRequiresConfig verifies an archive without a config file is
// rejected.
func TestRestoreRequiresConfig(t *testing.T) {
	zipData := zipWith(t, map[string]string{"certs/cert.pem": "CERT"})
	if _, err := restoreFromZip(zipData, t.TempDir()); err == nil {
		t.Fatal("archive without a config file accepted")
	}
}

// TestRestoreRejectsBadUpstreamSpec verifies a restored config whose
// upstream spec config.Validate accepts but upstream.Parse rejects fails the
// restore before any cert is written (applyPayload would have failed later,
// after the certs were already replaced).
func TestRestoreRejectsBadUpstreamSpec(t *testing.T) {
	cfg := config.Default()
	cfg.Upstreams = []string{"ftp://1.2.3.4"}
	cfgPath := filepath.Join(t.TempDir(), "irongrid.yaml")
	if err := cfg.Save(cfgPath); err != nil {
		t.Fatal(err)
	}
	cfgData, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	zipData := zipWith(t, map[string]string{
		"irongrid.yaml":  string(cfgData),
		"certs/cert.pem": "CERT",
	})
	certDir := filepath.Join(t.TempDir(), "certs")
	if _, err := restoreFromZip(zipData, certDir); err == nil {
		t.Fatal("config with an unparseable upstream accepted")
	}
	if _, err := os.Stat(certDir); !os.IsNotExist(err) {
		t.Fatal("cert dir was written despite an unparseable upstream")
	}
}

// TestRestoreRejectsOversizedEntry verifies an archive entry that expands
// past the per-entry limit is refused instead of silently truncated.
func TestRestoreRejectsOversizedEntry(t *testing.T) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	fw, err := zw.Create("certs/big.pem")
	if err != nil {
		t.Fatal(err)
	}
	// Highly compressible, so the archive itself stays tiny while the
	// decompressed entry trips the limit.
	huge := bytes.Repeat([]byte("a"), int(maxRestoreSize)+1)
	if _, err := fw.Write(huge); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := restoreFromZip(buf.Bytes(), t.TempDir()); err == nil {
		t.Fatal("oversized entry accepted")
	}
}

// TestRestoreRejectsInvalidConfig verifies a broken config in the archive
// fails the restore before anything is written to the real cert dir.
func TestRestoreRejectsInvalidConfig(t *testing.T) {
	zipData := zipWith(t, map[string]string{"irongrid.yaml": "not: [valid"})
	certDir := filepath.Join(t.TempDir(), "certs")
	if _, err := restoreFromZip(zipData, certDir); err == nil {
		t.Fatal("invalid config accepted")
	}
	if _, err := os.Stat(certDir); !os.IsNotExist(err) {
		t.Fatal("cert dir was created despite an invalid config")
	}
}

// TestRestoreSkipsUnknownCertTypes verifies only known cert file types are
// written to the cert dir — a crafted archive can't plant an executable.
func TestRestoreSkipsUnknownCertTypes(t *testing.T) {
	cfg := config.Default()
	cfgPath := filepath.Join(t.TempDir(), "irongrid.yaml")
	if err := cfg.Save(cfgPath); err != nil {
		t.Fatal(err)
	}
	cfgData, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	zipData := zipWith(t, map[string]string{
		"irongrid.yaml":  string(cfgData),
		"certs/evil.sh":  "#!/bin/sh\nrm -rf /",
		"certs/cert.pem": "CERT",
	})
	certDir := filepath.Join(t.TempDir(), "certs")
	if _, err := restoreFromZip(zipData, certDir); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(certDir, "evil.sh")); !os.IsNotExist(err) {
		t.Fatal("non-cert file was written to the cert dir")
	}
	if got, err := os.ReadFile(filepath.Join(certDir, "cert.pem")); err != nil || string(got) != "CERT" {
		t.Fatalf("cert.pem not restored correctly: %q, %v", got, err)
	}
}

// zipWith builds a zip archive from a name -> content map.
func zipWith(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, content := range files {
		fw, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := fw.Write([]byte(content)); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}
