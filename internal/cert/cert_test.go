package cert

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestGenerateECDSA(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	info, err := Generate(dir, []string{"dns.example.com", "192.168.1.10"}, "ecdsa", 0, 30)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if !info.Present {
		t.Fatal("info.Present = false, want true")
	}
	if info.Source != "self-signed" {
		t.Errorf("source = %q, want self-signed", info.Source)
	}
	if info.SubjectCN != "dns.example.com" {
		t.Errorf("subject CN = %q, want dns.example.com", info.SubjectCN)
	}
	if info.IssuerCN != "dns.example.com" {
		t.Errorf("issuer CN = %q, want same as subject (self-signed)", info.IssuerCN)
	}
	if len(info.SANs) != 2 {
		t.Errorf("SANs = %v, want 2 entries", info.SANs)
	}
	if !strings.Contains(info.KeyAlgo, "ECDSA") {
		t.Errorf("key algo = %q, want ECDSA", info.KeyAlgo)
	}
	if info.ExpiresInDays < 28 || info.ExpiresInDays > 31 {
		t.Errorf("expires_in_days = %d, want ~30", info.ExpiresInDays)
	}
	if len(info.FingerprintSHA256) != 95 { // 47 hex pairs joined by ':' = 47*3-1
		t.Errorf("fingerprint length = %d, want 95", len(info.FingerprintSHA256))
	}
	if info.Serial == "" {
		t.Error("serial is empty")
	}
	// Files must exist on disk with the right perms.
	if _, err := os.Stat(filepath.Join(dir, "cert.pem")); err != nil {
		t.Errorf("cert.pem missing: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "key.pem")); err != nil {
		t.Errorf("key.pem missing: %v", err)
	}
	// The generated pair must load as a valid TLS pair.
	if _, err := LoadOrGenerate("", "", dir, nil); err != nil {
		t.Errorf("LoadOrGenerate on generated cert: %v", err)
	}
}

func TestGenerateRSA(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	info, err := Generate(dir, []string{"localhost"}, "rsa", 2048, 0)
	if err != nil {
		t.Fatalf("Generate RSA: %v", err)
	}
	if !strings.Contains(info.KeyAlgo, "RSA 2048") {
		t.Errorf("key algo = %q, want RSA 2048", info.KeyAlgo)
	}
	if info.ExpiresInDays < 800 { // default 825 days when days <= 0
		t.Errorf("default validity = %d days, want ~825", info.ExpiresInDays)
	}
}

func TestGenerateOverwrites(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	a, err := Generate(dir, []string{"one.example.com"}, "ecdsa", 0, 30)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Generate(dir, []string{"two.example.com"}, "ecdsa", 0, 60)
	if err != nil {
		t.Fatal(err)
	}
	if a.FingerprintSHA256 == b.FingerprintSHA256 {
		t.Error("regenerating should produce a different certificate")
	}
	if b.SubjectCN != "two.example.com" {
		t.Errorf("regenerated subject = %q, want two.example.com", b.SubjectCN)
	}
}

func TestInspectNone(t *testing.T) {
	t.Parallel()
	info, err := Inspect(t.TempDir(), "", "")
	if err != nil {
		t.Fatalf("Inspect on empty dir: %v", err)
	}
	if info.Present {
		t.Error("Present = true for empty dir, want false")
	}
}

func TestInspectCustom(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	if _, err := Generate(dir, []string{"ca.example.com"}, "ecdsa", 0, 30); err != nil {
		t.Fatal(err)
	}
	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")

	info, err := Inspect("", certPath, keyPath)
	if err != nil {
		t.Fatalf("Inspect custom: %v", err)
	}
	if !info.Present {
		t.Fatal("Present = false, want true")
	}
	if info.Source != "custom" {
		t.Errorf("source = %q, want custom", info.Source)
	}
	if info.CertPath != certPath || info.KeyPath != keyPath {
		t.Errorf("paths = %q %q, want %q %q", info.CertPath, info.KeyPath, certPath, keyPath)
	}
}

func TestGenerateBadHosts(t *testing.T) {
	t.Parallel()
	if _, err := Generate(t.TempDir(), nil, "ecdsa", 0, 30); err != nil {
		t.Fatalf("Generate with nil hosts should default to localhost, got error: %v", err)
	}
}

func TestInspectNotAfterInFuture(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	info, err := Generate(dir, []string{"localhost"}, "ecdsa", 0, 30)
	if err != nil {
		t.Fatal(err)
	}
	if !info.NotAfter.After(time.Now()) {
		t.Error("NotAfter should be in the future")
	}
	if !info.NotBefore.Before(time.Now()) {
		t.Error("NotBefore should be in the past")
	}
}
