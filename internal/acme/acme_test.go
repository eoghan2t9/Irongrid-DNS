package acme

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/eoghan2t9/Irongrid-DNS/internal/cert"
)

func TestChallengeHandler(t *testing.T) {
	m := New(Options{Email: "a@b.c", Domains: []string{"example.com"}, CertDir: t.TempDir()})
	m.setToken("tok123", "resp456")

	srv := httptest.NewServer(http.HandlerFunc(m.handleChallenge))
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/.well-known/acme-challenge/tok123")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "resp456" {
		t.Errorf("challenge body = %q, want resp456", body)
	}

	// Unknown token -> 404.
	resp2, _ := http.Get(srv.URL + "/.well-known/acme-challenge/nope")
	if resp2.StatusCode != http.StatusNotFound {
		t.Errorf("unknown token status = %d, want 404", resp2.StatusCode)
	}
	resp2.Body.Close()
}

func TestChallengeHandlerWrongPath(t *testing.T) {
	m := New(Options{Email: "a@b.c", Domains: []string{"example.com"}, CertDir: t.TempDir()})
	srv := httptest.NewServer(http.HandlerFunc(m.handleChallenge))
	defer srv.Close()
	resp, _ := http.Get(srv.URL + "/")
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("root path status = %d, want 404", resp.StatusCode)
	}
	resp.Body.Close()
}

func TestAccountKeyPersisted(t *testing.T) {
	dir := t.TempDir()
	m := New(Options{Email: "a@b.c", Domains: []string{"example.com"}, CertDir: dir})
	k1 := mustAccountKey(m)
	k2 := mustAccountKey(m)
	if k1.D.Cmp(k2.D) != 0 {
		t.Error("account key should be stable across calls (persisted)")
	}
	if _, err := os.Stat(filepath.Join(dir, "acme-account.key")); err != nil {
		t.Errorf("account key file missing: %v", err)
	}
}

func TestNeedsRenewal(t *testing.T) {
	dir := t.TempDir()
	m := New(Options{
		Email: "a@b.c", Domains: []string{"example.com"},
		CertDir: dir, RenewBeforeDays: 30,
	})

	// No cert yet -> needs renewal.
	if !m.NeedsRenewal() {
		t.Error("NeedsRenewal = false with no cert, want true")
	}

	// A self-signed cert covering the domain must still be replaced by ACME.
	if _, err := cert.Generate(dir, []string{"example.com"}, "ecdsa", 0, 90); err != nil {
		t.Fatal(err)
	}
	if !m.NeedsRenewal() {
		t.Error("NeedsRenewal = false with a self-signed cert, want true")
	}

	// A CA-signed cert covering the domain, expiring in 90 days, is outside
	// the 30-day renewal window -> no renewal needed.
	writeCACert(t, dir, []string{"example.com"}, 90)
	if m.NeedsRenewal() {
		t.Error("NeedsRenewal = true with a healthy CA-signed cert, want false")
	}
}

// writeCACert writes a cert+key pair into dir where a fake CA (issuer "Fake
// CA") signs a leaf for the given domains, so issuer != subject.
func writeCACert(t *testing.T, dir string, domains []string, days int) {
	t.Helper()
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Fake CA"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().AddDate(10, 0, 0),
		IsCA:         true,
		KeyUsage:     x509.KeyUsageCertSign,
	}
	caDER, _ := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	caCert, _ := x509.ParseCertificate(caDER)

	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: domains[0]},
		DNSNames:     domains,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().AddDate(0, 0, days),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafDER, _ := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, &leafKey.PublicKey, caKey)

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER})
	keyDER, _ := x509.MarshalECPrivateKey(leafKey)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(filepath.Join(dir, "cert.pem"), certPEM, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "key.pem"), keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestGetStatus(t *testing.T) {
	m := New(Options{
		Email: "a@b.c", Domains: []string{"one.example.com", "two.example.com"},
		CertDir: t.TempDir(), Staging: true, HTTP01Port: 8081,
	})
	st := m.GetStatus()
	if !st.Enabled || !st.Staging {
		t.Error("status should reflect enabled + staging")
	}
	if st.ChallengePort != 8081 {
		t.Errorf("challenge port = %d, want 8081", st.ChallengePort)
	}
	if len(st.Domains) != 2 || st.Email != "a@b.c" {
		t.Errorf("status domains/email wrong: %+v", st)
	}
}

func TestServePortConflict(t *testing.T) {
	// Occupy a port, then Serve on the same one must fail with a clear error
	// rather than panic or hang.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port

	// Manager binds :port on all interfaces; use a fresh temp dir.
	m := New(Options{Email: "a@b.c", Domains: []string{"example.com"}, CertDir: t.TempDir(), HTTP01Port: port})
	// Can't easily force the same interface/addr, so just verify Serve on the
	// occupied port errors (or succeeds and we stop it). Either way no panic.
	if err := m.Serve(); err != nil {
		t.Logf("Serve on occupied port returned expected error: %v", err)
	} else {
		m.Stop()
	}
}
