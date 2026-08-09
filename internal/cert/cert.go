// Package cert builds TLS configurations for DoT/DoH/DoQ listeners,
// generating self-signed certificates when no CA-signed cert is provided,
// and inspecting the currently active certificate for the web UI.
package cert

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Info is the inspectable view of the active certificate, served by the
// SSL/TLS page in the dashboard.
type Info struct {
	Present           bool      `json:"present"`
	Source            string    `json:"source"` // "self-signed" | "custom" | ""
	CertPath          string    `json:"cert_path"`
	KeyPath           string    `json:"key_path"`
	SubjectCN         string    `json:"subject_cn"`
	IssuerCN          string    `json:"issuer_cn"`
	SANs              []string  `json:"sans"`
	NotBefore         time.Time `json:"not_before"`
	NotAfter          time.Time `json:"not_after"`
	ExpiresInDays     int       `json:"expires_in_days"`
	FingerprintSHA256 string    `json:"fingerprint_sha256"`
	KeyAlgo           string    `json:"key_algo"`
	Serial            string    `json:"serial"`
}

// LoadOrGenerate returns a *tls.Config for the DNS listeners. If certFile and
// keyFile are set, they are loaded. Otherwise a self-signed certificate for
// the given hosts is generated (and persisted under certDir) so the DoT/DoH/
// DoQ listeners can start immediately.
func LoadOrGenerate(certFile, keyFile, certDir string, hosts []string) (*tls.Config, error) {
	var cert tls.Certificate
	var err error
	if certFile != "" && keyFile != "" {
		cert, err = tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return nil, fmt.Errorf("load certificate: %w", err)
		}
	} else {
		cert, err = loadOrCreateSelfSigned(certDir, hosts)
		if err != nil {
			return nil, err
		}
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}, nil
}

func loadOrCreateSelfSigned(dir string, hosts []string) (tls.Certificate, error) {
	if dir == "" {
		dir = "data/certs"
	}
	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")

	if certPEM, err1 := os.ReadFile(certPath); err1 == nil {
		if keyPEM, err2 := os.ReadFile(keyPath); err2 == nil {
			if cert, err3 := tls.X509KeyPair(certPEM, keyPEM); err3 == nil {
				return cert, nil
			}
		}
	}

	info, err := Generate(dir, hosts, "ecdsa", 0, 0)
	if err != nil {
		return tls.Certificate{}, err
	}
	certPEM, err := os.ReadFile(info.CertPath)
	if err != nil {
		return tls.Certificate{}, err
	}
	keyPEM, err := os.ReadFile(info.KeyPath)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.X509KeyPair(certPEM, keyPEM)
}

// Generate creates a fresh self-signed certificate, overwriting cert.pem and
// key.pem under dir. keyType is "ecdsa" (P-256, default) or "rsa" (bits:
// 2048 or 4096). days is the validity period; <= 0 falls back to 825 days
// (like mkcert). hosts become the certificate SANs (DNS names and/or IPs).
func Generate(dir string, hosts []string, keyType string, keyBits, days int) (*Info, error) {
	if dir == "" {
		dir = "data/certs"
	}
	if len(hosts) == 0 {
		hosts = []string{"localhost"}
	}
	if days <= 0 {
		days = 825
	}

	var priv any
	switch strings.ToLower(keyType) {
	case "rsa":
		// Round to a standard RSA size; arbitrary bit lengths are unusual
		// and can confuse clients.
		switch {
		case keyBits >= 4096:
			keyBits = 4096
		case keyBits >= 3072:
			keyBits = 3072
		default:
			keyBits = 2048
		}
		k, err := rsa.GenerateKey(rand.Reader, keyBits)
		if err != nil {
			return nil, err
		}
		priv = k
	default: // ecdsa
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, err
		}
		priv = k
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}
	tmpl := x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: hosts[0], Organization: []string{"Irongrid DNS"}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().AddDate(0, 0, days),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{},
	}
	for _, h := range hosts {
		h = strings.TrimSpace(h)
		if h == "" {
			continue
		}
		if ip := net.ParseIP(h); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, h)
		}
	}
	if len(tmpl.DNSNames) == 0 && len(tmpl.IPAddresses) == 0 {
		return nil, fmt.Errorf("no valid hosts to put in the certificate")
	}

	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, publicKey(priv), priv)
	if err != nil {
		return nil, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	var keyPEM []byte
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		keyPEM = pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)})
	case *ecdsa.PrivateKey:
		keyDER, err := x509.MarshalECPrivateKey(k)
		if err != nil {
			return nil, err
		}
		keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	}

	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")
	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		return nil, err
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		return nil, err
	}
	return inspectPair(certPath, keyPath, "self-signed")
}

func publicKey(priv any) any {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		return &k.PublicKey
	case *ecdsa.PrivateKey:
		return &k.PublicKey
	}
	return nil
}

// Inspect reports the details of the currently active certificate: the custom
// pair when certFile/keyFile are configured, otherwise the self-signed pair
// under certDir. It returns Present=false (no error) when nothing exists yet.
func Inspect(certDir, certFile, keyFile string) (*Info, error) {
	if certFile != "" && keyFile != "" {
		if _, err := os.Stat(certFile); err == nil {
			return inspectPair(certFile, keyFile, "custom")
		}
	}
	if certDir == "" {
		certDir = "data/certs"
	}
	certPath := filepath.Join(certDir, "cert.pem")
	keyPath := filepath.Join(certDir, "key.pem")
	if _, err := os.Stat(certPath); err != nil {
		return &Info{Present: false}, nil
	}
	return inspectPair(certPath, keyPath, "self-signed")
}

func inspectPair(certPath, keyPath, source string) (*Info, error) {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, err
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, err
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return nil, err
	}

	sum := sha256.Sum256(leaf.Raw)
	fpParts := make([]string, len(sum))
	for i, b := range sum {
		fpParts[i] = hex.EncodeToString([]byte{b})
	}

	algo := leaf.PublicKeyAlgorithm.String()
	if leaf.PublicKeyAlgorithm == x509.RSA && leaf.PublicKey != nil {
		if pk, ok := leaf.PublicKey.(*rsa.PublicKey); ok {
			algo = fmt.Sprintf("RSA %d", pk.N.BitLen())
		}
	} else if leaf.PublicKeyAlgorithm == x509.ECDSA {
		if pk, ok := leaf.PublicKey.(*ecdsa.PublicKey); ok {
			algo = fmt.Sprintf("ECDSA %s", curveName(pk))
		}
	}

	return &Info{
		Present:           true,
		Source:            source,
		CertPath:          certPath,
		KeyPath:           keyPath,
		SubjectCN:         leaf.Subject.CommonName,
		IssuerCN:          leaf.Issuer.CommonName,
		SANs:              append(append([]string{}, leaf.DNSNames...), ipStrings(leaf.IPAddresses)...),
		NotBefore:         leaf.NotBefore,
		NotAfter:          leaf.NotAfter,
		ExpiresInDays:     int(time.Until(leaf.NotAfter).Hours() / 24),
		FingerprintSHA256: strings.ToUpper(strings.Join(fpParts, ":")),
		KeyAlgo:           algo,
		Serial:            leaf.SerialNumber.String(),
	}, nil
}

func curveName(pk *ecdsa.PublicKey) string {
	switch pk.Curve {
	case elliptic.P256():
		return "P-256"
	case elliptic.P384():
		return "P-384"
	case elliptic.P521():
		return "P-521"
	}
	return pk.Curve.Params().Name
}

func ipStrings(ips []net.IP) []string {
	out := make([]string, 0, len(ips))
	for _, ip := range ips {
		out = append(out, ip.String())
	}
	return out
}
