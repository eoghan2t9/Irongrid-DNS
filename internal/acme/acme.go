// Package acme implements automatic TLS certificate issuance from Let's
// Encrypt (or another RFC 8555 ACME CA) using the HTTP-01 challenge, plus
// background renewal. It stores issued certificates as cert.pem/key.pem in
// the configured cert dir, exactly where the rest of Irongrid expects them.
package acme

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/acme"
)

const (
	// LetsEncryptProd is the production ACME directory URL.
	LetsEncryptProd = "https://acme-v02.api.letsencrypt.org/directory"
	// LetsEncryptStaging issues test certificates (untrusted by clients).
	LetsEncryptStaging = "https://acme-staging-v02.api.letsencrypt.org/directory"
)

// Manager issues and renews certificates for the configured domains.
type Manager struct {
	mu       sync.Mutex
	email    string
	domains  []string
	dir      string
	staging  bool
	httpPort int
	renewIn  time.Duration

	// tokenHandler is installed by Serve: it answers /.well-known/acme-challenge/<token>.
	tokens   map[string]string
	tokensMu sync.Mutex
	srv      *http.Server
	ln       net.Listener

	// externalHTTP01 tells the manager that the web server's own HTTP
	// listener serves /.well-known/acme-challenge/* (used when web_redirect
	// shares the http-01 port), so it must not bind its own challenge server.
	externalHTTP01 bool

	// stopCh is closed by Stop to halt the renewal loop.
	stopCh   chan struct{}
	stopOnce func()

	// OnIssued, when non-nil, is called after a successful issuance so the
	// server can rebind its listeners with the fresh certificate.
	OnIssued func()

	// dns is the optional DNS-01 provider. When set, issuance uses TXT
	// records instead of the HTTP-01 challenge server.
	dns DNSProvider

	// dnsWait is how long to pause after Present before asking the CA to
	// validate, giving the TXT record time to propagate to the CA's
	// resolvers. lego's DNS providers don't wait internally (unlike the
	// hand-rolled providers this replaced), so the manager owns it.
	dnsWait time.Duration

	// Status mirrors the last issuance/renewal attempt for the dashboard.
	Status Status
}

// Status is the public state of the ACME manager.
type Status struct {
	Enabled     bool     `json:"enabled"`
	Email       string   `json:"email"`
	Domains     []string `json:"domains"`
	Staging     bool     `json:"staging"`
	Challenge   string   `json:"challenge"`    // "http-01" or "dns-01"
	DNSProvider string   `json:"dns_provider"` // e.g. "cloudflare" when dns-01
	// The timestamps are pointers so a manager that has never issued serializes
	// them as null instead of Go's zero time ("0001-01-01T00:00:00Z"), which
	// the dashboard rendered as "31/12/1" with absurd day counts.
	LastAttempt   *time.Time `json:"last_attempt"`
	LastSuccess   *time.Time `json:"last_success"`
	LastError     string     `json:"last_error,omitempty"`
	NextRenewal   *time.Time `json:"next_renewal"`
	ChallengePort int        `json:"challenge_port"`
	Running       bool       `json:"running"`
}

// Options configures a Manager.
type Options struct {
	Email           string
	Domains         []string
	CertDir         string
	Staging         bool
	HTTP01Port      int
	RenewBeforeDays int
	DNS             DNSProvider // optional DNS-01 provider
	DNSProvider     string      // provider name for status, e.g. "cloudflare"
	// DNSWait is how long to pause after publishing the TXT record before
	// asking the CA to validate it (propagation wait). Only used when DNS is set.
	DNSWait time.Duration
	// ExternalHTTP01 tells the manager that the web server serves the http-01
	// challenge on the same port (web_redirect on port 80), so it must not
	// bind its own challenge listener.
	ExternalHTTP01 bool
}

// New creates a Manager. The HTTP-01 challenge server is not started until
// Serve is called (called by the server when ACME is enabled).
func New(o Options) *Manager {
	if o.HTTP01Port == 0 {
		o.HTTP01Port = 80
	}
	if o.RenewBeforeDays <= 0 {
		o.RenewBeforeDays = 30
	}
	renewIn := time.Duration(o.RenewBeforeDays) * 24 * time.Hour
	m := &Manager{
		email:          o.Email,
		domains:        slices.Clone(o.Domains),
		dir:            o.CertDir,
		staging:        o.Staging,
		httpPort:       o.HTTP01Port,
		renewIn:        renewIn,
		dns:            o.DNS,
		dnsWait:        o.DNSWait,
		externalHTTP01: o.ExternalHTTP01,
		tokens:         map[string]string{},
		stopCh:         make(chan struct{}),
	}
	m.stopOnce = sync.OnceFunc(func() { close(m.stopCh) })
	m.Status.Enabled = true
	m.Status.Email = o.Email
	m.Status.Domains = m.domains
	m.Status.Staging = o.Staging
	m.Status.ChallengePort = o.HTTP01Port
	if m.dns != nil {
		m.Status.Challenge = "dns-01"
		m.Status.DNSProvider = o.DNSProvider
	} else {
		m.Status.Challenge = "http-01"
	}
	return m
}

// Dir returns the certificate directory.
func (m *Manager) Dir() string { return m.dir }

// Serve starts the HTTP-01 challenge listener on the configured port. It is
// only needed while an order is being validated, but the listener is kept up
// for the lifetime of the process so renewals work unattended.
func (m *Manager) Serve() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.srv != nil {
		return nil
	}
	addr := fmt.Sprintf(":%d", m.httpPort)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("acme: cannot listen on %s for the HTTP-01 challenge (Let's Encrypt validates your domain on port 80): %w", addr, err)
	}
	m.ln = ln
	m.srv = &http.Server{
		ReadHeaderTimeout: 10 * time.Second, // gosec G112: bound slow-header clients
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !m.HandleChallenge(w, r) {
				http.NotFound(w, r)
			}
		}),
	}
	go func() {
		if err := m.srv.Serve(ln); err != nil && err != http.ErrServerClosed {
			slog.Error("acme challenge server stopped", "addr", addr, "error", err)
		}
	}()
	m.Status.Running = true
	return nil
}

// Stop shuts the challenge listener down and halts the renewal loop.
func (m *Manager) Stop() {
	m.mu.Lock()
	if m.srv != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		_ = m.srv.Shutdown(ctx)
		cancel()
		m.srv = nil
	}
	m.Status.Running = false
	m.mu.Unlock()
	m.stopOnce()
}

// HandleChallenge serves an http-01 challenge token when the request path is
// an ACME challenge path. It reports whether the path was a challenge path
// (even when no token is found, so callers can stop processing). It is used
// by the web_redirect listener when it shares the challenge port.
func (m *Manager) HandleChallenge(w http.ResponseWriter, r *http.Request) bool {
	const prefix = "/.well-known/acme-challenge/"
	if !strings.HasPrefix(r.URL.Path, prefix) {
		return false
	}
	token := strings.TrimPrefix(r.URL.Path, prefix)
	m.tokensMu.Lock()
	val, ok := m.tokens[token]
	m.tokensMu.Unlock()
	if !ok {
		http.NotFound(w, r)
		return true
	}
	w.Header().Set("Content-Type", "text/plain")
	fmt.Fprint(w, val)
	return true
}

// setToken registers an http-01 response for the challenge server.
func (m *Manager) setToken(token, value string) {
	m.tokensMu.Lock()
	m.tokens[token] = value
	m.tokensMu.Unlock()
}

// clearTokens removes stale challenge tokens.
func (m *Manager) clearTokens() {
	m.tokensMu.Lock()
	m.tokens = map[string]string{}
	m.tokensMu.Unlock()
}

// Issue runs a full ACME order for the configured domains and writes the
// resulting certificate chain to cert.pem/key.pem in the cert dir. It is safe
// to call repeatedly (renewal does the same thing).
func (m *Manager) Issue(ctx context.Context) error {
	m.mu.Lock()
	attempt := time.Now()
	m.Status.LastAttempt = &attempt
	m.Status.LastError = ""
	m.mu.Unlock()

	// DNS-01 needs no inbound listener; HTTP-01 needs the challenge server
	// unless the web server serves the challenge externally (web_redirect on
	// the same port).
	if m.dns == nil && !m.externalHTTP01 {
		if err := m.Serve(); err != nil {
			m.noteErr(err)
			return err
		}
	}

	dirURL := LetsEncryptProd
	if m.staging {
		dirURL = LetsEncryptStaging
	}
	client := &acme.Client{
		Key:          mustAccountKey(m),
		DirectoryURL: dirURL,
	}

	// 1. Register the account (idempotent).
	_, err := client.Register(ctx, &acme.Account{Contact: []string{"mailto:" + m.email}}, acme.AcceptTOS)
	if err != nil {
		// ErrAccountAlreadyExists is fine: we can proceed with the existing account.
		if err != acme.ErrAccountAlreadyExists {
			m.noteErr(fmt.Errorf("register ACME account: %w", err))
			return fmt.Errorf("acme: register account: %w", err)
		}
	}

	// 2. Create an order for all domains.
	order, err := client.AuthorizeOrder(ctx, acme.DomainIDs(m.domains...))
	if err != nil {
		m.noteErr(fmt.Errorf("create order: %w", err))
		return fmt.Errorf("acme: create order: %w", err)
	}

	// 3. Fulfil the http-01 or dns-01 challenge for each pending authorization.
	m.clearTokens()
	for _, authzURL := range order.AuthzURLs {
		authz, err := client.GetAuthorization(ctx, authzURL)
		if err != nil {
			m.noteErr(fmt.Errorf("get authorization: %w", err))
			return err
		}
		if authz.Status == acme.StatusValid {
			continue // already validated (renewal)
		}
		domain := authz.Identifier.Value
		var chal *acme.Challenge
		want := "http-01"
		if m.dns != nil {
			want = "dns-01"
		}
		for _, c := range authz.Challenges {
			if c.Type == want {
				chal = c
				break
			}
		}
		if chal == nil {
			m.noteErr(fmt.Errorf("no %s challenge offered for %s", want, domain))
			return fmt.Errorf("acme: CA did not offer %s challenge for %s", want, domain)
		}
		if m.dns != nil {
			// DNS-01: publish the TXT record, then accept and wait. The record
			// is removed on every exit path so a failed order never leaks a
			// stale _acme-challenge record.
			//
			// keyAuth is the token + account-key thumbprint. It is the same
			// value regardless of challenge type — HTTP-01 serves it directly
			// (HTTP01ChallengeResponse), DNS-01 publishes its SHA-256 digest
			// instead. lego's DNS providers compute that digest themselves
			// from (domain, token, keyAuth), so they need keyAuth here, not
			// the pre-hashed DNS01ChallengeRecord value.
			keyAuth, err := client.HTTP01ChallengeResponse(chal.Token)
			if err != nil {
				m.noteErr(err)
				return err
			}
			if err := m.dns.Present(domain, chal.Token, keyAuth); err != nil {
				m.noteErr(fmt.Errorf("present dns-01 record for %s: %w", domain, err))
				return err
			}
			defer func() {
				if err := m.dns.CleanUp(domain, chal.Token, keyAuth); err != nil {
					slog.Error("acme TXT record cleanup failed", "domain", domain, "error", err)
				}
			}()
			if m.dnsWait > 0 {
				select {
				case <-time.After(m.dnsWait):
				case <-ctx.Done():
					m.noteErr(ctx.Err())
					return ctx.Err()
				}
			}
			if _, err := client.Accept(ctx, chal); err != nil {
				m.noteErr(fmt.Errorf("accept challenge: %w", err))
				return err
			}
			if _, err := client.WaitAuthorization(ctx, authzURL); err != nil {
				m.noteErr(fmt.Errorf("wait for authorization of %s: %w", domain, err))
				return err
			}
			continue
		}
		resp, err := client.HTTP01ChallengeResponse(chal.Token)
		if err != nil {
			m.noteErr(err)
			return err
		}
		m.setToken(chal.Token, resp)
		if _, err := client.Accept(ctx, chal); err != nil {
			m.noteErr(fmt.Errorf("accept challenge: %w", err))
			return err
		}
		if _, err := client.WaitAuthorization(ctx, authzURL); err != nil {
			m.noteErr(fmt.Errorf("wait for authorization of %s: %w", domain, err))
			return err
		}
	}

	// 4. Build a CSR and finalize the order.
	csr, keyPEM, err := makeCSR(m.domains)
	if err != nil {
		m.noteErr(err)
		return err
	}
	der, _, err := client.CreateOrderCert(ctx, order.FinalizeURL, csr, true)
	if err != nil {
		m.noteErr(fmt.Errorf("finalize order: %w", err))
		return err
	}
	if len(der) == 0 {
		m.noteErr(fmt.Errorf("CA returned no certificate"))
		return fmt.Errorf("acme: CA returned no certificate")
	}

	// 5. Persist cert chain + key.
	certPEM := make([]byte, 0, 4096)
	for _, d := range der {
		certPEM = append(certPEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: d})...)
	}
	if err := os.MkdirAll(m.dir, 0o755); err != nil {
		m.noteErr(err)
		return err
	}
	if err := os.WriteFile(filepath.Join(m.dir, "cert.pem"), certPEM, 0o600); err != nil {
		m.noteErr(err)
		return err
	}
	if err := os.WriteFile(filepath.Join(m.dir, "key.pem"), keyPEM, 0o600); err != nil {
		m.noteErr(err)
		return err
	}

	m.mu.Lock()
	issued := time.Now()
	m.Status.LastSuccess = &issued
	m.Status.LastError = ""
	next := issued.Add(m.renewIn)
	m.Status.NextRenewal = &next
	m.mu.Unlock()
	slog.Info("acme certificate issued", "domains", m.domains, "dir", m.dir)
	return nil
}

// notifyIssued fires OnIssued (wired in main to rebind listeners with the
// fresh certificate). Called only after a successful issuance.
func (m *Manager) notifyIssued() {
	if m.OnIssued != nil {
		m.OnIssued()
	}
}

// NeedsRenewal reports whether the current certificate is missing, expired,
// within the renewal window, or does not cover every configured ACME domain
// (e.g. only a self-signed fallback exists).
func (m *Manager) NeedsRenewal() bool {
	cert, err := tls.LoadX509KeyPair(
		filepath.Join(m.dir, "cert.pem"),
		filepath.Join(m.dir, "key.pem"),
	)
	if err != nil {
		return true
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return true
	}
	// The startup self-signed fallback must be replaced even if it happens
	// to cover the domain names (issuer == subject is the self-signed mark).
	if leaf.Issuer.CommonName == leaf.Subject.CommonName {
		return true
	}
	// A cert that doesn't cover the ACME domains must be replaced.
	covered := map[string]bool{}
	for _, d := range leaf.DNSNames {
		covered[strings.ToLower(d)] = true
	}
	for _, d := range m.domains {
		if !covered[strings.ToLower(d)] {
			return true
		}
	}
	return time.Until(leaf.NotAfter) < m.renewIn
}

// RunLoop renews on start when needed and then on a fixed daily schedule until
// ctx is cancelled.
func (m *Manager) RunLoop(ctx context.Context) {
	// Initial issuance/renewal in the background so startup isn't blocked on
	// the network.
	go func() {
		time.Sleep(2 * time.Second) // let listeners bind first
		// Abort if the manager was stopped while we waited (e.g. ACME toggled
		// off via a config reload during the startup window).
		select {
		case <-m.stopCh:
			return
		default:
		}
		if !m.NeedsRenewal() {
			return
		}
		slog.Info("acme certificate missing or expiring soon — issuing")
		if err := m.Issue(ctx); err != nil {
			slog.Error("acme initial issuance failed", "error", err)
			return
		}
		// Don't fire OnIssued if the manager was stopped while the issuance was
		// in flight (e.g. ACME toggled off via reload during the startup window).
		select {
		case <-m.stopCh:
			return
		default:
		}
		m.notifyIssued()
	}()
	t := time.NewTicker(24 * time.Hour)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			m.Stop()
			return
		case <-m.stopCh:
			return
		case <-t.C:
			if !m.NeedsRenewal() {
				continue
			}
			if err := m.Issue(ctx); err != nil {
				slog.Error("acme renewal failed", "error", err)
				continue
			}
			// Don't fire OnIssued if the manager was stopped while the issuance
			// was in flight (e.g. ACME toggled off via reload mid-renewal).
			select {
			case <-m.stopCh:
				return
			default:
			}
			m.notifyIssued()
		}
	}
}

func (m *Manager) noteErr(err error) {
	m.mu.Lock()
	m.Status.LastError = err.Error()
	m.mu.Unlock()
}

// GetStatus returns a copy of the manager status.
func (m *Manager) GetStatus() Status {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.Status
}

// accountKeyPath is where the ACME account key is persisted so renewals reuse
// the same account.
func (m *Manager) accountKeyPath() string {
	return filepath.Join(m.dir, "acme-account.key")
}

func mustAccountKey(m *Manager) *ecdsa.PrivateKey {
	path := m.accountKeyPath()
	if data, err := os.ReadFile(path); err == nil {
		if block, _ := pem.Decode(data); block != nil {
			if k, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
				return k
			}
		}
	}
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	der, err := x509.MarshalECPrivateKey(k)
	if err == nil {
		_ = os.MkdirAll(filepath.Dir(path), 0o755)
		_ = os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), 0o600)
	}
	return k
}

// makeCSR builds a CSR for the given domains and returns it plus the key PEM.
func makeCSR(domains []string) ([]byte, []byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	tmpl := &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: domains[0]},
		DNSNames: domains,
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	if err != nil {
		return nil, nil, err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return csrDER, keyPEM, nil
}

// ForceIssue is used by the API to trigger an immediate issuance.
func (m *Manager) ForceIssue(ctx context.Context) error {
	return m.Issue(ctx)
}
