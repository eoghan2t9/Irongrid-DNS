package recursive

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	neturl "net/url"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
)

// RootHintsURL is the authoritative root-server hints file published by
// IANA/Verisign — the canonical source DefaultRootHints is a snapshot of.
const RootHintsURL = "https://www.internic.net/domain/named.root"

// DefaultRefreshInterval is how often the authoritative root hints are
// re-fetched while the server runs. Root-server addresses change every few
// years at most, so a weekly check keeps the resolver current without
// putting any real load on internic.net.
const DefaultRefreshInterval = 7 * 24 * time.Hour

// hintFetchTimeout bounds each fetch so boot never blocks for long on an
// unreachable internic.net; the bundled hints are always the fallback.
const hintFetchTimeout = 10 * time.Second

// minRootServers is the smallest number of root NS records ParseRootHints
// will accept. A valid named.root always names all 13 letters; requiring
// them catches a truncated or mangled download before it can replace the
// bundled hints with something unusable.
const minRootServers = 13

// RootHintsKeyFP is the fingerprint of RootHintsKey, the Verisign
// "Registry Administrator" (nstld@verisign-grs.com) key that signs
// named.root. It is asserted when the key is loaded so a corrupted or
// swapped constant fails loudly instead of silently disabling signature
// checks.
const RootHintsKeyFP = "F0CB1A326BDF3F3EFA3A01FA937BB869E3A238C5"

// RootHintsKeyID is the low 64 bits of that fingerprint (the OpenPGP key
// ID), asserted on every verified signature so a keyring can never accept
// signatures from anything but the embedded key.
const RootHintsKeyID = "937BB869E3A238C5"

// RootHintsKey is the ASCII-armored public key used to verify named.root's
// detached PGP signature (published alongside the file at
// https://www.internic.net/domain/named.root.sig).
const RootHintsKey = `-----BEGIN PGP PUBLIC KEY BLOCK-----

mQGiBFafqDIRBACHHOCeRBfQePebenPDNbMyI65Jv2v7a+hcw99EkYsdnlx7+HM2
vEsmGxqPLGBwxwUGUtpjGH4389OtKSyjhVVM0xmXZDoisEnqPPYdfIlYK6LzbcDF
us9guMK3F9X0E4orOcs1f2eKnEvzujAgWgN2SdktFjRm4r/I26nQOFjc3wCg2ny2
ohDoWphSw/9hFK/nxM/gChcD/jAAkH/9vc48ePBVQaTxIaZEBa6qu5TQK9vknPJn
GrRIQAnnhL3Zlf8/FAc5LLs6r33NXJsV/exDiVRisE8y7wT5eoUAwQkm7GUuSx1d
9u9hCrF7BHhykH7hpvRes5DviCO6E0qoCWR59TKoEeglqTY5DA5u5Qzhcr6VZy64
iodGA/49sZnCbQP2lTa/3IwnDTGdNnsn+kaCfLqaVMEfkmfc2MyFVgeMxfdTJoMf
FgT5p2hazhYquJOfnkg5kXkoOsPf89OwkJ8bdkRC4pB4rekMWma/IEs9rfqup2hH
ByvlqRWIsLcFnqLRzT/jrl3SRBYeI2gQqggKnw59jJmyK4KJ6rQvUmVnaXN0cnkg
QWRtaW5pc3RyYXRvciA8bnN0bGRAdmVyaXNpZ24tZ3JzLmNvbT6IYAQTEQIAIAIb
AwYLCQgHAwIEFQIIAwQWAgMBAh4BAheABQJi/UgIAAoJEJN7uGnjojjFHlkAoL7v
FlB2s5WzI6WDXYZn0lUtR04PAJ0YLostb/cnxd315zTMaCIPM6qR8YhgBBMRAgAg
AhsDBgsJCAcDAgQVAggDBBYCAwECHgECF4AFAmL9QzsACgkQk3u4aeOiOMWqagCg
gmQOps/OhDQh2hN/D8xexmqaOTcAn2sMMTNBOG9yIW/vRDMjpzwcZqS+iGYEExEC
ACYCGwMGCwkIBwMCBBUCCAMEFgIDAQIeAQIXgAUCYpdmaAUJEAFWNgAKCRCTe7hp
46I4xR22AJsF5MlveDyojK6PpktE6aJqq5OKuwCdHrjdap/SKu5nyS+t0zTFVUuJ
E8qIZgQTEQIAJgIbAwYLCQgHAwIEFQIIAwQWAgMBAh4BAheABQJe3lMjBQkMQvzx
AAoJEJN7uGnjojjF+C8An36ZFLJEv1+Isg12aWXjX6DFksNfAJ9RiSp4SwMN4xmE
1azYOyApY6JUlIhmBBMRAgAmAhsDBgsJCAcDAgQVAggDBBYCAwECHgECF4AFAltg
au0FCQiDKbsACgkQk3u4aeOiOMXcogCgwMo2V3wWKeZjxsOqP0oq7gcdFIsAoNUo
hJ9XmL/UIzK1TQFlWUi6h28ziGYEExECACYCGwMGCwkIBwMCBBUCCAMEFgIDAQIe
AQIXgAUCWr6XwwUJBQw9kQAKCRCTe7hp46I4xQbrAJ9tIP9TCU8+nALa7Lmb1Wzc
LnjUnwCfeAp9stkJeizdh9cFPi/f+mlBoUSIZgQTEQIAJgUCVp+oMgIbAwUJBB6w
AAYLCQgHAwIEFQIIAwQWAgMBAh4BAheAAAoJEJN7uGnjojjF0S0AnArmleQRcXSy
mG0ObfIQZXqtRtfrAKCWQhSrUgsff64h7X9uvSkD/E1mrg==
=2blL
-----END PGP PUBLIC KEY BLOCK-----`

// rootHintsKeyring is RootHintsKey parsed once at startup; nil when the
// embedded constant is corrupt (verification then fails with a clear error
// instead of silently trusting unverified content).
var rootHintsKeyring = parseRootHintsKeyring()

func parseRootHintsKeyring() openpgp.EntityList {
	keyring, err := openpgp.ReadArmoredKeyRing(strings.NewReader(RootHintsKey))
	// Exactly one entity: the embedded constant must hold only the trusted
	// key, never a second key that could widen the trust set.
	if err != nil || len(keyring) != 1 {
		return nil
	}
	if fp := fmt.Sprintf("%X", keyring[0].PrimaryKey.Fingerprint); fp != RootHintsKeyFP {
		return nil
	}
	return keyring
}

// VerifyRootHints verifies a detached PGP signature (sig) over signed with
// the embedded Verisign key that signs the authoritative named.root file.
// The live fetch is gated on this check: unverified content is never
// trusted, even over HTTPS.
func VerifyRootHints(sig, signed []byte) error {
	if rootHintsKeyring == nil {
		return fmt.Errorf("embedded root hints verification key is corrupt (fingerprint %s)", RootHintsKeyFP)
	}
	entity, err := openpgp.CheckDetachedSignature(rootHintsKeyring, bytes.NewReader(signed), bytes.NewReader(sig), nil)
	if err != nil {
		return err
	}
	// Defense in depth: the keyring holds exactly the embedded key, but
	// insist the signing key matches it anyway.
	if id := fmt.Sprintf("%X", entity.PrimaryKey.KeyId); id != RootHintsKeyID {
		return fmt.Errorf("signature from unexpected key %s (want %s)", id, RootHintsKeyID)
	}
	return nil
}

// ParseRootHints parses IANA's named.root zone-file format into dial-ready
// "ip:port" hints: NS records owned by the root zone name the letters, and
// the A/AAAA records for those names supply the addresses. IPv4 addresses
// come first across the whole list (a host without IPv6 connectivity never
// pays a failed dial before reaching a working address), matching
// DefaultRootHints' ordering convention. Comments, blank lines and
// unparseable records are skipped; a file that doesn't plausibly describe
// the root (too few letters, no usable addresses, no IPv4) is rejected.
func ParseRootHints(data []byte) ([]string, error) {
	names := map[string]bool{}  // root nameserver hostnames, lowercased
	v4 := map[string][]string{} // hostname -> validated IPv4 addresses
	v6 := map[string][]string{} // hostname -> validated IPv6 addresses

	for line := range strings.SplitSeq(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, ";") {
			continue
		}
		f := strings.Fields(line)
		if len(f) < 4 {
			continue
		}
		// named.root omits the class ("IN"); tolerate it if a variant
		// includes it by shifting the type/rdata positions.
		typIdx, valIdx := 2, 3
		if strings.ToUpper(f[2]) == "IN" && len(f) >= 5 {
			typIdx, valIdx = 3, 4
		}
		owner := strings.ToLower(strings.TrimSuffix(f[0], "."))
		typ := strings.ToUpper(f[typIdx])
		val := f[valIdx]
		switch typ {
		case "NS":
			if owner == "" {
				names[strings.ToLower(strings.TrimSuffix(val, "."))] = true
			}
		case "A":
			if ip := net.ParseIP(val); ip != nil && ip.To4() != nil {
				v4[owner] = append(v4[owner], val)
			}
		case "AAAA":
			if ip := net.ParseIP(val); ip != nil && ip.To4() == nil {
				v6[owner] = append(v6[owner], val)
			}
		}
	}
	if len(names) < minRootServers {
		return nil, fmt.Errorf("root hints: expected at least %d root nameservers, found %d", minRootServers, len(names))
	}
	sorted := make([]string, 0, len(names))
	for n := range names {
		sorted = append(sorted, n)
	}
	sort.Strings(sorted)

	var out []string
	seen := map[string]bool{}
	for _, name := range sorted {
		for _, ip := range v4[name] {
			if a := net.JoinHostPort(ip, "53"); !seen[a] {
				seen[a] = true
				out = append(out, a)
			}
		}
	}
	for _, name := range sorted {
		for _, ip := range v6[name] {
			if a := net.JoinHostPort(ip, "53"); !seen[a] {
				seen[a] = true
				out = append(out, a)
			}
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("root hints: no server addresses found")
	}
	// A valid named.root carries IPv4 for every letter; refusing an
	// IPv6-only result keeps IPv4-only hosts from starting every walk on
	// unreachable addresses.
	if !hasIPv4(out) {
		return nil, fmt.Errorf("root hints: no IPv4 addresses found")
	}
	return out, nil
}

func hasIPv4(addrs []string) bool {
	for _, a := range addrs {
		host, _, err := net.SplitHostPort(a)
		if err == nil && net.ParseIP(host).To4() != nil {
			return true
		}
	}
	return false
}

// fetchRootHints downloads url and its detached PGP signature (url + ".sig").
func fetchRootHints(ctx context.Context, url string) (data, sig []byte, err error) {
	get := func(u string) ([]byte, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("User-Agent", "Irongrid-DNS/0.1 (+https://github.com/eoghan2t9/Irongrid-DNS)")
		client := &http.Client{Timeout: hintFetchTimeout}
		resp, err := client.Do(req)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
		}
		// 64 KiB cap; named.root is ~2 KiB and its signature ~100 bytes.
		return io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	}
	data, err = get(url)
	if err != nil {
		return nil, nil, err
	}
	sig, err = get(sigURLFor(url))
	if err != nil {
		return nil, nil, err
	}
	return data, sig, nil
}

// sigURLFor returns the URL of the detached PGP signature accompanying a
// named.root-style file. Appending ".sig" to the raw URL is only correct
// when the URL already has a path (https://host/domain/named.root); a bare
// host:port (as tests use) would mangle into "host:port.sig" and fail to
// parse, so the suffix is attached to the path instead.
func sigURLFor(u string) string {
	parsed, err := neturl.Parse(u)
	if err != nil || parsed.Path == "" || parsed.Path == "/" {
		return strings.TrimRight(u, "/") + "/named.root.sig"
	}
	parsed.Path += ".sig"
	return parsed.String()
}

// loadRootHints returns the best available root hints and where they came
// from. A live fetch of url is only trusted when its PGP signature checks
// out (via verify); a verified fetch is persisted to cachePath for the next
// offline start. When live fails, the last-known-good cache copy is used,
// then the bundled DefaultRootHints — so a recursive setup works even fully
// offline. reason explains any non-live outcome for the status line. Never
// returns an error: the bundled list always wins as a last resort.
func loadRootHints(ctx context.Context, url, cachePath string, verify func(sig, signed []byte) error) (hints []string, source string, verified bool, reason string) {
	liveFail := ""
	if data, sig, err := fetchRootHints(ctx, url); err != nil {
		liveFail = "fetch failed: " + err.Error()
	} else if err := verify(sig, data); err != nil {
		liveFail = "PGP signature verification failed: " + err.Error()
	} else if hints, err := ParseRootHints(data); err != nil {
		liveFail = "parse failed: " + err.Error()
	} else {
		if cachePath != "" {
			if err := os.MkdirAll(filepath.Dir(cachePath), 0o755); err == nil {
				// Only verified content is ever persisted, so the cache
				// stays trustworthy by construction.
				_ = os.WriteFile(cachePath, data, 0o600)
			}
		}
		return hints, "live", true, ""
	}

	if cachePath != "" {
		if raw, err := os.ReadFile(cachePath); err == nil {
			if hints, err := ParseRootHints(raw); err == nil {
				return hints, "cached", false, "live: " + liveFail
			}
		}
	}
	return DefaultRootHints, "bundled", false, "live: " + liveFail + "; cache: no usable copy"
}

// HintsManager owns the authoritative root-hints lifecycle: the startup
// fetch, periodic refresh, last-known-good disk cache, PGP verification and
// the status snapshot the dashboard shows.
type HintsManager struct {
	url       string
	cachePath string
	interval  time.Duration
	verify    func(sig, signed []byte) error

	mu        sync.Mutex
	source    string
	verified  bool
	lastFetch *time.Time
	lastError string
	addresses int
}

// NewHintsManager creates a manager that keeps the resolver's root hints
// current from url, caching last-known-good content at cachePath. A zero
// interval falls back to DefaultRefreshInterval.
func NewHintsManager(url, cachePath string, interval time.Duration) *HintsManager {
	if url == "" {
		url = RootHintsURL
	}
	if interval <= 0 {
		interval = DefaultRefreshInterval
	}
	return &HintsManager{url: url, cachePath: cachePath, interval: interval, verify: VerifyRootHints}
}

// Refresh runs one fetch -> verify -> parse -> persist -> apply cycle and
// records the outcome for Status. Safe for concurrent use. The caller
// usually runs the first Refresh synchronously at boot — before upstreams
// are parsed, since each resolver snapshots the default hints at
// construction — and Start for the rest.
func (m *HintsManager) Refresh(ctx context.Context) {
	hints, source, verified, reason := loadRootHints(ctx, m.url, m.cachePath, m.verify)
	SetDefaultRootHints(hints)

	m.mu.Lock()
	defer m.mu.Unlock()
	m.source = source
	m.verified = verified
	m.addresses = len(hints)
	m.lastError = ""
	switch source {
	case "live":
		now := time.Now()
		m.lastFetch = &now
	case "cached":
		m.lastError = reason
		if fi, err := os.Stat(m.cachePath); err == nil {
			t := fi.ModTime()
			m.lastFetch = &t
		}
	default: // bundled
		m.lastError = reason
	}
}

// Start refreshes the hints every interval until ctx is done. The initial
// Refresh is the caller's job (it must complete before upstreams are parsed
// at boot).
func (m *HintsManager) Start(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(m.interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				m.Refresh(ctx)
			}
		}
	}()
}

// HintsStatus is the snapshot GET /api/status exposes for the dashboard.
type HintsStatus struct {
	Source          string     `json:"source"`
	Verified        bool       `json:"verified"`
	LastFetch       *time.Time `json:"last_fetch"`
	LastError       string     `json:"last_error"`
	Addresses       int        `json:"addresses"`
	RefreshInterval string     `json:"refresh_interval"`
	KeyFingerprint  string     `json:"key_fingerprint"`
}

// Status returns a snapshot of the last refresh outcome.
func (m *HintsManager) Status() HintsStatus {
	m.mu.Lock()
	defer m.mu.Unlock()
	return HintsStatus{
		Source:          m.source,
		Verified:        m.verified,
		LastFetch:       m.lastFetch,
		LastError:       m.lastError,
		Addresses:       m.addresses,
		RefreshInterval: durationString(m.interval),
		KeyFingerprint:  RootHintsKeyFP,
	}
}

// durationString renders a duration the way the rest of the dashboard does:
// whole hours as "168h" rather than Go's verbose default.
func durationString(d time.Duration) string {
	if d%time.Hour == 0 {
		return fmt.Sprintf("%dh", int64(d/time.Hour))
	}
	return d.String()
}

// defaultHintsMu guards activeDefaultHints, the process-wide root hints that
// New seeds resolvers with. SetDefaultRootHints swaps it after a successful
// named.root fetch; New snapshots it per resolver so each instance keeps a
// stable hint set for its lifetime.
var (
	defaultHintsMu     sync.RWMutex
	activeDefaultHints = DefaultRootHints
)

// SetDefaultRootHints replaces the root hints future recursive resolvers
// start their walks from — called by HintsManager.Refresh after a verified
// fetch, so every recursive upstream (global and per-client-group alike,
// plus any created by a later config reload) uses fresh root addresses
// without per-upstream wiring. A nil/empty slice restores the bundled
// DefaultRootHints.
func SetDefaultRootHints(hints []string) {
	if len(hints) == 0 {
		hints = DefaultRootHints
	}
	// Copy: the process-wide default outlives the caller, so a later
	// mutation of its slice must not silently change every future resolver.
	hints = slices.Clone(hints)
	defaultHintsMu.Lock()
	activeDefaultHints = hints
	defaultHintsMu.Unlock()
}

// defaultHints returns the current process-wide root hints.
func defaultHints() []string {
	defaultHintsMu.RLock()
	defer defaultHintsMu.RUnlock()
	return activeDefaultHints
}
