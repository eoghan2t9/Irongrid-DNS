// Package dnssec implements opportunistic local DNSSEC chain-of-trust
// validation for a forwarding resolver: when an upstream response carries
// RRSIG records (because the query advertised the DO bit), this package
// verifies the signature chain up to a trust anchor itself, rather than
// only trusting the upstream's own AD bit. See Validator.Validate's doc
// comment for exactly what "opportunistic" means here (no NSEC/NSEC3
// denial-of-existence proof for provably-insecure delegations).
package dnssec

import (
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// RootAnchorsURL is IANA's published root zone trust anchor file.
const RootAnchorsURL = "https://data.iana.org/root-anchors/root-anchors.xml"

// DefaultAnchorRefreshInterval matches the root-hints manager's cadence —
// root KSK rollovers are rare (the 2017 and 2024/2026-era rollovers are
// each years apart), so weekly is generous, not lax.
const DefaultAnchorRefreshInterval = 7 * 24 * time.Hour

// TrustAnchor is one DS-form root (or other zone) trust anchor: the hash of
// a DNSKEY, not the key material itself — exactly what IANA publishes and
// what a DS record in a parent zone contains.
type TrustAnchor struct {
	Zone       string
	KeyTag     uint16
	Algorithm  uint8
	DigestType uint8
	Digest     string // hex, uppercase
}

// DefaultRootAnchors is the bundled last-resort fallback: the long-standing
// root KSK-2017 (key tag 20326) trust anchor, published by IANA since 2017.
// Root KSK rollovers keep a retiring anchor valid through an extended
// transition specifically so validators using an older bundled copy like
// this one don't break — but this is ONLY the final fallback tier: see
// AnchorManager, which fetches the live, current anchor set from IANA at
// boot and on every refresh, and only falls back to this (or a
// last-known-good disk cache) when that fetch fails.
var DefaultRootAnchors = []TrustAnchor{
	{Zone: ".", KeyTag: 20326, Algorithm: 8, DigestType: 2, Digest: "E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8"},
}

type rootAnchorsXML struct {
	XMLName    xml.Name `xml:"TrustAnchor"`
	KeyDigests []struct {
		KeyTag     uint16 `xml:"KeyTag"`
		Algorithm  uint8  `xml:"Algorithm"`
		DigestType uint8  `xml:"DigestType"`
		Digest     string `xml:"Digest"`
	} `xml:"KeyDigest"`
}

// ParseRootAnchorsXML parses IANA's root-anchors.xml. Every KeyDigest entry
// present is returned (not filtered by its validFrom/validUntil window):
// IANA deliberately lists two anchors during a rollover's overlap period,
// and accepting either is the conservative, correct behavior — it can only
// make validation succeed against a genuinely IANA-published anchor, never
// against a different key.
func ParseRootAnchorsXML(data []byte) ([]TrustAnchor, error) {
	var doc rootAnchorsXML
	if err := xml.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("dnssec: parse root-anchors.xml: %w", err)
	}
	if len(doc.KeyDigests) == 0 {
		return nil, fmt.Errorf("dnssec: root-anchors.xml has no KeyDigest entries")
	}
	anchors := make([]TrustAnchor, 0, len(doc.KeyDigests))
	for _, kd := range doc.KeyDigests {
		anchors = append(anchors, TrustAnchor{
			Zone:       ".",
			KeyTag:     kd.KeyTag,
			Algorithm:  kd.Algorithm,
			DigestType: kd.DigestType,
			Digest:     strings.ToUpper(strings.TrimSpace(kd.Digest)),
		})
	}
	return anchors, nil
}

// AnchorManager owns the root trust-anchor lifecycle: startup fetch,
// periodic refresh, last-known-good disk cache, and a bundled final
// fallback — the same three-tier shape as recursive.HintsManager, minus
// PGP verification (IANA distributes root-anchors.xml with a CMS/PKCS7
// detached signature, not OpenPGP; verifying it would need a new
// dependency this package deliberately avoids). Authenticity here instead
// comes from a validated HTTPS connection to data.iana.org — weaker than a
// detached-signature check, but a real, standard bootstrapping approach,
// and only the initial trust-anchor acquisition depends on it: every
// subsequent step in Validator's chain walk is a real cryptographic
// signature verification.
type AnchorManager struct {
	url       string
	cachePath string
	interval  time.Duration
	client    *http.Client

	mu        sync.Mutex
	anchors   []TrustAnchor
	source    string // "live", "cached", or "bundled"
	lastFetch *time.Time
	lastError string
}

// NewAnchorManager creates a manager that keeps the root trust anchor
// current from url, caching last-known-good content at cachePath. A zero
// url/interval falls back to RootAnchorsURL / DefaultAnchorRefreshInterval.
// The manager starts pre-seeded with DefaultRootAnchors so Anchors() is
// always usable even before the first Refresh completes.
func NewAnchorManager(url, cachePath string, interval time.Duration) *AnchorManager {
	if url == "" {
		url = RootAnchorsURL
	}
	if interval <= 0 {
		interval = DefaultAnchorRefreshInterval
	}
	return &AnchorManager{
		url:       url,
		cachePath: cachePath,
		interval:  interval,
		client:    &http.Client{Timeout: 15 * time.Second},
		anchors:   DefaultRootAnchors,
		source:    "bundled",
	}
}

// Refresh runs one fetch -> parse -> persist -> apply cycle. Safe for
// concurrent use; never blocks other Anchors() callers longer than the
// brief lock needed to swap the result in.
func (m *AnchorManager) Refresh(ctx context.Context) {
	anchors, source, lastErr := m.load(ctx)
	m.mu.Lock()
	defer m.mu.Unlock()
	m.anchors = anchors
	m.source = source
	m.lastError = lastErr
	if source == "live" {
		now := time.Now()
		m.lastFetch = &now
	}
}

func (m *AnchorManager) load(ctx context.Context) (anchors []TrustAnchor, source, lastErr string) {
	if data, err := m.fetch(ctx); err != nil {
		lastErr = "fetch failed: " + err.Error()
	} else if parsed, perr := ParseRootAnchorsXML(data); perr != nil {
		lastErr = "parse failed: " + perr.Error()
	} else {
		if m.cachePath != "" {
			if mkErr := os.MkdirAll(filepath.Dir(m.cachePath), 0o755); mkErr == nil {
				_ = os.WriteFile(m.cachePath, data, 0o600)
			}
		}
		return parsed, "live", ""
	}

	if m.cachePath != "" {
		if raw, err := os.ReadFile(m.cachePath); err == nil {
			if parsed, perr := ParseRootAnchorsXML(raw); perr == nil {
				return parsed, "cached", "live: " + lastErr
			}
		}
	}
	return DefaultRootAnchors, "bundled", "live: " + lastErr + "; cache: no usable copy"
}

func (m *AnchorManager) fetch(ctx context.Context) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, m.url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := m.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status %d", resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // 1MB cap, generous for this file
}

// Start refreshes the anchors every interval until ctx is done. The initial
// Refresh is the caller's job (call it synchronously at boot, like
// HintsManager, before anything depends on Anchors()).
func (m *AnchorManager) Start(ctx context.Context) {
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

// NewAnchorManagerForTest returns an AnchorManager pre-seeded with anchor
// and no live fetch capability (Refresh is a no-op-equivalent here — the
// manager will just report the given anchor forever). For tests that need
// a Validator wired to a specific, known trust anchor without depending on
// network access or a fetchable HTTP endpoint.
func NewAnchorManagerForTest(anchor TrustAnchor) *AnchorManager {
	return &AnchorManager{anchors: []TrustAnchor{anchor}, source: "test"}
}

// Anchors returns the current trust anchor set (a defensive copy).
func (m *AnchorManager) Anchors() []TrustAnchor {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]TrustAnchor, len(m.anchors))
	copy(out, m.anchors)
	return out
}

// AnchorStatus is a snapshot of the last refresh outcome, for the dashboard.
type AnchorStatus struct {
	Source    string     `json:"source"`
	LastFetch *time.Time `json:"last_fetch,omitempty"`
	LastError string     `json:"last_error,omitempty"`
	Count     int        `json:"count"`
}

// Status returns a snapshot of the last refresh outcome.
func (m *AnchorManager) Status() AnchorStatus {
	m.mu.Lock()
	defer m.mu.Unlock()
	return AnchorStatus{Source: m.source, LastFetch: m.lastFetch, LastError: m.lastError, Count: len(m.anchors)}
}
