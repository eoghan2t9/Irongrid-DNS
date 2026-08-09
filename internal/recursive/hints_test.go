package recursive

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
)

// sampleRootHints mirrors the structure of the real named.root — all 13
// letters with IPv4 + IPv6 addresses, plus junk lines the parser must skip.
// The duplicate A record with an explicit "IN" class exercises the parser's
// class-tolerance branch (and address dedup).
const sampleRootHints = `; authoritative root hints (test sample)
. 3600000 NS A.ROOT-SERVERS.NET.
. 3600000 NS B.ROOT-SERVERS.NET.
. 3600000 NS C.ROOT-SERVERS.NET.
. 3600000 NS D.ROOT-SERVERS.NET.
. 3600000 NS E.ROOT-SERVERS.NET.
. 3600000 NS F.ROOT-SERVERS.NET.
. 3600000 NS G.ROOT-SERVERS.NET.
. 3600000 NS H.ROOT-SERVERS.NET.
. 3600000 NS I.ROOT-SERVERS.NET.
. 3600000 NS J.ROOT-SERVERS.NET.
. 3600000 NS K.ROOT-SERVERS.NET.
. 3600000 NS L.ROOT-SERVERS.NET.
. 3600000 NS M.ROOT-SERVERS.NET.
A.ROOT-SERVERS.NET. 3600000 A 198.41.0.4
A.ROOT-SERVERS.NET. 3600000 AAAA 2001:503:ba3e::2:30
B.ROOT-SERVERS.NET. 3600000 A 170.247.170.2
B.ROOT-SERVERS.NET. 3600000 AAAA 2801:1b8:10::b
C.ROOT-SERVERS.NET. 3600000 A 192.33.4.12
C.ROOT-SERVERS.NET. 3600000 AAAA 2001:500:2::c
D.ROOT-SERVERS.NET. 3600000 A 199.7.91.13
D.ROOT-SERVERS.NET. 3600000 AAAA 2001:500:2d::d
E.ROOT-SERVERS.NET. 3600000 A 192.203.230.10
E.ROOT-SERVERS.NET. 3600000 AAAA 2001:500:a8::e
F.ROOT-SERVERS.NET. 3600000 A 192.5.5.241
F.ROOT-SERVERS.NET. 3600000 AAAA 2001:500:2f::f
G.ROOT-SERVERS.NET. 3600000 A 192.112.36.4
G.ROOT-SERVERS.NET. 3600000 AAAA 2001:500:12::d0d
H.ROOT-SERVERS.NET. 3600000 A 198.97.190.53
H.ROOT-SERVERS.NET. 3600000 AAAA 2001:500:1::53
I.ROOT-SERVERS.NET. 3600000 A 192.36.148.17
I.ROOT-SERVERS.NET. 3600000 AAAA 2001:7fe::53
J.ROOT-SERVERS.NET. 3600000 A 192.58.128.30
J.ROOT-SERVERS.NET. 3600000 AAAA 2001:503:c27::2:30
K.ROOT-SERVERS.NET. 3600000 A 193.0.14.129
K.ROOT-SERVERS.NET. 3600000 AAAA 2001:7fd::1
L.ROOT-SERVERS.NET. 3600000 A 199.7.83.42
L.ROOT-SERVERS.NET. 3600000 AAAA 2001:500:9f::42
M.ROOT-SERVERS.NET. 3600000 A 202.12.27.33
M.ROOT-SERVERS.NET. 3600000 AAAA 2001:dc3::35
A.ROOT-SERVERS.NET. 3600000 IN A 198.41.0.4
bad.root-servers.net. 3600000 A not-an-ip
extra.invalid. 3600000 TXT "ignored"
`

func TestParseRootHints(t *testing.T) {
	hints, err := ParseRootHints([]byte(sampleRootHints))
	if err != nil {
		t.Fatalf("ParseRootHints: %v", err)
	}
	if len(hints) != 26 {
		t.Fatalf("hints = %d, want 26", len(hints))
	}
	// IPv4 first across the whole list, letter order preserved, then IPv6 —
	// the same convention as DefaultRootHints.
	if hints[0] != "198.41.0.4:53" {
		t.Fatalf("hints[0] = %q, want 198.41.0.4:53", hints[0])
	}
	if hints[12] != "202.12.27.33:53" {
		t.Fatalf("hints[12] = %q, want 202.12.27.33:53", hints[12])
	}
	if hints[13] != "[2001:503:ba3e::2:30]:53" {
		t.Fatalf("hints[13] = %q, want [2001:503:ba3e::2:30]:53", hints[13])
	}
	if hints[25] != "[2001:dc3::35]:53" {
		t.Fatalf("hints[25] = %q, want [2001:dc3::35]:53", hints[25])
	}
}

func TestParseRootHintsRejectsMangled(t *testing.T) {
	var nsOnly, v6Only strings.Builder
	for _, l := range "abcdefghijklm" {
		name := fmt.Sprintf("%c.ROOT-SERVERS.NET.", l)
		fmt.Fprintf(&nsOnly, ". 3600000 NS %s\n", name)
		fmt.Fprintf(&v6Only, ". 3600000 NS %s\n%s. 3600000 AAAA 2001:db8::%d\n", name, name, int(l-'a')+1)
	}
	cases := map[string]string{
		"empty":        "",
		"too few NS":   ". 3600000 NS A.ROOT-SERVERS.NET.\nA.ROOT-SERVERS.NET. 3600000 A 198.41.0.4\n",
		"no addresses": nsOnly.String(),
		"no IPv4":      v6Only.String(),
	}
	for name, data := range cases {
		if _, err := ParseRootHints([]byte(data)); err == nil {
			t.Fatalf("%s: expected an error", name)
		}
	}
}

// testSigningEntity returns a package-shared test keypair (generated once —
// RSA keygen is slow) used to sign served hints in the PGP-path tests.
var (
	testEntityOnce sync.Once
	testEntity     *openpgp.Entity
)

func testSigningEntity(t *testing.T) *openpgp.Entity {
	t.Helper()
	testEntityOnce.Do(func() {
		e, err := openpgp.NewEntity("Test", "", "test@example.com", nil)
		if err != nil {
			t.Fatalf("NewEntity: %v", err)
		}
		testEntity = e
	})
	return testEntity
}

// signedHintsServer serves sampleRootHints and its detached signature
// (signed once with the test key) on url and url+".sig", mirroring
// internic.net.
func signedHintsServer(t *testing.T, entity *openpgp.Entity) *httptest.Server {
	t.Helper()
	var sig bytes.Buffer
	if err := openpgp.DetachSign(&sig, entity, bytes.NewReader([]byte(sampleRootHints)), nil); err != nil {
		t.Fatalf("sign: %v", err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, ".sig") {
			_, _ = w.Write(sig.Bytes())
			return
		}
		_, _ = w.Write([]byte(sampleRootHints))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestLoadRootHints(t *testing.T) {
	acceptAll := func(sig, signed []byte) error { return nil }
	srv := signedHintsServer(t, testSigningEntity(t))
	dir := t.TempDir()
	cachePath := filepath.Join(dir, "root-hints.txt")

	// Live fetch (signature accepted) wins and persists the cache.
	hints, source, verified, _ := loadRootHints(context.Background(), srv.URL, cachePath, acceptAll)
	if source != "live" {
		t.Fatalf("source = %q, want live", source)
	}
	if !verified {
		t.Fatal("expected verified = true for a live fetch")
	}
	if len(hints) != 26 {
		t.Fatalf("hints = %d, want 26", len(hints))
	}
	raw, err := os.ReadFile(cachePath)
	if err != nil {
		t.Fatalf("live fetch should persist the cache: %v", err)
	}
	if string(raw) != sampleRootHints {
		t.Fatal("cache content does not match the fetched named.root")
	}

	// Signature rejected -> the fetched content is NOT trusted; the
	// last-known-good cache is used instead.
	_, source, verified, _ = loadRootHints(context.Background(), srv.URL, cachePath,
		func(sig, signed []byte) error { return errors.New("bad signature") })
	if source != "cached" {
		t.Fatalf("source = %q, want cached", source)
	}
	if verified {
		t.Fatal("cached hints must not be marked verified")
	}

	// Fetch dead and no cache -> bundled fallback.
	srv.Close()
	hints, source, verified, _ = loadRootHints(context.Background(), srv.URL, filepath.Join(dir, "missing.txt"), acceptAll)
	if source != "bundled" {
		t.Fatalf("source = %q, want bundled", source)
	}
	if verified {
		t.Fatal("bundled hints must not be marked verified")
	}
	if !reflect.DeepEqual(hints, DefaultRootHints) {
		t.Fatal("bundled fallback should equal DefaultRootHints")
	}
}

func TestVerifyRootHintsFlow(t *testing.T) {
	entity := testSigningEntity(t)
	keyring := openpgp.EntityList{entity}
	verify := func(sig, signed []byte) error {
		_, err := openpgp.CheckDetachedSignature(keyring, bytes.NewReader(signed), bytes.NewReader(sig), nil)
		return err
	}

	srv := signedHintsServer(t, entity)
	dir := t.TempDir()
	hints, source, verified, _ := loadRootHints(context.Background(), srv.URL, filepath.Join(dir, "rh.txt"), verify)
	if source != "live" || !verified || len(hints) != 26 {
		t.Fatalf("expected live + verified, got source=%s verified=%v hints=%d", source, verified, len(hints))
	}

	// A tampered body must fail signature verification and never be used.
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, ".sig") {
			var sig bytes.Buffer
			_ = openpgp.DetachSign(&sig, entity, bytes.NewReader([]byte(sampleRootHints)), nil)
			_, _ = w.Write(sig.Bytes())
			return
		}
		_, _ = w.Write([]byte("; tampered\n. 3600000 NS A.ROOT-SERVERS.NET.\n"))
	}))
	defer bad.Close()
	_, source, verified, _ = loadRootHints(context.Background(), bad.URL, filepath.Join(t.TempDir(), "none.txt"), verify)
	if source != "bundled" || verified {
		t.Fatalf("tampered fetch must not be trusted: source=%s verified=%v", source, verified)
	}
}

// TestRootHintsEmbeddedKey pins the embedded Verisign key: it must parse,
// carry the documented fingerprint, and be what VerifyRootHints uses.
func TestRootHintsEmbeddedKey(t *testing.T) {
	keyring, err := openpgp.ReadArmoredKeyRing(strings.NewReader(RootHintsKey))
	if err != nil {
		t.Fatalf("embedded key does not parse: %v", err)
	}
	if len(keyring) != 1 {
		t.Fatalf("keyring entities = %d, want 1", len(keyring))
	}
	if fp := fmt.Sprintf("%X", keyring[0].PrimaryKey.Fingerprint); fp != RootHintsKeyFP {
		t.Fatalf("embedded key fingerprint = %s, want %s", fp, RootHintsKeyFP)
	}
	if rootHintsKeyring == nil {
		t.Fatal("rootHintsKeyring failed to load at init despite a valid key")
	}

	// A signature from any other key must be rejected.
	other, err := openpgp.NewEntity("Other", "", "other@example.com", nil)
	if err != nil {
		t.Fatalf("NewEntity: %v", err)
	}
	var sig bytes.Buffer
	if err := openpgp.DetachSign(&sig, other, bytes.NewReader([]byte("data")), nil); err != nil {
		t.Fatalf("DetachSign: %v", err)
	}
	if err := VerifyRootHints(sig.Bytes(), []byte("data")); err == nil {
		t.Fatal("VerifyRootHints accepted a signature from a non-embedded key")
	}
}

func TestHintsManager(t *testing.T) {
	entity := testSigningEntity(t)
	keyring := openpgp.EntityList{entity}
	srv := signedHintsServer(t, entity)
	dir := t.TempDir()
	cachePath := filepath.Join(dir, "root-hints.txt")

	verify := func(sig, signed []byte) error {
		_, err := openpgp.CheckDetachedSignature(keyring, bytes.NewReader(signed), bytes.NewReader(sig), nil)
		return err
	}
	m := &HintsManager{url: srv.URL, cachePath: cachePath, interval: time.Hour, verify: verify}
	m.Refresh(context.Background())
	st := m.Status()
	if st.Source != "live" || !st.Verified || st.Addresses != 26 || st.LastFetch == nil || st.LastError != "" {
		t.Fatalf("live status wrong: %+v", st)
	}
	if st.RefreshInterval != "1h" {
		t.Fatalf("refresh interval = %q, want 1h", st.RefreshInterval)
	}
	if st.KeyFingerprint != RootHintsKeyFP {
		t.Fatalf("status fingerprint = %q", st.KeyFingerprint)
	}
	// Refresh applies the process-wide default for future resolvers.
	defer SetDefaultRootHints(nil)
	if got := defaultHints(); len(got) != 26 {
		t.Fatalf("default hints not applied, len=%d", len(got))
	}

	// A manager whose signature check fails falls back to the cache.
	m2 := &HintsManager{url: srv.URL, cachePath: cachePath, interval: time.Hour,
		verify: func(sig, signed []byte) error { return errors.New("rejected") }}
	m2.Refresh(context.Background())
	st2 := m2.Status()
	if st2.Source != "cached" || st2.Verified || st2.LastError == "" {
		t.Fatalf("cached status wrong: %+v", st2)
	}
}

func TestHintsManagerStart(t *testing.T) {
	var calls atomic.Int32
	srv := signedHintsServer(t, testSigningEntity(t))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	m := &HintsManager{url: srv.URL, cachePath: "", interval: 30 * time.Millisecond,
		verify: func(sig, signed []byte) error { calls.Add(1); return nil }}
	m.Start(ctx)
	// Poll rather than sleep so a slow CI machine can't starve the ticker
	// into a false failure.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) && calls.Load() < 2 {
		time.Sleep(10 * time.Millisecond)
	}
	if n := calls.Load(); n < 2 {
		t.Fatalf("refresh ticks = %d, want >= 2", n)
	}
}

func TestSetDefaultRootHints(t *testing.T) {
	defer SetDefaultRootHints(nil) // restore the bundled list for other tests

	if got := defaultHints(); !reflect.DeepEqual(got, DefaultRootHints) {
		t.Fatalf("default hints = %v, want bundled", got)
	}

	want := []string{"198.51.100.1:53", "[2001:db8::1]:53"}
	SetDefaultRootHints(want)
	if got := defaultHints(); !reflect.DeepEqual(got, want) {
		t.Fatalf("default hints = %v, want %v", got, want)
	}

	// A fresh resolver snapshots the current default.
	if r := New(nil); !reflect.DeepEqual(r.rootHints, want) {
		t.Fatalf("New(nil) rootHints = %v, want %v", r.rootHints, want)
	}
	// Explicit hints still win over the default.
	if r := New([]string{"9.9.9.9:53"}); len(r.rootHints) != 1 || r.rootHints[0] != "9.9.9.9:53" {
		t.Fatalf("explicit hints not honored: %v", r.rootHints)
	}
}
