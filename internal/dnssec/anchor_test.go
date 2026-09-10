package dnssec

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

const sampleRootAnchorsXML = `<?xml version="1.0" encoding="UTF-8"?>
<TrustAnchor id="380DC50D-484E-40D0-A3AE-68F2B18F61C7" source="http://data.iana.org/root-anchors/root-anchors.xml">
  <Zone>.</Zone>
  <KeyDigest id="Kjqmt7v" validFrom="2017-02-02T00:00:00+00:00">
    <KeyTag>20326</KeyTag>
    <Algorithm>8</Algorithm>
    <DigestType>2</DigestType>
    <Digest>E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8</Digest>
  </KeyDigest>
</TrustAnchor>`

func TestParseRootAnchorsXML(t *testing.T) {
	anchors, err := ParseRootAnchorsXML([]byte(sampleRootAnchorsXML))
	if err != nil {
		t.Fatalf("ParseRootAnchorsXML: %v", err)
	}
	if len(anchors) != 1 {
		t.Fatalf("got %d anchors, want 1", len(anchors))
	}
	a := anchors[0]
	if a.Zone != "." || a.KeyTag != 20326 || a.Algorithm != 8 || a.DigestType != 2 {
		t.Errorf("unexpected anchor: %+v", a)
	}
	if a.Digest != "E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8" {
		t.Errorf("unexpected digest: %s", a.Digest)
	}
}

func TestParseRootAnchorsXMLRejectsEmpty(t *testing.T) {
	if _, err := ParseRootAnchorsXML([]byte(`<TrustAnchor><Zone>.</Zone></TrustAnchor>`)); err == nil {
		t.Fatal("expected an error for a TrustAnchor with no KeyDigest entries")
	}
}

func TestParseRootAnchorsXMLRejectsGarbage(t *testing.T) {
	if _, err := ParseRootAnchorsXML([]byte(`not xml at all`)); err == nil {
		t.Fatal("expected an error for non-XML input")
	}
}

func TestAnchorManagerLiveFetch(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(sampleRootAnchorsXML))
	}))
	defer srv.Close()

	dir := t.TempDir()
	m := NewAnchorManager(srv.URL, filepath.Join(dir, "root-anchors.xml"), time.Hour)
	m.Refresh(context.Background())

	st := m.Status()
	if st.Source != "live" {
		t.Fatalf("source = %q, want live (error: %s)", st.Source, st.LastError)
	}
	if st.Count != 1 {
		t.Fatalf("count = %d, want 1", st.Count)
	}
	anchors := m.Anchors()
	if len(anchors) != 1 || anchors[0].KeyTag != 20326 {
		t.Fatalf("unexpected anchors: %+v", anchors)
	}
	if _, err := os.Stat(filepath.Join(dir, "root-anchors.xml")); err != nil {
		t.Errorf("expected the fetched anchors to be cached to disk: %v", err)
	}
}

func TestAnchorManagerFallsBackToCacheOnFetchFailure(t *testing.T) {
	dir := t.TempDir()
	cachePath := filepath.Join(dir, "root-anchors.xml")
	if err := os.WriteFile(cachePath, []byte(sampleRootAnchorsXML), 0o600); err != nil {
		t.Fatalf("seed cache: %v", err)
	}

	// A server that always fails, so the manager must fall back to the
	// pre-seeded disk cache rather than the bundled default.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	m := NewAnchorManager(srv.URL, cachePath, time.Hour)
	m.Refresh(context.Background())

	st := m.Status()
	if st.Source != "cached" {
		t.Fatalf("source = %q, want cached", st.Source)
	}
	if len(m.Anchors()) != 1 {
		t.Fatalf("expected the cached anchor set to be used")
	}
}

func TestAnchorManagerFallsBackToBundledWithNoCacheOrNetwork(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	m := NewAnchorManager(srv.URL, "", time.Hour) // no cache path at all
	m.Refresh(context.Background())

	st := m.Status()
	if st.Source != "bundled" {
		t.Fatalf("source = %q, want bundled", st.Source)
	}
	anchors := m.Anchors()
	if len(anchors) != len(DefaultRootAnchors) || anchors[0].KeyTag != DefaultRootAnchors[0].KeyTag {
		t.Fatalf("expected the bundled default anchors, got %+v", anchors)
	}
}

func TestAnchorManagerPreSeededBeforeFirstRefresh(t *testing.T) {
	m := NewAnchorManager("http://127.0.0.1:0/unused", "", time.Hour)
	// Anchors() must be usable immediately, before any Refresh — a boot
	// sequence that queries before the first Refresh completes must not
	// see an empty anchor set.
	if len(m.Anchors()) == 0 {
		t.Fatal("expected the bundled anchors to be available before the first Refresh")
	}
}
