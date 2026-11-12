package acme

import (
	"context"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// The worked example from RFC 9773 Appendix A: a certificate with this
// Authority Key Identifier and serial 0x00 87 65 43 21 has this certID.
func TestARICertIDMatchesRFCVector(t *testing.T) {
	aki, _ := hex.DecodeString("69885B6B87464041E1B37B847BA0AE2CDE01C8D4")
	leaf := &x509.Certificate{
		AuthorityKeyId: aki,
		SerialNumber:   new(big.Int).SetBytes([]byte{0x87, 0x65, 0x43, 0x21}),
	}
	got, err := ariCertID(leaf)
	if err != nil {
		t.Fatal(err)
	}
	if want := "aYhba4dGQEHhs3uEe6CuLN4ByNQ.AIdlQyE"; got != want {
		t.Fatalf("certID = %q, want %q", got, want)
	}
	// A serial whose top bit is clear needs no padding octet.
	leaf.SerialNumber = big.NewInt(0x7f)
	got, _ = ariCertID(leaf)
	if !strings.HasSuffix(got, ".fw") { // base64url of 0x7f
		t.Errorf("certID = %q, want serial part \"fw\"", got)
	}
}

func TestARICertIDRequiresAKIAndSerial(t *testing.T) {
	if _, err := ariCertID(&x509.Certificate{SerialNumber: big.NewInt(5)}); err == nil {
		t.Error("missing AKI must be an error")
	}
	if _, err := ariCertID(&x509.Certificate{AuthorityKeyId: []byte{1}}); err == nil {
		t.Error("missing serial must be an error")
	}
}

func TestARIShouldRenew(t *testing.T) {
	now := time.Date(2026, 12, 1, 12, 0, 0, 0, time.UTC)
	day := 24 * time.Hour
	mk := func(start, end time.Duration) *ariInfo {
		return &ariInfo{Start: now.Add(start), End: now.Add(end)}
	}
	check := func(name string, a *ariInfo, pick float64, want bool) {
		t.Helper()
		if got := a.shouldRenew(now, 6*time.Hour, pick); got != want {
			t.Errorf("%s: got %v, want %v", name, got, want)
		}
	}
	check("window already over", mk(-3*day, -day), 0.9, true)
	check("inside window, early pick", mk(-day, day), 0.1, true)
	check("inside window, late pick", mk(-day, 5*day), 0.9, false) // wait for a later check
	check("window opens in 2 days", mk(2*day, 4*day), 0, false)
	check("window opens within the check interval", mk(2*time.Hour, 3*day), 0, true)
}

// ariServer fakes a CA directory that offers renewalInfo and answers for the
// certificate identified by wantID.
type ariServer struct {
	*httptest.Server
	hits   atomic.Int32
	start  time.Time
	end    time.Time
	status int
	retry  string
}

func newARIServer(t *testing.T, wantID *string) *ariServer {
	t.Helper()
	s := &ariServer{status: http.StatusOK}
	mux := http.NewServeMux()
	mux.HandleFunc("/dir", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `{"renewalInfo":%q}`, s.URL+"/renewal")
	})
	mux.HandleFunc("/renewal/", func(w http.ResponseWriter, r *http.Request) {
		s.hits.Add(1)
		if got := strings.TrimPrefix(r.URL.Path, "/renewal/"); got != *wantID {
			http.Error(w, "unknown certificate "+got, http.StatusNotFound)
			return
		}
		if s.status != http.StatusOK {
			http.Error(w, "boom", s.status)
			return
		}
		if s.retry != "" {
			w.Header().Set("Retry-After", s.retry)
		}
		fmt.Fprintf(w, `{"suggestedWindow":{"start":%q,"end":%q},"explanationURL":"https://ca.example/why"}`,
			s.start.UTC().Format(time.RFC3339), s.end.UTC().Format(time.RFC3339))
	})
	s.Server = httptest.NewServer(mux)
	t.Cleanup(s.Close)
	return s
}

// A manager whose on-disk certificate is healthy by the day-count rule (90
// days, 30-day window), pointed at the fake CA.
func ariManager(t *testing.T) (*Manager, *ariServer) {
	t.Helper()
	dir := t.TempDir()
	writeCACert(t, dir, []string{"example.com"}, 90)
	m := New(Options{Email: "a@b.c", Domains: []string{"example.com"}, CertDir: dir, RenewBeforeDays: 30})
	leaf, ok := m.leafCert()
	if !ok {
		t.Fatal("test certificate not usable")
	}
	id, err := ariCertID(leaf)
	if err != nil {
		t.Fatal(err)
	}
	srv := newARIServer(t, &id)
	m.dirOverride = srv.URL + "/dir"
	m.httpc = srv.Client()
	return m, srv
}

func TestARIRenewsWhenCAAsksForItEarly(t *testing.T) {
	m, srv := ariManager(t)
	if m.NeedsRenewal() {
		t.Fatal("precondition: day-count rule must say the cert is fine")
	}
	// The CA wants this certificate replaced now (e.g. a revocation event).
	srv.start, srv.end = time.Now().Add(-time.Hour), time.Now().Add(time.Hour)
	if !m.needsRenewalNow(context.Background()) {
		t.Fatal("CA-requested renewal was ignored")
	}
}

func TestARIDoesNotRenewBeforeWindow(t *testing.T) {
	m, srv := ariManager(t)
	srv.start, srv.end = time.Now().Add(40*24*time.Hour), time.Now().Add(42*24*time.Hour)
	if m.needsRenewalNow(context.Background()) {
		t.Fatal("renewed before the CA's window opened")
	}
}

// ARI must never be able to block or trigger renewal by failing.
func TestARIFailureIsNoOpinion(t *testing.T) {
	m, srv := ariManager(t)
	srv.status = http.StatusInternalServerError
	if m.ariWantsRenewal(context.Background()) {
		t.Fatal("a failing CA must not trigger renewal")
	}
	// ...and an unreachable one.
	m.dirOverride = "http://127.0.0.1:1/dir"
	if m.ariWantsRenewal(context.Background()) {
		t.Fatal("an unreachable CA must not trigger renewal")
	}
	// The day-count rule is unaffected by any of it.
	if m.NeedsRenewal() {
		t.Fatal("day-count rule changed")
	}
}

func TestARIAbsentFromDirectory(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"newOrder":"x"}`)
	}))
	defer srv.Close()
	m, _ := ariManager(t)
	m.dirOverride = srv.URL
	m.httpc = srv.Client()
	leaf, _ := m.leafCert()
	if _, err := fetchARI(context.Background(), m.httpClient(), m.directoryURL(), leaf); !errors.Is(err, errNoARI) {
		t.Fatalf("err = %v, want errNoARI", err)
	}
	if m.ariWantsRenewal(context.Background()) {
		t.Fatal("no ARI means no opinion")
	}
}

func TestARIHonoursRetryAfter(t *testing.T) {
	m, srv := ariManager(t)
	srv.start, srv.end = time.Now().Add(40*24*time.Hour), time.Now().Add(42*24*time.Hour)
	srv.retry = "3600"
	for range 3 {
		m.ariWantsRenewal(context.Background())
	}
	if n := srv.hits.Load(); n != 1 {
		t.Fatalf("CA queried %d times within its Retry-After, want 1", n)
	}
	// Once the CA's interval has elapsed it is asked again.
	m.mu.Lock()
	m.ari.fetched = time.Now().Add(-2 * time.Hour)
	m.mu.Unlock()
	m.ariWantsRenewal(context.Background())
	if n := srv.hits.Load(); n != 2 {
		t.Fatalf("CA queried %d times after Retry-After elapsed, want 2", n)
	}
}

func TestARIWindowDoesNotOutliveTheCertificate(t *testing.T) {
	m, srv := ariManager(t)
	srv.start, srv.end = time.Now().Add(-time.Hour), time.Now().Add(time.Hour)
	if !m.ariWantsRenewal(context.Background()) {
		t.Fatal("precondition: ARI asks for renewal")
	}
	// A different certificate (new serial) must not inherit that answer.
	m.mu.Lock()
	m.ari.serial = "some-other-serial"
	m.mu.Unlock()
	srv.start, srv.end = time.Now().Add(40*24*time.Hour), time.Now().Add(42*24*time.Hour)
	if m.ariWantsRenewal(context.Background()) {
		t.Fatal("stale answer for a previous certificate was reused")
	}
}

func TestARIEarlierWindowShowsAsNextRenewal(t *testing.T) {
	m, srv := ariManager(t)
	soon := time.Now().Add(48 * time.Hour)
	srv.start, srv.end = soon, soon.Add(24*time.Hour)
	m.ariWantsRenewal(context.Background())
	st := m.GetStatus()
	if st.NextRenewal == nil || st.NextRenewal.Sub(soon).Abs() > time.Second {
		t.Fatalf("NextRenewal = %v, want the CA's window start %v", st.NextRenewal, soon)
	}
	// A window later than our own threshold must not postpone renewal.
	srv.start, srv.end = time.Now().Add(80*24*time.Hour), time.Now().Add(82*24*time.Hour)
	m.mu.Lock()
	m.ari = nil
	m.mu.Unlock()
	m.ariWantsRenewal(context.Background())
	m.syncStatusFromCert()
	st = m.GetStatus()
	own := time.Until(*st.NextRenewal)
	if own < 59*24*time.Hour || own > 61*24*time.Hour {
		t.Fatalf("NextRenewal in %s, want about 60 days (own threshold, ARI must not postpone)", own)
	}
}
