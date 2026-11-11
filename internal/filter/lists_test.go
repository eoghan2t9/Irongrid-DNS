package filter

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestFetchOneCoalescesConcurrentDownloads verifies overlapping refresh
// triggers (boot FetchAll, the auto-refresh ticker, a manual refresh) don't
// download the same list twice at once.
func TestFetchOneCoalescesConcurrentDownloads(t *testing.T) {
	t.Parallel()
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		time.Sleep(300 * time.Millisecond) // keep the downloads overlapping
		_, _ = w.Write([]byte("example.com\n"))
	}))
	defer srv.Close()

	m := NewListManager(NewEngine(), t.TempDir())
	m.SetSpecs([]ListSpec{{ID: "test", Name: "Test", URL: srv.URL, Enabled: true}})

	const n = 4
	var wg sync.WaitGroup
	for range n {
		wg.Go(func() {
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			if err := m.FetchOne(ctx, "test"); err != nil {
				t.Errorf("FetchOne: %v", err)
			}
		})
	}
	wg.Wait()
	if got := hits.Load(); got != 1 {
		t.Fatalf("list server answered %d downloads, want 1 (concurrent fetches coalesced)", got)
	}
}

func TestValidateFetched(t *testing.T) {
	big := bytes.Repeat([]byte("0.0.0.0 ads.example.com\n"), 1000) // > 10 KiB
	cases := []struct {
		name    string
		content []byte
		prev    []byte
		wantErr bool
	}{
		{"ok", []byte("0.0.0.0 a.example.com\n"), nil, false},
		{"empty", []byte("  \n"), nil, true},
		{"html doctype", []byte("<!DOCTYPE html><html>502</html>"), nil, true},
		{"html tag", []byte("<html><body>err</body></html>"), nil, true},
		{"collapsed", []byte("0.0.0.0 a.example.com\n"), big, true},
		{"similar size ok", big, big, false},
	}
	for _, c := range cases {
		if err := validateFetched(c.content, c.prev); (err != nil) != c.wantErr {
			t.Errorf("%s: err=%v wantErr=%v", c.name, err, c.wantErr)
		}
	}
}

func TestFetchOneKeepsCacheOnBadBody(t *testing.T) {
	good := bytes.Repeat([]byte("0.0.0.0 ads.example.com\n"), 1000)
	body := good
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(body) }))
	defer srv.Close()
	m := NewListManager(NewEngine(), t.TempDir())
	m.SetSpecs([]ListSpec{{ID: "x", Name: "x", URL: srv.URL, Enabled: true}})
	if err := m.FetchOne(context.Background(), "x"); err != nil {
		t.Fatal(err)
	}
	body = []byte("<html>oops</html>")
	if err := m.FetchOne(context.Background(), "x"); err == nil {
		t.Fatal("expected rejection of HTML body")
	}
	if !bytes.Equal(m.GetContent("x"), good) {
		t.Fatal("cached content was overwritten by a bad response")
	}
	onDisk, _ := os.ReadFile(filepath.Join(m.dir, "x.txt"))
	if !bytes.Equal(onDisk, good) {
		t.Fatal("on-disk cache was overwritten by a bad response")
	}
}

func TestLoadCachedUsesFileMtime(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "x.txt")
	if err := os.WriteFile(p, []byte("0.0.0.0 a.example.com\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-20 * time.Hour)
	if err := os.Chtimes(p, old, old); err != nil {
		t.Fatal(err)
	}
	m := NewListManager(NewEngine(), dir)
	m.SetSpecs([]ListSpec{{ID: "x", Enabled: true}})
	m.LoadCached()
	got := m.store["x"].LastFetched
	if got == nil || got.Sub(old).Abs() > time.Second {
		t.Fatalf("LastFetched = %v, want ~%v", got, old)
	}
}

func TestFetchAllWithRetryRecovers(t *testing.T) {
	old := bootRetryDelays
	bootRetryDelays = []time.Duration{10 * time.Millisecond, 10 * time.Millisecond}
	defer func() { bootRetryDelays = old }()
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if hits.Add(1) < 2 {
			http.Error(w, "down", http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write([]byte("0.0.0.0 a.example.com\n"))
	}))
	defer srv.Close()
	m := NewListManager(NewEngine(), t.TempDir())
	m.SetSpecs([]ListSpec{{ID: "x", Name: "x", URL: srv.URL, Enabled: true}})
	if err := m.FetchAllWithRetry(context.Background()); err != nil {
		t.Fatalf("expected recovery after retry, got %v", err)
	}
	if hits.Load() < 2 {
		t.Fatal("no retry happened")
	}
}
