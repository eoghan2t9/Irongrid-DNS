package filter

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestFetchOneCoalescesConcurrentDownloads verifies overlapping refresh
// triggers (boot FetchAll, the auto-refresh ticker, a manual refresh) don't
// download the same list twice at once.
func TestFetchOneCoalescesConcurrentDownloads(t *testing.T) {
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
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
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
