package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/eoghan2t9/Irongrid-DNS/internal/config"
	"github.com/eoghan2t9/Irongrid-DNS/internal/kvstore"
	"github.com/eoghan2t9/Irongrid-DNS/internal/querylog"
)

func logPagingHandler(t *testing.T, n int) *Handler {
	t.Helper()
	store, err := kvstore.Open(kvstore.Options{InMemory: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	l, err := querylog.New(store, 30, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	for i := range n {
		l.Record(querylog.Entry{
			Time: time.Now(), Client: "127.0.0.1", Domain: fmt.Sprintf("d%03d.example.", i),
			Type: "A", Action: "allowed",
		})
	}
	h := &Handler{Cfg: &config.Config{}, Log: l}
	// The writer flushes asynchronously.
	deadline := time.Now().Add(3 * time.Second)
	for {
		got, _, _ := l.QueryPage(t.Context(), 1000, "", "", "", "", "")
		if len(got) >= n {
			return h
		}
		if time.Now().After(deadline) {
			t.Fatalf("only %d of %d entries flushed", len(got), n)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

type logResp struct {
	Entries []struct {
		ID     string `json:"id"`
		Domain string `json:"domain"`
	} `json:"entries"`
	Next string `json:"next"`
}

func getLogPage(t *testing.T, h *Handler, q url.Values) (int, logResp) {
	t.Helper()
	rr := httptest.NewRecorder()
	h.getLog(t.Context(), rr, httptest.NewRequest(http.MethodGet, "/api/log?"+q.Encode(), nil))
	var out logResp
	_ = json.Unmarshal(rr.Body.Bytes(), &out)
	return rr.Code, out
}

// Following "next" as "before" walks the whole log exactly once, newest first.
func TestGetLogCursorPagingReachesEveryEntry(t *testing.T) {
	t.Parallel()
	h := logPagingHandler(t, 25)

	seen := map[string]bool{}
	var domains []string
	q := url.Values{"limit": {"10"}}
	for range 10 {
		code, page := getLogPage(t, h, q)
		if code != http.StatusOK {
			t.Fatalf("status %d", code)
		}
		for _, e := range page.Entries {
			if seen[e.ID] {
				t.Fatalf("entry %s repeated across pages", e.ID)
			}
			seen[e.ID] = true
			domains = append(domains, e.Domain)
		}
		if page.Next == "" {
			break
		}
		q.Set("before", page.Next)
	}
	if len(seen) != 25 {
		t.Fatalf("paged %d entries, want 25", len(seen))
	}
	if domains[0] != "d024.example." || domains[24] != "d000.example." {
		t.Fatalf("not newest-first: %q ... %q", domains[0], domains[24])
	}
}

func TestGetLogRejectsMalformedCursor(t *testing.T) {
	t.Parallel()
	h := logPagingHandler(t, 3)
	if code, _ := getLogPage(t, h, url.Values{"before": {"not-an-id"}}); code != http.StatusBadRequest {
		t.Fatalf("malformed cursor status = %d, want 400", code)
	}
}

// The older offset form keeps working for existing callers.
func TestGetLogOffsetStillSupported(t *testing.T) {
	t.Parallel()
	h := logPagingHandler(t, 12)
	code, page := getLogPage(t, h, url.Values{"limit": {"5"}, "offset": {"5"}})
	if code != http.StatusOK || len(page.Entries) != 5 {
		t.Fatalf("offset page = %d with %d entries, want 200 with 5", code, len(page.Entries))
	}
	if page.Entries[0].Domain != "d006.example." {
		t.Fatalf("offset 5 starts at %q, want d006.example.", page.Entries[0].Domain)
	}
}
