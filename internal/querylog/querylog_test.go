package querylog

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

func entry(domain string) Entry {
	return Entry{
		Time: time.Now(), Client: "127.0.0.1", Domain: domain,
		Type: "A", Action: "allowed", Upstream: "udp://1.1.1.1:53",
		ResponseTimeMS: 12, Rcode: 0, Answers: 1,
	}
}

// TestRecordFlushesOnClose verifies entries enqueued before Close are flushed
// to the database — the final partial batch must not be lost at shutdown.
func TestRecordFlushesOnClose(t *testing.T) {
	path := filepath.Join(t.TempDir(), "queries.db")
	l, err := New(path, 30)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	for i := 0; i < 10; i++ {
		l.Record(entry("example.com."))
	}
	if err := l.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Reopen the same file and count what was persisted.
	r, err := New(path, 30)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer r.Close()
	entries, err := r.Query(context.Background(), 100, 0, "", "", "")
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(entries) != 10 {
		t.Fatalf("persisted %d entries, want 10", len(entries))
	}
}

// TestBatchFlush verifies queued entries are flushed without Close, via both
// the batch-size and the ticker paths.
func TestBatchFlush(t *testing.T) {
	l, err := New(filepath.Join(t.TempDir(), "queries.db"), 30)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer l.Close()
	const n = logBatchSize + 50
	for i := 0; i < n; i++ {
		l.Record(entry("example.com."))
	}
	deadline := time.Now().Add(3 * time.Second)
	for {
		entries, err := l.Query(context.Background(), n+10, 0, "", "", "")
		if err != nil {
			t.Fatalf("Query: %v", err)
		}
		if len(entries) >= n {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("only %d of %d entries flushed in time", len(entries), n)
		}
		time.Sleep(25 * time.Millisecond)
	}
}

// TestRecordAfterCloseIsSafe verifies Record never panics after Close.
func TestRecordAfterCloseIsSafe(t *testing.T) {
	l, err := New(filepath.Join(t.TempDir(), "queries.db"), 30)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := l.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	l.Record(entry("example.com.")) // must be a no-op, not a panic
}

// BenchmarkRecord measures the enqueue throughput of the async writer — the
// rate the DNS hot path can log at without ever blocking on disk.
func BenchmarkRecord(b *testing.B) {
	l, err := New(filepath.Join(b.TempDir(), "queries.db"), 30)
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		l.Record(entry("bench.example.com."))
	}
	b.StopTimer()
	_ = l.Close()
}
