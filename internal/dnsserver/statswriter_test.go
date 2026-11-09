package dnsserver

import (
	"errors"
	"sync/atomic"
	"testing"

	"github.com/miekg/dns"
)

// failWriter is a dns.ResponseWriter whose writes fail or succeed on demand.
type failWriter struct {
	dns.ResponseWriter
	err error
}

func (f *failWriter) WriteMsg(*dns.Msg) error     { return f.err }
func (f *failWriter) Write(b []byte) (int, error) { return len(b), f.err }

// TestStatsWriterCountsWriteErrors: the wrapper still records transport write
// failures on both write paths, and only failures.
func TestStatsWriterCountsWriteErrors(t *testing.T) {
	var errs atomic.Int64
	fw := &failWriter{err: errors.New("boom")}
	sw := getStatsWriter(fw, &errs)
	defer putStatsWriter(sw)

	if err := sw.WriteMsg(new(dns.Msg)); err == nil {
		t.Fatal("WriteMsg should surface the underlying error")
	}
	if _, err := sw.Write([]byte{1}); err == nil {
		t.Fatal("Write should surface the underlying error")
	}
	if got := errs.Load(); got != 2 {
		t.Fatalf("write errors = %d, want 2", got)
	}

	fw.err = nil
	_ = sw.WriteMsg(new(dns.Msg))
	_, _ = sw.Write([]byte{1})
	if got := errs.Load(); got != 2 {
		t.Fatalf("successful writes must not count: errors = %d, want 2", got)
	}
}

// TestStatsWriterPutClearsReferences: an idle pooled wrapper must not keep the
// previous query's connection (or counter) alive.
func TestStatsWriterPutClearsReferences(t *testing.T) {
	var errs atomic.Int64
	sw := getStatsWriter(&failWriter{}, &errs)
	putStatsWriter(sw)
	if sw.ResponseWriter != nil || sw.writeErrors != nil {
		t.Fatal("putStatsWriter left references behind")
	}
}

// TestStatsWriterNoAllocs: once warm, wrapping a query costs no allocation.
func TestStatsWriterNoAllocs(t *testing.T) {
	var errs atomic.Int64
	fw := &failWriter{}
	for range 8 {
		putStatsWriter(getStatsWriter(fw, &errs))
	}
	if n := testing.AllocsPerRun(1000, func() {
		putStatsWriter(getStatsWriter(fw, &errs))
	}); n != 0 {
		t.Fatalf("get/put allocated %v times, want 0", n)
	}
}
