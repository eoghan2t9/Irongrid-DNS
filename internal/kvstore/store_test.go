package kvstore

import (
	"fmt"
	"testing"
	"time"
)

func openTest(t testing.TB) *Store {
	t.Helper()
	s, err := Open(Options{InMemory: true})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func TestGetSetDelete(t *testing.T) {
	s := openTest(t)
	if _, _, ok := s.Get("missing"); ok {
		t.Fatal("Get of a missing key reported a hit")
	}
	if err := s.Set("k1", []byte("v1"), time.Hour); err != nil {
		t.Fatal(err)
	}
	v, ttl, ok := s.Get("k1")
	if !ok || string(v) != "v1" {
		t.Fatalf("Get = %q, %v", v, ok)
	}
	if ttl <= 0 || ttl > time.Hour {
		t.Fatalf("ttl = %v, want (0, 1h]", ttl)
	}
	if err := s.Set("forever", []byte("x"), 0); err != nil {
		t.Fatal(err)
	}
	if _, ttl, _ := s.Get("forever"); ttl != 0 {
		t.Fatalf("no-expiry key ttl = %v, want 0", ttl)
	}
	if err := s.Delete("k1"); err != nil {
		t.Fatal(err)
	}
	if _, _, ok := s.Get("k1"); ok {
		t.Fatal("key still present after Delete")
	}
	st := s.Stats()
	if st.Hits != 2 || st.Misses != 2 {
		t.Fatalf("stats hits/misses = %d/%d, want 2/2", st.Hits, st.Misses)
	}
}

func TestSubSecondTTLRoundsUp(t *testing.T) {
	s := openTest(t)
	if err := s.Set("k", []byte("v"), 300*time.Millisecond); err != nil {
		t.Fatal(err)
	}
	if _, _, ok := s.Get("k"); !ok {
		t.Fatal("a sub-second TTL expired instantly instead of rounding up to 1s")
	}
}

func TestTTLExpiry(t *testing.T) {
	if testing.Short() {
		t.Skip("waits for a real TTL")
	}
	s := openTest(t)
	if err := s.Set("k", []byte("v"), time.Second); err != nil {
		t.Fatal(err)
	}
	time.Sleep(2200 * time.Millisecond)
	if _, _, ok := s.Get("k"); ok {
		t.Fatal("key survived past its TTL")
	}
}

func TestGetManyAndHas(t *testing.T) {
	s := openTest(t)
	_ = s.Set("a", []byte("1"), time.Hour)
	_ = s.Set("empty", []byte{}, time.Hour)
	got := s.GetMany("a", "nope", "empty")
	if string(got[0]) != "1" || got[1] != nil || got[2] == nil || len(got[2]) != 0 {
		t.Fatalf("GetMany = %q", got)
	}
	if !s.Has("nope", "a") || s.Has("nope", "nada") {
		t.Fatal("Has gave the wrong answer")
	}
}

func TestSetBatchAndPrefix(t *testing.T) {
	s := openTest(t)
	var ws []Write
	for i := range 50 {
		ws = append(ws, Write{Key: fmt.Sprintf("p:%03d", i), Val: []byte("x"), TTL: time.Hour})
	}
	ws = append(ws, Write{Key: "other", Val: []byte("y")})
	if err := s.SetBatch(ws); err != nil {
		t.Fatal(err)
	}
	if n := s.CountPrefix("p:"); n != 50 {
		t.Fatalf("CountPrefix = %d, want 50", n)
	}
	n, err := s.DeletePrefix("p:")
	if err != nil || n != 50 {
		t.Fatalf("DeletePrefix = %d, %v", n, err)
	}
	if s.CountPrefix("p:") != 0 {
		t.Fatal("prefix keys remain after DeletePrefix")
	}
	if _, _, ok := s.Get("other"); !ok {
		t.Fatal("DeletePrefix removed an unrelated key")
	}
}

func appendN(t testing.TB, st *Stream, n int) {
	t.Helper()
	vals := make([][]byte, n)
	for i := range vals {
		vals[i] = fmt.Appendf(nil, `{"n":%d}`, i)
	}
	if err := st.Append(vals, time.Hour, 0); err != nil {
		t.Fatal(err)
	}
}

func TestStreamOrderAndWalk(t *testing.T) {
	st := openTest(t).Stream("log")
	appendN(t, st, 10)
	if st.Len() != 10 {
		t.Fatalf("Len = %d, want 10", st.Len())
	}

	var fwd []string
	if err := st.Walk(false, 0, 0, func(id string, v []byte) bool {
		fwd = append(fwd, string(v))
		return true
	}); err != nil {
		t.Fatal(err)
	}
	var rev []string
	if err := st.Walk(true, 0, 0, func(id string, v []byte) bool {
		rev = append(rev, string(v))
		return true
	}); err != nil {
		t.Fatal(err)
	}
	if len(fwd) != 10 || len(rev) != 10 {
		t.Fatalf("walked %d forward / %d reverse, want 10/10", len(fwd), len(rev))
	}
	for i := range fwd {
		if fwd[i] != rev[len(rev)-1-i] {
			t.Fatalf("reverse is not the mirror of forward at %d: %q vs %q", i, fwd[i], rev[len(rev)-1-i])
		}
	}
	if fwd[0] != `{"n":0}` || fwd[9] != `{"n":9}` {
		t.Fatalf("forward order wrong: %v", fwd)
	}
}

func TestStreamWalkBoundsAndEarlyExit(t *testing.T) {
	st := openTest(t).Stream("log")
	appendN(t, st, 20)

	count := 0
	_ = st.Walk(true, 0, 5, func(string, []byte) bool { count++; return true })
	if count != 5 {
		t.Fatalf("limit not enforced: visited %d, want 5", count)
	}
	count = 0
	_ = st.Walk(false, 0, 0, func(string, []byte) bool { count++; return count < 3 })
	if count != 3 {
		t.Fatalf("early exit visited %d, want 3", count)
	}
}

func TestStreamSinceMs(t *testing.T) {
	st := openTest(t).Stream("log")
	appendN(t, st, 3)
	future := time.Now().Add(time.Hour).UnixMilli()
	for _, rev := range []bool{false, true} {
		count := 0
		_ = st.Walk(rev, future, 0, func(string, []byte) bool { count++; return true })
		if count != 0 {
			t.Fatalf("reverse=%v: walked %d records newer than the future, want 0", rev, count)
		}
	}
	count := 0
	_ = st.Walk(true, time.Now().Add(-time.Minute).UnixMilli(), 0, func(string, []byte) bool { count++; return true })
	if count != 3 {
		t.Fatalf("walk since a minute ago saw %d, want 3", count)
	}
}

func TestStreamIDsStrictlyIncrease(t *testing.T) {
	st := openTest(t).Stream("log")
	appendN(t, st, 200) // far more than fit in one millisecond
	seen := map[string]bool{}
	_ = st.Walk(false, 0, 0, func(id string, _ []byte) bool {
		if seen[id] {
			t.Fatalf("duplicate stream ID %s", id)
		}
		seen[id] = true
		return true
	})
	if len(seen) != 200 {
		t.Fatalf("got %d distinct IDs, want 200", len(seen))
	}
}

func TestStreamMaxLenTrimsOldest(t *testing.T) {
	st := openTest(t).Stream("log")
	for i := range 40 {
		if err := st.Append([][]byte{fmt.Appendf(nil, "%d", i)}, time.Hour, 20); err != nil {
			t.Fatal(err)
		}
	}
	var got []string
	_ = st.Walk(false, 0, 0, func(_ string, v []byte) bool { got = append(got, string(v)); return true })
	if len(got) > 22 { // maxLen plus the slack that avoids trimming every batch
		t.Fatalf("stream holds %d records, want <= 22", len(got))
	}
	if got[len(got)-1] != "39" {
		t.Fatalf("newest record lost: %v", got)
	}
}

func TestStreamTrimBeforeAndClear(t *testing.T) {
	st := openTest(t).Stream("log")
	appendN(t, st, 5)
	n, err := st.TrimBefore(time.Now().Add(-time.Hour))
	if err != nil || n != 0 {
		t.Fatalf("TrimBefore(old cutoff) = %d, %v; want 0", n, err)
	}
	n, err = st.TrimBefore(time.Now().Add(time.Hour))
	if err != nil || n != 5 {
		t.Fatalf("TrimBefore(future cutoff) = %d, %v; want 5", n, err)
	}
	appendN(t, st, 3)
	if err := st.Clear(); err != nil {
		t.Fatal(err)
	}
	if st.Len() != 0 {
		t.Fatalf("Len after Clear = %d", st.Len())
	}
	count := 0
	_ = st.Walk(false, 0, 0, func(string, []byte) bool { count++; return true })
	if count != 0 {
		t.Fatalf("walked %d records after Clear", count)
	}
}

func TestStreamsAreIsolated(t *testing.T) {
	s := openTest(t)
	a, b := s.Stream("a"), s.Stream("b")
	appendN(t, a, 4)
	appendN(t, b, 2)
	if err := a.Clear(); err != nil {
		t.Fatal(err)
	}
	count := 0
	_ = b.Walk(false, 0, 0, func(string, []byte) bool { count++; return true })
	if count != 2 {
		t.Fatalf("clearing stream a disturbed stream b: %d records left, want 2", count)
	}
}

func TestClosedStore(t *testing.T) {
	s, err := Open(Options{InMemory: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Ping(); err != nil {
		t.Fatalf("Ping on open store: %v", err)
	}
	_ = s.Close()
	if err := s.Ping(); err == nil {
		t.Fatal("Ping on closed store returned nil")
	}
	if err := s.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}

func TestPersistsAcrossReopen(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(Options{Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	_ = s.Set("k", []byte("v"), time.Hour)
	appendN(t, s.Stream("log"), 3)
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = Open(Options{Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if v, _, ok := s.Get("k"); !ok || string(v) != "v" {
		t.Fatalf("value lost across reopen: %q %v", v, ok)
	}
	if st := s.Stream("log"); st.Len() != 3 {
		t.Fatalf("stream length after reopen = %d, want 3", st.Len())
	}
}
