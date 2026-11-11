package filter

import (
	"fmt"
	"testing"
)

func TestHashTableBasics(t *testing.T) {
	var tb *hashTable
	if _, ok := tb.get(hashName("x.com")); ok || tb.Len() != 0 {
		t.Fatal("nil table must be empty")
	}
	const n = 50000
	for i := range n {
		tb = tb.insert(hashName(fmt.Sprintf("host%d.example.com", i)), uint16(i%7))
	}
	if tb.Len() != n {
		t.Fatalf("Len = %d, want %d", tb.Len(), n)
	}
	for i := range n {
		li, ok := tb.get(hashName(fmt.Sprintf("host%d.example.com", i)))
		if !ok || li != uint16(i%7) {
			t.Fatalf("entry %d: got (%d,%v)", i, li, ok)
		}
	}
	for i := range n {
		if _, ok := tb.get(hashName(fmt.Sprintf("absent%d.example.org", i))); ok {
			t.Fatalf("false positive for absent%d", i)
		}
	}
	// re-inserting overwrites the payload without growing n
	tb = tb.insert(hashName("host1.example.com"), 99)
	if li, _ := tb.get(hashName("host1.example.com")); li != 99 || tb.Len() != n {
		t.Fatalf("overwrite failed: li=%d n=%d", li, tb.Len())
	}
}

func TestHashTableFitAndClone(t *testing.T) {
	var tb *hashTable
	for i := range 10000 {
		tb = tb.insert(hashName(fmt.Sprintf("d%d.test", i)), 1)
	}
	before := len(tb.fp)
	fit := tb.fit()
	if len(fit.fp) > before || fit.Len() != tb.Len() {
		t.Fatalf("fit grew or lost entries: %d -> %d slots, n %d vs %d", before, len(fit.fp), tb.Len(), fit.Len())
	}
	if float64(fit.n)/float64(len(fit.fp)) > 0.72 {
		t.Fatalf("load factor too high after fit: %.2f", float64(fit.n)/float64(len(fit.fp)))
	}
	cl := fit.clone()
	cl = cl.insert(hashName("only-in-clone.test"), 3)
	if _, ok := fit.get(hashName("only-in-clone.test")); ok {
		t.Fatal("clone shares storage with the original")
	}
	for i := range 10000 {
		if _, ok := cl.get(hashName(fmt.Sprintf("d%d.test", i))); !ok {
			t.Fatalf("clone lost d%d", i)
		}
	}
}

func BenchmarkHashTableMiss(b *testing.B) {
	var tb *hashTable
	for i := range 1_100_000 {
		tb = tb.insert(hashName(fmt.Sprintf("host%d.example.com", i)), 0)
	}
	tb = tb.fit()
	keys := make([]uint64, 1024)
	for i := range keys {
		keys[i] = hashName(fmt.Sprintf("miss%d.example.org", i))
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		tb.get(keys[i&1023])
	}
}
