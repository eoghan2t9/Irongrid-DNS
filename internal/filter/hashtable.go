package filter

import (
	"hash/maphash"
	"math/bits"
	"slices"
)

// hashTable is a compact, insert-only set of domain names with a small
// per-entry payload (the index of the list that contributed the entry).
//
// A Go map[string]struct{} spends roughly 70-90 bytes per domain once the
// string data, bucket metadata and load-factor slack are counted; a
// million-rule blocklist set cost ~160 MB. This stores only a 64-bit
// fingerprint of each name (8 B) plus a 2 B list index, in open-addressing
// slots at ~70% load: ~14 B per entry, a 5-6x reduction.
//
// Trade-off: the names themselves are not kept, so membership is decided by
// fingerprint equality. The hash is seeded per process (hashSeed), so an
// attacker cannot precompute colliding names, and a false match needs a full
// 64-bit collision: about n/2^64 per lookup (~6e-14 for a 1.1M-rule set).
// That is a negligible, accepted risk for blocklist lookups; the table must
// not be used where an exact answer is a hard requirement.
//
// The zero fingerprint marks an empty slot (hashName never returns 0).
// A nil *hashTable is a valid empty table. Tables are mutated only while
// private to one Engine; once published they are read-only (the Engine clones
// before any further write).
type hashTable struct {
	fp []uint64
	li []uint16
	n  int
}

// hashSeed is random per process; fingerprints are never persisted.
var hashSeed = maphash.MakeSeed()

// hashName fingerprints a normalized domain name. Never returns 0.
func hashName(s string) uint64 {
	h := maphash.String(hashSeed, s)
	if h == 0 {
		h = 1
	}
	return h
}

// slotFor maps a fingerprint to a slot without a modulo or a power-of-two
// size requirement (Lemire's fast range reduction).
func slotFor(h uint64, size int) int {
	hi, _ := bits.Mul64(h, uint64(size))
	return int(hi)
}

func newHashTable(size int) *hashTable {
	size = max(size, 16)
	return &hashTable{fp: make([]uint64, size), li: make([]uint16, size)}
}

// Len returns the number of distinct entries.
func (t *hashTable) Len() int {
	if t == nil {
		return 0
	}
	return t.n
}

// get returns the list index stored for h.
func (t *hashTable) get(h uint64) (uint16, bool) {
	if t == nil || t.n == 0 {
		return 0, false
	}
	size := len(t.fp)
	for i := slotFor(h, size); ; {
		f := t.fp[i]
		if f == 0 {
			return 0, false
		}
		if f == h {
			return t.li[i], true
		}
		if i++; i == size {
			i = 0
		}
	}
}

// put stores h -> li. The table must have a free slot (insert guarantees it).
func (t *hashTable) put(h uint64, li uint16) {
	size := len(t.fp)
	for i := slotFor(h, size); ; {
		f := t.fp[i]
		if f == 0 {
			t.fp[i], t.li[i] = h, li
			t.n++
			return
		}
		if f == h {
			t.li[i] = li // same name from a later list: last writer wins
			return
		}
		if i++; i == size {
			i = 0
		}
	}
}

// insert adds h -> li, growing as needed, and returns the table to keep
// (which differs from t when it was nil or had to grow).
func (t *hashTable) insert(h uint64, li uint16) *hashTable {
	if t == nil {
		t = newHashTable(16)
	}
	if (t.n+1)*10 > len(t.fp)*7 { // keep load factor <= 0.7
		t = t.resized(len(t.fp) * 2)
	}
	t.put(h, li)
	return t
}

// resized rebuilds the table with the given slot count.
func (t *hashTable) resized(size int) *hashTable {
	nt := newHashTable(size)
	for i, f := range t.fp {
		if f != 0 {
			nt.put(f, t.li[i])
		}
	}
	return nt
}

// fit shrinks an over-allocated table (incremental growth can leave up to 2x
// slack) to ~70% load. Returns t unchanged when it is already close.
func (t *hashTable) fit() *hashTable {
	if t == nil {
		return nil
	}
	want := t.n*10/7 + 1
	if len(t.fp) <= want*13/10 {
		return t
	}
	return t.resized(want)
}

// clone returns an independent copy.
func (t *hashTable) clone() *hashTable {
	if t == nil {
		return nil
	}
	return &hashTable{fp: slices.Clone(t.fp), li: slices.Clone(t.li), n: t.n}
}
