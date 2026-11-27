// Package kvstore is Irongrid's embedded key/value store: a thin wrapper over
// BadgerDB (a pure-Go LSM store) that backs both the DNS response cache's L2
// tier and the query log. It replaces the external DragonflyDB service the
// project used to depend on, so there is no separate process to install,
// monitor or keep in sync — the data lives in a directory owned by Irongrid.
//
// One Store is opened per process (Badger locks its directory) and shared by
// the cache and the query log; neither closes it.
package kvstore

import (
	"errors"
	"fmt"
	"log/slog"
	"runtime/debug"
	"strings"
	"sync/atomic"
	"time"

	"github.com/dgraph-io/badger/v4"
	"github.com/dgraph-io/badger/v4/options"
)

// ErrClosed is returned by operations on a closed Store.
var ErrClosed = errors.New("kvstore: closed")

// Options configures Open. The zero value (apart from Dir) picks conservative
// memory settings suited to a small DNS box.
type Options struct {
	// Dir is the data directory. Created if missing. Ignored when InMemory.
	Dir string
	// InMemory keeps everything in RAM and writes nothing to disk. Used by
	// tests; data is lost on Close.
	InMemory bool
	// MemTableMB is the size of each write buffer. 0 uses 16.
	MemTableMB int
	// BlockCacheMB is the decompressed-block read cache. 0 uses 32.
	BlockCacheMB int
	// IndexCacheMB is the table-index cache. 0 uses 16.
	IndexCacheMB int
}

// Store is an embedded, TTL-aware key/value store. Safe for concurrent use.
type Store struct {
	db     *badger.DB
	hits   atomic.Int64
	misses atomic.Int64
}

// Write is one entry for SetBatch. A TTL <= 0 stores the key without expiry.
type Write struct {
	Key string
	Val []byte
	TTL time.Duration
}

// Stats is a snapshot of the store's counters and footprint.
type Stats struct {
	// Hits and Misses count Get/GetMany key lookups since Open.
	Hits   int64
	Misses int64
	// DiskBytes is the on-disk size (LSM tables plus value log). It is
	// refreshed by Badger about once a minute and is 0 for an in-memory store.
	DiskBytes int64
}

// Open opens (creating if needed) the store described by opt.
func Open(opt Options) (*Store, error) {
	if !opt.InMemory && opt.Dir == "" {
		return nil, errors.New("kvstore: Dir is required")
	}
	bo := badger.DefaultOptions(opt.Dir).
		WithInMemory(opt.InMemory).
		WithLogger(slogLogger{}).
		WithMemTableSize(int64(orDefault(opt.MemTableMB, 16)) << 20).
		WithNumMemtables(2).
		WithBlockCacheSize(int64(orDefault(opt.BlockCacheMB, 32)) << 20).
		WithIndexCacheSize(int64(orDefault(opt.IndexCacheMB, 16)) << 20).
		// DNS answers are tiny; keep every value inline in the LSM so the
		// value log (and its garbage collector) is never involved.
		WithValueThreshold(1 << 20).
		// Blind overwrites only: no read-modify-write transactions, so
		// conflict detection would just cost memory and CPU.
		WithDetectConflicts(false).
		WithMetricsEnabled(false).
		WithNumCompactors(2).
		// Cache data is disposable and the query log tolerates losing the
		// last instant of writes on a crash; fsync per write isn't worth it.
		WithSyncWrites(false).
		WithCompression(options.Snappy)
	db, err := badger.Open(bo)
	if err != nil {
		return nil, fmt.Errorf("kvstore: open %q: %w", opt.Dir, err)
	}
	return &Store{db: db}, nil
}

func orDefault(v, def int) int {
	if v > 0 {
		return v
	}
	return def
}

// Close flushes and closes the store. Safe to call more than once.
func (s *Store) Close() error {
	if s == nil || s.db == nil || s.db.IsClosed() {
		return nil
	}
	return s.db.Close()
}

// Ping returns an error if the store is closed.
func (s *Store) Ping() error {
	if s == nil || s.db == nil || s.db.IsClosed() {
		return ErrClosed
	}
	return nil
}

// Sync flushes buffered writes to disk (the analogue of the old SAVE command).
func (s *Store) Sync() error {
	if err := s.Ping(); err != nil {
		return err
	}
	return s.db.Sync()
}

// Version returns the embedded engine's identifier, e.g. "badger v4.9.6".
func (s *Store) Version() string {
	if bi, ok := debug.ReadBuildInfo(); ok {
		for _, d := range bi.Deps {
			if d.Path == "github.com/dgraph-io/badger/v4" {
				return "badger " + d.Version
			}
		}
	}
	return "badger v4"
}

// Stats returns the store's counters.
func (s *Store) Stats() Stats {
	lsm, vlog := s.db.Size()
	return Stats{Hits: s.hits.Load(), Misses: s.misses.Load(), DiskBytes: lsm + vlog}
}

// ttlSeconds converts a TTL to Badger's whole-second granularity, rounding up
// so a sub-second TTL doesn't land in the current second and expire instantly.
func ttlSeconds(ttl time.Duration) time.Duration {
	if rem := ttl % time.Second; rem != 0 {
		ttl += time.Second - rem
	}
	return ttl
}

func newEntry(key string, val []byte, ttl time.Duration) *badger.Entry {
	e := badger.NewEntry([]byte(key), val)
	if ttl > 0 {
		e = e.WithTTL(ttlSeconds(ttl))
	}
	return e
}

// remaining converts an item's absolute expiry into a TTL; 0 means no expiry
// (an expired item is never returned by a read).
func remaining(it *badger.Item) time.Duration {
	ea := it.ExpiresAt()
	if ea == 0 {
		return 0
	}
	return max(time.Until(time.Unix(int64(ea), 0)), 0)
}

// Get returns the value for key and its remaining TTL (0 for no expiry). ok is
// false on a miss or any error.
func (s *Store) Get(key string) (val []byte, ttl time.Duration, ok bool) {
	err := s.db.View(func(txn *badger.Txn) error {
		it, err := txn.Get([]byte(key))
		if err != nil {
			return err
		}
		val, err = it.ValueCopy(nil)
		ttl = remaining(it)
		return err
	})
	if err != nil {
		s.misses.Add(1)
		return nil, 0, false
	}
	s.hits.Add(1)
	if val == nil {
		val = []byte{}
	}
	return val, ttl, true
}

// GetMany looks up several keys in one read snapshot. The result is parallel to
// keys: a nil entry is a miss. A present-but-empty value is returned as a
// non-nil empty slice.
func (s *Store) GetMany(keys ...string) [][]byte {
	out := make([][]byte, len(keys))
	_ = s.db.View(func(txn *badger.Txn) error {
		for i, k := range keys {
			it, err := txn.Get([]byte(k))
			if err != nil {
				s.misses.Add(1)
				continue
			}
			v, err := it.ValueCopy(nil)
			if err != nil {
				s.misses.Add(1)
				continue
			}
			if v == nil {
				v = []byte{}
			}
			out[i] = v
			s.hits.Add(1)
		}
		return nil
	})
	return out
}

// Has reports whether any of the keys is present, without copying values.
func (s *Store) Has(keys ...string) bool {
	found := false
	_ = s.db.View(func(txn *badger.Txn) error {
		for _, k := range keys {
			if _, err := txn.Get([]byte(k)); err == nil {
				found = true
				return nil
			}
		}
		return nil
	})
	if found {
		s.hits.Add(1)
	} else {
		s.misses.Add(1)
	}
	return found
}

// Set stores one value with an optional TTL.
func (s *Store) Set(key string, val []byte, ttl time.Duration) error {
	return s.db.Update(func(txn *badger.Txn) error {
		return txn.SetEntry(newEntry(key, val, ttl))
	})
}

// SetBatch commits many writes in one pass; it is the cache writer's flush.
func (s *Store) SetBatch(ws []Write) error {
	if len(ws) == 0 {
		return nil
	}
	wb := s.db.NewWriteBatch()
	defer wb.Cancel()
	for i := range ws {
		if err := wb.SetEntry(newEntry(ws[i].Key, ws[i].Val, ws[i].TTL)); err != nil {
			return err
		}
	}
	return wb.Flush()
}

// Delete removes a key (a missing key is not an error).
func (s *Store) Delete(key string) error {
	return s.db.Update(func(txn *badger.Txn) error {
		return txn.Delete([]byte(key))
	})
}

// CountPrefix counts live keys that start with prefix. It walks keys only (no
// values), so it is O(keys) — callers on a poll should memoize the result.
func (s *Store) CountPrefix(prefix string) int64 {
	var n int64
	_ = s.db.View(func(txn *badger.Txn) error {
		opt := badger.DefaultIteratorOptions
		opt.PrefetchValues = false
		opt.Prefix = []byte(prefix)
		it := txn.NewIterator(opt)
		defer it.Close()
		for it.Rewind(); it.Valid(); it.Next() {
			n++
		}
		return nil
	})
	return n
}

// DeletePrefix removes every key that starts with prefix and returns how many
// it removed. Unlike Badger's DropPrefix it does not block concurrent writers,
// so the cache keeps serving while a flush runs.
func (s *Store) DeletePrefix(prefix string) (int64, error) {
	keys, err := s.keysWithPrefix([]byte(prefix), 0)
	if err != nil || len(keys) == 0 {
		return 0, err
	}
	return s.deleteKeys(keys)
}

// keysWithPrefix returns up to limit keys (0 = all) under prefix, oldest key
// first. Only keys are read.
func (s *Store) keysWithPrefix(prefix []byte, limit int) ([][]byte, error) {
	var keys [][]byte
	err := s.db.View(func(txn *badger.Txn) error {
		opt := badger.DefaultIteratorOptions
		opt.PrefetchValues = false
		opt.Prefix = prefix
		it := txn.NewIterator(opt)
		defer it.Close()
		for it.Rewind(); it.Valid(); it.Next() {
			keys = append(keys, it.Item().KeyCopy(nil))
			if limit > 0 && len(keys) >= limit {
				break
			}
		}
		return nil
	})
	return keys, err
}

func (s *Store) deleteKeys(keys [][]byte) (int64, error) {
	wb := s.db.NewWriteBatch()
	defer wb.Cancel()
	for _, k := range keys {
		if err := wb.Delete(k); err != nil {
			return 0, err
		}
	}
	if err := wb.Flush(); err != nil {
		return 0, err
	}
	return int64(len(keys)), nil
}

// slogLogger routes Badger's own log lines into slog at sensible levels.
type slogLogger struct{}

func (slogLogger) Errorf(f string, a ...any)   { slog.Error("kvstore: " + trim(f, a)) }
func (slogLogger) Warningf(f string, a ...any) { slog.Warn("kvstore: " + trim(f, a)) }
func (slogLogger) Infof(f string, a ...any)    { slog.Debug("kvstore: " + trim(f, a)) }
func (slogLogger) Debugf(string, ...any)       {}

func trim(f string, a []any) string {
	return strings.TrimSpace(fmt.Sprintf(f, a...))
}
