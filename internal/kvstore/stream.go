package kvstore

import (
	"encoding/binary"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/dgraph-io/badger/v4"
)

// Stream is an append-only, time-ordered log inside a Store — the embedded
// replacement for the Redis stream the query log used to live in. Every record
// gets a "<ms>-<seq>" ID whose (ms, seq) pair is also its big-endian key suffix,
// so Badger's key order is time order and both a forward walk from a timestamp
// and a newest-first walk are plain iterator scans.
type Stream struct {
	s      *Store
	prefix []byte

	// mu serializes ID assignment so IDs are strictly increasing even when two
	// batches race.
	mu     sync.Mutex
	lastMs uint64
	seq    uint64

	// n is the approximate record count, used to enforce maxLen cheaply. It
	// can overshoot (records expire silently via their TTL), which trimTo
	// corrects with a real recount before deleting anything.
	n      atomic.Int64
	trimMu sync.Mutex
}

// Stream opens the named stream, counting what it already holds so maxLen
// enforcement is accurate from the first Append after a restart.
func (s *Store) Stream(name string) *Stream {
	st := &Stream{s: s, prefix: []byte("stream:" + name + ":")}
	st.n.Store(s.CountPrefix(string(st.prefix)))
	return st
}

// Len returns the approximate number of records (an upper bound: expired
// records are only dropped on the next recount).
func (st *Stream) Len() int64 { return st.n.Load() }

func (st *Stream) key(ms, seq uint64) []byte {
	k := make([]byte, len(st.prefix)+16)
	copy(k, st.prefix)
	binary.BigEndian.PutUint64(k[len(st.prefix):], ms)
	binary.BigEndian.PutUint64(k[len(st.prefix)+8:], seq)
	return k
}

// Append writes vals in order. Each record expires after ttl (<= 0 keeps it
// until trimmed). When maxLen > 0 the oldest records are trimmed to keep the
// stream at or below that length (with a little slack so the trim — and the
// recount that guards it — doesn't run on every batch).
func (st *Stream) Append(vals [][]byte, ttl time.Duration, maxLen int64) error {
	if len(vals) == 0 {
		return nil
	}
	wb := st.s.db.NewWriteBatch()
	defer wb.Cancel()

	st.mu.Lock()
	for _, v := range vals {
		ms := uint64(time.Now().UnixMilli())
		if ms <= st.lastMs {
			ms = st.lastMs
			st.seq++
		} else {
			st.seq = 0
		}
		st.lastMs = ms
		if err := wb.SetEntry(newEntry(string(st.key(ms, st.seq)), v, ttl)); err != nil {
			st.mu.Unlock()
			return err
		}
	}
	st.mu.Unlock()

	if err := wb.Flush(); err != nil {
		return err
	}
	st.n.Add(int64(len(vals)))
	if maxLen > 0 && st.n.Load() > maxLen+maxLen/10 {
		st.trimTo(maxLen)
	}
	return nil
}

// trimTo drops the oldest records so at most maxLen remain. It recounts first
// because n over-counts expired records; trimming off a stale count would
// delete live data.
func (st *Stream) trimTo(maxLen int64) {
	st.trimMu.Lock()
	defer st.trimMu.Unlock()
	real := st.s.CountPrefix(string(st.prefix))
	st.n.Store(real)
	if real <= maxLen {
		return
	}
	keys, err := st.s.keysWithPrefix(st.prefix, int(real-maxLen))
	if err != nil || len(keys) == 0 {
		return
	}
	if n, err := st.s.deleteKeys(keys); err == nil {
		st.n.Add(-n)
	}
}

// TrimBefore deletes every record older than cutoff and returns how many it
// removed. It also refreshes the approximate length.
func (st *Stream) TrimBefore(cutoff time.Time) (int64, error) {
	st.trimMu.Lock()
	defer st.trimMu.Unlock()
	end := st.key(uint64(max(cutoff.UnixMilli(), 0)), 0)
	var keys [][]byte
	err := st.s.db.View(func(txn *badger.Txn) error {
		opt := badger.DefaultIteratorOptions
		opt.PrefetchValues = false
		opt.Prefix = st.prefix
		it := txn.NewIterator(opt)
		defer it.Close()
		for it.Rewind(); it.Valid(); it.Next() {
			k := it.Item().Key()
			if string(k) >= string(end) {
				break
			}
			keys = append(keys, it.Item().KeyCopy(nil))
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	var n int64
	if len(keys) > 0 {
		if n, err = st.s.deleteKeys(keys); err != nil {
			return 0, err
		}
	}
	st.n.Store(st.s.CountPrefix(string(st.prefix)))
	return n, nil
}

// Clear deletes every record.
func (st *Stream) Clear() error {
	st.trimMu.Lock()
	defer st.trimMu.Unlock()
	_, err := st.s.DeletePrefix(string(st.prefix))
	st.n.Store(0)
	return err
}

// Walk visits records with ms >= sinceMs (0 = from the beginning): oldest-first
// when reverse is false, newest-first when true. At most limit records are
// visited (limit <= 0 is unbounded). fn receives the record ID and its value;
// the value is only valid during the call. Returning false stops the walk.
func (st *Stream) Walk(reverse bool, sinceMs int64, limit int, fn func(id string, val []byte) bool) error {
	return st.s.db.View(func(txn *badger.Txn) error {
		opt := badger.DefaultIteratorOptions
		opt.Prefix = st.prefix
		opt.Reverse = reverse
		it := txn.NewIterator(opt)
		defer it.Close()

		lo := uint64(0)
		if sinceMs > 0 {
			lo = uint64(sinceMs)
		}
		if reverse {
			top := make([]byte, len(st.prefix)+16)
			copy(top, st.prefix)
			for i := len(st.prefix); i < len(top); i++ {
				top[i] = 0xFF
			}
			it.Seek(top)
		} else {
			it.Seek(st.key(lo, 0))
		}

		visited := 0
		for ; it.Valid(); it.Next() {
			item := it.Item()
			k := item.Key()
			if len(k) != len(st.prefix)+16 {
				continue
			}
			ms := binary.BigEndian.Uint64(k[len(st.prefix):])
			if reverse && ms < lo {
				return nil
			}
			seq := binary.BigEndian.Uint64(k[len(st.prefix)+8:])
			id := strconv.FormatUint(ms, 10) + "-" + strconv.FormatUint(seq, 10)
			cont := true
			if err := item.Value(func(v []byte) error {
				cont = fn(id, v)
				return nil
			}); err != nil {
				return err
			}
			visited++
			if !cont || (limit > 0 && visited >= limit) {
				return nil
			}
		}
		return nil
	})
}
