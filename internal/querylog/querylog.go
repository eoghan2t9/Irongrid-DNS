// Package querylog stores every DNS request with its allow/block outcome in
// a pure-Go SQLite database (no CGO, no external tools).
package querylog

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	_ "modernc.org/sqlite"
)

const (
	// logQueueCap bounds the pending-entry queue. Serving never blocks on
	// logging: once the queue is full, new entries are dropped.
	logQueueCap = 8192
	// logBatchSize flushes the writer once this many entries have queued.
	logBatchSize = 256
	// logFlushInterval is the maximum age of a queued entry before the
	// writer flushes it in one transaction.
	logFlushInterval = 100 * time.Millisecond
)

// Entry is a single logged query.
type Entry struct {
	ID             int64     `json:"id"`
	Time           time.Time `json:"time"`
	Client         string    `json:"client"`
	Domain         string    `json:"domain"`
	Type           string    `json:"type"`   // A, AAAA, TXT...
	Action         string    `json:"action"` // "allowed", "blocked", "cached", "error"
	Reason         string    `json:"reason"`
	Upstream       string    `json:"upstream"`
	ResponseTimeMS int64     `json:"response_time_ms"`
	Rcode          int       `json:"rcode"`
	Answers        int       `json:"answers"`
}

// Log is a concurrency-safe query logger backed by SQLite. Entries are
// enqueued and written by a single background goroutine in batches (one
// transaction per flush), so per-query disk I/O never sits on the DNS hot
// path.
type Log struct {
	db        *sql.DB
	mu        sync.Mutex // serialises Exec/Prune (raw writes by callers)
	retention time.Duration
	dir       string

	entries chan Entry
	done    chan struct{}
	closed  atomic.Bool
	wg      sync.WaitGroup
}

// New opens (creating if needed) the query log database.
func New(path string, retentionDays int) (*Log, error) {
	if path == "" {
		return nil, fmt.Errorf("query log path required")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open query log: %w", err)
	}
	db.SetMaxOpenConns(1) // modernc sqlite is single-writer; serialize writes

	// WAL + NORMAL: batched commits skip per-write fsync without risking
	// corruption (a crash may lose at most the last ~100ms of entries).
	if _, err := db.Exec(`PRAGMA journal_mode=WAL`); err != nil {
		return nil, fmt.Errorf("enable WAL: %w", err)
	}
	if _, err := db.Exec(`PRAGMA synchronous=NORMAL`); err != nil {
		return nil, fmt.Errorf("set synchronous=NORMAL: %w", err)
	}
	if _, err := db.Exec(`PRAGMA busy_timeout=5000`); err != nil {
		return nil, fmt.Errorf("set busy_timeout: %w", err)
	}

	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS queries (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		ts INTEGER NOT NULL,
		client TEXT NOT NULL,
		domain TEXT NOT NULL,
		qtype TEXT NOT NULL,
		action TEXT NOT NULL,
		reason TEXT NOT NULL DEFAULT '',
		upstream TEXT NOT NULL DEFAULT '',
		rt_ms INTEGER NOT NULL DEFAULT 0,
		rcode INTEGER NOT NULL DEFAULT 0,
		answers INTEGER NOT NULL DEFAULT 0
	)`); err != nil {
		return nil, fmt.Errorf("create query log table: %w", err)
	}
	if _, err := db.Exec(`CREATE INDEX IF NOT EXISTS idx_queries_ts ON queries(ts)`); err != nil {
		return nil, err
	}
	if _, err := db.Exec(`CREATE INDEX IF NOT EXISTS idx_queries_domain ON queries(domain)`); err != nil {
		return nil, err
	}

	l := &Log{
		db:        db,
		retention: time.Duration(retentionDays) * 24 * time.Hour,
		dir:       filepath.Dir(path),
		entries:   make(chan Entry, logQueueCap),
		done:      make(chan struct{}),
	}
	l.wg.Add(1)
	go l.runWriter()
	return l, nil
}

// Record enqueues one query entry. It never blocks or slows query serving:
// the background writer batches entries and commits them in a single
// transaction. If the queue is full (or the log is closed), the entry is
// dropped — logging must never break DNS.
func (l *Log) Record(e Entry) {
	if l.closed.Load() {
		return
	}
	select {
	case l.entries <- e:
	default:
		// Queue full — drop rather than stall DNS serving.
	}
}

// runWriter drains the queue, flushing in batches of logBatchSize or every
// logFlushInterval, whichever comes first. Close() signals via l.done so the
// writer drains whatever is queued and flushes the final batch. The entries
// channel is deliberately never closed: Record may race Close and a send on
// a closed channel would panic.
func (l *Log) runWriter() {
	defer l.wg.Done()
	batch := make([]Entry, 0, logBatchSize)
	ticker := time.NewTicker(logFlushInterval)
	defer ticker.Stop()
	flush := func() {
		if len(batch) == 0 {
			return
		}
		l.writeBatch(batch)
		batch = batch[:0]
	}
	for {
		select {
		case e := <-l.entries:
			batch = append(batch, e)
			if len(batch) >= logBatchSize {
				flush()
			}
		case <-ticker.C:
			flush()
		case <-l.done:
			// Shutdown: drain everything still queued, then flush and exit.
			for {
				select {
				case e := <-l.entries:
					batch = append(batch, e)
					if len(batch) >= logBatchSize {
						flush()
					}
				default:
					flush()
					return
				}
			}
		}
	}
}

// writeBatch commits entries with one multi-row INSERT in a single
// transaction — one commit per batch instead of one per query.
func (l *Log) writeBatch(entries []Entry) {
	if len(entries) == 0 {
		return
	}
	var sb strings.Builder
	sb.WriteString(`INSERT INTO queries
		(ts, client, domain, qtype, action, reason, upstream, rt_ms, rcode, answers) VALUES `)
	args := make([]any, 0, len(entries)*10)
	for i, e := range entries {
		if i > 0 {
			sb.WriteString(",")
		}
		sb.WriteString("(?,?,?,?,?,?,?,?,?,?)")
		args = append(args, e.Time.Unix(), e.Client, e.Domain, e.Type, e.Action,
			e.Reason, e.Upstream, e.ResponseTimeMS, e.Rcode, e.Answers)
	}
	tx, err := l.db.Begin()
	if err != nil {
		return
	}
	defer tx.Rollback()
	if _, err := tx.Exec(sb.String(), args...); err != nil {
		// Drop the batch silently: logging must not break DNS.
		return
	}
	_ = tx.Commit()
}

// Query fetches recent entries with optional filters and pagination.
func (l *Log) Query(ctx context.Context, limit, offset int, action, domain, qtype string) ([]Entry, error) {
	q := `SELECT id, ts, client, domain, qtype, action, reason, upstream, rt_ms, rcode, answers
	      FROM queries WHERE 1=1`
	args := []any{}
	if action != "" {
		q += ` AND action = ?`
		args = append(args, action)
	}
	if qtype != "" {
		q += ` AND qtype = ?`
		args = append(args, qtype)
	}
	if domain != "" {
		q += ` AND domain LIKE ?`
		args = append(args, "%"+domain+"%")
	}
	q += ` ORDER BY id DESC LIMIT ? OFFSET ?`
	args = append(args, limit, offset)

	rows, err := l.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Entry
	for rows.Next() {
		var e Entry
		var ts int64
		if err := rows.Scan(&e.ID, &ts, &e.Client, &e.Domain, &e.Type, &e.Action,
			&e.Reason, &e.Upstream, &e.ResponseTimeMS, &e.Rcode, &e.Answers); err != nil {
			return nil, err
		}
		e.Time = time.Unix(ts, 0)
		out = append(out, e)
	}
	return out, rows.Err()
}

// Stats returns aggregate counters for a time window.
func (l *Log) Stats(ctx context.Context, since time.Time) (map[string]any, error) {
	stats := map[string]any{
		"total": 0, "allowed": 0, "blocked": 0, "cached": 0,
		"avg_rt_ms": 0, "top_blocked": []TopDomain{}, "top_clients": []TopDomain{},
	}
	if l.db == nil {
		return stats, nil
	}
	row := l.db.QueryRowContext(ctx,
		`SELECT COUNT(*),
		        SUM(CASE WHEN action='allowed' THEN 1 ELSE 0 END),
		        SUM(CASE WHEN action='blocked' THEN 1 ELSE 0 END),
		        SUM(CASE WHEN action='cached' THEN 1 ELSE 0 END),
		        AVG(rt_ms)
		 FROM queries WHERE ts >= ?`, since.Unix())
	var total, allowed, blocked, cached sql.NullInt64
	var avg sql.NullFloat64
	if err := row.Scan(&total, &allowed, &blocked, &cached, &avg); err == nil {
		stats["total"] = total.Int64
		stats["allowed"] = allowed.Int64
		stats["blocked"] = blocked.Int64
		stats["cached"] = cached.Int64
		stats["avg_rt_ms"] = avg.Float64
	}

	topBlocked, _ := l.top(ctx, "blocked", since, 10)
	topClients, _ := l.top(ctx, "", since, 10)
	stats["top_blocked"] = topBlocked
	stats["top_clients"] = topClients
	return stats, nil
}

type TopDomain struct {
	Domain string `json:"domain"`
	Count  int64  `json:"count"`
}

func (l *Log) top(ctx context.Context, action string, since time.Time, n int) ([]TopDomain, error) {
	q := `SELECT domain, COUNT(*) c FROM queries WHERE ts >= ?`
	args := []any{since.Unix()}
	if action != "" {
		q += ` AND action = ?`
		args = append(args, action)
	}
	q += ` GROUP BY domain ORDER BY c DESC LIMIT ?`
	args = append(args, n)
	rows, err := l.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []TopDomain
	for rows.Next() {
		var td TopDomain
		if err := rows.Scan(&td.Domain, &td.Count); err != nil {
			return nil, err
		}
		out = append(out, td)
	}
	return out, rows.Err()
}

// Exec runs a raw statement (used by the API to clear the log).
func (l *Log) Exec(ctx context.Context, query string, args ...any) (sql.Result, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.db.ExecContext(ctx, query, args...)
}

// Prune removes entries older than the retention window.
func (l *Log) Prune(ctx context.Context) {
	if l.retention <= 0 {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	cutoff := time.Now().Add(-l.retention).Unix()
	l.db.ExecContext(ctx, `DELETE FROM queries WHERE ts < ?`, cutoff)
}

// StartPruner periodically prunes old entries.
func (l *Log) StartPruner(ctx context.Context) {
	go func() {
		t := time.NewTicker(time.Hour)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				l.Prune(ctx)
			}
		}
	}()
}

// Close stops the writer (flushing any pending entries) and closes the
// database. Safe to call more than once.
func (l *Log) Close() error {
	if !l.closed.CompareAndSwap(false, true) {
		return nil
	}
	close(l.done) // writer drains the queue and flushes the final batch
	l.wg.Wait()
	return l.db.Close()
}
