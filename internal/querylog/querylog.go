// Package querylog stores every DNS request with its allow/block outcome in
// a pure-Go SQLite database (no CGO, no external tools).
package querylog

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

// Entry is a single logged query.
type Entry struct {
	ID        int64     `json:"id"`
	Time      time.Time `json:"time"`
	Client    string    `json:"client"`
	Domain    string    `json:"domain"`
	Type      string    `json:"type"` // A, AAAA, TXT...
	Action    string    `json:"action"` // "allowed", "blocked", "cached", "error"
	Reason    string    `json:"reason"`
	Upstream  string    `json:"upstream"`
	ResponseTimeMS int64 `json:"response_time_ms"`
	Rcode     int       `json:"rcode"`
	Answers   int       `json:"answers"`
}

// Log is a concurrency-safe query logger backed by SQLite.
type Log struct {
	db        *sql.DB
	mu        sync.Mutex
	insertStm *sql.Stmt
	retention time.Duration
	dir       string
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

	stm, err := db.Prepare(`INSERT INTO queries
		(ts, client, domain, qtype, action, reason, upstream, rt_ms, rcode, answers)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return nil, fmt.Errorf("prepare insert: %w", err)
	}

	return &Log{
		db:        db,
		insertStm: stm,
		retention: time.Duration(retentionDays) * 24 * time.Hour,
		dir:       filepath.Dir(path),
	}, nil
}

// Record writes one query entry. It never blocks query serving on DB errors.
func (l *Log) Record(e Entry) {
	l.mu.Lock()
	defer l.mu.Unlock()
	_, err := l.insertStm.Exec(
		e.Time.Unix(), e.Client, e.Domain, e.Type, e.Action,
		e.Reason, e.Upstream, e.ResponseTimeMS, e.Rcode, e.Answers,
	)
	if err != nil {
		// Drop silently on failure: logging must not break DNS.
		return
	}
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
		"total":    0, "allowed": 0, "blocked": 0, "cached": 0,
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

// Close closes the database.
func (l *Log) Close() error {
	if l.db != nil {
		return l.db.Close()
	}
	return nil
}
