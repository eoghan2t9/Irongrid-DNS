package filter

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// ListManager owns the blocklist sources, their cached content, and the
// periodic refresh loop.
type ListManager struct {
	mu     sync.Mutex
	specs  []ListSpec      // user-configured lists
	store  map[string]*StoredList
	engine *Engine
	dir    string
	client *http.Client
}

// ListSpec mirrors the config blocklist entry.
type ListSpec struct {
	ID         string        `json:"id"`
	Name       string        `json:"name"`
	URL        string        `json:"url"`
	Enabled    bool          `json:"enabled"`
	AutoUpdate time.Duration `json:"auto_update"`
}

// StoredList holds the last known good content of a list.
//
// Content is excluded from JSON on purpose: a large list (millions of
// domains) would balloon GET /api/lists into a multi-megabyte payload and
// stall the dashboard. The raw content is served separately via the
// /api/lists/<id>/content endpoint.
//
// LastFetched is a pointer so a never-fetched list serializes as null rather
// than Go's zero time ("0001-01-01T00:00:00Z"), which the dashboard would
// render as a year-1 date.
type StoredList struct {
	Spec        ListSpec   `json:"spec"`
	Content     []byte     `json:"-"`
	LastFetched *time.Time `json:"last_fetched"`
	LastError   string     `json:"last_error"`
	RuleCount   int        `json:"rule_count"`
}

// NewListManager creates a manager that persists cached list content under
// dir (e.g. data/lists).
func NewListManager(engine *Engine, dir string) *ListManager {
	return &ListManager{
		store:  map[string]*StoredList{},
		engine: engine,
		dir:    dir,
		client: &http.Client{Timeout: 60 * time.Second},
	}
}

// SetSpecs replaces the configured lists.
func (m *ListManager) SetSpecs(specs []ListSpec) {
	m.mu.Lock()
	defer m.mu.Unlock()
	keep := map[string]bool{}
	for _, s := range specs {
		keep[s.ID] = true
		if _, ok := m.store[s.ID]; !ok {
			m.store[s.ID] = &StoredList{Spec: s}
		} else {
			m.store[s.ID].Spec = s
		}
	}
	for id := range m.store {
		if !keep[id] {
			delete(m.store, id)
		}
	}
}

// ReloadAll recompiles the engine from every enabled list's cached content.
// It must be called after FetchAll or FetchOne. The engine's user lists are
// untouched; the caller re-applies them via SetUserLists + Compile if needed.
func (m *ListManager) ReloadAll() {
	m.mu.Lock()
	specs := make([]ListSpec, 0, len(m.store))
	for _, s := range m.store {
		specs = append(specs, s.Spec)
	}
	m.mu.Unlock()

	// Reset first so removed/disabled lists no longer contribute rules.
	m.engine.Reset()
	m.mu.Lock()
	for _, s := range specs {
		if !s.Enabled {
			continue
		}
		if stored, ok := m.store[s.ID]; ok {
			res, err := m.engine.LoadList(s.ID, s.Name, stored.Content)
			if err == nil {
				stored.RuleCount = res.Domains + res.ExactDomains + res.IPs
			}
		}
	}
	m.mu.Unlock()
	m.engine.Compile()
}

// Fetch downloads every enabled list (or reads local files) and stores the
// content. It does not recompile; call ReloadAll after.
func (m *ListManager) FetchAll(ctx context.Context) error {
	m.mu.Lock()
	specs := make([]ListSpec, 0, len(m.store))
	for _, s := range m.store {
		specs = append(specs, s.Spec)
	}
	m.mu.Unlock()

	var firstErr error
	for _, s := range specs {
		if !s.Enabled {
			continue
		}
		if err := m.FetchOne(ctx, s.ID); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// FetchOne refreshes a single list from its URL (or file).
func (m *ListManager) FetchOne(ctx context.Context, id string) error {
	m.mu.Lock()
	stored, ok := m.store[id]
	if !ok {
		m.mu.Unlock()
		return fmt.Errorf("unknown list %q", id)
	}
	spec := stored.Spec
	m.mu.Unlock()

	var content []byte
	var err error
	if strings.HasPrefix(spec.URL, "file://") {
		content, err = os.ReadFile(strings.TrimPrefix(spec.URL, "file://"))
	} else if spec.URL == "" {
		// A list with no URL holds only manual entries; nothing to fetch.
		return nil
	} else {
		content, err = m.download(ctx, spec.URL)
	}
	if err != nil {
		m.mu.Lock()
		stored.LastError = err.Error()
		m.mu.Unlock()
		return fmt.Errorf("list %s (%s): %w", spec.ID, spec.URL, err)
	}

	m.mu.Lock()
	now := time.Now()
	stored.Content = content
	stored.LastFetched = &now
	stored.LastError = ""
	m.mu.Unlock()
	return m.persist(id, content)
}

func (m *ListManager) download(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Irongrid-DNS/0.1 (+https://github.com/eoghan2t9/Irongrid-DNS)")
	resp, err := m.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 64<<20)) // 64 MB cap
}

func (m *ListManager) persist(id string, content []byte) error {
	if m.dir == "" {
		return nil
	}
	if err := os.MkdirAll(m.dir, 0o755); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(m.dir, id+".txt"), content, 0o644)
}

// LoadCached restores previously persisted list content on startup.
func (m *ListManager) LoadCached() {
	if m.dir == "" {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for id, stored := range m.store {
		path := filepath.Join(m.dir, id+".txt")
		if content, err := os.ReadFile(path); err == nil {
			if stored.Content == nil {
				now := time.Now()
				stored.Content = content
				stored.LastFetched = &now
			}
		}
	}
}

// StartRefresh runs the auto-update loop until ctx is cancelled.
func (m *ListManager) StartRefresh(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(10 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				now := time.Now()
				m.mu.Lock()
				var due []string
				for id, stored := range m.store {
					s := stored.Spec
					if !s.Enabled || s.AutoUpdate <= 0 {
						continue
					}
					if stored.LastFetched == nil || now.Sub(*stored.LastFetched) >= s.AutoUpdate {
						due = append(due, id)
					}
				}
				m.mu.Unlock()
				changed := false
				for _, id := range due {
					if err := m.FetchOne(ctx, id); err != nil {
						continue
					}
					changed = true
				}
				if changed {
					m.ReloadAll()
				}
			}
		}
	}()
}

// Snapshot returns a copy of all stored lists for the API.
func (m *ListManager) Snapshot() []StoredList {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]StoredList, 0, len(m.store))
	for _, s := range m.store {
		out = append(out, *s)
	}
	return out
}

// GetContent returns the cached content of a list.
func (m *ListManager) GetContent(id string) []byte {
	m.mu.Lock()
	defer m.mu.Unlock()
	if s, ok := m.store[id]; ok {
		return s.Content
	}
	return nil
}
