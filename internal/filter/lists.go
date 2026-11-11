package filter

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"github.com/eoghan2t9/Irongrid-DNS/internal/safego"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/errgroup"
	"golang.org/x/sync/singleflight"
)

// fetchConcurrency bounds how many lists (or countries, in the geoip
// package's equivalent) FetchAll downloads at once. A dashboard refresh or
// the auto-update ticker previously fetched every enabled list one at a
// time — sequential HTTP round trips that added up fast with many lists.
const fetchConcurrency = 8

// ListManager owns the blocklist sources, their cached content, and the
// periodic refresh loop.
type ListManager struct {
	mu     sync.Mutex
	store  map[string]*StoredList
	engine *Engine
	dir    string
	client *http.Client
	// autoUpdate is the single refresh interval applied to every enabled
	// list; 0 disables auto-refresh entirely. Set via SetAutoUpdate rather
	// than per-list — one global cadence instead of tracking a schedule per
	// list.
	autoUpdate time.Duration
	// fetchFlight coalesces concurrent downloads of the same list URL so
	// overlapping refresh triggers (boot FetchAll, the auto-refresh ticker,
	// a manual refresh) never fetch the same list twice at once (see
	// fetchRemote).
	fetchFlight singleflight.Group
	// OnChange, if set, is invoked after every successful ReloadAll. Used to
	// rebuild anything else that derives from the same cached list content
	// (e.g. per-client-group engines), which ReloadAll itself knows nothing
	// about.
	OnChange func()
}

// ListSpec mirrors the config blocklist entry.
type ListSpec struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	URL     string `json:"url"`
	Enabled bool   `json:"enabled"`
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

	// fetchedThisRun is set once the list has been downloaded successfully by
	// this process (as opposed to restored from the on-disk cache).
	fetchedThisRun bool

	// onDisk is true once Content is known to be persisted in the cache dir,
	// which makes it safe to drop the in-memory copy after compiling (see
	// ReloadAll / contentLocked). size is the byte length of the content
	// either way, kept for the shrink check in validateFetched.
	onDisk bool
	size   int
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

// SetAutoUpdate sets the global refresh interval used by StartRefresh's
// ticker; 0 disables auto-refresh. Safe to call while StartRefresh is
// running (e.g. after a config reload).
func (m *ListManager) SetAutoUpdate(d time.Duration) {
	m.mu.Lock()
	m.autoUpdate = d
	m.mu.Unlock()
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
// carried over automatically.
//
// The new rule set is built off to the side and swapped in atomically
// (Engine.Rebuild), so queries are never evaluated against an empty or
// half-loaded engine while a reload is in progress. Removed or disabled lists
// simply aren't loaded into the new set.
func (m *ListManager) ReloadAll() {
	m.mu.Lock()
	specs := make([]ListSpec, 0, len(m.store))
	for _, s := range m.store {
		specs = append(specs, s.Spec)
	}
	m.mu.Unlock()

	m.engine.Rebuild(func(nb *Engine) {
		for _, s := range specs {
			if !s.Enabled {
				continue
			}
			m.mu.Lock()
			stored, ok := m.store[s.ID]
			var content []byte
			if ok {
				content = m.contentLocked(stored)
			}
			m.mu.Unlock()
			if !ok {
				continue
			}
			res, err := nb.LoadList(s.ID, s.Name, content)
			if err == nil {
				m.mu.Lock()
				stored.RuleCount = res.Domains + res.ExactDomains + res.IPs
				m.mu.Unlock()
			}
		}
	})
	m.dropCompiledContent()
	if m.OnChange != nil {
		m.OnChange()
	}
}

// contentLocked returns a list's content, from memory when held, otherwise
// from the on-disk cache. Callers hold m.mu.
func (m *ListManager) contentLocked(s *StoredList) []byte {
	if s.Content != nil || !s.onDisk || m.dir == "" {
		return s.Content
	}
	b, err := os.ReadFile(filepath.Join(m.dir, s.Spec.ID+".txt"))
	if err != nil {
		return nil
	}
	return b
}

// dropCompiledContent frees the raw list text of every list that is safely
// persisted on disk. Once compiled into the engine the text is dead weight
// (tens of MB across a typical set of lists) and is only needed again for the
// content endpoint or a per-group engine rebuild, both of which read it back
// from disk via contentLocked.
func (m *ListManager) dropCompiledContent() {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, s := range m.store {
		if s.onDisk && s.Content != nil {
			s.size = len(s.Content)
			s.Content = nil
		}
	}
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

	// Concurrent, bounded: each list is an independent HTTP fetch (fetchRemote
	// already coalesces duplicate URLs via singleflight), so there's no
	// reason to pay for them one at a time. A single list's failure doesn't
	// stop the rest — same as the old sequential loop — errgroup.Group's
	// zero value (no WithContext) doesn't cancel siblings on the first error.
	//
	// Every failure is collected (errors.Join) rather than only the first, so
	// the caller can log each list that didn't refresh.
	var (
		g    errgroup.Group
		errM sync.Mutex
		errs []error
	)
	g.SetLimit(fetchConcurrency)
	for _, s := range specs {
		if !s.Enabled {
			continue
		}
		id := s.ID
		g.Go(func() error {
			if err := m.FetchOne(ctx, id); err != nil {
				errM.Lock()
				errs = append(errs, err)
				errM.Unlock()
			}
			return nil
		})
	}
	_ = g.Wait() // goroutines never return an error; failures are in errs
	return errors.Join(errs...)
}

// bootRetryDelays is the backoff between boot-time fetch attempts. At boot the
// process resolves list hostnames through itself (127.0.0.1:53), which isn't
// listening yet when the first attempt fires, so the early attempts commonly
// fail with "connection refused" and must be retried rather than abandoned.
var bootRetryDelays = []time.Duration{5 * time.Second, 15 * time.Second, 45 * time.Second, 2 * time.Minute, 5 * time.Minute}

// FetchAllWithRetry fetches every enabled list, then retries only the lists
// that failed with backoff until they succeed, the attempts run out, or ctx is
// cancelled. It returns the errors from the final attempt (nil when every list
// refreshed) and recompiles the engine whenever at least one list changed.
func (m *ListManager) FetchAllWithRetry(ctx context.Context) error {
	err := m.FetchAll(ctx)
	for _, d := range bootRetryDelays {
		if err == nil {
			break
		}
		slog.Warn("blocklist fetch failed, will retry", "retry_in", d.String(), "error", err)
		select {
		case <-ctx.Done():
			m.reloadIfFetched()
			return ctx.Err()
		case <-time.After(d):
		}
		var errs []error
		for _, id := range m.failedIDs() {
			if e := m.FetchOne(ctx, id); e != nil {
				errs = append(errs, e)
			}
		}
		err = errors.Join(errs...)
	}
	m.reloadIfFetched()
	return err
}

// reloadIfFetched recompiles the engine when any list was fetched since boot.
func (m *ListManager) reloadIfFetched() {
	m.mu.Lock()
	changed := false
	for _, s := range m.store {
		if s.fetchedThisRun {
			changed = true
			break
		}
	}
	m.mu.Unlock()
	if changed {
		m.ReloadAll()
	}
}

// failedIDs returns the enabled lists whose last fetch attempt errored.
func (m *ListManager) failedIDs() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	var ids []string
	for id, s := range m.store {
		if s.Spec.Enabled && s.LastError != "" {
			ids = append(ids, id)
		}
	}
	return ids
}

// validateFetched rejects a downloaded body that is evidently not a usable
// list, so a 200 response carrying an empty file or an HTML error page can't
// overwrite a good cached copy. prevSize is the byte length of the currently held content (0 if none).
func validateFetched(content []byte, prevSize int) error {
	trimmed := bytes.TrimSpace(content)
	if len(trimmed) == 0 {
		return errors.New("empty response body")
	}
	head := bytes.ToLower(trimmed[:min(len(trimmed), 256)])
	if bytes.HasPrefix(head, []byte("<!doctype")) || bytes.HasPrefix(head, []byte("<html")) {
		return errors.New("response is an HTML page, not a list")
	}
	// A list that suddenly shrinks to under a tenth of its previous size is
	// almost certainly truncated or replaced by an error stub.
	if prevSize > 10<<10 && len(content) < prevSize/10 {
		return fmt.Errorf("response is %d bytes, under 10%% of the cached %d bytes", len(content), prevSize)
	}
	return nil
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
	if after, ok0 := strings.CutPrefix(spec.URL, "file://"); ok0 {
		// Local reads are instant; no need to coalesce.
		content, err = os.ReadFile(after)
	} else if spec.URL == "" {
		// A list with no URL holds only manual entries; nothing to fetch.
		return nil
	} else {
		content, err = m.fetchRemote(ctx, spec.URL)
	}
	if err != nil {
		m.mu.Lock()
		stored.LastError = err.Error()
		m.mu.Unlock()
		return fmt.Errorf("list %s (%s): %w", spec.ID, spec.URL, err)
	}

	m.mu.Lock()
	prevSize := max(len(stored.Content), stored.size)
	m.mu.Unlock()
	if verr := validateFetched(content, prevSize); verr != nil {
		m.mu.Lock()
		stored.LastError = verr.Error()
		m.mu.Unlock()
		return fmt.Errorf("list %s (%s): rejected, keeping cached copy: %w", spec.ID, spec.URL, verr)
	}

	m.mu.Lock()
	now := time.Now()
	stored.Content = content
	stored.LastFetched = &now
	stored.LastError = ""
	stored.fetchedThisRun = true
	stored.size = len(content)
	stored.onDisk = false
	m.mu.Unlock()
	if err := m.persist(id, content); err != nil {
		return err // content stays in memory (onDisk=false), nothing is dropped
	}
	m.mu.Lock()
	stored.onDisk = m.dir != ""
	m.mu.Unlock()
	return nil
}

// fetchRemote downloads list content, coalescing concurrent downloads of the
// same URL into one HTTP round trip (a boot FetchAll overlapping the
// auto-refresh ticker or a manual refresh must not download each list
// twice). Keyed on the URL, so two lists pointing at the same source also
// share one fetch.
func (m *ListManager) fetchRemote(ctx context.Context, url string) ([]byte, error) {
	v, err, _ := m.fetchFlight.Do("list:"+url, func() (any, error) {
		return m.download(ctx, url)
	})
	if err != nil {
		return nil, err
	}
	return v.([]byte), nil
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
	// The list ID becomes a filename; reject anything that could escape the
	// cache dir via path traversal (G703).
	if id == "" || strings.ContainsAny(id, "/\\") || id == "." || id == ".." {
		return fmt.Errorf("invalid list id %q", id)
	}
	if err := os.MkdirAll(m.dir, 0o755); err != nil {
		return err
	}
	// Write to a temp file in the same directory and rename it into place so a
	// crash mid-write can never leave a truncated cache file behind.
	//nolint:gosec // G703: id is validated above (no separators, not . or ..).
	final := filepath.Join(m.dir, id+".txt")
	tmp, err := os.CreateTemp(m.dir, id+".*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(content); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return err
	}
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	if err := os.Rename(tmpName, final); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	return nil
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
				// Use the cache file's mtime, not "now": otherwise every
				// restart looks like a fresh fetch and pushes the next
				// auto-refresh a full interval into the future.
				fetched := time.Now()
				if fi, serr := os.Stat(path); serr == nil {
					fetched = fi.ModTime()
				}
				stored.Content = content
				stored.size = len(content)
				stored.onDisk = true
				stored.LastFetched = &fetched
			}
		}
	}
}

// StartRefresh runs the auto-update loop until ctx is cancelled.
func (m *ListManager) StartRefresh(ctx context.Context) {
	go func() {
		defer safego.Recover("lists refresh")
		ticker := time.NewTicker(10 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				now := time.Now()
				m.mu.Lock()
				interval := m.autoUpdate
				var due []string
				if interval > 0 {
					for id, stored := range m.store {
						if !stored.Spec.Enabled {
							continue
						}
						if stored.LastFetched == nil || now.Sub(*stored.LastFetched) >= interval {
							due = append(due, id)
						}
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

// Snapshot returns a deep copy of all stored lists for the API.
// The Content byte slice is cloned so concurrent fetches can't corrupt
// the snapshot while the JSON encoder serializes it.
func (m *ListManager) Snapshot() []StoredList {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]StoredList, 0, len(m.store))
	for _, s := range m.store {
		snap := *s
		if len(s.Content) > 0 {
			snap.Content = make([]byte, len(s.Content))
			copy(snap.Content, s.Content)
		}
		out = append(out, snap)
	}
	return out
}

// GetContent returns the cached content of a list.
func (m *ListManager) GetContent(id string) []byte {
	m.mu.Lock()
	defer m.mu.Unlock()
	if s, ok := m.store[id]; ok {
		return m.contentLocked(s)
	}
	return nil
}
