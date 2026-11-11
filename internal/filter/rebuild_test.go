package filter

import (
	"bytes"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
)

const rebuildList = "0.0.0.0 blocked.example.com\n0.0.0.0 other.example.net\n"

// A reader hammering DecideDomain while the lists are rebuilt must never see
// the engine empty (the old Reset-then-refill briefly allowed everything).
func TestReloadAllNeverExposesEmptyEngine(t *testing.T) {
	dir := t.TempDir()
	e := NewEngine()
	m := NewListManager(e, dir)
	m.SetSpecs([]ListSpec{{ID: "a", Name: "a", Enabled: true}})
	m.store["a"].Content = []byte(rebuildList)
	m.ReloadAll()
	if e.DecideDomain("blocked.example.com.").Action != Block {
		t.Fatal("setup: expected block")
	}

	var stop atomic.Bool
	var leaked atomic.Int64
	var wg sync.WaitGroup
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for !stop.Load() {
				if e.DecideDomain("blocked.example.com.").Action != Block {
					leaked.Add(1)
				}
			}
		}()
	}
	for range 200 {
		m.ReloadAll()
	}
	stop.Store(true)
	wg.Wait()
	if n := leaked.Load(); n != 0 {
		t.Fatalf("%d queries saw a rule set without the blocked domain during reloads", n)
	}
}

func TestRebuildCarriesUserListsAndDropsRemovedLists(t *testing.T) {
	e := NewEngine()
	e.SetUserLists([]string{"manual-block.example.org"}, []string{"blocked.example.com"})
	m := NewListManager(e, t.TempDir())
	m.SetSpecs([]ListSpec{{ID: "a", Name: "a", Enabled: true}})
	m.store["a"].Content = []byte(rebuildList)
	m.ReloadAll()
	if got := e.DecideDomain("blocked.example.com.").Action; got == Block {
		t.Fatal("user whitelist should override the list")
	}
	if e.DecideDomain("manual-block.example.org.").Action != Block {
		t.Fatal("user blacklist lost across rebuild")
	}
	if e.DecideDomain("other.example.net.").Action != Block {
		t.Fatal("list rule missing")
	}
	m.SetSpecs(nil) // list removed
	m.ReloadAll()
	if e.DecideDomain("other.example.net.").Action == Block {
		t.Fatal("removed list still blocking after rebuild")
	}
}

// Publishing shares maps with the snapshot, so later in-place edits must be
// copy-on-write. Run under -race with concurrent readers.
func TestCopyOnWriteIsolatesPublishedSnapshot(t *testing.T) {
	e := NewEngine()
	if _, err := e.LoadList("a", "a", []byte(rebuildList)); err != nil {
		t.Fatal(err)
	}
	e.Compile()
	snap := e.rs.Load()
	before := len(snap.blockDomains) + len(snap.blockExact)

	var stop atomic.Bool
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for !stop.Load() {
			e.DecideDomain("blocked.example.com.")
			_, _ = e.CheckIPs(nil)
		}
	}()
	for range 50 {
		e.AddIPBlock("203.0.113.9")
		e.SetUserLists(nil, []string{"blocked.example.com"})
		e.Compile() // mutates allow/block maps in place -> must unshare first
		e.RemoveIPBlock("203.0.113.9")
		e.SetUserLists(nil, nil)
		if _, err := e.LoadList("b", "b", []byte("0.0.0.0 more.example.io\n")); err != nil {
			t.Fatal(err)
		}
		e.Compile()
	}
	stop.Store(true)
	wg.Wait()
	if after := len(snap.blockDomains) + len(snap.blockExact); after != before {
		t.Fatalf("published snapshot was mutated in place: %d -> %d entries", before, after)
	}
}

func TestContentDroppedAfterCompileStillReadableAndReloadable(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a.txt"), []byte(rebuildList), 0o600); err != nil {
		t.Fatal(err)
	}
	e := NewEngine()
	m := NewListManager(e, dir)
	m.SetSpecs([]ListSpec{{ID: "a", Name: "a", Enabled: true}})
	m.LoadCached()
	m.ReloadAll()
	if m.store["a"].Content != nil {
		t.Fatal("raw content should be freed after compile when it is on disk")
	}
	if !bytes.Equal(m.GetContent("a"), []byte(rebuildList)) {
		t.Fatal("GetContent must fall back to the on-disk cache")
	}
	m.ReloadAll() // second reload must read from disk, not silently load nothing
	if e.DecideDomain("blocked.example.com.").Action != Block {
		t.Fatal("rules lost on reload after content was dropped")
	}
}

func TestContentKeptWhenNotPersisted(t *testing.T) {
	m := NewListManager(NewEngine(), "") // no cache dir: nothing on disk
	m.SetSpecs([]ListSpec{{ID: "a", Name: "a", Enabled: true}})
	m.store["a"].Content = []byte(rebuildList)
	m.ReloadAll()
	if m.store["a"].Content == nil {
		t.Fatal("content must be kept when it can't be re-read from disk")
	}
}
