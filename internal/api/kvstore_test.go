package api

import (
	"context"
	"sync"
	"testing"
	"time"
)

type memKVStore struct {
	mu   sync.Mutex
	data map[string][]byte
}

func newMemKVStore() *memKVStore {
	return &memKVStore{data: map[string][]byte{}}
}

func (m *memKVStore) GetKV(_ context.Context, key string) ([]byte, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	v, ok := m.data[key]
	if !ok {
		return nil, false
	}
	cp := make([]byte, len(v))
	copy(cp, v)
	return cp, true
}

func (m *memKVStore) SetKV(_ context.Context, key string, val []byte, _ time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := make([]byte, len(val))
	copy(cp, val)
	m.data[key] = cp
}

func (m *memKVStore) DelKV(_ context.Context, key string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.data, key)
}

func TestKVStorePersistence(t *testing.T) {
	store := newMemKVStore()
	now := time.Now()

	// hostCache: positive and negative entries survive a fresh instance.
	hc1 := newHostCacheWithStore(store)
	hc1.put("192.0.2.10", "router.lan", now)
	hc1.put("192.0.2.11", "", now)

	hc2 := newHostCacheWithStore(store)
	if name, ok := hc2.get("192.0.2.10", now.Add(time.Minute)); !ok || name != "router.lan" {
		t.Fatalf("hostCache positive restore = (%q, %v), want (router.lan, true)", name, ok)
	}
	if name, ok := hc2.get("192.0.2.11", now.Add(time.Minute)); !ok || name != "" {
		t.Fatalf("hostCache negative restore = (%q, %v), want (\"\", true)", name, ok)
	}

	// asnCache: positive and negative entries survive a fresh instance.
	ac1 := newASNCacheWithStore(store)
	ac1.put("192.0.2.10", asnInfo{ASN: "AS64500", Holder: "Example Net"}, now)
	ac1.put("192.0.2.11", asnInfo{}, now)

	ac2 := newASNCacheWithStore(store)
	if info, ok := ac2.get("192.0.2.10", now.Add(time.Minute)); !ok || info.ASN != "AS64500" {
		t.Fatalf("asnCache positive restore = (%+v, %v), want AS64500", info, ok)
	}
	if info, ok := ac2.get("192.0.2.11", now.Add(time.Minute)); !ok || info.ASN != "" {
		t.Fatalf("asnCache negative restore = (%+v, %v), want empty", info, ok)
	}

	// LoginGuard: lockout survives a fresh instance and clears on RecordSuccess.
	lg1 := NewLoginGuardWithStore(store)
	for range loginMaxFailures {
		lg1.RecordFailure("198.51.100.7")
	}
	lg2 := NewLoginGuardWithStore(store)
	if locked, rem := lg2.Locked("198.51.100.7"); !locked || rem <= 0 {
		t.Fatalf("LoginGuard lockout restore = (%v, %v), want (true, >0)", locked, rem)
	}
	lg2.RecordSuccess("198.51.100.7")
	lg3 := NewLoginGuardWithStore(store)
	if locked, _ := lg3.Locked("198.51.100.7"); locked {
		t.Fatalf("LoginGuard still locked after RecordSuccess")
	}
}
