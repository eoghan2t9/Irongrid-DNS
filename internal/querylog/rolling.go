// rollingAgg maintains the dashboard's aggregate set incrementally as the
// writer commits entries, so /api/stats polls are O(1) reads instead of a
// bounded re-walk of the stream every 30s (the old StatsBundle walk cost
// ~8µs, 15 allocs and 1.2KB per entry, i.e. up to ~820ms and 127MB of
// garbage per bucket at the 100k scan cap). The aggregate is owned by the
// writer goroutine (mutated under Lock, folded in only after a batch is
// durably in the stream) and read by API polls (snapshot under RLock).
//
// The 24h window is the 24 one-hour slots ending at the current hour —
// the same hour-aligned window the hourly chart has always used — so an
// entry at the window's far edge may be excluded up to an hour early
// (entries at the boundary of a live sliding window need per-entry expiry
// tracking to be exact; the walk was exact only because it re-read the
// stream). Entries are bucketed by their recorded query time (Entry.Time),
// so a backdated entry is properly outside the window. Today totals are
// maintained separately and reset when the day rolls over.
package querylog

import (
	"sync"
	"time"
)

// aggSlots is the number of one-hour slots covering the 24h window.
const aggSlots = 24

// slotAgg is one hour's counts, including per-domain/per-client maps so the
// top-N lists can age out with their slot instead of drifting.
type slotAgg struct {
	total, allowed, blocked, cached int64
	rtSum                           float64
	blockedDomains                  map[string]int64 // domain -> blocked count this hour
	clients                         map[string]int64 // client -> count this hour
}

type rollingAgg struct {
	mu sync.RWMutex

	// slotHour[i] is the unix hour of slots[i]; slots[0] is the oldest hour
	// (window start) and slots[aggSlots-1] the current hour. A zero
	// slotHour[0] means the ring is uninitialized (first add anchors it).
	slotHour [aggSlots]int64
	slots    [aggSlots]*slotAgg // nil = no entries that hour

	// Running 24h totals — the exact sum of the 24 slots, kept here so a
	// snapshot never re-sums or re-merges per-slot maps.
	total, allowed, blocked, cached int64
	rtSum                           float64
	blockedCnt                      map[string]int64
	clientCnt                       map[string]int64

	// Today totals since local midnight (todayDate is that midnight).
	// Reset lazily: on the first write after midnight and on any read once
	// the day has rolled over, so a quiet night can't leave a poll serving
	// yesterday's numbers.
	todayDate                           time.Time
	tTotal, tAllowed, tBlocked, tCached int64
	tRtSum                              float64
	tBlockedCnt                         map[string]int64
	tClientCnt                          map[string]int64
}

func newRollingAgg() *rollingAgg {
	return &rollingAgg{
		blockedCnt:  map[string]int64{},
		clientCnt:   map[string]int64{},
		tBlockedCnt: map[string]int64{},
		tClientCnt:  map[string]int64{},
	}
}

// midnightOf returns the local midnight starting t's day.
func midnightOf(t time.Time) time.Time {
	return time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, t.Location())
}

// resetTodayLocked zeroes the today counters and moves the boundary to
// now's midnight. Caller holds mu.
func (a *rollingAgg) resetTodayLocked(now time.Time) {
	a.todayDate = midnightOf(now)
	a.tTotal, a.tAllowed, a.tBlocked, a.tCached = 0, 0, 0, 0
	a.tRtSum = 0
	clear(a.tBlockedCnt)
	clear(a.tClientCnt)
}

// resetTodayIfNeeded drops the today counters once the day has rolled over.
// Called on read; the writer also resets on the first post-midnight write,
// but reads must not depend on a write happening.
func (a *rollingAgg) resetTodayIfNeeded(now time.Time) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if !a.todayDate.IsZero() && !now.Before(a.todayDate.Add(24*time.Hour)) {
		a.resetTodayLocked(now)
	}
}

// rollToLocked advances the ring so slots[aggSlots-1] is hour (the current
// hour, as a unix-hour value), aging out every slot that falls out of the
// window and subtracting its contribution from the running totals. Caller
// holds mu.
func (a *rollingAgg) rollToLocked(hour int64) {
	if a.slotHour[0] == 0 { // uninitialized: build the ring around hour
		for i := range aggSlots {
			a.slotHour[i] = hour - aggSlots + 1 + int64(i)
		}
		return
	}
	newest := a.slotHour[aggSlots-1]
	if hour <= newest {
		return
	}
	n := min(int(hour-newest), aggSlots) // long idle: the whole window rolled
	for i := range n {
		a.subtractSlotLocked(i)
	}
	copy(a.slotHour[:aggSlots-n], a.slotHour[n:])
	copy(a.slots[:aggSlots-n], a.slots[n:])
	for i := aggSlots - n; i < aggSlots; i++ {
		a.slotHour[i] = hour - aggSlots + 1 + int64(i)
		a.slots[i] = nil
	}
}

// subtractSlotLocked removes slot i's contribution from the running totals
// (its hour aged out of the window). Caller holds mu.
func (a *rollingAgg) subtractSlotLocked(i int) {
	s := a.slots[i]
	if s == nil {
		return
	}
	a.slots[i] = nil
	a.total -= s.total
	a.allowed -= s.allowed
	a.blocked -= s.blocked
	a.cached -= s.cached
	a.rtSum -= s.rtSum
	for d, c := range s.blockedDomains {
		if a.blockedCnt[d] -= c; a.blockedCnt[d] <= 0 {
			delete(a.blockedCnt, d)
		}
	}
	for c, n := range s.clients {
		if a.clientCnt[c] -= n; a.clientCnt[c] <= 0 {
			delete(a.clientCnt, c)
		}
	}
}

// add folds one committed entry into the aggregate. The ring anchors on
// the first entry's hour (an entry at the current hour sets the window
// end) and rolls forward as newer entries arrive, so seeding and live
// writes share one path.
func (a *rollingAgg) add(e Entry) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.addLocked(e)
}

// addLocked is add with mu held. Caller holds mu.
func (a *rollingAgg) addLocked(e Entry) {
	// Today totals, resetting when the entry crosses midnight.
	if !e.Time.Before(a.todayDate.Add(24 * time.Hour)) {
		a.resetTodayLocked(e.Time)
	}
	if !e.Time.Before(a.todayDate) {
		a.tTotal++
		a.tRtSum += float64(e.ResponseTimeMS)
		switch e.Action {
		case "allowed":
			a.tAllowed++
		case "blocked":
			a.tBlocked++
			a.tBlockedCnt[e.Domain]++
		case "cached":
			a.tCached++
		}
		a.tClientCnt[e.Client]++
	}

	// 24h window: slot the entry by its own hour.
	h := e.Time.Truncate(time.Hour).Unix() / 3600 // unix hour
	if a.slotHour[0] == 0 {
		a.rollToLocked(h)
	}
	if h < a.slotHour[0] {
		return // older than the window: not counted
	}
	if h > a.slotHour[aggSlots-1] {
		a.rollToLocked(h)
	}
	if h < a.slotHour[0] {
		return
	}
	idx := int(h - a.slotHour[0])
	s := a.slots[idx]
	if s == nil {
		s = &slotAgg{}
		a.slots[idx] = s
	}
	s.total++
	s.rtSum += float64(e.ResponseTimeMS)
	switch e.Action {
	case "allowed":
		s.allowed++
	case "blocked":
		s.blocked++
		if s.blockedDomains == nil {
			s.blockedDomains = map[string]int64{}
		}
		s.blockedDomains[e.Domain]++
	case "cached":
		s.cached++
	}
	if s.clients == nil {
		s.clients = map[string]int64{}
	}
	s.clients[e.Client]++

	a.total++
	a.rtSum += float64(e.ResponseTimeMS)
	switch e.Action {
	case "allowed":
		a.allowed++
	case "blocked":
		a.blocked++
		a.blockedCnt[e.Domain]++
	case "cached":
		a.cached++
	}
	a.clientCnt[e.Client]++
}

// snapshot returns the aggregate bundle under RLock: O(1) plus the two
// top-N sorts (over the running maps, which are read-only here).
func (a *rollingAgg) snapshot() StatsBundle {
	a.mu.RLock()
	defer a.mu.RUnlock()

	stats := emptyStats()
	if a.total > 0 {
		stats["avg_rt_ms"] = a.rtSum / float64(a.total)
	}
	stats["total"] = a.total
	stats["allowed"] = a.allowed
	stats["blocked"] = a.blocked
	stats["cached"] = a.cached
	stats["top_blocked"] = topN(a.blockedCnt, 10)
	stats["top_clients"] = topN(a.clientCnt, 10)

	today := emptyStats()
	if a.tTotal > 0 {
		today["avg_rt_ms"] = a.tRtSum / float64(a.tTotal)
	}
	today["total"] = a.tTotal
	today["allowed"] = a.tAllowed
	today["blocked"] = a.tBlocked
	today["cached"] = a.tCached
	today["top_blocked"] = topN(a.tBlockedCnt, 10)
	today["top_clients"] = topN(a.tClientCnt, 10)

	hourly := make([]HourBucket, 0, aggSlots)
	for i := range aggSlots {
		var total, blocked int64
		if s := a.slots[i]; s != nil {
			total, blocked = s.total, s.blocked
		}
		hourly = append(hourly, HourBucket{
			Hour:    time.Unix(a.slotHour[i]*3600, 0).Format(time.RFC3339),
			Total:   total,
			Blocked: blocked,
		})
	}
	return StatsBundle{Stats: stats, Today: today, Hourly: hourly}
}

// clear resets the aggregate after the stream was deleted. The ring is
// fully zeroed so the next add re-anchors it.
func (a *rollingAgg) clear() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.slotHour = [aggSlots]int64{}
	a.slots = [aggSlots]*slotAgg{}
	a.total, a.allowed, a.blocked, a.cached = 0, 0, 0, 0
	a.rtSum = 0
	clear(a.blockedCnt)
	clear(a.clientCnt)
	a.todayDate = time.Time{}
	a.tTotal, a.tAllowed, a.tBlocked, a.tCached = 0, 0, 0, 0
	a.tRtSum = 0
	clear(a.tBlockedCnt)
	clear(a.tClientCnt)
}
