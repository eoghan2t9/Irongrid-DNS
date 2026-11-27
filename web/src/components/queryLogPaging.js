// Helpers for the Query Log page's paging. Entry IDs are "<ms>-<seq>" and sort
// chronologically, so "newer" is a numeric comparison of the two parts.

export const PAGE_SIZE = 200
// Cap on entries held in the page; the oldest are dropped past this so a long
// "Live" session can't grow the table without bound.
export const MAX_ENTRIES = 5000

export function compareIds(a, b) {
  const [am, as] = a.split('-').map(Number)
  const [bm, bs] = b.split('-').map(Number)
  return am !== bm ? am - bm : as - bs
}

// mergeHead folds a freshly fetched newest page (head) into the entries already
// on screen (prev, newest first), so the live refresh adds new rows on top
// without discarding older pages the user has loaded.
//
// head is the newest contiguous run of entries, so if it overlaps prev nothing
// can be missing between them. If it does not overlap (more arrived since the
// last refresh than one page holds, or the log was cleared) the join point is
// unknown, so the list starts over from head.
//
// Returns { list, cursor }. cursor is the new "load older" cursor when it must
// change (a reset or a trim), or undefined to keep the current one.
export function mergeHead(prev, head, headNext = '') {
  if (!prev.length || !head.length) return { list: head, cursor: headNext }
  const newest = prev[0].id
  const fresh = head.filter((e) => compareIds(e.id, newest) > 0)
  if (fresh.length === head.length) return { list: head, cursor: headNext }
  if (!fresh.length) return { list: prev, cursor: undefined }
  const list = [...fresh, ...prev]
  if (list.length > MAX_ENTRIES) {
    const kept = list.slice(0, MAX_ENTRIES)
    // Older entries were dropped from the bottom, so resume from the last one kept.
    return { list: kept, cursor: kept[kept.length - 1].id }
  }
  return { list, cursor: undefined }
}

// appendOlder adds a page of older entries below the current list, skipping any
// already present.
export function appendOlder(prev, more) {
  const seen = new Set(prev.map((e) => e.id))
  return [...prev, ...more.filter((e) => !seen.has(e.id))]
}
