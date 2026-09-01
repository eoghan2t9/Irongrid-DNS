import { useEffect } from 'react'

// usePolling re-fires `load` every intervalMs, and immediately again when
// the tab regains visibility — a backgrounded tab gets its timers
// throttled by the browser, so on return this clears any staleness (and
// any leftover error banner) without waiting up to intervalMs for the next
// tick. Every polling view used to hand-roll this exact setInterval +
// visibilitychange pair with small, easy-to-miss variations — Dhcp's had no
// visibility listener at all, so a backgrounded tab could sit on a stale
// lease table for minutes after being restored.
//
// This hook owns only the *recurring* part. Call the initial load yourself
// (typically `useEffect(() => { load() }, [load])`) — some callers (e.g.
// QueryLog reacting to a filter change) need that initial call to run
// regardless of whether polling itself is currently enabled.
export function usePolling(load, intervalMs, enabled = true) {
  useEffect(() => {
    if (!enabled) return
    const t = setInterval(load, intervalMs)
    const onVisible = () => {
      if (document.visibilityState === 'visible') load()
    }
    document.addEventListener('visibilitychange', onVisible)
    return () => {
      clearInterval(t)
      document.removeEventListener('visibilitychange', onVisible)
    }
  }, [load, intervalMs, enabled])
}
