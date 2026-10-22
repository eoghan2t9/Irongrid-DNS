import { useCallback, useEffect, useRef, useState } from 'react'
import { api } from '../api'
import { useToast } from '../toast-context'

const RESTART_POLL_MS = 1500
const RESTART_TIMEOUT_MS = 90000

// statusOf folds a tool row into one label + badge tone, most urgent first.
function statusOf(t) {
  if (t.error) return { label: 'Check failed', badge: 'error' }
  if (t.restart_pending) return { label: 'Restart needed', badge: 'warn' }
  if (t.update_available) return { label: 'Update available', badge: 'cached' }
  if (!t.current_version) return { label: 'Not installed', badge: 'warn' }
  return { label: 'Up to date', badge: 'allowed' }
}

const fmtChecked = (iso) => {
  if (!iso) return ''
  const d = new Date(iso)
  return (
    d.toLocaleTimeString([], { hour12: false }) + ' ' + d.toLocaleDateString([], { month: 'short', day: 'numeric' })
  )
}

// pollForVersion polls /api/status until the service reports newVersion, then
// reloads the page; onTimeout runs if it never does. It lives outside the
// component because it reads the clock, which render-scope code must not.
function pollForVersion(newVersion, timerRef, onTimeout) {
  const deadline = Date.now() + RESTART_TIMEOUT_MS
  const tick = async () => {
    try {
      const st = await api.status({ cache: 'no-store' })
      const running = st?.version_tag || st?.version || ''
      if (running.includes(newVersion)) {
        window.location.reload()
        return
      }
    } catch {
      // service still down — keep polling
    }
    if (Date.now() < deadline) {
      timerRef.current = setTimeout(tick, RESTART_POLL_MS)
    } else {
      onTimeout()
    }
  }
  timerRef.current = setTimeout(tick, RESTART_POLL_MS)
}

export default function Updates() {
  const toast = useToast()
  const [data, setData] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  // id of the tool currently being updated; one at a time keeps the page
  // honest about which restart/reload is in flight.
  const [busy, setBusy] = useState('')
  const [notice, setNotice] = useState({})
  const pollRef = useRef(null)

  const load = useCallback(async () => {
    setLoading(true)
    try {
      setData(await api.updates())
      setError('')
    } catch (e) {
      setError(e.message || 'Could not check for updates')
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    load()
    // pollRef holds a timer id, not a DOM node: the latest value is the one
    // to cancel on unmount.
    // eslint-disable-next-line react-hooks/exhaustive-deps
    return () => clearTimeout(pollRef.current)
  }, [load])

  const say = (id, msg) => setNotice((n) => ({ ...n, [id]: msg }))

  // Irongrid replaces its own binary and restarts, so the page goes away
  // under us: poll /api/status until the new version answers, then reload.
  // The signed session cookie survives the restart, so the user stays in.
  const waitForIrongrid = (newVersion) =>
    pollForVersion(newVersion, pollRef, () => {
      setBusy('')
      say('irongrid', 'The service restarted slowly — reload the page to continue.')
    })

  const install = async (tool) => {
    if (busy) return
    if (
      tool.id === 'dragonfly' &&
      !confirm(
        `Update Dragonfly to ${tool.latest_version}?\n\nThe cache restarts for a few seconds. Cached answers reload from a snapshot taken just before.`,
      )
    )
      return
    setBusy(tool.id)
    say(tool.id, '')
    try {
      if (tool.id === 'irongrid') {
        const res = await api.updateInstall()
        if (res?.restarting) {
          say('irongrid', `Installed ${res.new_version} — restarting the service…`)
          waitForIrongrid(res.new_version)
          return
        }
        say('irongrid', res?.note || 'Installed. Restart Irongrid manually to run the new version.')
      } else if (tool.id === 'dragonfly') {
        const res = await api.updatesDragonflyInstall()
        if (!res.installed) toast(res.note || 'Dragonfly is already up to date')
        else if (res.restarting) toast(`Dragonfly updated to ${res.running_version || res.new_version}`)
        else toast(res.note || 'Dragonfly installed — restart it to apply', 'error')
        if (res.note) say('dragonfly', res.note)
      } else if (tool.id === 'cloudflared') {
        const res = await api.tunnelCheckCloudflaredUpdate()
        toast(res.installed ? `cloudflared updated to ${res.new_version}` : 'cloudflared is already up to date')
        if (res.note) say('cloudflared', res.note)
      }
      await load()
    } catch (e) {
      toast('Update failed: ' + e.message, 'error')
    }
    setBusy('')
  }

  const restartDragonfly = async () => {
    if (busy) return
    if (!confirm('Restart Dragonfly now? The cache is unavailable for a few seconds.')) return
    setBusy('dragonfly')
    try {
      const res = await api.updatesDragonflyRestart()
      if (res.restarting) toast(`Dragonfly restarted${res.running_version ? ` (${res.running_version})` : ''}`)
      else toast(res.note || 'Restart did not run', 'error')
      await load()
    } catch (e) {
      toast('Restart failed: ' + e.message, 'error')
    }
    setBusy('')
  }

  const tools = data?.tools || []

  return (
    <div className="stack">
      <div className="row-between">
        <p className="field-hint" style={{ fontSize: 13, margin: 0 }}>
          The programs Irongrid depends on, checked against their latest releases.
          {data?.checked_at && <> Checked {fmtChecked(data.checked_at)}.</>}
        </p>
        <button className="btn ghost small" onClick={load} disabled={loading || !!busy}>
          ⟳ {loading ? 'Checking…' : 'Check again'}
        </button>
      </div>

      {error && (
        <div className="card">
          <div className="empty">{error}</div>
        </div>
      )}

      {loading && !data && <div className="empty">Checking for updates…</div>}

      {tools.map((t) => {
        const st = statusOf(t)
        const working = busy === t.id
        return (
          <div key={t.id} className="card">
            <div className="row-between">
              <div>
                <div className="row" style={{ gap: 10, alignItems: 'center' }}>
                  <strong>{t.name}</strong>
                  <span className={`badge badge-${st.badge}`}>{st.label}</span>
                </div>
                <div className="field-hint" style={{ marginTop: 4 }}>
                  {t.purpose}
                </div>
              </div>
              <div className="row" style={{ gap: 8, alignItems: 'center' }}>
                {t.release_url && (
                  <a className="btn tiny ghost" href={t.release_url} target="_blank" rel="noreferrer">
                    Release notes ↗
                  </a>
                )}
                {t.restart_pending && t.id === 'dragonfly' && (
                  <button className="btn small" onClick={restartDragonfly} disabled={!!busy}>
                    {working ? 'Restarting…' : 'Restart Dragonfly'}
                  </button>
                )}
                {t.update_available && !t.error && (
                  <button className="btn primary small" onClick={() => install(t)} disabled={!!busy || !t.installable}>
                    {working ? 'Updating…' : `Update to ${t.latest_version || 'latest'}`}
                  </button>
                )}
              </div>
            </div>

            <div className="row" style={{ gap: 8, alignItems: 'center', marginTop: 12 }}>
              <span className="dim small">Installed</span>
              <span className="chip">{t.current_version || '—'}</span>
              {t.running_version && t.running_version !== t.current_version && (
                <>
                  <span className="dim small">running</span>
                  <span className="chip">{t.running_version}</span>
                </>
              )}
              {t.latest_version && (
                <>
                  <span className="dim small">latest</span>
                  <span className={t.update_available ? 'chip chip-new' : 'chip'}>{t.latest_version}</span>
                </>
              )}
            </div>

            {(t.error || t.note || notice[t.id]) && (
              <div className="field-hint" style={{ marginTop: 10 }}>
                {t.error ? `Could not check: ${t.error}` : notice[t.id] || t.note}
              </div>
            )}
          </div>
        )
      })}
    </div>
  )
}
