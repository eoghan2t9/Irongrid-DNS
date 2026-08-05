import React, { useCallback, useEffect, useRef, useState } from 'react'
import { api } from '../api'
import { renderMarkdown } from '../markdown'

const DISMISS_KEY = 'irongrid_dismissed_update'
const INSTALL_CMD = 'curl -fsSL https://raw.githubusercontent.com/eoghan2t9/Irongrid-DNS/main/install.sh | bash'

export default function UpdateChecker({ onNavigate }) {
  const [info, setInfo] = useState(null)
  const [loading, setLoading] = useState(false)
  const [show, setShow] = useState(false)
  // idle | downloading | restarting
  const [installing, setInstalling] = useState('idle')
  const [installNotice, setInstallNotice] = useState('')
  const autoChecked = useRef(false)

  const dismissedFor = (version) => version && localStorage.getItem(DISMISS_KEY) === version

  const check = useCallback(
    async (force = false) => {
      if (loading) return
      setLoading(true)
      try {
        const res = await api.updateCheck()
        setInfo(res)
        if (res && res.available && (force || !dismissedFor(res.latest_version))) {
          setShow(true)
        }
      } catch (e) {
        setInfo({ error: e.message })
      } finally {
        setLoading(false)
      }
    },
    [loading]
  )

  // Auto-check once shortly after the dashboard loads. The guard lives
  // inside the timeout so StrictMode's double effect (mount → cleanup →
  // mount) still fires exactly once.
  useEffect(() => {
    const t = setTimeout(() => {
      if (!autoChecked.current) {
        autoChecked.current = true
        check()
      }
    }, 4000)
    return () => clearTimeout(t)
  }, [check])

  // Close on Escape.
  useEffect(() => {
    if (!show) return
    const onKey = (e) => e.key === 'Escape' && setShow(false)
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [show])

  const dismiss = (forever) => {
    if (forever && info) localStorage.setItem(DISMISS_KEY, info.latest_version || '')
    setShow(false)
  }

  // In-place update: the server downloads the release, verifies its checksum
  // and swaps its own binary, then restarts the service. The page reloads
  // once the service is back (the session cookie keeps us logged in).
  const install = async () => {
    if (installing !== 'idle' || !info) return
    setInstallNotice('')
    setInstalling('downloading')
    try {
      const res = await api.updateInstall()
      if (res && res.restarting) {
        setInstalling('restarting')
        setInstallNotice('Installed — restarting the service…')
        setTimeout(() => window.location.reload(), 6000)
      } else {
        setInstalling('idle')
        setInstallNotice((res && res.note) || 'Update installed. Restart Irongrid manually to apply it.')
      }
    } catch (e) {
      setInstalling('idle')
      setInstallNotice(e.message || 'Update failed')
    }
  }

  const badge = info && info.available && !dismissedFor(info.latest_version)

  return (
    <>
      <button
        className="btn ghost small updater-btn"
        onClick={() => check(true)}
        disabled={loading}
        title={info?.error ? `Update check failed: ${info.error}` : 'Check for updates'}
      >
        ⬆ {loading ? 'Checking…' : 'Updates'}
        {badge && <span className="updater-dot" />}
      </button>

      {show && info && (
        <div className="modal-overlay" onClick={() => setShow(false)}>
          <div className="modal updater-modal" onClick={(e) => e.stopPropagation()} role="dialog" aria-modal="true">
            <div className="modal-head">
              <div>
                <div className="modal-title">New version available ✨</div>
                <div className="modal-sub">
                  <span className="chip">{info.current_version}</span>
                  <span className="modal-arrow">→</span>
                  <span className="chip chip-new">{info.latest_version}</span>
                  {info.published_at && <span className="modal-date">released {new Date(info.published_at).toLocaleDateString()}</span>}
                </div>
              </div>
              <button className="modal-x" onClick={() => setShow(false)} aria-label="Close">
                ✕
              </button>
            </div>

            <div className="modal-body changelog">{renderMarkdown(info.changelog)}</div>

            {info.download_url && (
              <div className="modal-install">
                <div className="field-hint">or update from the terminal:</div>
                <code>{INSTALL_CMD}</code>
                <a className="manual-link" href={info.download_url} target="_blank" rel="noreferrer">
                  or download {info.asset_name} manually
                </a>
              </div>
            )}

            {installNotice && <div className="modal-note install-note">{installNotice}</div>}

            <div className="modal-foot">
              {info.download_url ? (
                <button className="btn primary" onClick={install} disabled={installing !== 'idle'}>
                  {installing === 'downloading'
                    ? '⬇ Downloading…'
                    : installing === 'restarting'
                      ? '⟳ Restarting…'
                      : `⬇ Install ${info.latest_version}`}
                </button>
              ) : (
                info.release_url && (
                  <a className="btn primary" href={info.release_url} target="_blank" rel="noreferrer">
                    View release
                  </a>
                )
              )}
              {info.release_url && (
                <a className="btn" href={info.release_url} target="_blank" rel="noreferrer">
                  Release notes
                </a>
              )}
              {onNavigate && (
                <button
                  className="btn"
                  onClick={() => {
                    setShow(false)
                    onNavigate('changelog')
                  }}
                >
                  Full changelog
                </button>
              )}
              <span className="modal-spacer" />
              <button className="btn ghost" onClick={() => dismiss(false)}>
                Later
              </button>
              <button className="btn ghost" onClick={() => dismiss(true)}>
                Don't show again
              </button>
            </div>
          </div>
        </div>
      )}
    </>
  )
}
