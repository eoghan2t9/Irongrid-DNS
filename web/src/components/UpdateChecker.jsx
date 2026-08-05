import React, { useCallback, useEffect, useRef, useState } from 'react'
import { api } from '../api'

const DISMISS_KEY = 'irongrid_dismissed_update'
const INSTALL_CMD = 'curl -fsSL https://raw.githubusercontent.com/eoghan2t9/Irongrid-DNS/main/install.sh | bash'

// rich turns the GitHub changelog's **bold** and [label](url) into nodes.
function rich(text) {
  const out = []
  const re = /(\*\*[^*]+\*\*|\[[^\]]+\]\(https?:\/\/[^)\s]+\))/g
  let last = 0
  let m
  let k = 0
  while ((m = re.exec(text))) {
    if (m.index > last) out.push(text.slice(last, m.index))
    const tok = m[0]
    if (tok.startsWith('**')) {
      out.push(<strong key={k++}>{tok.slice(2, -2)}</strong>)
    } else {
      const mm = tok.match(/^\[([^\]]+)\]\((https?:\/\/[^)\s]+)\)$/)
      out.push(
        <a key={k++} href={mm[2]} target="_blank" rel="noreferrer">
          {mm[1]}
        </a>
      )
    }
    last = m.index + tok.length
  }
  if (last < text.length) out.push(text.slice(last))
  return out
}

// renderChangelog renders the release body with ## / ### headers and bullets.
function renderChangelog(body) {
  if (!body || !body.trim()) {
    return <p className="modal-note">No changelog was published for this release.</p>
  }
  const out = []
  let list = []
  let key = 0
  const flush = () => {
    if (list.length) {
      out.push(<ul key={`ul-${key++}`}>{list}</ul>)
      list = []
    }
  }
  body.split('\n').forEach((line) => {
    const t = line.trim()
    if (/^###\s+/.test(t)) {
      flush()
      out.push(<h5 key={key++}>{t.replace(/^###\s+/, '')}</h5>)
    } else if (/^##\s+/.test(t)) {
      flush()
      out.push(<h4 key={key++}>{t.replace(/^##\s+/, '')}</h4>)
    } else if (/^[-*]\s+/.test(t)) {
      list.push(<li key={key++}>{rich(t.replace(/^[-*]\s+/, ''))}</li>)
    } else if (t === '') {
      flush()
    } else {
      flush()
      out.push(<p key={key++}>{rich(t)}</p>)
    }
  })
  flush()
  return out
}

export default function UpdateChecker() {
  const [info, setInfo] = useState(null)
  const [loading, setLoading] = useState(false)
  const [show, setShow] = useState(false)
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
          <div className="modal" onClick={(e) => e.stopPropagation()} role="dialog" aria-modal="true">
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

            <div className="modal-body changelog">{renderChangelog(info.changelog)}</div>

            {info.download_url && (
              <div className="modal-install">
                <div className="field-hint">or update from the terminal:</div>
                <code>{INSTALL_CMD}</code>
              </div>
            )}

            <div className="modal-foot">
              {info.download_url ? (
                <a className="btn primary" href={info.download_url} target="_blank" rel="noreferrer">
                  ⬇ Download {info.asset_name}
                </a>
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
