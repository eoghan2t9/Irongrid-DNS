import React, { useCallback, useEffect, useState } from 'react'
import { api } from '../api'
import { renderMarkdown } from '../markdown'

const GITHUB_URL = 'https://github.com/eoghan2t9/Irongrid-DNS/releases'

export default function Changelog() {
  const [data, setData] = useState(null)
  const [loading, setLoading] = useState(true)

  const load = useCallback(async () => {
    setLoading(true)
    try {
      setData(await api.updateChangelog())
    } catch (e) {
      setData({ error: e.message })
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    load()
  }, [load])

  const releases = data?.releases || []
  const hasError = !loading && (!data || data.error || releases.length === 0)

  return (
    <div className="changelog-page">
      <div className="row-between" style={{ marginBottom: 16 }}>
        <div className="page-intro">
          <p className="field-hint" style={{ fontSize: 13, margin: 0 }}>
            Release notes for Irongrid DNS
            {data?.current_version ? (
              <> — you're running <span className="chip chip-new">{data.current_version}</span></>
            ) : null}
          </p>
        </div>
        <button className="btn ghost small" onClick={load} disabled={loading}>
          ⟳ {loading ? 'Refreshing…' : 'Refresh'}
        </button>
      </div>

      {loading && <div className="empty">Loading releases…</div>}

      {hasError && (
        <div className="card">
          <div className="empty">
            {data?.error || 'No releases found yet.'}
            <div style={{ marginTop: 10 }}>
              <a className="btn small" href={GITHUB_URL} target="_blank" rel="noreferrer">
                Open releases on GitHub
              </a>
            </div>
          </div>
        </div>
      )}

      {!loading && !hasError && (
        <div className="changelog-list">
          {releases.map((r) => (
            <article key={r.tag_name} className="card changelog-entry">
              <header className="row-between changelog-entry-head">
                <div className="changelog-tags">
                  <span className="chip chip-new">{r.tag_name}</span>
                  {r.name && r.name !== r.tag_name && (
                    <span className="changelog-name">{r.name}</span>
                  )}
                </div>
                <div className="changelog-meta">
                  {r.published_at && (
                    <span className="modal-date">
                      {new Date(r.published_at).toLocaleDateString(undefined, {
                        year: 'numeric',
                        month: 'short',
                        day: 'numeric',
                      })}
                    </span>
                  )}
                  {r.html_url && (
                    <a className="btn tiny ghost" href={r.html_url} target="_blank" rel="noreferrer">
                      GitHub ↗
                    </a>
                  )}
                </div>
              </header>
              <div className="changelog">{renderMarkdown(r.body)}</div>
            </article>
          ))}
        </div>
      )}
    </div>
  )
}
