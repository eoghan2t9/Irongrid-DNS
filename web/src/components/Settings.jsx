import React, { useEffect, useState, useCallback } from 'react'
import { api } from '../api'

export default function Settings() {
  const [config, setConfig] = useState(null)
  const [diagName, setDiagName] = useState('example.com')
  const [diagType, setDiagType] = useState('A')
  const [diagResult, setDiagResult] = useState(null)
  const [msg, setMsg] = useState('')

  const load = useCallback(async () => {
    try {
      setConfig(await api.config())
    } catch { /* ignore */ }
  }, [])

  useEffect(() => { load() }, [load])

  const runDiag = async (e) => {
    e.preventDefault()
    try {
      const r = await api.diagDNS(diagName, diagType)
      setDiagResult(r)
    } catch (err) {
      setDiagResult({ error: err.message })
    }
  }

  const flush = async () => {
    const r = await api.flushCache()
    setMsg(`Cache flushed (${r.deleted} keys removed)`)
  }

  return (
    <div className="stack">
      {msg && <div className="info-banner">{msg}</div>}

      <div className="card">
        <h3>DNS diagnostic</h3>
        <form onSubmit={runDiag} className="form-grid">
          <input className="input" value={diagName} onChange={(e) => setDiagName(e.target.value)} />
          <select className="input" value={diagType} onChange={(e) => setDiagType(e.target.value)}>
            {['A', 'AAAA', 'TXT', 'MX', 'NS', 'CNAME'].map((t) => <option key={t}>{t}</option>)}
          </select>
          <button className="btn primary" type="submit">Resolve</button>
        </form>
        {diagResult && (
          <div className="diag-box">
            {diagResult.error ? (
              <div className="error-text">{diagResult.error}</div>
            ) : (
              <>
                <div className="dim small">
                  via <span className="mono">{diagResult.upstream}</span> · rcode {diagResult.rcode}
                  {diagResult.blocked_by_ip && <span className="error-text"> · blocked by IP rule ({diagResult.reason})</span>}
                </div>
                <ul className="diag-answers">
                  {(diagResult.answers || []).map((a, i) => <li key={i} className="mono">{a}</li>)}
                </ul>
              </>
            )}
          </div>
        )}
      </div>

      <div className="card">
        <h3>Cache &amp; maintenance</h3>
        <div className="quick-actions">
          <button className="btn" onClick={flush}>Flush DNS cache (Dragonfly)</button>
          <button className="btn" onClick={() => api.refreshLists().then(() => setMsg('Blocklists refreshed'))}>Refresh blocklists</button>
        </div>
      </div>

      <div className="card">
        <h3>Configuration</h3>
        {!config ? (
          <div className="empty">Could not load configuration.</div>
        ) : (
          <pre className="config-view">{JSON.stringify(config, null, 2)}</pre>
        )}
        <p className="dim small">
          Listeners, upstreams, cache and TLS are configured in <code>irongrid.yaml</code> — edit it and restart the
          service to apply changes.
        </p>
      </div>
    </div>
  )
}
