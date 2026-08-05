import React, { useEffect, useState, useCallback } from 'react'
import { api } from '../api'

const fmtTime = (iso) => {
  const d = new Date(iso)
  return d.toLocaleTimeString([], { hour12: false }) + ' ' + d.toLocaleDateString([], { month: 'short', day: 'numeric' })
}

const ACTION_LABEL = { allowed: 'Allowed', blocked: 'Blocked', cached: 'Cached', error: 'Error', rewrite: 'Local DNS' }

export default function QueryLog() {
  const [entries, setEntries] = useState([])
  const [action, setAction] = useState('')
  const [domain, setDomain] = useState('')
  const [qtype, setQtype] = useState('')
  const [autoRefresh, setAutoRefresh] = useState(true)
  const [busy, setBusy] = useState(false)

  const load = useCallback(async () => {
    if (busy) return
    setBusy(true)
    try {
      const res = await api.log({ limit: 200, action, domain, qtype })
      setEntries(res.entries || [])
    } catch (e) {
      /* ignore transient */
    }
    setBusy(false)
  }, [action, domain, qtype])

  useEffect(() => {
    load()
  }, [load])

  useEffect(() => {
    if (!autoRefresh) return
    const t = setInterval(load, 5000)
    return () => clearInterval(t)
  }, [autoRefresh, load])

  const clearLog = async () => {
    if (!confirm('Clear the entire query log?')) return
    await api.clearLog()
    load()
  }

  return (
    <div className="stack">
      <div className="card">
        <div className="log-filters">
          <select className="input" value={action} onChange={(e) => setAction(e.target.value)}>
            <option value="">All actions</option>
            <option value="allowed">Allowed</option>
            <option value="blocked">Blocked</option>
            <option value="cached">Cached</option>
            <option value="error">Errors</option>
            <option value="rewrite">Local DNS</option>
          </select>
          <input
            className="input"
            placeholder="Filter by domain…"
            value={domain}
            onChange={(e) => setDomain(e.target.value)}
          />
          <input
            className="input"
            placeholder="Type (A, AAAA, TXT…)"
            value={qtype}
            onChange={(e) => setQtype(e.target.value)}
          />
          <label className="toggle-label">
            <input type="checkbox" checked={autoRefresh} onChange={(e) => setAutoRefresh(e.target.checked)} />
            Live
          </label>
          <button className="btn ghost" onClick={load} aria-label="Refresh query log">⟳</button>
          <button className="btn danger ghost" onClick={clearLog}>Clear</button>
        </div>
      </div>

      <div className="card table-card">
        {entries.length === 0 ? (
          <div className="empty">No queries recorded yet. Send a DNS query to your server.</div>
        ) : (
          <table className="table">
            <thead>
              <tr>
                <th>Time</th>
                <th>Client</th>
                <th>Domain</th>
                <th>Type</th>
                <th>Action</th>
                <th>Reason / Upstream</th>
                <th>ms</th>
              </tr>
            </thead>
            <tbody>
              {entries.map((e) => (
                <tr key={e.id}>
                  <td className="mono dim">{fmtTime(e.time)}</td>
                  <td className="mono">{e.client}</td>
                  <td className="domain-cell" title={e.domain}>{e.domain}</td>
                  <td><span className="chip">{e.type}</span></td>
                  <td>
                    <span className={`badge badge-${e.action}`}>{ACTION_LABEL[e.action] || e.action}</span>
                  </td>
                  <td className="dim small">{e.reason || e.upstream || ''}</td>
                  <td className="mono dim">{e.response_time_ms}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  )
}
