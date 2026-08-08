import React, { useEffect, useState, useCallback } from 'react'
import { api } from '../api'

const fmtTime = (iso) => {
  const d = new Date(iso)
  return d.toLocaleTimeString([], { hour12: false }) + ' ' + d.toLocaleDateString([], { month: 'short', day: 'numeric' })
}

const ACTION_LABEL = { allowed: 'Allowed', blocked: 'Blocked', cached: 'Cached', error: 'Error', rewrite: 'Local DNS', 'geo-blocked': 'Geo-blocked', 'ip-blocked': 'IP-blocked', honeypot: 'Honeypot' }

export default function QueryLog() {
  const [entries, setEntries] = useState([])
  const [action, setAction] = useState('')
  const [domain, setDomain] = useState('')
  const [qtype, setQtype] = useState('')
  // The client filter can be pre-set via ?client=… in the URL — the
  // dashboard's top-client rows deep-link here — so seed it from the
  // address bar on mount.
  const [client, setClient] = useState(() => new URLSearchParams(window.location.search).get('client') || '')
  const [autoRefresh, setAutoRefresh] = useState(true)
  const [busy, setBusy] = useState(false)

  const load = useCallback(async () => {
    if (busy) return
    setBusy(true)
    try {
      const res = await api.log({ limit: 200, action, domain, qtype, client })
      setEntries(res.entries || [])
    } catch (e) {
      /* ignore transient */
    }
    setBusy(false)
  }, [action, domain, qtype, client])

  useEffect(() => {
    load()
  }, [load])

  useEffect(() => {
    if (!autoRefresh) return
    const t = setInterval(load, 5000)
    return () => clearInterval(t)
  }, [autoRefresh, load])

  // Back/forward: if the URL's client filter changes (e.g. back from a
  // deep-linked client view to the plain log), re-sync the filter state.
  useEffect(() => {
    const onPop = () => setClient(new URLSearchParams(window.location.search).get('client') || '')
    window.addEventListener('popstate', onPop)
    return () => window.removeEventListener('popstate', onPop)
  }, [])

  // setClientFilter keeps the filter in the address bar so it survives a
  // refresh and stays shareable, without a page reload.
  const setClientFilter = (v) => {
    setClient(v)
    const u = new URL(window.location)
    if (v) u.searchParams.set('client', v)
    else u.searchParams.delete('client')
    window.history.replaceState(null, '', u)
  }

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
            <option value="geo-blocked">Geo-blocked</option>
            <option value="ip-blocked">IP-blocked</option>
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
          <input
            className="input"
            placeholder="Client IP…"
            value={client}
            onChange={(e) => setClientFilter(e.target.value)}
            title="Filter by source client IP (exact match)"
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
