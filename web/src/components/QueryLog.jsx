import { useEffect, useState, useCallback, useRef } from 'react'
import { api } from '../api'
import { EmptyState } from './ui'

const fmtTime = (iso) => {
  const d = new Date(iso)
  return (
    d.toLocaleTimeString([], { hour12: false }) + ' ' + d.toLocaleDateString([], { month: 'short', day: 'numeric' })
  )
}

const ACTION_LABEL = {
  allowed: 'Allowed',
  blocked: 'Blocked',
  cached: 'Cached',
  error: 'Error',
  rewrite: 'Local DNS',
  'geo-blocked': 'Geo-blocked',
  'ip-blocked': 'IP-blocked',
  honeypot: 'Honeypot',
}

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
  // Re-entry guard so overlapping loads (auto-refresh tick, manual load,
  // visibility re-fetch) don't stack duplicate fetches. A ref, not state:
  // the guard must be synchronous and the value is never rendered.
  const busyRef = useRef(false)
  // The domain filter input, so the global / shortcut can jump straight to
  // it (the App shell dispatches 'irongrid:focus-log-search').
  const domainRef = useRef(null)
  // Reverse-DNS names and BGP/ISP owner info for the client IPs on this
  // page, resolved lazily via /api/log/hostnames + /api/log/asn (both
  // server-cached) and dropped when a client scrolls out of the loaded
  // window.
  const [hosts, setHosts] = useState({})
  const [asns, setAsns] = useState({})

  // Resolve hostnames + ISP info for the unique client IPs of the currently
  // loaded entries. The server caches results (PTR 1h/15m, ASN 24h), so the
  // 5-second auto-refresh stays cheap.
  useEffect(() => {
    const ips = [...new Set(entries.map((e) => e.client).filter(Boolean))].slice(0, 40)
    if (!ips.length) return
    let live = true
    api
      .hostnames(ips)
      .then((res) => {
        if (!live) return
        const names = res.hostnames || {}
        setHosts((prev) => {
          const cur = {}
          for (const e of entries) if (prev[e.client]) cur[e.client] = prev[e.client]
          return { ...cur, ...names }
        })
      })
      .catch(() => {})
    api
      .asnInfo(ips)
      .then((res) => {
        if (!live) return
        const infos = res.asn || {}
        setAsns((prev) => {
          const cur = {}
          for (const e of entries) if (prev[e.client]) cur[e.client] = prev[e.client]
          return { ...cur, ...infos }
        })
      })
      .catch(() => {})
    return () => {
      live = false
    }
  }, [entries])

  const load = useCallback(async () => {
    if (busyRef.current) return
    busyRef.current = true
    try {
      const res = await api.log({ limit: 200, action, domain, qtype, client })
      setEntries(res.entries || [])
    } catch {
      /* ignore transient */
    }
    busyRef.current = false
  }, [action, domain, qtype, client])

  useEffect(() => {
    load()
  }, [load])

  useEffect(() => {
    if (!autoRefresh) return
    const t = setInterval(load, 5000)
    // Refresh right away when the tab regains visibility instead of waiting
    // for the next 5s tick (same pattern as the dashboard): backgrounded
    // tabs get their timers throttled, so on return we want fresh data
    // immediately rather than up to 5s of stale rows.
    const onVisible = () => {
      if (document.visibilityState === 'visible') load()
    }
    document.addEventListener('visibilitychange', onVisible)
    return () => {
      clearInterval(t)
      document.removeEventListener('visibilitychange', onVisible)
    }
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

  // The global / shortcut lands here: focus the domain filter and select its
  // current text so typing replaces the old filter.
  useEffect(() => {
    const onFocus = () => {
      if (!domainRef.current) return
      domainRef.current.focus()
      domainRef.current.select()
    }
    window.addEventListener('irongrid:focus-log-search', onFocus)
    return () => window.removeEventListener('irongrid:focus-log-search', onFocus)
  }, [])

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
            ref={domainRef}
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
          <button className="btn ghost" onClick={load} aria-label="Refresh query log">
            ⟳
          </button>
          <button className="btn danger ghost" onClick={clearLog}>
            Clear
          </button>
        </div>
      </div>

      <div className="card table-card">
        {entries.length === 0 ? (
          <EmptyState
            icon={
              <svg
                width="20"
                height="20"
                viewBox="0 0 24 24"
                fill="none"
                stroke="currentColor"
                strokeWidth="1.8"
                strokeLinecap="round"
                strokeLinejoin="round"
                aria-hidden="true"
              >
                <line x1="8" y1="6" x2="21" y2="6" />
                <line x1="8" y1="12" x2="21" y2="12" />
                <line x1="8" y1="18" x2="21" y2="18" />
                <line x1="3" y1="6" x2="3.01" y2="6" />
                <line x1="3" y1="12" x2="3.01" y2="12" />
                <line x1="3" y1="18" x2="3.01" y2="18" />
              </svg>
            }
            title="No queries yet"
            body="Queries appear here the moment your server answers one — try a site on your network or run nslookup from a device pointed at this server."
          />
        ) : (
          <table className="table">
            <thead>
              <tr>
                <th>Time</th>
                <th>Client</th>
                <th>ISP</th>
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
                  <td>
                    <div className="mono">{e.client}</div>
                    {hosts[e.client] && (
                      <div className="dim small client-host" title={hosts[e.client]}>
                        {hosts[e.client]}
                      </div>
                    )}
                  </td>
                  <td className="dim small">
                    {/* Prefer the server's own attribution (entry.asn, from the local ip2asn
                        tables — instant, offline, and the same number the X-Irongrid-Client-ASN
                        header and asn-blocked reasons use), enriching it with the RIPEstat holder
                        name when one is available. Fall back to the RIPEstat lookup otherwise. */}
                    {e.asn ? (
                      <span
                        className="client-host"
                        title={`local IP→ASN: AS${e.asn}${asns[e.client]?.holder ? ` · ${asns[e.client].holder}` : ''}`}
                      >
                        AS{e.asn}
                        {asns[e.client]?.holder ? ` · ${asns[e.client].holder}` : ''}
                      </span>
                    ) : asns[e.client]?.asn ? (
                      <span
                        className="client-host"
                        title={`${asns[e.client].asn} · ${asns[e.client].holder || asns[e.client].name || ''}${asns[e.client].prefix ? ` · ${asns[e.client].prefix}` : ''}`}
                      >
                        {asns[e.client].asn} · {asns[e.client].holder || asns[e.client].name}
                      </span>
                    ) : (
                      <span className="dim">—</span>
                    )}
                  </td>
                  <td className="domain-cell" title={e.domain}>
                    {e.domain}
                  </td>
                  <td>
                    <span className="chip">{e.type}</span>
                  </td>
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
