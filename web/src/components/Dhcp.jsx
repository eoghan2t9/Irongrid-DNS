import { useEffect, useState, useCallback } from 'react'
import { api } from '../api'

export default function Dhcp() {
  const [data, setData] = useState(null)
  const [error, setError] = useState('')

  const load = useCallback(async () => {
    try {
      setData(await api.dhcpLeases())
      setError('')
    } catch (e) {
      setError(e.message)
    }
  }, [])

  useEffect(() => { load() }, [load])

  // Poll every 10s so a lease table changes on its own (new device boots,
  // lease expires, hostname registers) without a manual refresh.
  useEffect(() => {
    const t = setInterval(load, 10000)
    return () => clearInterval(t)
  }, [load])

  const leases = (data && data.leases) || []
  const enabled = !!(data && data.enabled)
  const v4 = leases.filter((l) => l.ip.includes('.'))
  const v6 = leases.filter((l) => !l.ip.includes('.'))

  const row = (l) => {
    const expired = !l.static && l.expires && new Date(l.expires).getTime() < Date.now()
    return (
      <tr key={l.ip + (l.mac || '') + (l.duid || '')} className={expired ? 'row-dim' : ''}>
        <td className="mono">{l.ip}</td>
        <td className="mono dim">{l.mac || l.duid || '—'}</td>
        <td>{l.hostname ? <span className="strong">{l.hostname}</span> : <span className="dim">—</span>}</td>
        <td>
          {l.static ? (
            <span className="badge badge-cached">static</span>
          ) : l.expires ? (
            <span className="dim small">
              {expired ? (
                <span className="error-text">expired</span>
              ) : (
                <>until {new Date(l.expires).toLocaleString()}</>
              )}
            </span>
          ) : (
            <span className="dim small">—</span>
          )}
        </td>
      </tr>
    )
  }

  const table = (title, rows) => (
    <div className="card" key={title}>
      <h3>{title} <span className="dim small">({rows.length})</span></h3>
      {rows.length === 0 ? (
        <p className="dim small">
          No {title.toLowerCase()} leases yet — devices that request an address from this server appear here.
        </p>
      ) : (
        <table className="table">
          <thead>
            <tr>
              <th>Address</th>
              <th>MAC / DUID</th>
              <th>Hostname</th>
              <th>Lease</th>
            </tr>
          </thead>
          <tbody>{rows.map(row)}</tbody>
        </table>
      )}
    </div>
  )

  return (
    <div className="stack">
      <div className="card">
        <div className="row-between">
          <h3 style={{ margin: 0 }}>DHCP server</h3>
          <span
            className="badge"
            style={enabled
              ? { background: 'rgba(46, 204, 113, 0.12)', borderColor: 'rgba(46, 204, 113, 0.35)', color: 'var(--emerald)' }
              : { background: 'rgba(217, 154, 27, 0.12)', borderColor: 'rgba(217, 154, 27, 0.35)', color: 'var(--amber)' }}
          >
            {enabled ? 'enabled' : 'disabled'}
          </span>
        </div>
        {error ? (
          <p className="error-text">{error}</p>
        ) : (
          <p className="dim small" style={{ marginTop: 8 }}>
            {enabled ? (
              <>
                Leases handed out by the built-in server. Client hostnames registered here are
                resolvable in the local DNS — <span className="mono">hostname</span> and{' '}
                <span className="mono">hostname.domain</span> both answer (Pi-hole style). Configure
                the pool, reservations and options under <strong>Settings → DHCP server</strong>.
              </>
            ) : (
              <>
                The built-in DHCP server is <strong>off</strong>. Enable it under{' '}
                <strong>Settings → DHCP server</strong> to hand out addresses from a pool, keep
                static reservations, and make client hostnames resolvable in the local DNS.
              </>
            )}
          </p>
        )}
        <div className="quick-actions" style={{ marginTop: 8 }}>
          <button className="btn small" onClick={load}>Refresh leases</button>
        </div>
      </div>

      {data && (enabled || leases.length > 0) && (
        <>
          {table('IPv4 leases', v4)}
          {table('IPv6 leases', v6)}
        </>
      )}
    </div>
  )
}
