import { useEffect, useState, useCallback } from 'react'
import { api } from '../api'
import { usePolling } from '../hooks/usePolling'

// BlockedClients is a dedicated page for the clients currently blocked —
// honeypot auto-blocks (persisted, firewall-dropped) and rate-limit
// auto-blocks — each with one-click actions: report to AbuseIPDB (honeypot
// sources only — they're confirmed attackers by a real handshake), look up
// the owning ASN/host for ISP reports, block the IP or its /24, unblock, and
// export everything as a CSV for bulk abuse reporting. It refreshes on a 10s
// interval, so a fresh honeypot hit appears within seconds. Split out of the
// Dashboard (where it lived as a card) so the table has room to breathe.
export default function BlockedClients() {
  const [honey, setHoney] = useState([])
  const [rate, setRate] = useState([])
  const [error, setError] = useState('')
  const [msg, setMsg] = useState('')
  const [asn, setAsn] = useState({}) // ip -> { asn, name, holder, prefix } | 'loading'
  const [reporting, setReporting] = useState({}) // ip -> bool
  // Reverse-DNS names + BGP/ISP owner for the blocked client IPs
  // (server-cached lookups, so the 10s refresh stays cheap).
  const [hosts, setHosts] = useState({})
  const [asns, setAsns] = useState({}) // ip -> { asn, name, holder, prefix }

  const load = useCallback(async () => {
    try {
      setHoney((await api.geoBlocked()).blocked || [])
    } catch {
      /* optional */
    }
    try {
      setRate((await api.rateBlocked()).blocked || [])
    } catch {
      /* optional */
    }
  }, [])

  // Resolve hostnames + ISP owner for the currently blocked clients so it's
  // clear who is hammering. The server caches PTR results (1h/15m) and ASN
  // lookups (24h), so the 10s refresh is cheap.
  useEffect(() => {
    const ips = [...new Set([...honey, ...rate.map((b) => b.ip)].filter(Boolean))].slice(0, 40)
    if (!ips.length) return
    let live = true
    api
      .hostnames(ips)
      .then((res) => {
        if (live) setHosts((prev) => ({ ...prev, ...(res.hostnames || {}) }))
      })
      .catch(() => {})
    api
      .asnInfo(ips)
      .then((res) => {
        if (live) setAsns((prev) => ({ ...prev, ...(res.asn || {}) }))
      })
      .catch(() => {})
    return () => {
      live = false
    }
  }, [honey, rate])

  useEffect(() => {
    load()
  }, [load])
  usePolling(load, 10000)

  const act = async (fn) => {
    setError('')
    try {
      await fn()
      await load()
    } catch (e) {
      setError(e.message || 'Action failed')
    }
  }

  // blockNet permanently adds a honeypot-hit client (or its /24 or /64
  // network) to geo_block.ips — DNS REFUSED plus a host-firewall drop at the
  // packet level.
  const blockNet = async (ip, prefix) => {
    const label = prefix ? `${ip}/${prefix}` : ip
    if (
      !window.confirm(
        `Permanently block ${label}? It is added to geo_block.ips (config, survives restarts) and dropped at the host firewall. Remove it under Blocked client IPs in Settings to undo.`,
      )
    )
      return
    setError('')
    try {
      await api.geoBlockIP(ip, prefix)
      await load()
    } catch (e) {
      setError(e.message || 'Block failed')
    }
  }

  // report submits a honeypot-confirmed attacker to AbuseIPDB (category
  // DDoS). Only honeypot rows offer this: they were auto-blocked over a real
  // handshake, so the source is genuine.
  const report = async (ip) => {
    if (
      !window.confirm(
        `Report ${ip} to AbuseIPDB (DDoS category)? Requires an API key set under Settings → Abuse reporting.`,
      )
    )
      return
    setError('')
    setMsg('')
    setReporting((s) => ({ ...s, [ip]: true }))
    try {
      const r = await api.abuseReport(ip)
      setMsg(`Reported ${ip} to AbuseIPDB — abuse confidence ${r.abuse_confidence_score ?? 'n/a'}.`)
    } catch (e) {
      setError('Report failed: ' + e.message)
    } finally {
      setReporting((s) => ({ ...s, [ip]: false }))
    }
  }

  // toggleAsn lazily looks up the owning ASN / host of an IP (free RIPEstat)
  // and expands the row with the result, so you know which provider to report
  // to.
  const toggleAsn = async (ip) => {
    if (asn[ip]) {
      setAsn((s) => {
        const n = { ...s }
        delete n[ip]
        return n
      })
      return
    }
    setAsn((s) => ({ ...s, [ip]: 'loading' }))
    try {
      const info = await api.abuseASN(ip)
      setAsn((s) => ({ ...s, [ip]: info }))
    } catch (e) {
      setAsn((s) => ({ ...s, [ip]: { error: e.message } }))
    }
  }

  const exportCsv = async () => {
    try {
      const blob = await api.abuseExport()
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `irongrid-blocked-clients-${new Date().toISOString().slice(0, 10)}.csv`
      a.click()
      URL.revokeObjectURL(url)
      setMsg('Exported blocked clients as CSV — paste the rows into your ISP/abuse-desk report.')
    } catch (e) {
      setError('Export failed: ' + e.message)
    }
  }

  const AsnRow = ({ ip }) => {
    const info = asn[ip]
    if (!info) return null
    return (
      <div className="dim small mono" style={{ margin: '2px 0 6px' }}>
        {info === 'loading' ? (
          'Looking up ASN…'
        ) : info.error ? (
          `ASN lookup failed: ${info.error}`
        ) : info.asn ? (
          <>
            {info.asn} · {info.holder || info.name || 'unknown network'} · {info.prefix || ''}
            {info.country ? ` · ${info.country}` : ''}
          </>
        ) : (
          'No routing information for this address — it may be reserved or unassigned.'
        )}
      </div>
    )
  }

  const hasHoney = honey.length > 0
  const hasRate = rate.length > 0
  const blockPrefix = (ip) => (ip.includes(':') ? 64 : 24)
  return (
    <div className="stack">
      <div className="card table-card">
        <div className="row-between" style={{ padding: '12px 8px 8px' }}>
          <h3 style={{ margin: 0 }}>Blocked clients</h3>
          <div className="row">
            <span className="dim small">honeypot hits &amp; rate-limit auto-blocks</span>
            <button
              className="btn small"
              type="button"
              onClick={exportCsv}
              title="Download all blocked client IPs as CSV for bulk abuse reporting"
            >
              Export CSV
            </button>
          </div>
        </div>
        {msg && (
          <div className="text-ok small" style={{ margin: '4px 8px 0' }}>
            {msg}
          </div>
        )}
        {error && (
          <div className="error-text small" style={{ margin: '4px 8px 0' }}>
            {error}
          </div>
        )}
        {!hasHoney && !hasRate ? (
          <p className="dim small" style={{ margin: '14px 8px' }}>
            No clients currently blocked — honeypot hits and rate-limit offenders appear here. Spoofed-UDP flood sources
            are refused but never auto-blocked, so a pure UDP flood can show an empty list even while the{' '}
            <strong>Honeypot hits</strong> counter climbs.
          </p>
        ) : (
          <table className="table">
            <thead>
              <tr>
                <th>Client</th>
                <th>Source</th>
                <th>Blocked</th>
                <th className="actions-cell">Actions</th>
              </tr>
            </thead>
            <tbody>
              {honey.map((ip) => (
                <tr key={ip}>
                  <td>
                    <div className="mono">{ip}</div>
                    {hosts[ip] && (
                      <div className="dim small client-host" title={hosts[ip]}>
                        {hosts[ip]}
                      </div>
                    )}
                    {asns[ip]?.asn && (
                      <div
                        className="dim small client-host"
                        title={`${asns[ip].asn} · ${asns[ip].holder || asns[ip].name || ''}${asns[ip].prefix ? ` · ${asns[ip].prefix}` : ''}`}
                      >
                        {asns[ip].asn} · {asns[ip].holder || asns[ip].name}
                      </div>
                    )}
                    <AsnRow ip={ip} />
                  </td>
                  <td>
                    <span className="badge badge-honeypot">Honeypot</span>
                  </td>
                  <td className="dim small">permanently · firewall drop</td>
                  <td className="actions-cell">
                    <button
                      className="btn ghost tiny"
                      type="button"
                      onClick={() => report(ip)}
                      disabled={reporting[ip]}
                    >
                      {reporting[ip] ? 'Reporting…' : 'Report'}
                    </button>
                    <button className="btn ghost tiny" type="button" onClick={() => toggleAsn(ip)}>
                      ASN
                    </button>
                    <button className="btn tiny" type="button" onClick={() => blockNet(ip, 0)}>
                      Block IP
                    </button>
                    <button className="btn tiny" type="button" onClick={() => blockNet(ip, blockPrefix(ip))}>
                      Block /{blockPrefix(ip)}
                    </button>
                    <button className="btn tiny danger" type="button" onClick={() => act(() => api.geoUnblock(ip))}>
                      Unblock
                    </button>
                  </td>
                </tr>
              ))}
              {rate.map((b) => (
                <tr key={b.ip}>
                  <td>
                    <div className="mono">{b.ip}</div>
                    {hosts[b.ip] && (
                      <div className="dim small client-host" title={hosts[b.ip]}>
                        {hosts[b.ip]}
                      </div>
                    )}
                    {asns[b.ip]?.asn && (
                      <div
                        className="dim small client-host"
                        title={`${asns[b.ip].asn} · ${asns[b.ip].holder || asns[b.ip].name || ''}${asns[b.ip].prefix ? ` · ${asns[b.ip].prefix}` : ''}`}
                      >
                        {asns[b.ip].asn} · {asns[b.ip].holder || asns[b.ip].name}
                      </div>
                    )}
                    <AsnRow ip={b.ip} />
                  </td>
                  <td>
                    <span className="badge badge-error">Rate limit</span>
                  </td>
                  <td className="dim small">
                    {b.blocked_until ? `until ${new Date(b.blocked_until).toLocaleString()}` : 'refused'}
                    {b.blocks ? ` · ${b.blocks}×` : ''}
                  </td>
                  <td className="actions-cell">
                    <button className="btn ghost tiny" type="button" onClick={() => toggleAsn(b.ip)}>
                      ASN
                    </button>
                    <button className="btn tiny danger" type="button" onClick={() => act(() => api.rateUnblock(b.ip))}>
                      Unblock
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  )
}
