import React, { useEffect, useState, useCallback } from 'react'
import { api } from '../api'

const fmt = (n) => (n ?? 0).toLocaleString()

export default function Dashboard({ onNavigate }) {
  const [stats, setStats] = useState(null)
  const [tls, setTls] = useState(null)
  const [error, setError] = useState('')

  const load = useCallback(async () => {
    try {
      setStats(await api.stats())
    } catch (e) {
      setError(e.message)
    }
    try {
      setTls(await api.tlsStatus())
    } catch { /* optional */ }
  }, [])

  useEffect(() => {
    load()
    const t = setInterval(load, 10000)
    return () => clearInterval(t)
  }, [load])

  if (!stats) return <div className="card loading">Loading dashboard…</div>

  const c = stats.counters || {}
  const q = stats.query || {}
  const total = c.total || 0
  const blockedPct = total ? Math.round(((c.blocked || 0) / total) * 100) : 0
  const protocol = stats.protocol || {}
  const protoTotal = Object.values(protocol).reduce((a, b) => a + b, 0) || 1

  const cards = [
    { label: 'Total queries', value: fmt(c.total), accent: 'cyan', sub: `${c.errors || 0} errors` },
    { label: 'Blocked', value: fmt(c.blocked), accent: 'rose', sub: `${blockedPct}% of traffic` },
    { label: 'Allowed', value: fmt(c.allowed), accent: 'emerald', sub: `${fmt(q.allowed)} in log` },
    { label: 'Cache hits', value: fmt(c.cached), accent: 'violet', sub: 'served instantly' },
    { label: 'Avg latency', value: `${(q.avg_rt_ms || 0).toFixed(2)} ms`, accent: 'amber', sub: 'last 24h' },
  ]

  const topBlocked = q.top_blocked || []

  const cert = tls?.info
  const certExpiring = cert && cert.expires_in_days >= 0 && cert.expires_in_days < 30
  const certExpired = cert && cert.expires_in_days < 0

  return (
    <div className="stack">
      {error && <div className="error-banner">{error}</div>}
      {certExpired && (
        <div className="error-banner" role="button" tabIndex={0} onClick={() => onNavigate('tls')} onKeyDown={(e) => e.key === 'Enter' && onNavigate('tls')} style={{ cursor: 'pointer' }}>
          ⚠ The TLS certificate has <strong>expired</strong> — DoT/DoH/DoQ clients will fail. Generate a new one, upload a CA cert, or renew via Let's Encrypt on the <strong>SSL / TLS</strong> page.
        </div>
      )}
      {certExpiring && !certExpired && (
        <div className="info-banner" role="button" tabIndex={0} onClick={() => onNavigate('tls')} onKeyDown={(e) => e.key === 'Enter' && onNavigate('tls')} style={{ cursor: 'pointer' }}>
          ⚠ The TLS certificate expires in <strong>{cert.expires_in_days} days</strong> ({new Date(cert.not_after).toLocaleDateString()}). Renew it on the <strong>SSL / TLS</strong> page.
        </div>
      )}

      <div className="cards">
        {cards.map((card) => (
          <div key={card.label} className={`card stat-card accent-${card.accent}`}>
            <div className="stat-value">{card.value}</div>
            <div className="stat-label">{card.label}</div>
            <div className="stat-sub">{card.sub}</div>
          </div>
        ))}
      </div>

      <div className="grid-2">
        <div className="card">
          <h3>Protocol usage</h3>
          <div className="proto-bars">
            {['udp', 'tcp', 'dot', 'doh', 'doq'].map((p) => (
              <div className="proto-row" key={p}>
                <span className="proto-name">{p.toUpperCase()}</span>
                <div className="proto-track">
                  <div
                    className="proto-fill"
                    style={{ width: `${((protocol[p] || 0) / protoTotal) * 100}%` }}
                  />
                </div>
                <span className="proto-count">{fmt(protocol[p] || 0)}</span>
              </div>
            ))}
          </div>
          <div className="card-hint">
            UDP &amp; TCP on :53 · DoT/DoQ on :853 · DoH on :443
          </div>
        </div>

        <div className="card">
          <h3>Top blocked domains</h3>
          {topBlocked.length === 0 ? (
            <div className="empty">Nothing blocked yet — add blocklists in the Blocklists view.</div>
          ) : (
            <div className="top-list">
              {topBlocked.map((t, i) => (
                <div className="top-row" key={t.domain}>
                  <span className="top-rank">{i + 1}</span>
                  <span className="top-domain" title={t.domain}>{t.domain}</span>
                  <span className="top-count">{fmt(t.count)}</span>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>

      <div className="card">
        <h3>Quick actions</h3>
        <div className="quick-actions">
          <button className="btn primary" onClick={() => onNavigate('blocklists')}>
            Manage blocklists
          </button>
          <button className="btn" onClick={() => onNavigate('log')}>
            View query log
          </button>
          <button className="btn" onClick={() => onNavigate('lists')}>
            Whitelist a domain
          </button>
          <button className="btn ghost" onClick={() => api.flushCache().then(load)}>
            Flush DNS cache
          </button>
        </div>
      </div>
    </div>
  )
}
