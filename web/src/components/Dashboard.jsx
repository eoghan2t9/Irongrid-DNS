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
      setError('')
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
    // Refresh right away when the tab regains visibility (e.g. after being
    // minimised) instead of waiting for the next 10s tick: the pooled
    // connection can go stale while backgrounded, so this both retries
    // promptly and clears any leftover error banner without a visible delay.
    const onVisible = () => {
      if (document.visibilityState === 'visible') load()
    }
    document.addEventListener('visibilitychange', onVisible)
    return () => {
      clearInterval(t)
      document.removeEventListener('visibilitychange', onVisible)
    }
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

      <AcmeCard acme={tls?.acme} onNavigate={onNavigate} onRenewed={load} />
    </div>
  )
}

function daysBetween(a, b) {
  if (!a || !b) return null
  return Math.round((new Date(b) - new Date(a)) / 86400000)
}

// AcmeCard summarises the Let's Encrypt manager state on the dashboard.
function AcmeCard({ acme, onNavigate, onRenewed }) {
  const [busy, setBusy] = useState(false)
  const [msg, setMsg] = useState(null) // { ok, text }
  if (!acme || !acme.enabled) return null
  const ok = !acme.last_error
  const days = daysBetween(new Date(), acme.next_renewal)
  const since = daysBetween(acme.last_success, new Date())

  const renew = async (e) => {
    e.stopPropagation()
    if (busy) return
    setBusy(true)
    setMsg(null)
    try {
      const r = await api.tlsAcmeIssue()
      setMsg({
        ok: true,
        text: r.apply_error
          ? `Certificate issued but not hot-applied: ${r.apply_error}`
          : 'Certificate issued and applied to the listeners.',
      })
      onRenewed && onRenewed()
    } catch (err) {
      setMsg({ ok: false, text: err.message || 'Renewal failed' })
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className={`card acme-card ${ok ? '' : 'acme-error'}`} role="button" tabIndex={0}
      onClick={() => onNavigate('tls')} onKeyDown={(e) => e.key === 'Enter' && onNavigate('tls')}
      style={{ cursor: 'pointer' }}>
      <div className="row-between">
        <h3 style={{ margin: 0 }}>
          Let&apos;s Encrypt{' '}
          <span className={`badge ${ok ? 'badge-allowed' : 'badge-error'}`}>
            {ok ? 'healthy' : 'needs attention'}
          </span>
        </h3>
        <span className="dim small">{acme.staging ? 'staging CA' : 'production CA'}</span>
      </div>
      <div className="kv-grid" style={{ marginTop: 8 }}>
        <div className="kv-row">
          <span className="kv-label">Challenge</span>
          <span className="kv-value">
            {acme.challenge || 'http-01'}
            {acme.dns_provider ? ` · ${acme.dns_provider}` : ''}
          </span>
        </div>
        <div className="kv-row">
          <span className="kv-label">Domains</span>
          <span className="kv-value">{(acme.domains || []).join(', ') || '—'}</span>
        </div>
        <div className="kv-row">
          <span className="kv-label">Last issued</span>
          <span className="kv-value">
            {acme.last_success ? new Date(acme.last_success).toLocaleDateString() : 'never'}
            {since != null && since >= 0 ? ` (${since}d ago)` : ''}
          </span>
        </div>
        <div className="kv-row">
          <span className="kv-label">Next renewal</span>
          <span className="kv-value">
            {acme.next_renewal ? new Date(acme.next_renewal).toLocaleDateString() : '—'}
            {days != null && <span className={`badge ${days < 15 ? 'badge-warn' : ''}`}>in {days}d</span>}
          </span>
        </div>
      </div>
      {acme.last_error && (
        <div className="error-text small" style={{ marginTop: 8 }}>
          ⚠ {acme.last_error} — click to fix on the SSL / TLS page.
        </div>
      )}
      <div className="row-between" style={{ marginTop: 12 }}>
        <button
          className="btn primary small"
          onClick={renew}
          onKeyDown={(e) => e.stopPropagation()}
          disabled={busy}
          title="Trigger an immediate Let's Encrypt issuance / renewal"
        >
          {busy ? 'Renewing…' : 'Renew now'}
        </button>
        <span className={`small ${msg ? (msg.ok ? 'text-ok' : 'error-text') : 'dim'}`}>
          {msg ? msg.text : 'Renews automatically before expiry'}
        </span>
      </div>
    </div>
  )
}
