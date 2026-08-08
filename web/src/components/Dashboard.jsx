import React, { useEffect, useState, useCallback, useRef } from 'react'
import { api } from '../api'

const fmt = (n) => (n ?? 0).toLocaleString()

export default function Dashboard({ onNavigate }) {
  const [stats, setStats] = useState(null)
  const [tls, setTls] = useState(null)
  const [status, setStatus] = useState(null)
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
    try {
      setStatus(await api.status())
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
    { label: 'Honeypot hits', value: fmt(c.honeypot), accent: 'amber', sub: 'trap domains refused' },
    { label: 'Avg latency', value: `${(q.avg_rt_ms || 0).toFixed(2)} ms`, accent: 'cyan', sub: 'last 24h' },
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

      <CacheCard cache={stats.cache} />

      <RootHintsCard status={status} />

      <BlockedClientsCard />

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

      <QueryLogCard today={stats.query_today} q24={q} hourly={stats.query_hourly} onNavigate={onNavigate} />

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

// CacheCard shows how hard the two cache layers are working: the in-process
// L1 (counters reset on restart) and Dragonfly's L2 (cumulative counters since
// the Dragonfly process started, plus its memory/keys). This is what the
// "Cache: online" sidebar dot doesn't tell you.
function CacheCard({ cache }) {
  if (!cache) return null
  const l1 = cache.l1
  const l2 = cache.l2
  // First-seen L2 snapshot (cumulative since Dragonfly started): the delta
  // against it is the hit-rate of traffic since THIS page loaded, which is
  // what the card should reflect — the all-time ratio is dominated by the
  // DDoS flood's write-once queries. A ref, not state: no re-render needed.
  const baseRef = useRef(null)
  if (l2 && !baseRef.current) baseRef.current = { hits: l2.hits, misses: l2.misses }
  const pct = (h, m) => {
    const t = (h || 0) + (m || 0)
    return t ? Math.round((100 * (h || 0)) / t) : null
  }
  const l1Rate = pct(l1?.hits, l1?.misses)
  const dH = baseRef.current ? Math.max(0, (l2?.hits || 0) - baseRef.current.hits) : null
  const dM = baseRef.current ? Math.max(0, (l2?.misses || 0) - baseRef.current.misses) : null
  const l2Rate = pct(dH, dM)
  const l2AllTime = pct(l2?.hits, l2?.misses)
  const memUsed = l2?.used_memory || 0
  const memMax = l2?.max_memory || 0
  const memPct = memMax ? Math.min(100, Math.round((100 * memUsed) / memMax)) : null
  const mb = (n) => (n ? (n / 1048576).toFixed(1) : '0')
  return (
    <div className="card">
      <div className="row-between">
        <h3 style={{ margin: 0 }}>Dragonfly cache</h3>
        <span className="dim small">L1 in-process · L2 DragonflyDB</span>
      </div>
      <div className="kv-grid" style={{ marginTop: 8 }}>
        <div className="kv-row">
          <span className="kv-label">L1 hit rate</span>
          <span className="kv-value">
            {l1Rate == null ? '—' : `${l1Rate}%`}
            {' '}<span className="dim small">({fmt(l1?.hits || 0)} of {fmt((l1?.hits || 0) + (l1?.misses || 0))} since restart)</span>
          </span>
        </div>
        <div className="kv-row">
          <span className="kv-label">L2 hit rate</span>
          <span className="kv-value">
            {l2Rate == null ? '—' : `${l2Rate}%`}
            {' '}<span className="dim small">({fmt(dH ?? 0)} of {fmt((dH ?? 0) + (dM ?? 0))} since page load)</span>
          </span>
        </div>
        <div className="kv-row">
          <span className="kv-label">Memory</span>
          <span className="kv-value">{mb(memUsed)} MB of {mb(memMax)} MB</span>
        </div>
        <div className="kv-row">
          <span className="kv-label">Keys · expired · evicted</span>
          <span className="kv-value">{fmt(l2?.keys)} · {fmt(l2?.expired)} · {fmt(l2?.evicted)}</span>
        </div>
      </div>
      {memPct != null && (
        <div className="proto-track" style={{ marginTop: 8 }} title={`${memPct}% of the Dragonfly memory budget in use`}>
          <div className="proto-fill" style={{ width: `${memPct}%` }} />
        </div>
      )}
      <div className="card-hint">
        The L2 rate above is for traffic since this page loaded; all-time it is{' '}
        {l2AllTime == null ? '—' : `${l2AllTime}%`} (since Dragonfly started). A low
        all-time rate is normal — the flood wrote millions of one-off queries — and
        most repeat queries are absorbed by L1 anyway. L2 is the shared,
        restart-surviving layer, and the query log lives here too.
      </div>
    </div>
  )
}

// QueryLogCard summarises what the Dragonfly query-log stream recorded: the
// volume and outcome split since local midnight, a 24h volume sparkline, and
// the busiest clients — all computed server-side from the same stream the
// Query Log page reads. Top-client rows deep-link to the query log filtered
// to that client.
function QueryLogCard({ today, q24, hourly, onNavigate }) {
  const t = today || {}
  const clients = t.top_clients || []
  const openClient = (ip) => onNavigate && onNavigate('log?client=' + encodeURIComponent(ip))
  return (
    <div className="card">
      <div className="row-between">
        <h3 style={{ margin: 0 }}>Query log</h3>
        <span className="dim small">live from Dragonfly</span>
      </div>
      <div className="kv-grid" style={{ marginTop: 8 }}>
        <div className="kv-row">
          <span className="kv-label">Queries today</span>
          <span className="kv-value">{fmt(t.total || 0)}</span>
        </div>
        <div className="kv-row">
          <span className="kv-label">Allowed · blocked · cached</span>
          <span className="kv-value">{fmt(t.allowed || 0)} · {fmt(t.blocked || 0)} · {fmt(t.cached || 0)}</span>
        </div>
        <div className="kv-row">
          <span className="kv-label">Avg latency today</span>
          <span className="kv-value">{(t.avg_rt_ms || 0).toFixed(2)} ms</span>
        </div>
        <div className="kv-row">
          <span className="kv-label">Queries last 24h</span>
          <span className="kv-value">{fmt(q24?.total || 0)}</span>
        </div>
      </div>
      <Sparkline data={hourly} />
      {clients.length > 0 && (
        <>
          <h4 style={{ margin: '14px 0 8px' }}>Top clients today</h4>
          <div className="top-list">
            {clients.slice(0, 8).map((c, i) => (
              <div
                className="top-row top-row-click"
                key={c.domain}
                role="button"
                tabIndex={0}
                title={`Show ${c.domain}'s queries in the query log`}
                onClick={() => openClient(c.domain)}
                onKeyDown={(e) => e.key === 'Enter' && openClient(c.domain)}
              >
                <span className="top-rank">{i + 1}</span>
                <span className="top-domain" title={c.domain}>{c.domain}</span>
                <span className="top-count">{fmt(c.count)}</span>
                <span className="top-go" aria-hidden="true">›</span>
              </div>
            ))}
          </div>
          <div className="card-hint">Click a client to open its queries in the query log.</div>
        </>
      )}
    </div>
  )
}

// Sparkline renders the last 24 hours of query volume as bars (total in the
// base tone, blocked overlaid in rose), with per-hour tooltips. Hours with
// no traffic stay empty so quiet gaps are visible.
function Sparkline({ data }) {
  if (!data || data.length === 0) return null
  const max = Math.max(...data.map((d) => d.total), 1)
  const H = 56
  const W = 240
  const bw = W / data.length
  const bh = (n) => (n ? Math.max(2, Math.round((n / max) * (H - 6))) : 0)
  return (
    <div>
      <svg
        className="spark-svg"
        viewBox={`0 0 ${W} ${H}`}
        preserveAspectRatio="none"
        role="img"
        aria-label="Queries per hour over the last 24 hours"
      >
        {data.map((d, i) => (
          <g key={d.hour}>
            <title>{`${new Date(d.hour).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })} — ${fmt(d.total)} query${d.total === 1 ? '' : 's'}${d.blocked ? ` (${fmt(d.blocked)} blocked)` : ''}`}</title>
            <rect className="spark-total" x={i * bw + 0.5} y={H - bh(d.total)} width={bw - 1} height={bh(d.total)} rx={1} />
            {d.blocked > 0 && (
              <rect className="spark-blocked" x={i * bw + 0.5} y={H - bh(d.blocked)} width={bw - 1} height={bh(d.blocked)} rx={1} />
            )}
          </g>
        ))}
      </svg>
      <div className="spark-legend">
        <span><i className="spark-legend-total" /> queries</span>
        <span><i className="spark-legend-blocked" /> blocked</span>
        <span className="dim small">per hour · last 24h</span>
      </div>
    </div>
  )
}

// BlockedClientsCard shows the clients currently blocked — honeypot
// auto-blocks (persisted, firewall-dropped) and rate-limit auto-blocks —
// each with one-click actions: report to AbuseIPDB (honeypot sources only —
// they're confirmed attackers by a real handshake), look up the owning
// ASN/host for ISP reports, block the IP or its /24, unblock, and export
// everything as a CSV for bulk abuse reporting. It refreshes on the same
// cadence as the dashboard's stat cards, so a fresh honeypot hit appears
// within seconds.
function BlockedClientsCard() {
  const [honey, setHoney] = useState([])
  const [rate, setRate] = useState([])
  const [error, setError] = useState('')
  const [msg, setMsg] = useState('')
  const [asn, setAsn] = useState({}) // ip -> { asn, name, holder, prefix } | 'loading'
  const [reporting, setReporting] = useState({}) // ip -> bool
  // Reverse-DNS names for the blocked client IPs (server-cached lookups).
  const [hosts, setHosts] = useState({})

  const load = useCallback(async () => {
    try { setHoney((await api.geoBlocked()).blocked || []) } catch { /* optional */ }
    try { setRate((await api.rateBlocked()).blocked || []) } catch { /* optional */ }
  }, [])

  // Resolve hostnames for the currently blocked clients so it's clear who is
  // hammering. The server caches PTR results, so the 10s refresh is cheap.
  useEffect(() => {
    const ips = [...new Set([...honey, ...rate.map((b) => b.ip)].filter(Boolean))].slice(0, 40)
    if (!ips.length) return
    let live = true
    api.hostnames(ips)
      .then((res) => { if (live) setHosts((prev) => ({ ...prev, ...(res.hostnames || {}) })) })
      .catch(() => {})
    return () => { live = false }
  }, [honey, rate])

  useEffect(() => {
    load()
    const t = setInterval(load, 10000)
    // Same as the parent dashboard: refresh promptly when the tab regains
    // visibility instead of waiting for the next 10s tick.
    const onVisible = () => {
      if (document.visibilityState === 'visible') load()
    }
    document.addEventListener('visibilitychange', onVisible)
    return () => {
      clearInterval(t)
      document.removeEventListener('visibilitychange', onVisible)
    }
  }, [load])

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
    if (!window.confirm(`Permanently block ${label}? It is added to geo_block.ips (config, survives restarts) and dropped at the host firewall. Remove it under Blocked client IPs in Settings to undo.`)) return
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
    if (!window.confirm(`Report ${ip} to AbuseIPDB (DDoS category)? Requires an API key set under Settings → Abuse reporting.`)) return
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
      setAsn((s) => { const n = { ...s }; delete n[ip]; return n })
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
        {info === 'loading' ? 'Looking up ASN…' : (
          info.error ? `ASN lookup failed: ${info.error}` : (
            <>{info.asn || 'n/a'} · {info.holder || info.name || 'unknown network'} · {info.prefix || ''}{info.country ? ` · ${info.country}` : ''}</>
          )
        )}
      </div>
    )
  }

  const hasHoney = honey.length > 0
  const hasRate = rate.length > 0
  return (
    <div className="card">
      <div className="row-between">
        <h3 style={{ margin: 0 }}>Blocked clients</h3>
        <div className="row">
          <span className="dim small">honeypot hits &amp; rate-limit auto-blocks</span>
          <button className="btn small" type="button" onClick={exportCsv} title="Download all blocked client IPs as CSV for bulk abuse reporting">Export CSV</button>
        </div>
      </div>
      {msg && <div className="text-ok small" style={{ marginTop: 8 }}>{msg}</div>}
      {error && <div className="error-text small" style={{ marginTop: 8 }}>{error}</div>}
      <div className="stack" style={{ marginTop: 8 }}>
        {!hasHoney && !hasRate ? (
          <p className="dim small" style={{ margin: 0 }}>
            No clients currently blocked. Honeypot hits over TCP/DoT/DoH/DoQ and
            rate-limit offenders appear here. Spoofed-UDP sources are refused but
            never auto-blocked — they can&apos;t be trusted — so a pure UDP flood can
            show nothing here even while the <strong>Honeypot hits</strong> counter
            climbs. Export CSV and ⓘ ASN work whenever clients do get blocked.
          </p>
        ) : (
          <>
          {hasHoney && (
            <div>
              <div className="dim small" style={{ marginBottom: 6 }}>
                <span className="badge badge-honeypot">Honeypot</span> — blocked permanently, dropped at the firewall
              </div>
              {honey.map((ip) => (
                <div key={ip}>
                  <div className="list-row">
                    <div style={{ minWidth: 0 }}>
                      <div className="mono">{ip}</div>
                      {hosts[ip] && <div className="dim small client-host" title={hosts[ip]}>{hosts[ip]}</div>}
                    </div>
                    <button className="btn small" type="button" onClick={() => report(ip)} disabled={reporting[ip]}>
                      {reporting[ip] ? 'Reporting…' : 'Report'}
                    </button>
                    <button className="btn small" type="button" onClick={() => toggleAsn(ip)}>ⓘ ASN</button>
                    <button className="btn small" type="button" onClick={() => blockNet(ip, 0)}>Block IP</button>
                    <button className="btn small" type="button" onClick={() => blockNet(ip, ip.includes(':') ? 64 : 24)}>Block /{ip.includes(':') ? 64 : 24}</button>
                    <button className="btn small danger" type="button" onClick={() => act(() => api.geoUnblock(ip))}>Unblock</button>
                  </div>
                  <AsnRow ip={ip} />
                </div>
              ))}
            </div>
          )}
          {hasRate && (
            <div>
              <div className="dim small" style={{ marginBottom: 6 }}>
                <span className="badge badge-error">Rate limit</span> — hammering clients refused until cooldown
              </div>
              {rate.map((b) => (
                <div key={b.ip}>
                  <div className="list-row" style={{ alignItems: 'flex-start' }}>
                    <div style={{ minWidth: 0 }}>
                      <div className="mono">{b.ip}</div>
                      {hosts[b.ip] && <div className="dim small client-host" title={hosts[b.ip]}>{hosts[b.ip]}</div>}
                      {b.blocked_until && (
                        <span className="dim small">
                          {' '}· blocked until {new Date(b.blocked_until).toLocaleString()}
                          {b.blocks ? ` · ${b.blocks}×` : ''}
                        </span>
                      )}
                    </div>
                    <button className="btn small" type="button" onClick={() => toggleAsn(b.ip)}>ⓘ ASN</button>
                    <button className="btn small danger" type="button" onClick={() => act(() => api.rateUnblock(b.ip))}>Unblock</button>
                  </div>
                  <AsnRow ip={b.ip} />
                </div>
              ))}
            </div>
          )}
          </>
        )}
      </div>
    </div>
  )
}

// RootHintsCard summarises the authoritative root-hints source: whether the
// resolver walks referrals from a live PGP-verified named.root fetch, a
// last-known-good disk cache, or the bundled fallback.
function RootHintsCard({ status }) {
  const rh = status?.root_hints
  if (!rh?.enabled) return null
  const badge =
    rh.source === 'live' ? 'badge-allowed'
      : rh.source === 'cached' ? 'badge-warn'
        : 'badge-error'
  const sourceLabel =
    rh.source === 'live' ? 'Live (named.root)'
      : rh.source === 'cached' ? 'Disk cache'
        : 'Bundled fallback'
  return (
    <div className="card">
      <div className="row-between">
        <h3 style={{ margin: 0 }}>Root hints</h3>
        <span className={`badge ${badge}`}>{sourceLabel}</span>
      </div>
      <div className="kv-grid" style={{ marginTop: 8 }}>
        <div className="kv-row">
          <span className="kv-label">Signature</span>
          <span className="kv-value">
            {rh.verified
              ? '✓ PGP-verified (Verisign)'
              : 'not verified — using trusted fallback'}
          </span>
        </div>
        <div className="kv-row">
          <span className="kv-label">Addresses</span>
          <span className="kv-value">{rh.addresses ?? 0} root server addresses</span>
        </div>
        <div className="kv-row">
          <span className="kv-label">Last fetch</span>
          <span className="kv-value">
            {rh.last_fetch ? new Date(rh.last_fetch).toLocaleString() : '—'}
          </span>
        </div>
        <div className="kv-row">
          <span className="kv-label">Refresh</span>
          <span className="kv-value">every {rh.refresh_interval || '7d'}</span>
        </div>
      </div>
      {rh.last_error && (
        <div className="error-text small" style={{ marginTop: 8 }}>
          ⚠ {rh.last_error}
        </div>
      )}
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
