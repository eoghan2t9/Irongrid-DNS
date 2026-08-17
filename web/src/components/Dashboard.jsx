import { useEffect, useState, useCallback, useRef } from 'react'
import { api } from '../api'
import { EmptyState, CheckIcon, AlertIcon } from './ui'

const fmt = (n) => (n ?? 0).toLocaleString()

export default function Dashboard({ onNavigate }) {
  const [stats, setStats] = useState(null)
  const [tls, setTls] = useState(null)
  const [status, setStatus] = useState(null)
  const [error, setError] = useState('')
  // Beginner checklist state: what the operator has already configured on
  // this box. Derived from the live config (not defaults) so an already-set
  // up server hides the card automatically.
  const [setupConfig, setSetupConfig] = useState(null)

  const load = useCallback(async () => {
    try {
      setStats(await api.stats())
      setError('')
    } catch (e) {
      setError(e.message)
    }
    try {
      setTls(await api.tlsStatus())
    } catch {
      /* optional */
    }
    try {
      setStatus(await api.status())
    } catch {
      /* optional */
    }
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

  // One config fetch on mount drives the setup checklist — the config is
  // tiny and the dashboard is the natural place a first-time operator lands.
  useEffect(() => {
    api
      .config()
      .then(setSetupConfig)
      .catch(() => {})
  }, [])

  // The ⌘K palette's "Refresh everything" action pokes the dashboard to
  // reload immediately instead of waiting for the next 10s tick.
  useEffect(() => {
    const onRefresh = () => load()
    window.addEventListener('irongrid:refresh-dashboard', onRefresh)
    return () => window.removeEventListener('irongrid:refresh-dashboard', onRefresh)
  }, [load])

  if (!stats) return <DashboardSkeleton />

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

  const checklist = buildChecklist(setupConfig)

  return (
    <div className="stack">
      {error && <div className="error-banner">{error}</div>}
      {checklist && <SetupChecklist items={checklist} onNavigate={onNavigate} />}
      {certExpired && (
        <div
          className="error-banner"
          role="button"
          tabIndex={0}
          onClick={() => onNavigate('tls')}
          onKeyDown={(e) => e.key === 'Enter' && onNavigate('tls')}
          style={{ cursor: 'pointer', display: 'flex', gap: 8, alignItems: 'flex-start' }}
        >
          <AlertIcon size={14} style={{ flexShrink: 0, marginTop: 2 }} />
          <span>
            The TLS certificate has <strong>expired</strong> — DoT/DoH/DoQ clients will fail. Generate a new one, upload
            a CA cert, or renew via Let's Encrypt on the <strong>SSL / TLS</strong> page.
          </span>
        </div>
      )}
      {certExpiring && !certExpired && (
        <div
          className="info-banner"
          role="button"
          tabIndex={0}
          onClick={() => onNavigate('tls')}
          onKeyDown={(e) => e.key === 'Enter' && onNavigate('tls')}
          style={{ cursor: 'pointer', display: 'flex', gap: 8, alignItems: 'flex-start' }}
        >
          <AlertIcon size={14} style={{ flexShrink: 0, marginTop: 2 }} />
          <span>
            The TLS certificate expires in <strong>{cert.expires_in_days} days</strong> (
            {new Date(cert.not_after).toLocaleDateString()}). Renew it on the <strong>SSL / TLS</strong> page.
          </span>
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

      <PerformanceCard latency={stats.latency} counters={c} avg24={q.avg_rt_ms} coalesce={stats.coalesce} />

      <UpstreamsCard upstreams={stats.upstreams} />

      <CacheCard cache={stats.cache} />

      <WarmerCard warmer={stats.warmer} onWarmed={load} />

      <RootHintsCard status={status} />

      <TuningCard status={status} />

      <BlockedClientsCard />

      <div className="grid-2">
        <div className="card">
          <h3>Protocol usage</h3>
          <div className="proto-bars">
            {['udp', 'tcp', 'dot', 'doh', 'doq'].map((p) => (
              <div className="proto-row" key={p}>
                <span className="proto-name">{p.toUpperCase()}</span>
                <div className="proto-track">
                  <div className="proto-fill" style={{ width: `${((protocol[p] || 0) / protoTotal) * 100}%` }} />
                </div>
                <span className="proto-count">{fmt(protocol[p] || 0)}</span>
              </div>
            ))}
          </div>
          <div className="card-hint">UDP &amp; TCP on :53 · DoT/DoQ on :853 · DoH on :443</div>
        </div>

        <div className="card">
          <h3>Top blocked domains</h3>
          {topBlocked.length === 0 ? (
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
                  <path d="M12 2 20 6v6c0 5-3.5 8.5-8 10-4.5-1.5-8-5-8-10V6z" />
                </svg>
              }
              title="Nothing blocked yet"
              body="Your network is quiet. Add a curated blocklist to start filtering ads, trackers and malware."
              action="Add a blocklist"
              onAction={() => onNavigate('blocklists')}
            />
          ) : (
            <div className="top-list">
              {topBlocked.map((t, i) => (
                <div className="top-row" key={t.domain}>
                  <span className="top-rank">{i + 1}</span>
                  <span className="top-domain" title={t.domain}>
                    {t.domain}
                  </span>
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

// buildChecklist turns the live config into the beginner setup checklist:
// one entry per thing worth configuring on a fresh install. Returns null
// when the config isn't loaded yet or everything is already done (or the
// operator dismissed it). Each entry carries a plain-English question, the
// action that fixes it, and the page that hosts that action.
function buildChecklist(cfg) {
  if (!cfg) return null
  const items = []

  const blocklists = (cfg.filter && cfg.filter.blocklists) || []
  const hasBlocklist = blocklists.some((b) => b.enabled)
  if (!hasBlocklist) {
    items.push({
      key: 'blocklists',
      q: 'Block ads and trackers',
      a: 'Add a blocklist — one click on a curated list like OISD or StevenBlack.',
      to: 'blocklists',
      cta: 'Add a blocklist',
    })
  }

  if (!cfg.server || !cfg.server.web_tls) {
    items.push({
      key: 'https',
      q: 'Encrypt the dashboard',
      a: 'Serve this dashboard over HTTPS so your sign-in travels encrypted, not in the clear.',
      to: 'settings',
      cta: 'Turn on HTTPS',
    })
  }

  if (!cfg.rate_limit || !cfg.rate_limit.enabled) {
    items.push({
      key: 'ratelimit',
      q: 'Protect against abuse',
      a: 'Rate limiting stops one device — or a public attacker — from hammering your server.',
      to: 'settings',
      cta: 'Enable rate limiting',
    })
  }

  if (!cfg.dhcp || !cfg.dhcp.enabled) {
    items.push({
      key: 'dhcp',
      q: 'Serve your own network',
      a: 'Optional: hand out addresses and device names to your LAN with the built-in DHCP server.',
      to: 'dhcp',
      cta: 'Set up DHCP',
    })
  }

  if (items.length === 0) return null
  // Respect a prior dismiss (stored per key, so a re-added feature resurfaces).
  const dismissed = (localStorage.getItem('irongrid_setup_dismissed') || '').split(',').filter(Boolean)
  const pending = items.filter((i) => !dismissed.includes(i.key))
  return pending.length ? pending : null
}

// SetupChecklist is the first-run card: a compact to-do list with a progress
// bar that deep-links into the page where each item lives. Ticking an item
// (or Dismiss) persists the item key in localStorage so the card stays gone
// across reloads and navigation — the dashboard unmounts when you switch
// views, so nothing may live only in component state. When every pending
// item is done it flips to a short "all set" confirmation instead of
// vanishing without feedback.
function SetupChecklist({ items, onNavigate }) {
  const [done, setDone] = useState(() => new Set())
  // hidden closes the card locally (the "Got it" button on the all-set
  // state, or Dismiss mid-way). The parent re-render would eventually hide
  // it anyway once every key is persisted, but an explicit close shouldn't
  // depend on the next 10s stats tick.
  const [hidden, setHidden] = useState(false)
  const remaining = items.filter((i) => !done.has(i.key))
  const finished = remaining.length === 0
  const total = items.length
  const doneCount = total - remaining.length
  const pct = total ? Math.round((100 * doneCount) / total) : 100
  const persist = (keys) => {
    const cur = (localStorage.getItem('irongrid_setup_dismissed') || '').split(',').filter(Boolean)
    localStorage.setItem('irongrid_setup_dismissed', [...new Set([...cur, ...keys])].join(','))
  }
  const tick = (key) => {
    persist([key])
    setDone((s) => new Set(s).add(key))
  }
  const dismiss = () => {
    persist(items.map((i) => i.key))
    setHidden(true)
  }
  if (hidden) return null
  return (
    <div className={`card setup-card ${finished ? 'setup-done' : ''}`}>
      <div className="row-between">
        <div>
          <h3 style={{ margin: 0 }}>Getting started</h3>
          <p className="dim small" style={{ margin: '4px 0 0' }}>
            {finished
              ? 'Everything on the list is set up — you are ready to go.'
              : `${remaining.length} thing${remaining.length === 1 ? '' : 's'} left — tap one to jump straight to it.`}
          </p>
        </div>
        <button
          className="btn ghost small"
          type="button"
          onClick={dismiss}
          title={finished ? 'Hide this card' : 'Hide this checklist'}
        >
          {finished ? 'Got it' : 'Dismiss'}
        </button>
      </div>
      {!finished && (
        <>
          <div
            className="setup-progress"
            role="progressbar"
            aria-valuemin={0}
            aria-valuemax={total}
            aria-valuenow={doneCount}
            aria-label="Setup progress"
          >
            <div className="setup-progress-fill" style={{ width: `${pct}%` }} />
          </div>
          <div className="setup-list">
            {remaining.map((i) => (
              <div className="setup-row" key={i.key}>
                <button
                  className="setup-check"
                  type="button"
                  onClick={() => tick(i.key)}
                  title="Mark as done"
                  aria-label={`Mark "${i.q}" as done`}
                >
                  <CheckIcon size={13} />
                </button>
                <div className="setup-info">
                  <div className="setup-q">{i.q}</div>
                  <div className="setup-a">{i.a}</div>
                </div>
                <button className="btn small" type="button" onClick={() => onNavigate(i.to)}>
                  {i.cta} →
                </button>
              </div>
            ))}
          </div>
        </>
      )}
      {finished && (
        <div className="setup-complete">
          <span className="setup-check done" aria-hidden="true">
            <CheckIcon size={13} />
          </span>
          <div>
            <div className="setup-q">All set</div>
            <div className="setup-a">
              You have worked through the essentials. Add more lists, rules and servers any time from the sidebar — or
              search with Ctrl+K.
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

// DashboardSkeleton shows shimmering placeholder cards while the first stats
// fetch is in flight, so the first paint reads as a page taking shape rather
// than a bare "Loading…" line.
function DashboardSkeleton() {
  return (
    <div className="stack" aria-busy="true" aria-label="Loading dashboard">
      <div className="cards">
        {Array.from({ length: 6 }, (_, i) => (
          <div key={i} className="card stat-card skel" />
        ))}
      </div>
      <div className="card skel" style={{ height: 168 }} />
      <div className="card skel" style={{ height: 96 }} />
      <div className="card skel" style={{ height: 96 }} />
    </div>
  )
}

// PerformanceCard shows the response-time percentiles the recent latency
// work targets: p50/p95/p99 estimated from an in-process histogram of every
// query (since restart), the 24h average from the query log, the share of
// queries answered from cache, and the in-flight request pool's coalescing
// (how many concurrent identical queries were served by one upstream round
// trip instead of starting their own).
function PerformanceCard({ latency, counters, avg24, coalesce }) {
  const total = counters?.total || 0
  const cached = counters?.cached || 0
  const hitRate = total ? Math.round((100 * cached) / total) : null
  const f = (v) => (v ? `${v.toFixed(1)} ms` : '—')
  const cells = [
    { k: 'p50', v: latency?.p50, hint: 'median' },
    { k: 'p95', v: latency?.p95, hint: 'slowest 5%' },
    { k: 'p99', v: latency?.p99, hint: 'tail — watch this' },
  ]
  return (
    <div className="card">
      <div className="row-between">
        <h3 style={{ margin: 0 }}>Performance</h3>
        <span className="dim small">{fmt(latency?.count || 0)} queries since restart</span>
      </div>
      <div className="latency-row">
        {cells.map((cell) => (
          <div className="latency-cell" key={cell.k}>
            <div className="latency-value">{f(cell.v)}</div>
            <div className="latency-label">
              {cell.k.toUpperCase()} · <span className="dim">{cell.hint}</span>
            </div>
          </div>
        ))}
      </div>
      <div className="kv-grid" style={{ marginTop: 8 }}>
        <div className="kv-row">
          <span className="kv-label">Avg latency (24h)</span>
          <span className="kv-value">{(avg24 || 0).toFixed(2)} ms</span>
        </div>
        <div className="kv-row">
          <span className="kv-label">Cache hit rate</span>
          <span className="kv-value">
            {hitRate == null ? '—' : `${hitRate}%`}{' '}
            <span className="dim small">
              ({fmt(cached)} of {fmt(total)} queries served from cache)
            </span>
          </span>
        </div>
        <div className="kv-row">
          <span className="kv-label">Coalesced queries</span>
          <span className="kv-value">
            {fmt(coalesce?.merged)}{' '}
            <span className="dim small">
              queries shared {fmt(coalesce?.flights)} upstream flight{coalesce?.flights === 1 ? '' : 's'} ·{' '}
              {fmt(coalesce?.saved || 0)} round trips saved
            </span>
          </span>
        </div>
        <div className="kv-row">
          <span className="kv-label">ASN headers</span>
          <span className="kv-value">
            {fmt(counters?.asn_header || 0)}{' '}
            <span className="dim small">DoH responses carrying X-Irongrid-Client-ASN</span>
          </span>
        </div>
      </div>
      <div className="card-hint">
        Percentiles are estimated from an in-process histogram (blocked, cached and upstream-served queries all count).
        A p99 spike usually means an upstream round trip or a serve-stale fallback; prefetch and serve-stale keep repeat
        queries in the low buckets. The coalescing row counts queries that hit the in-flight request pool: bursts of
        identical questions collapse into one upstream query.
      </div>
    </div>
  )
}

// UpstreamsCard shows each upstream's circuit-breaker state: healthy, degraded
// (some consecutive failures but still being tried) or cooling down (skipped
// until the cooldown re-arms so queries fail fast instead of stalling).
function UpstreamsCard({ upstreams }) {
  const hasCooldown = (upstreams || []).some((u) => u && !u.available)
  // Live "re-arms in Ns" countdown: the clock is read inside the interval
  // callback (never during render, per the purity rule) and stored in state.
  const [now, setNow] = useState(0)
  useEffect(() => {
    if (!hasCooldown) return
    setNow(Date.now())
    const t = setInterval(() => setNow(Date.now()), 1000)
    return () => clearInterval(t)
  }, [hasCooldown])
  if (!upstreams || upstreams.length === 0) return null
  const state = (u) => {
    if (!u.available) return { cls: 'badge-error', label: 'cooling down' }
    if (u.fails > 0) return { cls: 'badge-warn', label: `degraded · ${u.fails} consecutive fails` }
    return { cls: 'badge-allowed', label: 'healthy' }
  }
  // now is 0 until the effect's first tick; guard so the very first frame
  // never computes a bogus epoch-based countdown.
  const secs = (u) => (now && u.cooldown_until ? Math.max(0, Math.round((new Date(u.cooldown_until) - now) / 1000)) : 0)
  return (
    <div className="card">
      <div className="row-between">
        <h3 style={{ margin: 0 }}>Upstreams</h3>
        <span className="dim small">circuit-breaker health</span>
      </div>
      <div className="top-list" style={{ marginTop: 8 }}>
        {upstreams.map((u) => {
          const s = state(u)
          return (
            <div className="top-row" key={u.name}>
              <span className={`badge ${s.cls}`}>{s.label}</span>
              <span className="top-domain mono" title={u.name}>
                {u.name}
              </span>
              <span className="dim small" style={{ marginLeft: 'auto' }}>
                {u.transport}
              </span>
              {!u.available && <span className="top-count dim small">re-arms in {secs(u)}s</span>}
            </div>
          )
        })}
      </div>
      <div className="card-hint">
        After 3 consecutive failures an upstream is skipped for 30s instead of burning its full timeout on every query;
        any success resets it. While cooling down, queries fail fast to the next upstream or serve-stale.
      </div>
    </div>
  )
}

// CacheCard shows how hard the two cache layers are working: the in-process
// L1 (counters reset on restart) and Dragonfly's L2 (cumulative counters since
// the Dragonfly process started, plus its memory/keys). This is what the
// "Cache: online" sidebar dot doesn't tell you.
function CacheCard({ cache }) {
  // First-seen L2 snapshot (cumulative since Dragonfly started): the delta
  // against it is the hit-rate of traffic since THIS page loaded, which is
  // what the card should reflect — the all-time ratio is dominated by the
  // DDoS flood's write-once queries. The base is snapshotted in an effect
  // (refs must not be touched during render) and the delta is derived there
  // too, into state. Declared above the early return so the hooks stay
  // unconditional.
  const baseRef = useRef(null)
  const [l2Delta, setL2Delta] = useState(null) // { hits, misses } since page load
  const l2 = cache?.l2
  // All hooks run unconditionally (before the early return) so the hook
  // order is stable across renders.
  useEffect(() => {
    if (!l2) return
    if (!baseRef.current) baseRef.current = { hits: l2.hits, misses: l2.misses }
    setL2Delta({
      hits: Math.max(0, (l2.hits || 0) - baseRef.current.hits),
      misses: Math.max(0, (l2.misses || 0) - baseRef.current.misses),
    })
  }, [l2])
  if (!cache) return null
  const l1 = cache.l1
  const pct = (h, m) => {
    const t = (h || 0) + (m || 0)
    return t ? Math.round((100 * (h || 0)) / t) : null
  }
  const l1Rate = pct(l1?.hits, l1?.misses)
  const dH = l2Delta ? l2Delta.hits : null
  const dM = l2Delta ? l2Delta.misses : null
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
            {l1Rate == null ? '—' : `${l1Rate}%`}{' '}
            <span className="dim small">
              ({fmt(l1?.hits || 0)} of {fmt((l1?.hits || 0) + (l1?.misses || 0))} since restart)
            </span>
          </span>
        </div>
        <div className="kv-row">
          <span className="kv-label">L2 hit rate</span>
          <span className="kv-value">
            {l2Rate == null ? '—' : `${l2Rate}%`}{' '}
            <span className="dim small">
              ({fmt(dH ?? 0)} of {fmt((dH ?? 0) + (dM ?? 0))} since page load)
            </span>
          </span>
        </div>
        <div className="kv-row">
          <span className="kv-label">Memory</span>
          <span className="kv-value">
            {mb(memUsed)} MB of {mb(memMax)} MB
          </span>
        </div>
        <div className="kv-row">
          <span className="kv-label">Keys · expired · evicted</span>
          <span className="kv-value">
            {fmt(l2?.keys)} · {fmt(l2?.expired)} · {fmt(l2?.evicted)}
          </span>
        </div>
      </div>
      {memPct != null && (
        <div
          className="proto-track"
          style={{ marginTop: 8 }}
          title={`${memPct}% of the Dragonfly memory budget in use`}
        >
          <div className="proto-fill" style={{ width: `${memPct}%` }} />
        </div>
      )}
      <div className="card-hint">
        The L2 rate above is for traffic since this page loaded; all-time it is{' '}
        {l2AllTime == null ? '—' : `${l2AllTime}%`} (since Dragonfly started). A low all-time rate is normal — the flood
        wrote millions of one-off queries — and most repeat queries are absorbed by L1 anyway. L2 is the shared,
        restart-surviving layer, and the query log lives here too.
      </div>
    </div>
  )
}

// WarmerCard shows the proactive cache warmer's state: how many active
// domains the last passes considered, how many answers were written to the
// cache (A + AAAA), how many were skipped (blocked / rewritten / already
// fresh) and how many resolutions failed. Off it explains how to turn it on.
function WarmerCard({ warmer, onWarmed }) {
  const [busy, setBusy] = useState(false)
  if (!warmer) return null
  if (!warmer.enabled) {
    return (
      <div className="card">
        <div className="row-between">
          <h3 style={{ margin: 0 }}>Cache warmer</h3>
          <span className="badge badge-warn">off</span>
        </div>
        <p className="dim small" style={{ margin: '8px 0 0' }}>
          Pre-cache answers for every domain your network queried in the last 24h, so a restart or cache flush
          doesn&apos;t leave the first query for each domain cold. Enable it under{' '}
          <strong>Settings → Cache warmer</strong>.
        </p>
      </div>
    )
  }
  const warmNow = async () => {
    if (busy) return
    setBusy(true)
    try {
      await api.warmCache()
      onWarmed && onWarmed()
    } catch {
      // Best-effort kick: the next 10s poll reflects the warmer state anyway.
    } finally {
      setBusy(false)
    }
  }
  return (
    <div className="card">
      <div className="row-between">
        <h3 style={{ margin: 0 }}>Cache warmer</h3>
        <div className="row">
          <span className="badge badge-allowed">on</span>
          <button
            className="btn small"
            type="button"
            onClick={warmNow}
            disabled={busy}
            title="Kick a warming pass now (e.g. right after flushing the cache)"
          >
            {busy ? 'Warming…' : 'Warm now'}
          </button>
        </div>
      </div>
      <div className="kv-grid" style={{ marginTop: 8 }}>
        <div className="kv-row">
          <span className="kv-label">Last pass</span>
          <span className="kv-value">{warmer.last_run ? new Date(warmer.last_run).toLocaleString() : '—'}</span>
        </div>
        <div className="kv-row">
          <span className="kv-label">Passes</span>
          <span className="kv-value">{fmt(warmer.runs)}</span>
        </div>
        <div className="kv-row">
          <span className="kv-label">Domains considered</span>
          <span className="kv-value">{fmt(warmer.domains)}</span>
        </div>
        <div className="kv-row">
          <span className="kv-label">Warmed · skipped · failed</span>
          <span className="kv-value">
            {fmt(warmer.warmed)} · {fmt(warmer.skipped)} · {fmt(warmer.failed)}
          </span>
        </div>
      </div>
      {warmer.last_error && (
        <div className="error-text small" style={{ marginTop: 8, display: 'flex', gap: 6, alignItems: 'flex-start' }}>
          <AlertIcon size={13} style={{ flexShrink: 0, marginTop: 1 }} />
          <span>{warmer.last_error}</span>
        </div>
      )}
      <div className="card-hint">
        Each pass takes the domains queried in the lookback window from the query log and re-resolves them (A + AAAA)
        through your upstreams into Dragonfly.
        <strong>Skipped</strong> covers blocked / rewritten domains plus questions the cache already answers fresh;{' '}
        <strong>failed</strong> is upstream or cache write errors. Fresh probes don&apos;t count toward the cache
        hit-rate cards above.
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
          <span className="kv-value">
            {fmt(t.allowed || 0)} · {fmt(t.blocked || 0)} · {fmt(t.cached || 0)}
          </span>
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
                <span className="top-domain" title={c.domain}>
                  {c.domain}
                </span>
                <span className="top-count">{fmt(c.count)}</span>
                <span className="top-go" aria-hidden="true">
                  ›
                </span>
              </div>
            ))}
          </div>
          <div className="card-hint">Click a client to open its queries in the query log.</div>
        </>
      )}
    </div>
  )
}

// Sparkline renders the last 24 hours of query volume as a smooth area
// chart: total traffic as a gradient cyan area with a hairline ridge, and
// blocked volume overlaid as a rose area on the same baseline. Per-hour
// tooltips hover; quiet hours dip visibly toward zero.
function Sparkline({ data }) {
  if (!data || data.length === 0) return null
  const max = Math.max(...data.map((d) => d.total), 1)
  const H = 64
  const W = 300
  const PAD = 2
  const inner = H - PAD * 2
  const pts = data.map((d, i) => {
    const x = PAD + (i / (data.length - 1)) * (W - PAD * 2)
    const yTotal = PAD + inner - (d.total / max) * inner
    const yBlocked = PAD + inner - ((d.blocked || 0) / max) * inner
    return { ...d, x, yTotal, yBlocked }
  })
  // Smooth path through the points (catmull-rom → cubic bézier) so the
  // chart reads as a curve rather than a zig-zag of straight segments.
  const line = (pts, yKey) => {
    if (pts.length === 1) return `M ${pts[0].x} ${pts[0][yKey]} L ${pts[0].x + 1} ${pts[0][yKey]}`
    return pts.reduce((acc, p, i) => {
      if (i === 0) return `M ${p.x} ${p[yKey]}`
      const prev = pts[i - 1]
      const cx = (prev.x + p.x) / 2
      return `${acc} C ${cx} ${prev[yKey]}, ${cx} ${p[yKey]}, ${p.x} ${p[yKey]}`
    }, '')
  }
  const totalLine = line(pts, 'yTotal')
  const blockedLine = line(pts, 'yBlocked')
  const area = (l) => `${l} L ${pts[pts.length - 1].x} ${H} L ${pts[0].x} ${H} Z`
  const uid = `spark${(pts[0]?.hour || '').replace(/\D/g, '') || 'g'}`
  return (
    <div>
      <svg
        className="spark-svg"
        viewBox={`0 0 ${W} ${H}`}
        preserveAspectRatio="none"
        role="img"
        aria-label="Queries per hour over the last 24 hours"
      >
        <defs>
          <linearGradient id={`${uid}-total`} x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor="var(--cyan)" stopOpacity="0.4" />
            <stop offset="100%" stopColor="var(--cyan)" stopOpacity="0.03" />
          </linearGradient>
          <linearGradient id={`${uid}-blocked`} x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor="var(--rose)" stopOpacity="0.5" />
            <stop offset="100%" stopColor="var(--rose)" stopOpacity="0.04" />
          </linearGradient>
        </defs>
        {pts.map((d) => (
          <g key={d.hour}>
            <title>{`${new Date(d.hour).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })} — ${fmt(d.total)} query${d.total === 1 ? '' : 's'}${d.blocked ? ` (${fmt(d.blocked)} blocked)` : ''}`}</title>
            {/* transparent hit-slab so the tooltip covers the whole column */}
            <rect x={d.x - 5} y={0} width={10} height={H} fill="transparent" />
          </g>
        ))}
        <path className="spark-blocked" d={area(blockedLine)} style={{ fill: `url(#${uid}-blocked)` }} />
        {/* pathLength="1" normalises the path length so the CSS draw-in can
            use a constant dash length for any data shape */}
        <path className="spark-blocked-line" d={blockedLine} pathLength={1} />
        <path className="spark-total" d={area(totalLine)} style={{ fill: `url(#${uid}-total)` }} />
        <path className="spark-total-line" d={totalLine} pathLength={1} />
      </svg>
      <div className="spark-legend">
        <span>
          <i className="spark-legend-total" /> queries
        </span>
        <span>
          <i className="spark-legend-blocked" /> blocked
        </span>
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
        ) : (
          <>
            {info.asn || 'n/a'} · {info.holder || info.name || 'unknown network'} · {info.prefix || ''}
            {info.country ? ` · ${info.country}` : ''}
          </>
        )}
      </div>
    )
  }

  const hasHoney = honey.length > 0
  const hasRate = rate.length > 0
  const blockPrefix = (ip) => (ip.includes(':') ? 64 : 24)
  return (
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
                  <button className="btn ghost tiny" type="button" onClick={() => report(ip)} disabled={reporting[ip]}>
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
  )
}

// RootHintsCard summarises the authoritative root-hints source: whether the
// resolver walks referrals from a live PGP-verified named.root fetch, a
// last-known-good disk cache, or the bundled fallback.
function RootHintsCard({ status }) {
  const rh = status?.root_hints
  if (!rh?.enabled) return null
  const badge = rh.source === 'live' ? 'badge-allowed' : rh.source === 'cached' ? 'badge-warn' : 'badge-error'
  const sourceLabel =
    rh.source === 'live' ? 'Live (named.root)' : rh.source === 'cached' ? 'Disk cache' : 'Bundled fallback'
  return (
    <div className="card">
      <div className="row-between">
        <h3 style={{ margin: 0 }}>Root hints</h3>
        <span className={`badge ${badge}`}>{sourceLabel}</span>
      </div>
      <div className="kv-grid" style={{ marginTop: 8 }}>
        <div className="kv-row">
          <span className="kv-label">Signature</span>
          <span className="kv-value" style={{ display: 'inline-flex', alignItems: 'center', gap: 5 }}>
            {rh.verified ? (
              <>
                <CheckIcon size={12} /> PGP-verified (Verisign)
              </>
            ) : (
              'not verified — using trusted fallback'
            )}
          </span>
        </div>
        <div className="kv-row">
          <span className="kv-label">Addresses</span>
          <span className="kv-value">{rh.addresses ?? 0} root server addresses</span>
        </div>
        <div className="kv-row">
          <span className="kv-label">Last fetch</span>
          <span className="kv-value">{rh.last_fetch ? new Date(rh.last_fetch).toLocaleString() : '—'}</span>
        </div>
        <div className="kv-row">
          <span className="kv-label">Refresh</span>
          <span className="kv-value">every {rh.refresh_interval || '7d'}</span>
        </div>
      </div>
      {rh.last_error && (
        <div className="error-text small" style={{ marginTop: 8, display: 'flex', gap: 6, alignItems: 'flex-start' }}>
          <AlertIcon size={13} style={{ flexShrink: 0, marginTop: 1 }} />
          <span>{rh.last_error}</span>
        </div>
      )}
    </div>
  )
}

// TuningCard summarises the system-level tuning from /api/status: the
// file-descriptor limit (with what boot raised it from), the per-socket
// buffer size, the Linux socket sysctls with live values, and the Go runtime
// settings. A knob below its target shows "low" — raise it with root, a
// sysctl.d drop-in, or docker --sysctl / compose sysctls.
function TuningCard({ status }) {
  const t = status?.tuning
  if (!t) return null
  const fmtFd = (n) => {
    if (n == null) return 'n/a'
    if (Number(n) > 1e15) return 'unlimited' // RLIM_INFINITY (macOS)
    return Number(n).toLocaleString()
  }
  const bytes = (n) => {
    if (!n || n <= 0) return '—'
    if (Number(n) > 1e15) return 'unlimited' // math.MaxInt64: GOMEMLIMIT not set
    if (n >= 1073741824) return (n / 1073741824).toFixed(1) + ' GiB'
    return (n / 1048576).toFixed(0) + ' MiB'
  }
  // socketPips renders one pip per bound SO_REUSEPORT socket (capped at 8
  // for the display; the exact count is still printed next to it).
  const socketPips = (n) => (
    <span className="socket-pips" aria-hidden="true">
      {Array.from({ length: Math.min(Number(n) || 0, 8) }, (_, i) => (
        <span key={i} className="socket-pip" />
      ))}
      {Number(n) > 8 && <span className="socket-pip-more">+{Number(n) - 8}</span>}
    </span>
  )
  const fdState = () => {
    if (t.fd_soft == null) return { cls: 'badge', label: 'no fd limit on Windows' }
    if (t.fd_raised) return { cls: 'badge-allowed', label: `raised ${fmtFd(t.fd_raised_from)} → ${fmtFd(t.fd_soft)}` }
    if (t.fd_soft >= t.fd_hard) return { cls: 'badge-allowed', label: 'at hard limit' }
    return { cls: 'badge-warn', label: 'not raised' }
  }
  const f = fdState()
  return (
    <div className="card">
      <div className="row-between">
        <h3 style={{ margin: 0 }}>System tuning</h3>
        <span className="dim small">{t.os}</span>
      </div>
      <div className="kv-grid" style={{ marginTop: 8 }}>
        <div className="kv-row">
          <span className="kv-label">File descriptors</span>
          <span className="kv-value">
            {fmtFd(t.fd_soft)} soft / {fmtFd(t.fd_hard)} hard <span className={`badge ${f.cls}`}>{f.label}</span>
          </span>
        </div>
        <div className="kv-row">
          <span className="kv-label">Socket buffers</span>
          <span className="kv-value">{bytes(t.socket_buffer)} per socket · every listener &amp; upstream</span>
        </div>
        <div className="kv-row">
          <span className="kv-label">UDP listener sockets</span>
          <span className="kv-value">
            {socketPips(status?.udp_sockets)} {status?.udp_sockets ?? 0} plain UDP
            {' · '}
            {socketPips(status?.doq_sockets)} {status?.doq_sockets ?? 0} DoQ{' '}
            <span className="badge badge-allowed">SO_REUSEPORT</span>
          </span>
        </div>
        <div className="kv-row">
          <span className="kv-label">Go runtime</span>
          <span className="kv-value">
            GOMAXPROCS {t.gomaxprocs} · GOMEMLIMIT {bytes(t.gomemlimit)} · GOGC {t.gogc < 0 ? 'off' : t.gogc}
          </span>
        </div>
      </div>
      {t.sysctls && t.sysctls.length > 0 && (
        <>
          <h4 style={{ margin: '14px 0 8px' }}>Linux socket sysctls</h4>
          <div className="kv-grid">
            {t.sysctls.map((s) => (
              <div className="kv-row" key={s.key}>
                <span className="kv-label mono">net.core.{s.key}</span>
                <span className="kv-value">
                  {Number(s.value).toLocaleString()}{' '}
                  <span className={`badge ${s.value >= s.target ? 'badge-allowed' : 'badge-warn'}`}>
                    {s.value >= s.target ? 'ok' : 'low'}
                  </span>
                  <span className="dim small" style={{ marginLeft: 6 }}>
                    {s.note}
                  </span>
                </span>
              </div>
            ))}
          </div>
          <div className="card-hint">
            The kernel clamps SO_RCVBUF to net.core.rmem_max, so a low value caps the socket buffers above. Applied
            automatically as root at boot; for Docker set the same values under <code>sysctls:</code> in
            docker-compose.yml, or run as root (or with CAP_NET_ADMIN) for the in-process raise.
          </div>
        </>
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
    <div
      className={`card acme-card ${ok ? '' : 'acme-error'}`}
      role="button"
      tabIndex={0}
      onClick={() => onNavigate('tls')}
      onKeyDown={(e) => e.key === 'Enter' && onNavigate('tls')}
      style={{ cursor: 'pointer' }}
    >
      <div className="row-between">
        <h3 style={{ margin: 0 }}>
          Let&apos;s Encrypt{' '}
          <span className={`badge ${ok ? 'badge-allowed' : 'badge-error'}`}>{ok ? 'healthy' : 'needs attention'}</span>
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
        <div className="error-text small" style={{ marginTop: 8, display: 'flex', gap: 6, alignItems: 'flex-start' }}>
          <AlertIcon size={13} style={{ flexShrink: 0, marginTop: 1 }} />
          <span>{acme.last_error} — click to fix on the SSL / TLS page.</span>
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
