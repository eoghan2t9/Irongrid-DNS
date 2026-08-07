import React, { useEffect, useState, useCallback } from 'react'
import { api } from '../api'
import { useToast } from '../toast'

const empty = () => ({
  server: {
    listen_udp: '', listen_tcp: '', listen_dot: '', listen_doh: '', listen_doq: '',
    doh_path: '/dns-query', web_listen: '', web_tls: false, web_redirect: false, web_redirect_port: 80, timeout_sec: 5,
  },
  upstreams: [],
  cache: { addr: '', password: '', db: 0, ttl: '6h', negative_ttl: '1m' },
  tls: { cert_file: '', key_file: '', generate_self_signed: true, self_signed_hosts: [], cert_dir: '', acme: { enabled: false, email: '', domains: [], staging: false, http01_port: 80, renew_before_days: 30, dns01: { provider: '', propagation_wait_sec: 60, cloudflare_token: '', digitalocean_token: '', hetzner_token: '', godaddy_key: '', godaddy_secret: '', aws_access_key_id: '', aws_secret_access_key: '' } } },
  filter: { block_response: 'nxdomain', block_ttl: 600, blocklists: [], whitelist: [], blacklist: [], auto_update: '24h' },
  log: { query_log_file: '', retention_days: 30, verbose: true },
  web: { username: 'admin', password: '' },
  tunnel: { enabled: false, token: '', config_file: '', quick_tunnel: false, quick_tunnel_url: '', hostname: '' },
  rewrites: [],
  client_groups: [],
  rate_limit: { enabled: false, qps: 20, burst: 40, auto_block: false, block_after: 3, block_for: '10m' },
  geo_block: { enabled: false, countries: [], allowlist: [], base_url: '', auto_update: '168h' },
  dnssec: { enabled: false, require_ad: true },
})

export default function Settings({ onSessionInvalidated }) {
  const toast = useToast()
  const [cfg, setCfg] = useState(null)
  const [initialUser, setInitialUser] = useState('')
  const [dirty, setDirty] = useState(false)
  const [saving, setSaving] = useState(false)
  const [restartNeeded, setRestartNeeded] = useState([])
  const [restarting, setRestarting] = useState(false)
  const [diagName, setDiagName] = useState('example.com')
  const [diagType, setDiagType] = useState('A')
  const [diagResult, setDiagResult] = useState(null)
  const [blocked, setBlocked] = useState([])
  const [geoInfo, setGeoInfo] = useState({ enabled: false, countries: [] })

  const load = useCallback(async () => {
    try {
      const c = await api.config()
      setCfg(c)
      setInitialUser((c.web && c.web.username) || '')
    } catch { /* ignore */ }
  }, [])

  const loadAbuse = useCallback(async () => {
    try { setBlocked((await api.rateBlocked()).blocked || []) } catch { /* ignore */ }
    try { setGeoInfo(await api.geoStatus()) } catch { /* ignore */ }
  }, [])

  useEffect(() => { load() }, [load])
  useEffect(() => { loadAbuse() }, [loadAbuse])

  const set = (path, value) => {
    setCfg((prev) => {
      const next = JSON.parse(JSON.stringify(prev || empty()))
      const keys = path.split('.')
      let o = next
      for (let i = 0; i < keys.length - 1; i++) o = o[keys[i]]
      o[keys[keys.length - 1]] = value
      return next
    })
    setDirty(true)
  }

  const setListItem = (path, index, value) => {
    setCfg((prev) => {
      const next = JSON.parse(JSON.stringify(prev))
      next[path][index] = value
      return next
    })
    setDirty(true)
  }

  const addList = (path) => {
    setCfg((prev) => {
      const next = JSON.parse(JSON.stringify(prev))
      next[path] = [...(next[path] || []), '']
      return next
    })
    setDirty(true)
  }

  const removeList = (path, index) => {
    setCfg((prev) => {
      const next = JSON.parse(JSON.stringify(prev))
      next[path] = next[path].filter((_, i) => i !== index)
      return next
    })
    setDirty(true)
  }

  const save = async () => {
    setSaving(true)
    try {
      // A non-empty password field means "change the password" — the server
      // then rotates the session secret, invalidating every session cookie
      // including this one. Changing the username invalidates them too (each
      // cookie is bound to the username). Either way the next API call would
      // 401, so hand it to the app: sign out locally and prompt to sign in
      // with the updated credentials.
      const passwordChanged = !!(cfg.web && cfg.web.password)
      const usernameChanged = !!(initialUser && cfg.web && cfg.web.username && cfg.web.username !== initialUser)
      const credsChanged = passwordChanged || usernameChanged
      const r = await api.saveConfig(cfg)
      if (credsChanged && onSessionInvalidated) {
        onSessionInvalidated(
          passwordChanged
            ? 'Password changed — all sessions were signed out. Sign in with your new password.'
            : 'Username changed — all sessions were signed out. Sign in with your updated credentials.'
        )
        return
      }
      const restart = r.restart_required || []
      setRestartNeeded(restart)
      toast(
        restart.length
          ? `Saved. Block policy, filter lists and upstreams applied live. Restart needed for: ${restart.join(', ')}.`
          : 'Saved and applied live — no restart required.'
      )
      setDirty(false)
      await load()
      await loadAbuse()
    } catch (e) {
      toast(e.message, 'error')
    } finally {
      setSaving(false)
    }
  }

  const unblock = async (ip) => {
    try {
      await api.rateUnblock(ip)
      toast(`Unblocked ${ip}`)
      await loadAbuse()
    } catch (e) {
      toast('Unblock failed: ' + e.message, 'error')
    }
  }

  const refreshGeo = async () => {
    try {
      await api.geoRefresh()
      toast('Country data refresh started — status will update shortly.')
      setTimeout(loadAbuse, 2000)
    } catch (e) {
      toast('Geo refresh failed: ' + e.message, 'error')
    }
  }

  const restart = async () => {
    if (!window.confirm('Rebind DNS listeners, cache, TLS and the web server now? This takes a moment and briefly interrupts DNS service.')) return
    setRestarting(true)
    try {
      const r = await api.reloadConfig()
      const remaining = r.still_requires_restart || []
      setRestartNeeded(remaining)
      toast(
        remaining.length
          ? `Reloaded in place — listeners, cache, TLS and upstreams are live. ${remaining.join(', ')} still needs a process restart.`
          : 'Restarted in place — all configuration is now live.'
      )
      await load()
    } catch (e) {
      toast('Restart failed: ' + e.message, 'error')
    } finally {
      setRestarting(false)
    }
  }

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
    try {
      const r = await api.flushCache()
      toast(`Cache flushed (${r.deleted} keys removed)`)
    } catch (e) {
      toast('Flush failed: ' + e.message, 'error')
    }
  }

  if (!cfg) return <div className="loading">Loading configuration…</div>

  const field = (label, hint, input) => (
    <label className="field">
      <span className="field-label">{label}</span>
      {input}
      {hint && <span className="field-hint">{hint}</span>}
    </label>
  )

  // deepGet resolves a dotted path like 'tls.acme.dns01.provider'.
  const deepGet = (path, fallback) => {
    let o = cfg
    for (const k of path.split('.')) {
      if (o == null) return fallback
      o = o[k]
    }
    return o ?? fallback
  }

  const text = (label, path, hint, placeholder) =>
    field(label, hint, (
      <input
        className="input mono"
        value={deepGet(path, '')}
        onChange={(e) => set(path, e.target.value)}
        placeholder={placeholder}
      />
    ))

  const textarea = (label, path, hint) =>
    field(label, hint, (
      <textarea
        className="input mono"
        rows={3}
        value={(deepGet(path, []) || []).join('\n')}
        onChange={(e) => set(path, e.target.value.split('\n').map((s) => s.trim()).filter(Boolean))}
        placeholder="one entry per line"
      />
    ))

  const number = (label, path, hint) =>
    field(label, hint, (
      <input
        className="input mono"
        type="number"
        value={deepGet(path, 0)}
        onChange={(e) => set(path, Number(e.target.value))}
      />
    ))

  const toggle = (label, path) => (
    <label className="toggle-field">
      <span className="field-label">{label}</span>
      <span className="switch">
        <input type="checkbox" checked={!!deepGet(path, false)} onChange={(e) => set(path, e.target.checked)} />
        <span className="slider" />
      </span>
    </label>
  )

  const listEditor = (label, path, hint) => (
    <div className="field span-2">
      <span className="field-label">{label}</span>
      {(cfg[path] || []).map((item, i) => (
        <div className="list-row" key={i}>
          <input className="input mono" value={item} onChange={(e) => setListItem(path, i, e.target.value)} aria-label={`${label} entry ${i + 1}`} />
          <button className="btn small danger" type="button" onClick={() => removeList(path, i)} aria-label={`Remove ${item || 'this entry'}`}>✕</button>
        </div>
      ))}
      <button className="btn small" type="button" onClick={() => addList(path)}>+ Add</button>
      {hint && <span className="field-hint">{hint}</span>}
    </div>
  )

  return (
    <div className="stack">
      <div className="card">
        <div className="row-between">
          <h3 style={{ margin: 0 }}>Configuration</h3>
          <div className="row">
            {dirty && <span className="dim small">unsaved changes</span>}
            {restartNeeded.length > 0 && !dirty && (
              <button className="btn primary" onClick={restart} disabled={restarting}>
                {restarting ? 'Restarting…' : `Apply & restart (${restartNeeded.length})`}
              </button>
            )}
            <button className="btn primary" onClick={save} disabled={saving || !dirty}>
              {saving ? 'Saving…' : 'Save & apply'}
            </button>
          </div>
        </div>
        <p className="dim small">
          Editing <code>irongrid.yaml</code>. Block policy, filter lists and upstreams apply immediately;
          listener/cache/TLS changes can be applied in place with <strong>Apply &amp; restart</strong> — no process
          restart needed.
        </p>
      </div>

      <div className="card">
        <h3>Server listeners</h3>
        <div className="form-grid">
          {text('UDP listener', 'server.listen_udp', 'plain DNS over UDP, "" disables', '0.0.0.0:53')}
          {text('TCP listener', 'server.listen_tcp', null, '0.0.0.0:53')}
          {text('DoT (TLS)', 'server.listen_dot', null, '0.0.0.0:853')}
          {text('DoH (HTTPS)', 'server.listen_doh', null, '0.0.0.0:443')}
          {text('DoQ (QUIC)', 'server.listen_doq', null, '0.0.0.0:853')}
          {text('DoH path', 'server.doh_path', null, '/dns-query')}
          {text('Web dashboard', 'server.web_listen', null, '0.0.0.0:8080')}
          {toggle('Serve dashboard over HTTPS (web_tls)', 'server.web_tls')}
          {toggle('Redirect plain HTTP to HTTPS (web_redirect)', 'server.web_redirect')}
          {number('Redirect listener port', 'server.web_redirect_port')}
          {number('Upstream timeout (s)', 'server.timeout_sec')}
        </div>
      </div>

      <div className="card">
        <h3>Upstreams</h3>
        {listEditor('upstreams', 'upstreams', 'udp://, tcp://, tls://, https://, quic://, recursive:// — tried in order')}
        <p className="dim small" style={{ marginTop: -6 }}>
          <code>recursive://</code> resolves from the root servers itself instead of forwarding — no third-party
          resolver sees your query stream, at the cost of slower cold lookups and no upstream DNSSEC validation to
          rely on. Mix it with forwarders (tried in order) or list it alone.
        </p>
      </div>

      <div className="card">
        <h3>DNSSEC</h3>
        <p className="dim small" style={{ marginTop: -6 }}>
          Irongrid forwards queries rather than validating the signature chain itself — like Pi-hole, AdGuard Home
          and dnsmasq, it trusts an upstream that already validates. Enabling this sets the DO bit on upstream
          queries and (optionally) rejects answers the upstream didn't mark authenticated. This is only meaningful
          with an <strong>encrypted upstream</strong> (DoT/DoH/QUIC to e.g. Cloudflare, Google or Quad9) — over
          plain UDP/TCP the authentication flag can be stripped or forged in transit.
        </p>
        <div className="form-grid">
          {toggle('Enable DNSSEC (trust upstream validation)', 'dnssec.enabled')}
          {toggle('Reject unauthenticated answers (SERVFAIL)', 'dnssec.require_ad')}
        </div>
      </div>      <div className="card">
        <h3>Rate limiting &amp; abuse protection</h3>
        <p className="dim small" style={{ marginTop: -6 }}>
          Throttles queries per client IP — a defense against a compromised LAN device or a public listener being
          abused for DNS amplification. UDP queries over the limit are dropped silently (answering at all would still
          amplify toward a spoofed source); TCP/DoT/DoH/DoQ get REFUSED. With <strong>auto-block</strong>, a client that
          keeps tripping the limit is refused entirely for the cooldown window instead of just being throttled back.
        </p>
        <div className="form-grid">
          {toggle('Enable rate limiting', 'rate_limit.enabled')}
          {number('Sustained queries/sec per client', 'rate_limit.qps')}
          {number('Burst allowance per client', 'rate_limit.burst')}
          {toggle('Auto-block repeat offenders', 'rate_limit.auto_block')}
          {number('Violations before blocking', 'rate_limit.block_after')}
          {text('Block cooldown', 'rate_limit.block_for', 'e.g. 10m, 1h', '10m')}
        </div>
        <h4 style={{ margin: '16px 0 10px' }}>Currently blocked clients</h4>
        {blocked.length === 0 ? (
          <p className="dim small">No clients are currently auto-blocked.</p>
        ) : (
          <div>
            {blocked.map((b) => (
              <div className="list-row" key={b.ip} style={{ alignItems: 'flex-start' }}>
                <div style={{ minWidth: 0 }}>
                  <div className="mono">{b.ip}</div>
                  <div className="dim small">
                    blocked until {new Date(b.blocked_until).toLocaleString()} · {b.queries ?? 0} queries ·
                    {' '}blocked {b.blocks ?? 0}×
                    {b.first_seen ? <> · first seen {new Date(b.first_seen).toLocaleString()}</> : null}
                  </div>
                </div>
                <button className="btn small danger" type="button" onClick={() => unblock(b.ip)}>Unblock</button>
              </div>
            ))}
          </div>
        )}
        <div className="quick-actions" style={{ marginTop: 8 }}>
          <button className="btn small" type="button" onClick={loadAbuse}>Refresh list</button>
        </div>
      </div>

      <div className="card">
        <h3>Geo blocking</h3>
        <p className="dim small" style={{ marginTop: -6 }}>
          Refuses queries (<strong>REFUSED</strong> on every transport) from client IPs that belong to the selected
          countries. Country data comes from free per-country CIDR lists (ipverse/rir-ip) fetched automatically and
          cached locally — no account or API key needed. Allowlisted IPs/CIDRs always pass.
        </p>
        <div className="form-grid">
          {toggle('Enable geo blocking', 'geo_block.enabled')}
          {textarea('Blocked countries (ISO 3166-1 alpha-2)', 'geo_block.countries', 'one per line, e.g. RU, CN, KP')}
          {textarea('Allowlist (IPs / CIDRs)', 'geo_block.allowlist', 'clients that are never geo-blocked')}
          {text('Data source URL (optional)', 'geo_block.base_url', 'defaults to ipverse/rir-ip; appends &lt;cc&gt;/ipv4-aggregated.txt and &lt;cc&gt;/ipv6-aggregated.txt (lowercase codes)')}
          {field('Auto-refresh country data', 'how often the per-country CIDR lists re-fetch themselves', (
            <select className="input" value={deepGet('geo_block.auto_update', '') || ''} onChange={(e) => set('geo_block.auto_update', e.target.value)}>
              <option value="">Never</option>
              <option value="6h">Every 6 hours</option>
              <option value="24h">Daily</option>
              <option value="168h">Weekly</option>
            </select>
          ))}
        </div>
        {deepGet('geo_block.enabled', false) && (deepGet('geo_block.countries', []) || []).length === 0 && (
          <p className="dim small" style={{ marginTop: 8, color: 'var(--amber)' }}>
            ⚠ Geo blocking is on but no countries are listed — add ISO codes above (one per line, e.g. RU, CN), save, then refresh.
          </p>
        )}
        <h4 style={{ margin: '16px 0 10px' }}>Geo data status</h4>
        {geoInfo && geoInfo.countries && geoInfo.countries.length > 0 ? (
          <div>
            {geoInfo.countries.map((c) => (
              <div className="list-row" key={c.code}>
                <span className="mono">{c.code}</span>
                <span className="dim small">
                  {c.ipv4_ranges} IPv4 · {c.ipv6_ranges} IPv6 ranges
                  {c.last_fetch && <> · updated {new Date(c.last_fetch).toLocaleString()}</>}
                  {c.error && <span className="error-text"> · {c.error}</span>}
                </span>
              </div>
            ))}
          </div>
        ) : (
          <p className="dim small">No country data loaded yet — enable geo blocking, add country codes above, save, then refresh.</p>
        )}
        {geoInfo && geoInfo.next_refresh && deepGet('geo_block.enabled', false) && (
          <p className="dim small" style={{ marginTop: 8 }}>
            Next automatic refresh: {new Date(geoInfo.next_refresh).toLocaleString()}
          </p>
        )}
        <div className="quick-actions" style={{ marginTop: 8 }}>
          <button className="btn small" type="button" onClick={refreshGeo}>Refresh country data</button>
        </div>
      </div>

      <div className="card">
        <h3>Cache (Dragonfly)</h3>
        <div className="form-grid">
          {text('Address', 'cache.addr', null, 'localhost:6379')}
          {text('Password', 'cache.password', 'optional auth')}
          {number('DB index', 'cache.db')}
          {text('Positive TTL', 'cache.ttl', 'e.g. 6h, 30m, 1h30m')}
          {text('Negative TTL', 'cache.negative_ttl', 'e.g. 1m')}
        </div>
      </div>

      <div className="card">
        <h3>TLS</h3>
        <p className="dim small" style={{ marginTop: -6 }}>
          Prefer the dedicated <strong>SSL / TLS</strong> page for generating or uploading
          certificates — these fields are the raw config behind it.
        </p>
        <div className="form-grid">
          {text('Cert file', 'tls.cert_file', null, 'data/certs/cert.pem')}
          {text('Key file', 'tls.key_file', null, 'data/certs/key.pem')}
          {text('Cert directory', 'tls.cert_dir', null, 'data/certs')}
          {toggle('Generate self-signed', 'tls.generate_self_signed')}
          {textarea('Self-signed hosts (SANs)', 'tls.self_signed_hosts', 'one per line')}
        </div>
        <h4 style={{ margin: '16px 0 10px' }}>Let&apos;s Encrypt (ACME)</h4>
        <div className="form-grid">
          {toggle('Enable ACME auto-issuance', 'tls.acme.enabled')}
          {text('Email (account contact)', 'tls.acme.email', 'required when enabled', 'you@example.com')}
          {textarea('Domains', 'tls.acme.domains', 'public hostnames, one per line')}
          {toggle('Use staging CA (test certificates)', 'tls.acme.staging')}
          {field('DNS-01 provider', 'empty = HTTP-01 (domain answers on port 80)', (
            <select
              className="input"
              value={deepGet('tls.acme.dns01.provider', '')}
              onChange={(e) => set('tls.acme.dns01.provider', e.target.value)}
            >
              <option value="">HTTP-01 (no DNS API)</option>
              <option value="cloudflare">Cloudflare</option>
              <option value="digitalocean">DigitalOcean</option>
              <option value="hetzner">Hetzner</option>
              <option value="godaddy">GoDaddy</option>
              <option value="route53">AWS Route53</option>
            </select>
          ))}
          {deepGet('tls.acme.dns01.provider', '') === 'cloudflare' &&
            text('Cloudflare API token', 'tls.acme.dns01.cloudflare_token', 'Zone:DNS:Edit permission', '••••')}
          {deepGet('tls.acme.dns01.provider', '') === 'digitalocean' &&
            text('DigitalOcean token', 'tls.acme.dns01.digitalocean_token', 'personal access token with DNS:edit', '••••')}
          {deepGet('tls.acme.dns01.provider', '') === 'hetzner' &&
            text('Hetzner DNS token', 'tls.acme.dns01.hetzner_token', 'Hetzner DNS API token', '••••')}
          {deepGet('tls.acme.dns01.provider', '') === 'godaddy' && (
            <>
              {text('GoDaddy API key', 'tls.acme.dns01.godaddy_key', 'GoDaddy developer key', '••••')}
              {text('GoDaddy API secret', 'tls.acme.dns01.godaddy_secret', 'matching secret', '••••')}
            </>
          )}
          {deepGet('tls.acme.dns01.provider', '') === 'route53' && (
            <>
              {text('AWS access key ID', 'tls.acme.dns01.aws_access_key_id', 'IAM key with Route53 change-resource-record-sets', 'AKIA…')}
              {text('AWS secret access key', 'tls.acme.dns01.aws_secret_access_key', 'matching secret', '••••')}
            </>
          )}
          {deepGet('tls.acme.dns01.provider', '') !== '' &&
            number('DNS-01 propagation wait (s)', 'tls.acme.dns01.propagation_wait_sec')}
          {deepGet('tls.acme.dns01.provider', '') === '' &&
            number('HTTP-01 challenge port', 'tls.acme.http01_port')}
          {number('Renew when < N days left', 'tls.acme.renew_before_days')}
        </div>
      </div>

      <div className="card">
        <h3>Filtering</h3>
        <p className="dim small" style={{ marginTop: -6 }}>
          Manage which blocklists are installed on the dedicated <strong>Blocklists</strong> page — this is just
          the global behavior that applies to all of them.
        </p>
        <div className="form-grid">
          {field('Block response', 'nxdomain, refused, or an IP like 0.0.0.0', (
            <input
              className="input mono"
              value={cfg.filter.block_response}
              onChange={(e) => set('filter.block_response', e.target.value)}
            />
          ))}
          {number('Block TTL (s)', 'filter.block_ttl')}
          {field('Blocklist auto-update', 'how often every enabled blocklist refreshes itself', (
            <select className="input" value={cfg.filter.auto_update || ''} onChange={(e) => set('filter.auto_update', e.target.value)}>
              <option value="">Never</option>
              <option value="6h">Every 6 hours</option>
              <option value="24h">Daily</option>
              <option value="168h">Weekly</option>
            </select>
          ))}
          {textarea('Whitelist (always allow)', 'filter.whitelist')}
          {textarea('Blacklist (always block)', 'filter.blacklist')}
        </div>
      </div>

      <div className="card">
        <h3>Query log</h3>
        <div className="form-grid">
          {text('Log file', 'log.query_log_file', null, 'data/querylog.db')}
          {number('Retention (days)', 'log.retention_days')}
          {toggle('Verbose logging', 'log.verbose')}
        </div>
      </div>

      <div className="card">
        <h3>Web credentials</h3>
        <div className="form-grid">
          {text('Username', 'web.username')}
          {field('Password', 'leave blank to keep the current password; changing it signs out every device (including this one)', (
            <input className="input" type="password" value={cfg.web.password} onChange={(e) => set('web.password', e.target.value)} autoComplete="new-password" />
          ))}
        </div>
      </div>

      <div className="card">
        <h3>Tunnel (cloudflared)</h3>
        <div className="form-grid">
          {toggle('Start on boot', 'tunnel.enabled')}
          {toggle('Quick tunnel', 'tunnel.quick_tunnel')}
          {text('Token', 'tunnel.token', 'named tunnel token')}
          {text('Config file', 'tunnel.config_file', 'cloudflared YAML path')}
          {text('Origin URL', 'tunnel.quick_tunnel_url')}
          {text('Hostname', 'tunnel.hostname')}
        </div>
      </div>

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
          <button className="btn" onClick={() => api.refreshLists().then(() => toast('Blocklists refreshed')).catch((e) => toast('Refresh failed: ' + e.message, 'error'))}>Refresh blocklists</button>
        </div>
      </div>
    </div>
  )
}
