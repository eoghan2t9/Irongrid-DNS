import { useEffect, useState, useCallback } from 'react'
import { api } from '../api'
import { useToast } from '../toast'

// Sections for the Settings jump-nav — every card above keeps its id in
// this list so the anchors stay in sync with the page.
const SETTINGS_SECTIONS = [
  { id: 'settings-listeners', label: 'Listeners' },
  { id: 'settings-upstreams', label: 'Upstreams' },
  { id: 'settings-dnssec', label: 'DNSSEC' },
  { id: 'settings-ratelimit', label: 'Rate limit' },
  { id: 'settings-geo', label: 'Geo block' },
  { id: 'settings-abuse', label: 'Abuse' },
  { id: 'settings-cache', label: 'Cache' },
  { id: 'settings-warmer', label: 'Warmer' },
  { id: 'settings-tls', label: 'TLS' },
  { id: 'settings-filtering', label: 'Filtering' },
  { id: 'settings-log', label: 'Query log' },
  { id: 'settings-credentials', label: 'Login' },
  { id: 'settings-tunnel', label: 'Tunnel' },
  { id: 'settings-dhcp', label: 'DHCP' },
  { id: 'settings-backup', label: 'Backup' },
  { id: 'settings-diagnostic', label: 'Diagnostic' },
  { id: 'settings-maintenance', label: 'Maintenance' },
]

const empty = () => ({
  server: {
    listen_udp: '', listen_tcp: '', listen_dot: '', listen_doh: '', listen_doh3: '', listen_doq: '',
    doh_path: '/dns-query', web_listen: '', web_tls: false, web_redirect: false, web_redirect_port: 80, timeout_sec: 5, udp_sockets: 0, padding: false, cookies: false,
  },
  upstreams: [],
  upstream_mode: 'race',
  upstream_routes: [],
  cache: { addr: '', password: '', db: 0, ttl: '6h', negative_ttl: '1m', l1_entries: 0, serve_stale: '5m', prefetch: true, lookup_timeout: '150ms', failure_ttl: '5s' },
  recursive: { server_timeout: '' },
  tls: { cert_file: '', key_file: '', generate_self_signed: true, self_signed_hosts: [], cert_dir: '', acme: { enabled: false, email: '', domains: [], staging: false, http01_port: 80, renew_before_days: 30, dns01: { provider: '', propagation_wait_sec: 60, cloudflare_token: '', digitalocean_token: '', hetzner_token: '', godaddy_key: '', godaddy_secret: '', aws_access_key_id: '', aws_secret_access_key: '' } } },
  filter: { block_response: 'nxdomain', block_ttl: 600, blocklists: [], whitelist: [], blacklist: [], auto_update: '24h', cname_cloaking_protection: false },
  log: { query_log_file: '', retention_days: 30, verbose: true },
  web: { username: 'admin', password: '' },
  tunnel: { enabled: false, token: '', config_file: '', quick_tunnel: false, quick_tunnel_url: '', hostname: '' },
  rewrites: [],
  client_groups: [],
  rate_limit: { enabled: false, qps: 20, burst: 40, auto_block: false, block_after: 3, block_for: '10m' },
  geo_block: { enabled: false, countries: [], allowlist: [], ips: [], honeypots: [], base_url: '', auto_update: '168h', trust_udp: false },
  abuse: { abuseipdb_key: '' },
  dnssec: { enabled: false, require_ad: true },
  warmer: { enabled: false, interval: '15m', lookback: '24h', max_domains: 5000, concurrency: 8 },
  dhcp: {
    enabled: false, interface: '', subnet: '', range_start: '', range_end: '', gateway: '',
    dns: [], lease_time: '24h', domain: 'lan', static_leases: [],
    ipv6: false, ipv6_prefix: '', ipv6_range_start: '', ipv6_range_end: '',
  },
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
  const [fastest, setFastest] = useState(null)
  const [fastestBusy, setFastestBusy] = useState(false)
  const [fastestErr, setFastestErr] = useState('')
  // benchmarkAdded tracks the specs added from the benchmark that haven't
  // been saved yet, so an unsaved change can't silently vanish (or be
  // forgotten). Tracked as a list (not a count) so the banner stays accurate
  // if the user manually removes one of the added entries again.
  const [benchmarkAdded, setBenchmarkAdded] = useState([])
  const [blocked, setBlocked] = useState([])
  const [geoInfo, setGeoInfo] = useState({ enabled: false, countries: [] })
  const [honeyBlocked, setHoneyBlocked] = useState([])
  const [backupBusy, setBackupBusy] = useState(false)
  const [backupErr, setBackupErr] = useState('')
  const [restoring, setRestoring] = useState(false)
  const [restoreMsg, setRestoreMsg] = useState('')
  const [backupPassphrase, setBackupPassphrase] = useState('')

  const load = useCallback(async () => {
    try {
      const c = await api.config()
      setCfg(c)
      setInitialUser((c.web && c.web.username) || '')
    } catch { /* ignore */ }
    // A fresh load reflects the authoritative config, so any unsaved
    // benchmark adds are gone (or saved) — clear the tracking.
    setBenchmarkAdded([])
  }, [])

  const loadAbuse = useCallback(async () => {
    try { setBlocked((await api.rateBlocked()).blocked || []) } catch { /* ignore */ }
    try { setGeoInfo(await api.geoStatus()) } catch { /* ignore */ }
    try { setHoneyBlocked((await api.geoBlocked()).blocked || []) } catch { /* ignore */ }
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
      setBenchmarkAdded([])
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

  const reportAbuse = async (ip) => {
    if (!window.confirm(`Report ${ip} to AbuseIPDB (DDoS category)? Uses the AbuseIPDB key from the Abuse reporting section above.`)) return
    try {
      const r = await api.abuseReport(ip)
      toast(`Reported ${ip} to AbuseIPDB — abuse confidence ${r.abuse_confidence_score ?? 'n/a'}.`)
    } catch (e) {
      toast('Report failed: ' + e.message, 'error')
    }
  }

  const unblockHoney = async (ip) => {
    try {
      await api.geoUnblock(ip)
      toast(`Unblocked ${ip}`)
      await loadAbuse()
    } catch (e) {
      toast('Unblock failed: ' + e.message, 'error')
    }
  }

  // blockNet permanently adds a honeypot-hit client (or its /24 or /64
  // network) to geo_block.ips — the config-level block list, enforced by DNS
  // REFUSED and the host firewall at the packet level.
  const blockNet = async (ip, prefix) => {
    const label = prefix ? `${ip}/${prefix}` : ip
    if (!window.confirm(`Permanently block ${label}? It is added to geo_block.ips (config, survives restarts) and dropped at the host firewall. Remove it under Blocked client IPs in Settings to undo.`)) return
    try {
      await api.geoBlockIP(ip, prefix)
      toast(`Blocked ${label}`)
      await loadAbuse()
    } catch (e) {
      toast('Block failed: ' + e.message, 'error')
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

  // findFastest benchmarks the major public resolvers from this server and
  // ranks them by real lookup latency, so the fastest upstreams for the
  // server's location can be added with one click.
  const findFastest = async () => {
    setFastestBusy(true)
    setFastestErr('')
    try {
      setFastest(await api.toolsFastest())
    } catch (e) {
      setFastestErr(e.message)
    } finally {
      setFastestBusy(false)
    }
  }

  const setStaticLease = (index, field, value) => {
    setCfg((prev) => {
      const next = JSON.parse(JSON.stringify(prev))
      const leases = next.dhcp.static_leases || []
      if (!leases[index]) leases[index] = {}
      leases[index] = { ...leases[index], [field]: value }
      next.dhcp.static_leases = leases
      return next
    })
    setDirty(true)
  }

  const addStaticLease = () => {
    setCfg((prev) => {
      const next = JSON.parse(JSON.stringify(prev))
      next.dhcp.static_leases = [...(next.dhcp.static_leases || []), {}]
      return next
    })
    setDirty(true)
  }

  const removeStaticLease = (index) => {
    setCfg((prev) => {
      const next = JSON.parse(JSON.stringify(prev))
      next.dhcp.static_leases = (next.dhcp.static_leases || []).filter((_, i) => i !== index)
      return next
    })
    setDirty(true)
  }

  const setRoute = (index, field, value) => {
    setCfg((prev) => {
      const next = JSON.parse(JSON.stringify(prev))
      const routes = next.upstream_routes || []
      if (!routes[index]) routes[index] = {}
      routes[index] = { ...routes[index], [field]: value }
      next.upstream_routes = routes
      return next
    })
    setDirty(true)
  }

  const addRoute = () => {
    setCfg((prev) => {
      const next = JSON.parse(JSON.stringify(prev))
      next.upstream_routes = [...(next.upstream_routes || []), { domain: '', upstreams: [] }]
      return next
    })
    setDirty(true)
  }

  const removeRoute = (index) => {
    setCfg((prev) => {
      const next = JSON.parse(JSON.stringify(prev))
      next.upstream_routes = (next.upstream_routes || []).filter((_, i) => i !== index)
      return next
    })
    setDirty(true)
  }

  const downloadBackup = async () => {
    setBackupBusy(true)
    setBackupErr('')
    setRestoreMsg('')
    try {
      const blob = await api.configBackup(backupPassphrase)
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      const ext = backupPassphrase ? 'zip.enc' : 'zip'
      a.download = `irongrid-backup-${new Date().toISOString().slice(0, 10)}.${ext}`
      document.body.appendChild(a)
      a.click()
      a.remove()
      URL.revokeObjectURL(url)
      toast(backupPassphrase ? 'Encrypted backup downloaded' : 'Backup downloaded')
    } catch (e) {
      setBackupErr(e.message)
    } finally {
      setBackupBusy(false)
    }
  }

  const onRestoreFile = async (e) => {
    const file = e.target.files && e.target.files[0]
    e.target.value = '' // allow re-selecting the same file
    if (!file) return
    if (!window.confirm('Restore this backup? It replaces the current config, TLS certificates and admin credentials.')) return
    setRestoring(true)
    setBackupErr('')
    setRestoreMsg('')
    try {
      const res = await api.configRestore(file, backupPassphrase)
      const notes = (res.restart_required && res.restart_required.length)
        ? ` Restart needed for: ${res.restart_required.join(', ')}.`
        : ''
      const authNote = res.auth_restored
        ? ' The restored admin credentials are now active — you may need to sign in again.'
        : ''
      setRestoreMsg(`Backup restored.${notes}${authNote}`)
      toast('Backup restored')
      await load() // refresh the form with the restored config
    } catch (err) {
      setBackupErr(err.message)
    } finally {
      setRestoring(false)
    }
  }

  const addUpstream = (spec) => {
    if ((cfg.upstreams || []).includes(spec)) return
    set('upstreams', [...(cfg.upstreams || []), spec])
    setBenchmarkAdded((arr) => [...new Set([...arr, spec])])
    toast(`Added ${spec} — save to apply`)
    // Flip the row to "in use" locally so the table reflects the add without
    // a re-benchmark (authoritative state follows on save).
    setFastest((f) => f && { ...f, results: f.results.map((r) => (r.spec === spec ? { ...r, in_use: true } : r)) })
  }

  const addFastestTop = (n) => {
    const picks = (fastest?.results || []).filter((r) => !r.error && !r.in_use).slice(0, n).map((r) => r.spec)
    const fresh = picks.filter((s) => !(cfg.upstreams || []).includes(s))
    if (!fresh.length) {
      toast('Fastest resolvers are already in your upstreams', 'error')
      return
    }
    set('upstreams', [...(cfg.upstreams || []), ...fresh])
    setBenchmarkAdded((arr) => [...new Set([...arr, ...fresh])])
    toast(`Added ${fresh.length} fast upstream${fresh.length > 1 ? 's' : ''} — save to apply`)
    // Mark the picks in_use locally so the table reflects them without a
    // re-benchmark (the authoritative state follows on save).
    setFastest((f) => f && { ...f, results: f.results.map((r) => (picks.includes(r.spec) ? { ...r, in_use: true } : r)) })
  }

  const transportLabel = (t) => ({ udp: 'plain UDP', tls: 'DNS-over-TLS', https: 'DNS-over-HTTPS' }[t] || t)

  // Specs added from the benchmark that are still in the (unsaved) upstream
  // list — manual removals drop out of the count automatically.
  const pendingBenchmarkAdds = (benchmarkAdded || []).filter((s) => (cfg.upstreams || []).includes(s)).length

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
        {/* Jump links for the long page: anchor into each section below. */}
        <div className="settings-jump">
          {SETTINGS_SECTIONS.map((s) => (
            <a className="btn ghost small" href={`#${s.id}`} key={s.id}>
              {s.label}
            </a>
          ))}
        </div>
      </div>

      <div className="card" id="settings-listeners">
        <h3>Server listeners</h3>
        <div className="form-grid">
          {text('UDP listener', 'server.listen_udp', 'plain DNS over UDP, "" disables', '0.0.0.0:53')}
          {text('TCP listener', 'server.listen_tcp', null, '0.0.0.0:53')}
          {text('DoT (TLS)', 'server.listen_dot', null, '0.0.0.0:853')}
          {text('DoH (HTTPS)', 'server.listen_doh', null, '0.0.0.0:443')}
          {text('DoH3 (HTTP/3)', 'server.listen_doh3', 'DNS over HTTP/3 over UDP — same /dns-query path as DoH; typically the DoH port (443) since TCP and UDP ports are independent. Must differ from the DoQ address.', '0.0.0.0:443')}
          {text('DoQ (QUIC)', 'server.listen_doq', null, '0.0.0.0:853')}
          {text('DoH path', 'server.doh_path', null, '/dns-query')}
          {text('Web dashboard', 'server.web_listen', null, '0.0.0.0:8080')}
          {toggle('Serve dashboard over HTTPS (web_tls)', 'server.web_tls')}
          {toggle('Redirect plain HTTP to HTTPS (web_redirect)', 'server.web_redirect')}
          {number('Redirect listener port', 'server.web_redirect_port')}
          {number('Upstream timeout (s)', 'server.timeout_sec')}
          {number('UDP sockets (0 = auto)', 'server.udp_sockets', 'SO_REUSEPORT sockets for the UDP + DoQ + DoH3 listeners; 0 = one per CPU (auto, capped), 1 = single exclusive socket, N = exactly N')}
          {toggle('Pad encrypted responses (RFC 7830)', 'server.padding')}
          {toggle('DNS cookies (RFC 7873)', 'server.cookies')}
        </div>
      </div>

      <div className="card" id="settings-upstreams">
        <h3>Upstreams</h3>
        {listEditor('upstreams', 'upstreams', 'udp://, tcp://, tls://, https://, quic://, recursive://')}
        {/* This paragraph follows the list editor's format hint (not a heading), so it needs real
            spacing instead of the -6px tightening used under card headings — otherwise the two text
            blocks sit flush against each other. */}
        <p className="dim small" style={{ marginTop: 10 }}>
          <code>recursive://</code> resolves from the root servers itself instead of forwarding — no third-party
          resolver sees your query stream, at the cost of slower cold lookups and no upstream DNSSEC validation to
          rely on. Mix it with forwarders (the Resolution strategy below governs the order) or list it alone.
        </p>
        <div className="form-grid">
          {text('Recursive per-server timeout', 'recursive.server_timeout', 'how long a recursive:// walk waits on one nameserver before moving on; empty = 3s built-in default', '3s')}
          {field('Resolution strategy', 'how multiple upstreams are queried — race queries them all at once and uses the fastest answer; sequential tries them in list order, failing over to the next when one errors or answers SERVFAIL', (
            <select className="input" value={cfg.upstream_mode || 'race'} onChange={(e) => set('upstream_mode', e.target.value)}>
              <option value="race">Race — all at once, fastest wins</option>
              <option value="sequential">Sequential — one at a time, in order</option>
            </select>
          ))}
        </div>
        <h4 style={{ margin: '16px 0 10px' }}>Conditional upstreams (split horizon)</h4>
        <p className="dim small" style={{ marginTop: -6 }}>
          Send queries for one domain subtree to a dedicated upstream set instead of the global ones
          above — e.g. <span className="mono">lan</span> → <span className="mono">udp://192.168.1.1:53</span> so
          internal names never leave the network. A route matches its domain and every subdomain under it;
          the longest match wins when routes overlap, and a route overrides both the global list and a
          client group's upstream override.
        </p>
        {(deepGet('upstream_routes', []) || []).map((rt, i) => (
          <div className="list-row" key={i} style={{ alignItems: 'flex-start' }}>
            <input className="input mono" placeholder="domain (e.g. lan)" value={rt.domain || ''} onChange={(e) => setRoute(i, 'domain', e.target.value)} style={{ maxWidth: 200 }} />
            <textarea
              className="input mono"
              placeholder={'upstreams, one per line (udp://, tls://, …)'}
              rows={2}
              value={(rt.upstreams || []).join('\n')}
              onChange={(e) => setRoute(i, 'upstreams', e.target.value.split('\n').map((s) => s.trim()).filter(Boolean))}
              style={{ flex: 1, minHeight: 44 }}
            />
            <button className="btn small danger" type="button" onClick={() => removeRoute(i)}>✕</button>
          </div>
        ))}
        <button className="btn small" type="button" onClick={addRoute}>+ Add route</button>
        <div className="row-between" style={{ marginTop: 16 }}>
          <h4 style={{ margin: 0, fontSize: 13 }}>Find the fastest upstreams for this server</h4>
          <button className="btn small" type="button" onClick={findFastest} disabled={fastestBusy}>
            {fastestBusy ? 'Benchmarking…' : 'Benchmark public resolvers'}
          </button>
        </div>
        <p className="dim small" style={{ marginTop: 4 }}>
          Measures real lookup latency from this server to the major public resolvers (plain UDP, DoT and DoH) and ranks
          them — the fastest for your location win. One click adds them to the list above; save to apply.
        </p>
        {pendingBenchmarkAdds > 0 && (
          <div className="info-banner" style={{ marginTop: 8 }}>
            ⚠ {pendingBenchmarkAdds} upstream{pendingBenchmarkAdds === 1 ? ' was' : 's were'} added from the benchmark but
            not saved yet — click <strong>Save &amp; apply</strong> at the top of this page to make it live.
          </div>
        )}
        {fastestErr && <div className="error-banner" style={{ marginTop: 8 }}>{fastestErr}</div>}
        {fastest && (
          <div style={{ marginTop: 10 }}>
            <div className="row-between">
              <span className="dim small">
                probe <span className="mono">{fastest.query}</span> {fastest.type} · best of 3
              </span>
              <button className="btn small" type="button" onClick={() => addFastestTop(3)} disabled={!fastest.results.some((r) => !r.error && !r.in_use)}>
                Add fastest 3
              </button>
            </div>
            <div style={{ maxHeight: 320, overflowY: 'auto', marginTop: 6 }}>
              <table className="table">
                <thead>
                  <tr><th>#</th><th>Resolver</th><th>Endpoint</th><th>Latency</th><th className="action-col"></th></tr>
                </thead>
                <tbody>
                  {fastest.results.map((res, i) => {
                    const lat = res.error ? null : res.latency_ms
                    const latColor = lat == null ? null : lat < 15 ? 'var(--emerald)' : lat < 60 ? 'var(--cyan)' : 'var(--amber)'
                    return (
                      <tr key={res.spec}>
                        <td className="dim mono">{i + 1}</td>
                        <td>
                          <div className="strong">{res.label}</div>
                          <div className="dim small">{transportLabel(res.transport)}</div>
                        </td>
                        <td className="mono">{res.spec}</td>
                        <td>
                          {lat == null ? (
                            <span className="badge badge-error" title={res.error}>unreachable</span>
                          ) : (
                            <span className="mono" style={{ color: latColor, fontWeight: 650 }}>{lat} ms</span>
                          )}
                        </td>
                        <td className="action-col">
                          {res.in_use ? (
                            <span className="badge badge-cached">in use</span>
                          ) : lat == null ? null : (
                            <button className="btn small" type="button" onClick={() => addUpstream(res.spec)}>Add</button>
                          )}
                        </td>
                      </tr>
                    )
                  })}
                </tbody>
              </table>
            </div>
          </div>
        )}
      </div>

      <div className="card" id="settings-dnssec">
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
      </div>      <div className="card" id="settings-ratelimit">
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

      <div className="card" id="settings-geo">
        <h3>Geo blocking</h3>
        <p className="dim small" style={{ marginTop: -6 }}>
          Refuses queries (<strong>REFUSED</strong> on every transport) from client IPs that belong to the selected
          countries. Country data comes from free per-country CIDR lists (ipverse/rir-ip) fetched automatically and
          cached locally — no account or API key needed. Allowlisted IPs/CIDRs always pass.
        </p>
        <div className="form-grid">
          {toggle('Enable geo blocking', 'geo_block.enabled')}
          {textarea('Blocked countries (ISO 3166-1 alpha-2)', 'geo_block.countries', 'one per line, e.g. RU, CN, KP')}
          {textarea('Blocked client IPs / CIDRs', 'geo_block.ips', 'always refused regardless of country — e.g. known proxy-exit ranges like 38.11.0.0/17; feeds DNS and the host firewall')}
          {textarea('Honeypot domains', 'geo_block.honeypots', 'one per line — a trap matches the domain AND every subdomain under it (DDoS floods randomise the first label), so any client that queries it over TCP/DoT/DoH/DoQ is blocked permanently (persisted, dropped at the firewall) until you unblock it below; spoofable UDP queries are refused but never auto-block; trap traffic is not written to the query log')}
          {toggle('Trust UDP honeypot hits (auto-block UDP sources)', 'geo_block.trust_udp')}
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
        {deepGet('geo_block.enabled', false) && (deepGet('geo_block.countries', []) || []).length === 0 && (deepGet('geo_block.ips', []) || []).length === 0 && (deepGet('geo_block.honeypots', []) || []).length === 0 && (
          <p className="dim small" style={{ marginTop: 8, color: 'var(--amber)' }}>
            ⚠ Geo blocking is on but nothing is configured — add countries, blocked IPs, or honeypot domains above, save, then refresh.
          </p>
        )}
        {!deepGet('geo_block.enabled', false) && ((deepGet('geo_block.honeypots', []) || []).length > 0 || (deepGet('geo_block.ips', []) || []).length > 0) && (
          <p className="dim small" style={{ marginTop: 8, color: 'var(--amber)' }}>
            ⚠ Honeypot domains / blocked IPs are configured but <strong>Enable geo blocking</strong> is off — nothing is enforced until you turn it on and save.
          </p>
        )}
        {deepGet('geo_block.trust_udp', false) && (
          <p className="dim small" style={{ marginTop: 8, color: 'var(--amber)' }}>
            ⚠ UDP sources can be spoofed — with this on, a spoofed honeypot packet can permanently block an innocent victim. Only enable on a trusted network where client addresses are genuine.
          </p>
        )}
        <h4 style={{ margin: '16px 0 10px' }}>Honeypot-blocked clients</h4>
        {honeyBlocked.length === 0 ? (
          <p className="dim small">No clients blocked yet — honeypot-domain queries auto-block their client here.</p>
        ) : (
          <div>
            {honeyBlocked.map((ip) => (
              <div className="list-row" key={ip}>
                <span className="mono">{ip}</span>
                <button className="btn small" type="button" onClick={() => reportAbuse(ip)}>Report</button>
                <button className="btn small" type="button" onClick={() => blockNet(ip, 0)}>Block IP</button>
                <button className="btn small" type="button" onClick={() => blockNet(ip, ip.includes(':') ? 64 : 24)}>Block /{ip.includes(':') ? 64 : 24}</button>
                <button className="btn small danger" type="button" onClick={() => unblockHoney(ip)}>Unblock</button>
              </div>
            ))}
          </div>
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
          <p className="dim small">No country data loaded — countries are optional; blocked-IP and honeypot blocking above work without them. Add ISO codes above, save, then refresh to load country ranges.</p>
        )}
        {geoInfo && geoInfo.next_refresh && deepGet('geo_block.enabled', false) && (
          <p className="dim small" style={{ marginTop: 8 }}>
            Next automatic refresh: {new Date(geoInfo.next_refresh).toLocaleString()}
          </p>
        )}
        {geoInfo && geoInfo.firewall && geoInfo.firewall.available && (
          <p className="dim small" style={{ marginTop: 8 }}>
            Host firewall:{' '}
            {geoInfo.firewall.active ? (
              <strong>active</strong>
            ) : (
              <span className="error-text">rules inactive</span>
            )}{' '}
            ({geoInfo.firewall.backend || 'no backend'}) — all new inbound traffic from the blocked
            countries is dropped at the packet level, not just DNS. Established connections and
            allowlisted clients always pass. If inactive, check the service runs with root or
            CAP_NET_ADMIN privileges.
          </p>
        )}
        <div className="quick-actions" style={{ marginTop: 8 }}>
          <button className="btn small" type="button" onClick={refreshGeo}>Refresh country data</button>
        </div>
      </div>

      <div className="card" id="settings-abuse">
        <h3>Abuse reporting</h3>
        <p className="dim small" style={{ marginTop: -6 }}>
          One-click reporting of honeypot-confirmed attackers to{' '}
          <strong>AbuseIPDB</strong> (free account at abuseipdb.com; DDoS category).
          Reports are sent from the server using this key, which is stored in{' '}
          <code>irongrid.yaml</code>. No key is needed for the{' '}
          <strong>Export CSV</strong> and <strong>ⓘ ASN</strong> actions on the
          dashboard (those use free RIPEstat lookups and your own abuse desks).
        </p>
        <div className="form-grid">
          {field('AbuseIPDB API key', 'free tier: 1,000 checks/reports per day, one report per IP per 15 min', (
            <input
              className="input mono"
              type="password"
              value={deepGet('abuse.abuseipdb_key', '')}
              onChange={(e) => set('abuse.abuseipdb_key', e.target.value)}
              autoComplete="new-password"
            />
          ))}
        </div>
      </div>

      <div className="card" id="settings-cache">
        <h3>Cache (Dragonfly)</h3>
        <p className="dim small" style={{ marginTop: -6 }}>
          Dragonfly is the response cache <em>and</em> the query log's home. Watch live utilisation on the
          dashboard's <strong>Dragonfly cache</strong> card.
        </p>
        <div className="form-grid">
          {text('Address', 'cache.addr', null, 'localhost:6379')}
          {text('Password', 'cache.password', 'optional auth')}
          {number('DB index', 'cache.db')}
          {text('Positive TTL', 'cache.ttl', 'e.g. 6h, 30m, 1h30m')}
          {text('Negative TTL', 'cache.negative_ttl', 'e.g. 1m')}
          {number('L1 entries (per shard)', 'cache.l1_entries', 'in-process cache in front of Dragonfly; 0 = auto-sized from available RAM (default), -1 disables it, N = exact per-shard cap')}
          {text('Serve stale', 'cache.serve_stale', 'keep entries answerable this long past expiry (RFC 8767) — used when the upstream is unreachable; 0 disables', '5m')}
          {toggle('Prefetch hot entries', 'cache.prefetch')}
          {text('Cache lookup timeout', 'cache.lookup_timeout', 'how long a Dragonfly read may take on the hot path before the query goes straight upstream; empty = 150ms default', '150ms')}
          {text('Failure cache TTL', 'cache.failure_ttl', 'how long a resolution failure (unreachable upstream, no stale data) is cached as SERVFAIL so retries don\'t re-pay the full timeout; short = a recovered upstream shows up quickly; empty = use negative_ttl', '5s')}
        </div>
      </div>

      <div className="card" id="settings-warmer">
        <h3>Cache warmer</h3>
        <p className="dim small" style={{ marginTop: -6 }}>
          Proactively pre-caches answers for every domain your network queried within
          the <strong>lookback</strong> window (read from the query log), so a restart
          or cache flush doesn&apos;t leave the first query for each domain cold. A pass runs
          once at boot, then every <strong>interval</strong>, resolving only entries that
          are missing, expired or inside their serve-stale window. Off by default because
          it uses your upstreams even when nobody is asking.
        </p>
        <div className="form-grid">
          {toggle('Enable cache warmer', 'warmer.enabled')}
          {text('Interval', 'warmer.interval', 'how often a warming pass runs', '15m')}
          {text('Lookback', 'warmer.lookback', 'how far back into the query log to find active domains', '24h')}
          {number('Max domains per pass', 'warmer.max_domains', 'cap on upstream traffic per pass; 0 = all in the window')}
          {number('Parallel resolutions', 'warmer.concurrency', '0 = default (8)')}
        </div>
      </div>

      <div className="card" id="settings-tls">
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

      <div className="card" id="settings-filtering">
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
        <p className="dim small">
          <strong>CNAME cloaking protection</strong> checks every CNAME a query resolves through, not just the name
          you asked for — trackers hide behind first-party-looking subdomains that CNAME to a blocklisted domain,
          and this catches that. Off by default: a CNAME chain through a shared CDN could in principle collide with
          an overly broad blocklist entry.
        </p>
        <div className="form-grid">
          {toggle('Block CNAME-cloaked trackers', 'filter.cname_cloaking_protection')}
        </div>
      </div>

      <div className="card" id="settings-log">
        <h3>Query log</h3>
        <p className="dim small" style={{ marginTop: -6 }}>
          The query log lives in <strong>Dragonfly</strong> (stream <code>irongrid:log</code>) alongside the DNS
          cache — no separate database file. View and filter it on the <strong>Query Log</strong> page; retention
          below prunes old entries automatically (hourly).
        </p>
        <div className="form-grid">
          {number('Retention (days)', 'log.retention_days')}
          {toggle('Verbose logging', 'log.verbose')}
        </div>
      </div>

      <div className="card" id="settings-credentials">
        <h3>Web credentials</h3>
        <div className="form-grid">
          {text('Username', 'web.username')}
          {field('Password', 'leave blank to keep the current password; changing it signs out every device (including this one)', (
            <input className="input" type="password" value={cfg.web.password} onChange={(e) => set('web.password', e.target.value)} autoComplete="new-password" />
          ))}
        </div>
      </div>

      <div className="card" id="settings-tunnel">
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

      <div className="card" id="settings-dhcp">
        <h3>DHCP server</h3>
        <p className="dim small" style={{ marginTop: -6 }}>
          A built-in DHCP server for the LAN this box is the DNS for: hands out IPv4 addresses from
          a pool (and optionally stateful IPv6 via DHCPv6), honours static reservations, and registers
          client hostnames so <span className="mono">hostname</span> and{' '}
          <span className="mono">hostname.{deepGet('dhcp.domain', 'lan')}</span> resolve locally — Pi-hole
          style. Requires the server to have an address inside the served subnet. Only enable on the
          NIC your LAN actually uses.
        </p>
        <div className="form-grid">
          {toggle('Enable DHCP server', 'dhcp.enabled')}
          {text('Interface', 'dhcp.interface', 'NIC to serve on (e.g. eth0, br0); empty = all interfaces', 'eth0')}
          {text('IPv4 subnet', 'dhcp.subnet', 'the network served, e.g. 192.168.1.0/24')}
          {text('Pool start', 'dhcp.range_start', 'first dynamic address, e.g. 192.168.1.100')}
          {text('Pool end', 'dhcp.range_end', 'last dynamic address, e.g. 192.168.1.200')}
          {text('Gateway', 'dhcp.gateway', 'router option advertised; empty = this server\'s own address on the subnet')}
          {textarea('DNS servers', 'dhcp.dns', 'advertised DNS option, one per line; empty = this server')}
          {text('Lease time', 'dhcp.lease_time', 'e.g. 24h, 12h', '24h')}
          {text('Domain suffix', 'dhcp.domain', 'hostnames resolve as hostname.domain; empty disables hostname resolution', 'lan')}
          {toggle('Enable DHCPv6', 'dhcp.ipv6')}
          {deepGet('dhcp.ipv6', false) && text('IPv6 prefix', 'dhcp.ipv6_prefix', 'e.g. fd00::/64 (ULA)')}
          {deepGet('dhcp.ipv6', false) && text('IPv6 pool start', 'dhcp.ipv6_range_start', 'first stateful address (inside the prefix)')}
          {deepGet('dhcp.ipv6', false) && text('IPv6 pool end', 'dhcp.ipv6_range_end', 'last stateful address')}
        </div>
        <h4 style={{ margin: '16px 0 10px' }}>Static reservations</h4>
        <p className="dim small" style={{ marginTop: -6 }}>
          Fixed addresses that never expire. MAC keys a DHCPv4 reservation, DUID a DHCPv6 one — either
          is fine (v4 clients match on MAC, v6 clients on DUID). A hostname pins the local-DNS name.
        </p>
        {(deepGet('dhcp.static_leases', []) || []).map((sl, i) => (
          <div className="list-row" key={i} style={{ alignItems: 'flex-start' }}>
            <input className="input mono" placeholder="mac (aa:bb:…)" value={sl.mac || ''} onChange={(e) => setStaticLease(i, 'mac', e.target.value)} />
            <input className="input mono" placeholder="duid" value={sl.duid || ''} onChange={(e) => setStaticLease(i, 'duid', e.target.value)} />
            <input className="input mono" placeholder="ip" value={sl.ip || ''} onChange={(e) => setStaticLease(i, 'ip', e.target.value)} />
            <input className="input" placeholder="hostname" value={sl.hostname || ''} onChange={(e) => setStaticLease(i, 'hostname', e.target.value)} />
            <button className="btn small danger" type="button" onClick={() => removeStaticLease(i)}>✕</button>
          </div>
        ))}
        <button className="btn small" type="button" onClick={addStaticLease}>+ Add reservation</button>
      </div>

      <div className="card" id="settings-backup">
        <h3>Backup &amp; restore</h3>
        <p className="dim small" style={{ marginTop: -6 }}>
          Download an archive of the config file and TLS certificates — handy before upgrades or when moving
          servers. The archive contains the <strong>TLS private key</strong> and the password hash, so keep it as
          secure as a key file — or set a passphrase below to encrypt it.
        </p>
        <div className="form-grid" style={{ marginTop: 10 }}>
          <label>
            Passphrase (optional)
            <input
              className="input"
              type="password"
              autoComplete="new-password"
              placeholder="Leave blank for an unencrypted backup"
              value={backupPassphrase}
              onChange={(e) => setBackupPassphrase(e.target.value)}
            />
          </label>
        </div>
        {backupPassphrase && (
          <p className="dim small" style={{ marginTop: 4 }}>
            There is no way to recover an encrypted backup without this passphrase — if it's lost, the archive is
            unusable.
          </p>
        )}
        <div className="quick-actions" style={{ marginTop: 10 }}>
          <button className="btn small" type="button" onClick={downloadBackup} disabled={backupBusy}>
            {backupBusy ? 'Packing…' : '⬇ Download backup'}
          </button>
          <label className="btn small" style={{ margin: 0 }}>
            {restoring ? 'Restoring…' : '⬆ Restore backup'}
            <input
              type="file"
              accept=".zip,.enc,application/zip,application/octet-stream"
              style={{ display: 'none' }}
              onChange={onRestoreFile}
              disabled={restoring}
            />
          </label>
        </div>
        <p className="dim small" style={{ marginTop: 4 }}>
          To restore an encrypted backup, enter its passphrase above first, then choose the file.
        </p>
        {backupErr && <div className="error-banner" style={{ marginTop: 8 }}>{backupErr}</div>}
        {restoreMsg && <div className="info-banner" style={{ marginTop: 8 }}>{restoreMsg}</div>}
      </div>

      <div className="card" id="settings-diagnostic">
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

      <div className="card" id="settings-maintenance">
        <h3>Cache &amp; maintenance</h3>
        <div className="quick-actions">
          <button className="btn" onClick={flush}>Flush DNS cache (Dragonfly)</button>
          <button className="btn" onClick={() => api.refreshLists().then(() => toast('Blocklists refreshed')).catch((e) => toast('Refresh failed: ' + e.message, 'error'))}>Refresh blocklists</button>
        </div>
      </div>
    </div>
  )
}
