import { useEffect, useState, useCallback } from 'react'
import { api } from '../api'
import { useToast } from '../toast-context'
import { LineListField, XIcon } from './ui'
import ServerTab from './settings/ServerTab'
import SecurityTab from './settings/SecurityTab'
import FilteringTab from './settings/FilteringTab'
import CacheTab from './settings/CacheTab'
import NetworkTab from './settings/NetworkTab'
import SystemTab from './settings/SystemTab'

// Settings is split into tabbed sub pages — each ./settings/*Tab component
// is one sub page, rendered below the tab strip in the header card.

const empty = () => ({
  server: {
    listen_udp: '',
    listen_tcp: '',
    listen_dot: '',
    listen_doh: '',
    listen_doh3: '',
    listen_doq: '',
    doh_path: '/dns-query',
    web_listen: '',
    web_tls: false,
    web_redirect: false,
    web_redirect_port: 80,
    timeout_sec: 5,
    udp_sockets: 0,
    udp_workers: 0,
    padding: false,
    cookies: false,
  },
  upstreams: [],
  upstream_mode: 'race',
  upstream_routes: [],
  cache: {
    addr: '',
    password: '',
    db: 0,
    ttl: '6h',
    negative_ttl: '1m',
    l1_entries: 0,
    serve_stale: '5m',
    prefetch: true,
    lookup_timeout: '150ms',
    failure_ttl: '5s',
  },
  recursive: { server_timeout: '' },
  tls: {
    cert_file: '',
    key_file: '',
    generate_self_signed: true,
    self_signed_hosts: [],
    cert_dir: '',
    acme: {
      enabled: false,
      email: '',
      domains: [],
      staging: false,
      http01_port: 80,
      renew_before_days: 30,
      dns01: {
        provider: '',
        propagation_wait_sec: 60,
        cloudflare_token: '',
        digitalocean_token: '',
        hetzner_token: '',
        godaddy_key: '',
        godaddy_secret: '',
        aws_access_key_id: '',
        aws_secret_access_key: '',
      },
    },
  },
  filter: {
    block_response: 'nxdomain',
    block_ttl: 600,
    blocklists: [],
    whitelist: [],
    blacklist: [],
    auto_update: '24h',
    cname_cloaking_protection: false,
  },
  log: { query_log_file: '', retention_days: 30, verbose: true },
  web: { username: 'admin', password: '' },
  tunnel: { enabled: false, token: '', config_file: '', quick_tunnel: false, quick_tunnel_url: '', hostname: '' },
  rewrites: [],
  client_groups: [],
  rate_limit: { enabled: false, qps: 20, burst: 40, auto_block: false, block_after: 3, block_for: '10m' },
  geo_block: {
    enabled: false,
    countries: [],
    allowlist: [],
    ips: [],
    honeypots: [],
    allow_asns: [],
    block_asns: [],
    base_url: '',
    asn_base_url: '',
    auto_update: '168h',
    trust_udp: false,
  },
  abuse: { abuseipdb_key: '' },
  dnssec: { enabled: false, require_ad: true },
  warmer: { enabled: false, interval: '15m', lookback: '24h', max_domains: 5000, concurrency: 8 },
  dhcp: {
    enabled: false,
    interface: '',
    subnet: '',
    range_start: '',
    range_end: '',
    gateway: '',
    dns: [],
    lease_time: '24h',
    domain: 'lan',
    static_leases: [],
    ipv6: false,
    ipv6_prefix: '',
    ipv6_range_start: '',
    ipv6_range_end: '',
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
  // numCPU is the server's tuned CPU count from /api/status (num_cpu — the
  // same GOMAXPROCS the Go-side auto sizing runs off), used by the
  // "recommended values" button for the UDP settings.
  const [numCPU, setNumCPU] = useState(null)

  // Tabs split the one-page mega-form into sub pages (each ./settings/*Tab
  // component is one sub page). The active tab rides in the URL (?tab=) so it
  // survives reloads and is shareable; replaceState keeps tab switches from
  // spamming the history stack. Declared with the other hooks so the order is
  // stable across the early return below.
  const TABS = [
    { id: 'server', label: 'Server', desc: 'Listeners, upstreams, DNSSEC, TLS' },
    { id: 'security', label: 'Security', desc: 'Rate limit, geo block, abuse reporting' },
    { id: 'filtering', label: 'Filtering', desc: 'Block response, lists, CNAME cloaking' },
    { id: 'cache', label: 'Cache & log', desc: 'Dragonfly cache, warmer, query log' },
    { id: 'network', label: 'Network', desc: 'Tunnel, DHCP server' },
    { id: 'system', label: 'System', desc: 'Credentials, backup, diagnostics' },
  ]
  const [tab, setTab] = useState(() => new URLSearchParams(window.location.search).get('tab') || 'server')
  const switchTab = (id) => {
    setTab(id)
    window.history.replaceState(null, '', '?tab=' + id)
  }

  const load = useCallback(async () => {
    try {
      const c = await api.config()
      setCfg(c)
      setInitialUser((c.web && c.web.username) || '')
    } catch {
      /* ignore */
    }
    // A fresh load reflects the authoritative config, so any unsaved
    // benchmark adds are gone (or saved) — clear the tracking.
    setBenchmarkAdded([])
    try {
      setNumCPU((await api.status()).num_cpu ?? null)
    } catch {
      /* ignore */
    }
  }, [])

  const loadAbuse = useCallback(async () => {
    try {
      setBlocked((await api.rateBlocked()).blocked || [])
    } catch {
      /* ignore */
    }
    try {
      setGeoInfo(await api.geoStatus())
    } catch {
      /* ignore */
    }
    try {
      setHoneyBlocked((await api.geoBlocked()).blocked || [])
    } catch {
      /* ignore */
    }
  }, [])

  useEffect(() => {
    load()
  }, [load])
  useEffect(() => {
    loadAbuse()
  }, [loadAbuse])

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
            : 'Username changed — all sessions were signed out. Sign in with your updated credentials.',
        )
        return
      }
      const restart = r.restart_required || []
      setRestartNeeded(restart)
      toast(
        restart.length
          ? `Saved. Block policy, filter lists and upstreams applied live. Restart needed for: ${restart.join(', ')}.`
          : 'Saved and applied live — no restart required.',
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
    if (
      !window.confirm(
        `Report ${ip} to AbuseIPDB (DDoS category)? Uses the AbuseIPDB key from the Abuse reporting section above.`,
      )
    )
      return
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
    if (
      !window.confirm(
        `Permanently block ${label}? It is added to geo_block.ips (config, survives restarts) and dropped at the host firewall. Remove it under Blocked client IPs in Settings to undo.`,
      )
    )
      return
    try {
      await api.geoBlockIP(ip, prefix)
      toast(`Blocked ${label}`)
      await loadAbuse()
    } catch (e) {
      toast('Block failed: ' + e.message, 'error')
    }
  }

  // applyRecommendedUDP fills the UDP socket/worker fields with the values
  // the server itself would pick in auto mode (0): one SO_REUSEPORT socket
  // per CPU capped at 8, and 4 x CPU workers per socket (floor 16, capped
  // 256), computed from the live status's num_cpu. Pinning the concrete
  // numbers instead of leaving 0 makes them visible and tweakable.
  const applyRecommendedUDP = async () => {
    let cpu = numCPU
    if (cpu == null) {
      try {
        const s = await api.status()
        cpu = s.num_cpu ?? null
        setNumCPU(cpu)
      } catch (e) {
        toast('Could not read the server CPU count: ' + e.message, 'error')
        return
      }
    }
    if (cpu == null || cpu < 1) {
      toast('Server CPU count unknown — cannot compute recommended values', 'error')
      return
    }
    const sockets = Math.max(1, Math.min(8, cpu))
    const workers = Math.max(16, Math.min(256, 4 * cpu))
    set('server.udp_sockets', sockets)
    set('server.udp_workers', workers)
    toast(`Set recommended values for a ${cpu}-CPU server: ${sockets} UDP socket(s), ${workers} workers per socket.`)
  }

  const restart = async () => {
    if (
      !window.confirm(
        'Rebind DNS listeners, cache, TLS and the web server now? This takes a moment and briefly interrupts DNS service.',
      )
    )
      return
    setRestarting(true)
    try {
      const r = await api.reloadConfig()
      const remaining = r.still_requires_restart || []
      setRestartNeeded(remaining)
      toast(
        remaining.length
          ? `Reloaded in place — listeners, cache, TLS and upstreams are live. ${remaining.join(', ')} still needs a process restart.`
          : 'Restarted in place — all configuration is now live.',
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

  const refreshLists = () =>
    api
      .refreshLists()
      .then(() => toast('Blocklists refreshed'))
      .catch((e) => toast('Refresh failed: ' + e.message, 'error'))

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
    if (!window.confirm('Restore this backup? It replaces the current config, TLS certificates and admin credentials.'))
      return
    setRestoring(true)
    setBackupErr('')
    setRestoreMsg('')
    try {
      const res = await api.configRestore(file, backupPassphrase)
      const notes =
        res.restart_required && res.restart_required.length
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
    const picks = (fastest?.results || [])
      .filter((r) => !r.error && !r.in_use)
      .slice(0, n)
      .map((r) => r.spec)
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
    setFastest(
      (f) => f && { ...f, results: f.results.map((r) => (picks.includes(r.spec) ? { ...r, in_use: true } : r)) },
    )
  }

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
    field(
      label,
      hint,
      <input
        className="input mono"
        value={deepGet(path, '')}
        onChange={(e) => set(path, e.target.value)}
        placeholder={placeholder}
      />,
    )

  // LineListField holds a draft while typing so Enter creates a real new
  // line; the list is normalised into the config only on blur.
  const textarea = (label, path, hint) =>
    field(
      label,
      hint,
      <LineListField value={deepGet(path, []) || []} onChange={(v) => set(path, v)} placeholder="one entry per line" />,
    )

  const number = (label, path, hint) =>
    field(
      label,
      hint,
      <input
        className="input mono"
        type="number"
        value={deepGet(path, 0)}
        onChange={(e) => set(path, Number(e.target.value))}
      />,
    )

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
          <input
            className="input mono"
            value={item}
            onChange={(e) => setListItem(path, i, e.target.value)}
            aria-label={`${label} entry ${i + 1}`}
          />
          <button
            className="btn small danger"
            type="button"
            onClick={() => removeList(path, i)}
            aria-label={`Remove ${item || 'this entry'}`}
          >
            <XIcon size={12} />
          </button>
        </div>
      ))}
      <button className="btn small" type="button" onClick={() => addList(path)}>
        + Add
      </button>
      {hint && <span className="field-hint">{hint}</span>}
    </div>
  )

  // Everything a tab component may need, in one bundle: the form helpers
  // (which close over cfg) plus the page-level handlers and data.
  const f = {
    cfg,
    set,
    field,
    text,
    number,
    toggle,
    textarea,
    listEditor,
    deepGet,
    toast,
    api,
    // server
    numCPU,
    applyRecommendedUDP,
    setRoute,
    removeRoute,
    addRoute,
    findFastest,
    fastest,
    fastestBusy,
    fastestErr,
    addUpstream,
    addFastestTop,
    pendingBenchmarkAdds,
    // security
    blocked,
    unblock,
    loadAbuse,
    geoInfo,
    honeyBlocked,
    reportAbuse,
    blockNet,
    unblockHoney,
    refreshGeo,
    // network
    setStaticLease,
    addStaticLease,
    removeStaticLease,
    // system
    diagName,
    setDiagName,
    diagType,
    setDiagType,
    runDiag,
    diagResult,
    backupPassphrase,
    setBackupPassphrase,
    downloadBackup,
    onRestoreFile,
    backupBusy,
    restoring,
    backupErr,
    restoreMsg,
    flush,
    refreshLists,
  }

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
        <div className="settings-tabs" role="tablist" aria-label="Settings sections">
          {TABS.map((t) => (
            <button
              key={t.id}
              type="button"
              role="tab"
              aria-selected={tab === t.id}
              className={`btn small ${tab === t.id ? 'active' : 'ghost'}`}
              onClick={() => switchTab(t.id)}
              title={t.desc}
            >
              {t.label}
            </button>
          ))}
        </div>
      </div>

      {tab === 'server' && <ServerTab f={f} />}
      {tab === 'security' && <SecurityTab f={f} />}
      {tab === 'filtering' && <FilteringTab f={f} />}
      {tab === 'cache' && <CacheTab f={f} />}
      {tab === 'network' && <NetworkTab f={f} />}
      {tab === 'system' && <SystemTab f={f} />}
    </div>
  )
}
