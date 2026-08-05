import React, { useEffect, useState, useCallback } from 'react'
import { api } from '../api'

const empty = () => ({
  server: {
    listen_udp: '', listen_tcp: '', listen_dot: '', listen_doh: '', listen_doq: '',
    doh_path: '/dns-query', web_listen: '', timeout_sec: 5,
  },
  upstreams: [],
  cache: { addr: '', password: '', db: 0, ttl: '6h', negative_ttl: '1m' },
  tls: { cert_file: '', key_file: '', generate_self_signed: true, self_signed_hosts: [], cert_dir: '' },
  filter: { block_response: 'nxdomain', block_ttl: 600, blocklists: [], whitelist: [], blacklist: [] },
  log: { query_log_file: '', retention_days: 30, verbose: true },
  web: { username: 'admin', password: '' },
  tunnel: { enabled: false, token: '', config_file: '', quick_tunnel: false, quick_tunnel_url: '', hostname: '' },
})

export default function Settings() {
  const [cfg, setCfg] = useState(null)
  const [dirty, setDirty] = useState(false)
  const [saving, setSaving] = useState(false)
  const [restartNeeded, setRestartNeeded] = useState([])
  const [restarting, setRestarting] = useState(false)
  const [msg, setMsg] = useState('')
  const [err, setErr] = useState('')
  const [diagName, setDiagName] = useState('example.com')
  const [diagType, setDiagType] = useState('A')
  const [diagResult, setDiagResult] = useState(null)

  const load = useCallback(async () => {
    try {
      const c = await api.config()
      setCfg(c)
    } catch { /* ignore */ }
  }, [])

  useEffect(() => { load() }, [load])

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
    setErr('')
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
    setErr('')
    setMsg('')
    try {
      const r = await api.saveConfig(cfg)
      const restart = r.restart_required || []
      setRestartNeeded(restart)
      setMsg(
        restart.length
          ? `Saved. Block policy, filter lists and upstreams applied live. Restart needed for: ${restart.join(', ')}.`
          : 'Saved and applied live — no restart required.'
      )
      setDirty(false)
      await load()
    } catch (e) {
      setErr(e.message)
    } finally {
      setSaving(false)
    }
  }

  const restart = async () => {
    if (!window.confirm('Rebind DNS listeners, cache, TLS and the web server now? This takes a moment and briefly interrupts DNS service.')) return
    setRestarting(true)
    setErr('')
    try {
      const r = await api.reloadConfig()
      const remaining = r.still_requires_restart || []
      setRestartNeeded(remaining)
      setMsg(
        remaining.length
          ? `Reloaded in place — listeners, cache, TLS and upstreams are live. ${remaining.join(', ')} still needs a process restart.`
          : 'Restarted in place — all configuration is now live.'
      )
      await load()
    } catch (e) {
      setErr('Restart failed: ' + e.message)
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
    const r = await api.flushCache()
    setMsg(`Cache flushed (${r.deleted} keys removed)`)
  }

  if (!cfg) return <div className="loading">Loading configuration…</div>

  const field = (label, hint, input) => (
    <label className="field">
      <span className="field-label">{label}</span>
      {input}
      {hint && <span className="field-hint">{hint}</span>}
    </label>
  )

  const text = (label, path, hint, placeholder) =>
    field(label, hint, (
      <input
        className="input mono"
        value={cfg[path.split('.')[0]][path.split('.')[1]] ?? ''}
        onChange={(e) => set(path, e.target.value)}
        placeholder={placeholder}
      />
    ))

  const textarea = (label, path, hint) =>
    field(label, hint, (
      <textarea
        className="input mono"
        rows={3}
        value={(cfg[path.split('.')[0]][path.split('.')[1]] || []).join('\n')}
        onChange={(e) => set(path, e.target.value.split('\n').map((s) => s.trim()).filter(Boolean))}
        placeholder="one entry per line"
      />
    ))

  const number = (label, path, hint) =>
    field(label, hint, (
      <input
        className="input mono"
        type="number"
        value={cfg[path.split('.')[0]][path.split('.')[1]] ?? 0}
        onChange={(e) => set(path, Number(e.target.value))}
      />
    ))

  const toggle = (label, path) => (
    <label className="toggle-field">
      <span className="field-label">{label}</span>
      <span className="switch">
        <input type="checkbox" checked={!!cfg[path.split('.')[0]][path.split('.')[1]]} onChange={(e) => set(path, e.target.checked)} />
        <span className="slider" />
      </span>
    </label>
  )

  const listEditor = (label, path, hint) => (
    <div className="field span-2">
      <span className="field-label">{label}</span>
      {(cfg[path] || []).map((item, i) => (
        <div className="list-row" key={i}>
          <input className="input mono" value={item} onChange={(e) => setListItem(path, i, e.target.value)} />
          <button className="btn small danger" type="button" onClick={() => removeList(path, i)}>✕</button>
        </div>
      ))}
      <button className="btn small" type="button" onClick={() => addList(path)}>+ Add</button>
      {hint && <span className="field-hint">{hint}</span>}
    </div>
  )

  const setBlocklist = (i, patch) => {
    setCfg((prev) => {
      const next = JSON.parse(JSON.stringify(prev))
      next.filter.blocklists[i] = { ...next.filter.blocklists[i], ...patch }
      return next
    })
    setDirty(true)
  }

  const addBlocklist = () => {
    setCfg((prev) => {
      const next = JSON.parse(JSON.stringify(prev))
      next.filter.blocklists = [...(next.filter.blocklists || []), { id: '', name: '', url: '', enabled: true, auto_update: '' }]
      return next
    })
    setDirty(true)
  }

  const removeBlocklist = (i) => {
    setCfg((prev) => {
      const next = JSON.parse(JSON.stringify(prev))
      next.filter.blocklists = next.filter.blocklists.filter((_, x) => x !== i)
      return next
    })
    setDirty(true)
  }

  return (
    <div className="stack">
      {msg && <div className="info-banner">{msg}</div>}
      {err && <div className="error-banner">{err}</div>}

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
          {number('Upstream timeout (s)', 'server.timeout_sec')}
        </div>
      </div>

      <div className="card">
        <h3>Upstreams</h3>
        {listEditor('upstreams', 'upstreams', 'udp://, tcp://, tls://, https://, quic:// — tried in order')}
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
        <div className="form-grid">
          {text('Cert file', 'tls.cert_file', null, 'data/certs/cert.pem')}
          {text('Key file', 'tls.key_file', null, 'data/certs/key.pem')}
          {text('Cert directory', 'tls.cert_dir', null, 'data/certs')}
          {toggle('Generate self-signed', 'tls.generate_self_signed')}
          {textarea('Self-signed hosts (SANs)', 'tls.self_signed_hosts', 'one per line')}
        </div>
      </div>

      <div className="card">
        <h3>Filtering</h3>
        <div className="form-grid">
          {field('Block response', 'nxdomain, refused, or an IP like 0.0.0.0', (
            <input
              className="input mono"
              value={cfg.filter.block_response}
              onChange={(e) => set('filter.block_response', e.target.value)}
            />
          ))}
          {number('Block TTL (s)', 'filter.block_ttl')}
          {textarea('Whitelist (always allow)', 'filter.whitelist')}
          {textarea('Blacklist (always block)', 'filter.blacklist')}
        </div>
      </div>

      <div className="card">
        <h3>Blocklists</h3>
        <p className="dim small">Same lists as the Blocklists page — kept in sync with this config.</p>
        {(cfg.filter.blocklists || []).map((bl, i) => (
          <div className="blocklist-row" key={i}>
            <div className="list-row">
              <input className="input" placeholder="ID" value={bl.id || ''} onChange={(e) => setBlocklist(i, { id: e.target.value })} />
              <input className="input" placeholder="Name" value={bl.name || ''} onChange={(e) => setBlocklist(i, { name: e.target.value })} />
            </div>
            <div className="list-row">
              <input className="input mono" placeholder="URL or file:// path" value={bl.url || ''} onChange={(e) => setBlocklist(i, { url: e.target.value })} />
              <input className="input" placeholder="Auto update (e.g. 24h)" value={bl.auto_update || ''} onChange={(e) => setBlocklist(i, { auto_update: e.target.value })} />
              <label className="switch" title="Enabled">
                <input type="checkbox" checked={!!bl.enabled} onChange={(e) => setBlocklist(i, { enabled: e.target.checked })} />
                <span className="slider" />
              </label>
              <button className="btn small danger" type="button" onClick={() => removeBlocklist(i)}>✕</button>
            </div>
          </div>
        ))}
        <div className="quick-actions" style={{ marginTop: 12 }}>
          <button className="btn small" type="button" onClick={addBlocklist}>+ Add blocklist</button>
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
          {field('Password', 'leave blank to keep the current password', (
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
          <button className="btn" onClick={() => api.refreshLists().then(() => setMsg('Blocklists refreshed'))}>Refresh blocklists</button>
        </div>
      </div>
    </div>
  )
}
