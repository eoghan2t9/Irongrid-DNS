import { useEffect, useState, useCallback } from 'react'
import { api } from '../api'
import { useToast } from '../toast-context'
import TunnelCloudflare from './TunnelCloudflare'
import TunnelHostnames from './TunnelHostnames'
import TunnelDNSRecords from './TunnelDNSRecords'

export default function Tunnel() {
  const toast = useToast()
  const [status, setStatus] = useState(null)
  // Cloudflare-side view (account, tunnel, suggested origins); null until loaded.
  const [cf, setCf] = useState(null)
  const [mode, setMode] = useState('quick')
  const [token, setToken] = useState('')
  const [configFile, setConfigFile] = useState('')
  const [origin, setOrigin] = useState('http://localhost:8080')
  const [logLines, setLogLines] = useState([])

  const load = useCallback(async () => {
    try {
      const s = await api.tunnelStatus()
      setStatus(s)
    } catch {
      /* ignore */
    }
  }, [])

  const loadCF = useCallback(async () => {
    try {
      setCf(await api.cfStatus())
    } catch {
      /* keep the last view; the cards report their own errors */
    }
  }, [])

  useEffect(() => {
    load()
    loadCF()
    // Pre-fill the form from the persisted config: once a token / config
    // path has been saved (tunnelStart persists it), it survives restarts
    // and shows up here without re-typing.
    api
      .config()
      .then((cfg) => {
        const t = cfg?.tunnel
        if (!t) return
        if (t.token) {
          setToken(t.token)
          setMode('token')
        } else if (t.config_file) {
          setConfigFile(t.config_file)
          setMode('config')
        } else if (t.quick_tunnel) {
          setMode('quick')
        }
        if (t.quick_tunnel_url) setOrigin(t.quick_tunnel_url)
      })
      .catch(() => {})
    const t = setInterval(() => {
      load()
      api
        .tunnelLog()
        .then((r) => setLogLines(r.lines || []))
        .catch(() => {})
    }, 5000)
    return () => clearInterval(t)
  }, [load, loadCF])

  const start = async (e) => {
    e.preventDefault()
    try {
      await api.tunnelStart({
        mode,
        token,
        config_file: configFile,
        origin,
        hostname: '',
      })
      toast('Tunnel started')
      load()
    } catch (err) {
      toast('Failed: ' + err.message, 'error')
    }
  }

  const stop = async () => {
    try {
      await api.tunnelStop()
      toast('Tunnel stopped')
      load()
    } catch (e) {
      toast('Failed to stop: ' + e.message, 'error')
    }
  }

  // A running tunnel keeps the cloudflared binary it started with, so an update
  // is followed by a restart; the server only does that when something was
  // actually installed.
  const checkCloudflaredUpdate = async () => {
    const restart = !!status?.running
    if (
      restart &&
      !confirm(
        'Check for a cloudflared update?\n\nIf one is found the running tunnel restarts to use it, and remote access through it drops for a few seconds.',
      )
    )
      return
    try {
      const r = await api.tunnelCheckCloudflaredUpdate(restart)
      toast(
        r.installed
          ? `cloudflared updated to ${r.new_version}${r.restarting ? ' — restarting the tunnel' : ''}`
          : 'cloudflared is already up to date',
      )
      load()
      if (r.restarting) setTimeout(load, 3000)
    } catch (e) {
      toast('Update check failed: ' + e.message, 'error')
    }
  }

  const restartTunnel = async () => {
    if (!confirm('Restart the tunnel now? Remote access through it drops for a few seconds.')) return
    try {
      await api.tunnelRestart()
      toast('Restarting the tunnel…')
      setTimeout(load, 3000)
    } catch (e) {
      toast('Restart failed: ' + e.message, 'error')
    }
  }

  // The installed binary can be newer than the process that is running.
  const restartPending =
    !!status?.running &&
    !!status?.running_version &&
    !!status?.binary?.version &&
    status.running_version !== status.binary.version

  return (
    <div className="stack">
      <div className="card">
        <div className="row-between">
          <h3>Cloudflare Tunnel</h3>
          <span className={`badge ${status?.running ? 'badge-allowed' : 'badge-error'}`}>
            {status?.running ? 'RUNNING' : 'STOPPED'}
          </span>
        </div>
        <p className="dim">
          Irongrid manages a cloudflared binary automatically — it's downloaded and kept up to date for you, no manual
          install required. Expose your DoH endpoint (<code>/dns-query</code>) or the dashboard to the internet, or
          route a hostname for Android Private DNS.
        </p>
        {status?.started && (
          <div className="dim small">
            Mode: <span className="mono">{status.mode}</span> · started{' '}
            {new Date(status.started).toLocaleString([], { hour12: false })}
            {status.running && status.running_version && (
              <>
                {' '}
                · running cloudflared <span className="mono">{status.running_version}</span>
              </>
            )}
            {status.error && <div className="error-text">Last error: {status.error}</div>}
          </div>
        )}
        <div className="dim small row-between">
          <span>
            cloudflared binary: <span className="mono">{status?.binary?.version || 'not installed yet'}</span>
            {status?.binary?.last_error && (
              <div className="error-text">Update check failed: {status.binary.last_error}</div>
            )}
          </span>
          <span className="row" style={{ gap: 8 }}>
            {restartPending && (
              <button className="btn" type="button" onClick={restartTunnel}>
                Restart tunnel to run {status.binary.version}
              </button>
            )}
            <button className="btn" type="button" onClick={checkCloudflaredUpdate}>
              Check for cloudflared update
            </button>
          </span>
        </div>
      </div>

      <TunnelCloudflare cf={cf} reload={loadCF} tunnelRunning={!!status?.running} />
      <TunnelHostnames cf={cf} />
      <TunnelDNSRecords cf={cf} />

      <div className="card">
        <h3>{status?.running ? 'Tunnel is running' : 'Start a tunnel'}</h3>
        <form onSubmit={start} className="form-grid">
          <label className="input-label">
            Mode
            <select className="input" value={mode} onChange={(e) => setMode(e.target.value)}>
              <option value="quick">Quick tunnel (trycloudflare.com, no auth)</option>
              <option value="token">Named tunnel (Zero Trust token)</option>
              <option value="config">Named tunnel (config file)</option>
            </select>
          </label>
          {mode === 'quick' && (
            <input
              className="input"
              placeholder="Origin URL"
              value={origin}
              onChange={(e) => setOrigin(e.target.value)}
            />
          )}
          {mode === 'token' && (
            <input
              className="input span-2"
              placeholder="Tunnel token"
              value={token}
              onChange={(e) => setToken(e.target.value)}
            />
          )}
          {mode === 'config' && (
            <input
              className="input span-2"
              placeholder="Path to cloudflared config YAML"
              value={configFile}
              onChange={(e) => setConfigFile(e.target.value)}
            />
          )}
          <div className="row">
            <button className="btn primary" type="submit" disabled={status?.running}>
              Start
            </button>
            <button className="btn danger" type="button" onClick={stop} disabled={!status?.running}>
              Stop
            </button>
          </div>
        </form>
        <p className="dim small">
          Starting saves these settings to the config file, so the tunnel auto-starts on boot. Stopping disables
          auto-start (the token stays saved for next time).
        </p>
      </div>

      <div className="card">
        <h3>Tunnel log</h3>
        <pre className="log-view">
          {logLines.length === 0 ? '(no log output yet — start the tunnel)' : logLines.join('\n')}
        </pre>
      </div>

      <div className="card hint-card">
        <h3>Android Private DNS setup</h3>
        <p className="dim">
          1. Connect your Cloudflare account above and pick or create a tunnel (or paste an existing tunnel&apos;s token
          below).
          <br />
          2. Add a hostname (e.g. <code>dns.example.com</code>) pointing at your DoH server — the DNS record is created
          for you.
          <br />
          3. Start the tunnel, then on Android: Settings → Network → Private DNS → <code>dns.example.com</code>.
        </p>
      </div>
    </div>
  )
}
