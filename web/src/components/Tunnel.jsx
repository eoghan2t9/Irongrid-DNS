import React, { useEffect, useState, useCallback } from 'react'
import { api } from '../api'

export default function Tunnel() {
  const [status, setStatus] = useState(null)
  const [mode, setMode] = useState('quick')
  const [token, setToken] = useState('')
  const [configFile, setConfigFile] = useState('')
  const [origin, setOrigin] = useState('http://localhost:8080')
  const [logLines, setLogLines] = useState([])
  const [msg, setMsg] = useState('')

  const load = useCallback(async () => {
    try {
      const s = await api.tunnelStatus()
      setStatus(s)
    } catch { /* ignore */ }
  }, [])

  useEffect(() => {
    load()
    const t = setInterval(() => {
      load()
      api.tunnelLog().then((r) => setLogLines(r.lines || [])).catch(() => {})
    }, 5000)
    return () => clearInterval(t)
  }, [load])

  const start = async (e) => {
    e.preventDefault()
    setMsg('Starting tunnel…')
    try {
      await api.tunnelStart({
        mode,
        token,
        config_file: configFile,
        origin,
        hostname: '',
      })
      setMsg('Tunnel started')
      load()
    } catch (err) {
      setMsg('Failed: ' + err.message)
    }
  }

  const stop = async () => {
    await api.tunnelStop()
    setMsg('Tunnel stopped')
    load()
  }

  return (
    <div className="stack">
      {msg && <div className="info-banner">{msg}</div>}

      <div className="card">
        <div className="row-between">
          <h3>Cloudflare Tunnel (cloudflared baked in)</h3>
          <span className={`badge ${status?.running ? 'badge-allowed' : 'badge-error'}`}>
            {status?.running ? 'RUNNING' : 'STOPPED'}
          </span>
        </div>
        <p className="dim">
          The cloudflared agent is compiled into this binary — no external installation needed.
          Expose your DoH endpoint (<code>/dns-query</code>) or the dashboard to the internet,
          or route a hostname for Android Private DNS.
        </p>
        {status?.started && (
          <div className="dim small">
            Mode: <span className="mono">{status.mode}</span> · started {new Date(status.started).toLocaleString([], { hour12: false })}
            {status.error && <div className="error-text">Last error: {status.error}</div>}
          </div>
        )}
      </div>

      <div className="card">
        <h3>{status?.running ? 'Tunnel is running' : 'Start a tunnel'}</h3>
        <form onSubmit={start} className="form-grid">
          <label className="input-label">Mode
            <select className="input" value={mode} onChange={(e) => setMode(e.target.value)}>
              <option value="quick">Quick tunnel (trycloudflare.com, no auth)</option>
              <option value="token">Named tunnel (Zero Trust token)</option>
              <option value="config">Named tunnel (config file)</option>
            </select>
          </label>
          {mode === 'quick' && (
            <input className="input" placeholder="Origin URL" value={origin} onChange={(e) => setOrigin(e.target.value)} />
          )}
          {mode === 'token' && (
            <input className="input span-2" placeholder="Tunnel token" value={token} onChange={(e) => setToken(e.target.value)} />
          )}
          {mode === 'config' && (
            <input className="input span-2" placeholder="Path to cloudflared config YAML" value={configFile} onChange={(e) => setConfigFile(e.target.value)} />
          )}
          <div className="row">
            <button className="btn primary" type="submit" disabled={status?.running}>Start</button>
            <button className="btn danger" type="button" onClick={stop} disabled={!status?.running}>Stop</button>
          </div>
        </form>
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
          1. Create a named tunnel in Cloudflare Zero Trust and paste its token here.<br />
          2. Route your hostname (e.g. <code>dns.example.com</code>) to <code>https://localhost:8443</code> (your DoH server).<br />
          3. On Android: Settings → Network → Private DNS → <code>dns.example.com</code>.
        </p>
      </div>
    </div>
  )
}
