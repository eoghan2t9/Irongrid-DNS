import React, { useEffect, useState, useCallback } from 'react'
import { api } from '../api'

const fmtDate = (iso) => {
  if (!iso) return '—'
  const d = new Date(iso)
  return d.toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' })
}

export default function Tls() {
  const [status, setStatus] = useState(null)
  const [busy, setBusy] = useState(false)
  const [msg, setMsg] = useState('')
  const [err, setErr] = useState('')

  // generate form
  const [hosts, setHosts] = useState('localhost\ndns.example.com')
  const [keyType, setKeyType] = useState('ecdsa')
  const [keyBits, setKeyBits] = useState('2048')
  const [days, setDays] = useState('825')

  // upload form
  const [certPEM, setCertPEM] = useState('')
  const [keyPEM, setKeyPEM] = useState('')

  const load = useCallback(async () => {
    try {
      setStatus(await api.tlsStatus())
    } catch (e) {
      setErr(e.message)
    }
  }, [])

  useEffect(() => { load() }, [load])

  const generate = async (e) => {
    e.preventDefault()
    setBusy(true)
    setErr('')
    setMsg('')
    try {
      const hostList = hosts.split('\n').map((s) => s.trim()).filter(Boolean)
      if (!hostList.length) throw new Error('enter at least one host')
      const r = await api.tlsGenerate({ hosts: hostList, key_type: keyType, key_bits: Number(keyBits), days: Number(days) })
      setStatus(r.status)
      setMsg(
        r.applied
          ? 'Certificate generated and applied to the DoT/DoH/DoQ listeners.'
          : `Certificate saved but could not be applied in place: ${r.apply_error || 'reload hook unavailable'}.`
      )
    } catch (e) {
      setErr(e.message)
    } finally {
      setBusy(false)
    }
  }

  const upload = async (e) => {
    e.preventDefault()
    setBusy(true)
    setErr('')
    setMsg('')
    try {
      const r = await api.tlsUpload({ cert_pem: certPEM, key_pem: keyPEM })
      setStatus(r.status)
      setMsg(
        r.applied
          ? 'Certificate uploaded and applied to the DoT/DoH/DoQ listeners.'
          : `Certificate saved but could not be applied in place: ${r.apply_error || 'reload hook unavailable'}.`
      )
    } catch (e) {
      setErr(e.message)
    } finally {
      setBusy(false)
    }
  }

  const download = async () => {
    try {
      const blob = await api.tlsCertDownload()
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = 'irongrid-cert.pem'
      a.click()
      URL.revokeObjectURL(url)
      setMsg('Certificate downloaded — install it as a trusted CA on your clients.')
    } catch (e) {
      setErr(e.message)
    }
  }

  if (!status) return <div className="loading">Loading TLS status…</div>

  const info = status.info
  const expiry = info ? Math.max(0, info.expires_in_days) : null
  const expired = info ? info.expires_in_days < 0 : false
  const expiryClass = expired ? 'expiry-bad' : expiry == null ? '' : expiry < 30 ? 'expiry-bad' : expiry < 90 ? 'expiry-warn' : 'expiry-ok'

  const kv = (label, value, mono = false) => (
    <div className="kv-row">
      <span className="kv-label">{label}</span>
      <span className={`kv-value ${mono ? 'mono' : ''}`}>{value || '—'}</span>
    </div>
  )

  return (
    <div className="stack">
      {msg && <div className="info-banner">{msg}</div>}
      {err && <div className="error-banner">{err}</div>}

      <div className="card">
        <div className="row-between">
          <h3 style={{ margin: 0 }}>SSL / TLS certificate</h3>
          <div className="row">
            <button className="btn" onClick={download} disabled={!info}>
              ⬇ Download cert
            </button>
            <button className="btn ghost small" onClick={load}>⟳ Refresh</button>
          </div>
        </div>

        {!info ? (
          <div className="empty">
            No certificate yet — generate a self-signed one below, or upload a CA-signed
            certificate. Until then the DoT/DoH/DoQ listeners cannot start.
          </div>
        ) : (
          <div className="cert-summary">
            <div className="row">
              <span className={`badge ${info.source === 'custom' ? 'badge-allowed' : 'badge-cached'}`}>
                {info.source === 'custom' ? 'CA-signed (custom)' : 'self-signed'}
              </span>
              <span className={`badge ${expired ? 'badge-error' : expiryClass === 'expiry-warn' ? 'badge-warn' : 'badge-allowed'}`}>
                {expired ? 'expired' : `expires in ${expiry} days`}
              </span>
              <span className="chip">SHA-256 {info.fingerprint_sha256}</span>
            </div>
            <div className="kv-grid">
              {kv('Common name', info.subject_cn)}
              {kv('Issuer', info.issuer_cn)}
              {kv('Valid from', fmtDate(info.not_before))}
              {kv('Valid until', fmtDate(info.not_after), true)}
              {kv('Key', info.key_algo)}
              {kv('Serial', info.serial, true)}
              {kv('Files', `${info.cert_path} + ${info.key_path}`, true)}
            </div>
            <div className="san-block">
              <span className="field-label">SANs (subjectAltName)</span>
              <div className="tag-list">
                {(info.sans || []).map((s) => <span className="chip" key={s}>{s}</span>)}
              </div>
            </div>
            <div className="san-block">
              <span className="field-label">Encrypted listeners using this certificate</span>
              <div className="tag-list">
                {status.listeners?.dot && <span className="chip">DoT :853</span>}
                {status.listeners?.doh && <span className="chip">DoH :443</span>}
                {status.listeners?.doq && <span className="chip">DoQ :853</span>}
                {!status.listeners?.dot && !status.listeners?.doh && !status.listeners?.doq && (
                  <span className="dim small">none enabled — enable DoT/DoH/DoQ in Settings</span>
                )}
              </div>
            </div>
          </div>
        )}
      </div>

      <div className="grid-2">
        <div className="card">
          <h3>Generate self-signed</h3>
          <p className="dim small" style={{ marginTop: -6 }}>
            Perfect for your own devices (Android Private DNS) or a private setup.
            Overwrites the current self-signed certificate.
          </p>
          <form onSubmit={generate} className="form-grid">
            <label className="field span-2">
              <span className="field-label">Hosts / SANs (one per line)</span>
              <textarea className="input mono" rows={4} value={hosts}
                onChange={(e) => setHosts(e.target.value)}
                placeholder="dns.example.com&#10;localhost&#10;192.168.1.10" />
            </label>
            <label className="field">
              <span className="field-label">Key type</span>
              <select className="input" value={keyType} onChange={(e) => setKeyType(e.target.value)}>
                <option value="ecdsa">ECDSA (P-256)</option>
                <option value="rsa">RSA</option>
              </select>
            </label>
            {keyType === 'rsa' && (
              <label className="field">
                <span className="field-label">Key size</span>
                <select className="input" value={keyBits} onChange={(e) => setKeyBits(e.target.value)}>
                  <option value="2048">2048 bits</option>
                  <option value="3072">3072 bits</option>
                  <option value="4096">4096 bits</option>
                </select>
              </label>
            )}
            <label className="field span-2">
              <span className="field-label">Validity (days)</span>
              <input className="input" type="number" min="1" value={days} onChange={(e) => setDays(e.target.value)} />
            </label>
            <div className="span-2">
              <button className="btn primary" type="submit" disabled={busy}>
                {busy ? 'Working…' : 'Generate & apply'}
              </button>
            </div>
          </form>
        </div>

        <div className="card">
          <h3>Upload CA-signed certificate</h3>
          <p className="dim small" style={{ marginTop: -6 }}>
            Paste a certificate chain and its private key (e.g. from Let&apos;s
            Encrypt or your CA) to serve DoT/DoH/DoQ with a trusted cert.
          </p>
          <form onSubmit={upload} className="form-grid">
            <label className="field span-2">
              <span className="field-label">Certificate (PEM)</span>
              <textarea className="input mono pem-box" rows={6} value={certPEM}
                onChange={(e) => setCertPEM(e.target.value)}
                placeholder="-----BEGIN CERTIFICATE-----&#10;…" />
            </label>
            <label className="field span-2">
              <span className="field-label">Private key (PEM)</span>
              <textarea className="input mono pem-box" rows={6} value={keyPEM}
                onChange={(e) => setKeyPEM(e.target.value)}
                placeholder="-----BEGIN PRIVATE KEY-----&#10;…" />
            </label>
            <div className="span-2">
              <button className="btn primary" type="submit" disabled={busy || !certPEM || !keyPEM}>
                {busy ? 'Working…' : 'Upload & apply'}
              </button>
            </div>
          </form>
        </div>
      </div>

      <div className="card hint-card">
        <h3>How the certificate is used</h3>
        <p className="dim small">
          The certificate secures the <strong>DoT (853), DoH (443) and DoQ (853)</strong> DNS
          listeners. Generating or uploading applies it immediately by rebinding the listeners
          (a sub-second interruption) — no process restart needed. For a public hostname, route
          it through the Cloudflare Tunnel and use a CA-signed certificate so phones trust it
          without extra setup; for local use, <button className="btn-link" onClick={download} disabled={!info}>download
          this certificate</button> and install it as a trusted CA on each device.
        </p>
      </div>
    </div>
  )
}
