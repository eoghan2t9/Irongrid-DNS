import { useEffect, useState, useCallback } from 'react'
import { api } from '../api'
import { useToast } from '../toast-context'
import { XIcon } from './ui'

const fmtDate = (iso) => {
  if (!iso) return '—'
  const d = new Date(iso)
  return d.toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' })
}

// Stroke-only SVG icons for the header actions — the design standard across
// the app (see App.jsx's navSvg) so no glyph can render as a colored emoji.
const TrustIcon = (
  <svg
    width="13"
    height="13"
    viewBox="0 0 24 24"
    fill="none"
    stroke="currentColor"
    strokeWidth="2"
    strokeLinecap="round"
    strokeLinejoin="round"
    aria-hidden="true"
  >
    <path d="M12 2 20 6v6c0 5-3.5 8.5-8 10-4.5-1.5-8-5-8-10V6z" />
    <path d="M9 12l2 2 4-4" />
  </svg>
)
const DownloadIcon = (
  <svg
    width="13"
    height="13"
    viewBox="0 0 24 24"
    fill="none"
    stroke="currentColor"
    strokeWidth="2"
    strokeLinecap="round"
    strokeLinejoin="round"
    aria-hidden="true"
  >
    <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" />
    <polyline points="7 10 12 15 17 10" />
    <line x1="12" y1="15" x2="12" y2="3" />
  </svg>
)

const TRUST_STEPS = [
  {
    os: 'Android',
    steps: [
      'Download the certificate (⬇ button above).',
      'Open Settings → Security → Encryption & credentials → Install a certificate → CA certificate.',
      'Pick the downloaded irongrid-cert.pem file and confirm.',
    ],
  },
  {
    os: 'iOS / macOS',
    steps: [
      'Download the certificate.',
      'Open it from Files/Downloads — the profile installer appears.',
      'Install the profile, then go to Settings → General → About → Certificate Trust Settings and enable full trust for it.',
    ],
  },
  {
    os: 'Windows',
    steps: [
      'Download the certificate.',
      'Double-click it → Install Certificate → Local Machine → Place all certificates in: Trusted Root Certification Authorities.',
    ],
  },
  {
    os: 'Linux',
    steps: [
      'Download the certificate.',
      'Copy it into the system trust store, e.g.: sudo cp irongrid-cert.pem /usr/local/share/ca-certificates/ && sudo update-ca-certificates',
    ],
  },
]

export default function Tls() {
  const toast = useToast()
  const [status, setStatus] = useState(null)
  const [busy, setBusy] = useState(false)
  const [showTrust, setShowTrust] = useState(false)

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
      toast(e.message, 'error')
    }
  }, [toast])

  useEffect(() => {
    load()
  }, [load])

  const generate = async (e) => {
    e.preventDefault()
    setBusy(true)
    try {
      const hostList = hosts
        .split('\n')
        .map((s) => s.trim())
        .filter(Boolean)
      if (!hostList.length) throw new Error('enter at least one host')
      const r = await api.tlsGenerate({
        hosts: hostList,
        key_type: keyType,
        key_bits: Number(keyBits),
        days: Number(days),
      })
      setStatus(r.status)
      toast(
        r.applied
          ? 'Certificate generated and applied to the DoT/DoH/DoQ listeners.'
          : `Certificate saved but could not be applied in place: ${r.apply_error || 'reload hook unavailable'}.`,
        r.applied ? 'info' : 'error',
      )
    } catch (e) {
      toast(e.message, 'error')
    } finally {
      setBusy(false)
    }
  }

  const upload = async (e) => {
    e.preventDefault()
    setBusy(true)
    try {
      const r = await api.tlsUpload({ cert_pem: certPEM, key_pem: keyPEM })
      setStatus(r.status)
      toast(
        r.applied
          ? 'Certificate uploaded and applied to the DoT/DoH/DoQ listeners.'
          : `Certificate saved but could not be applied in place: ${r.apply_error || 'reload hook unavailable'}.`,
        r.applied ? 'info' : 'error',
      )
    } catch (e) {
      toast(e.message, 'error')
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
      toast('Certificate downloaded — install it as a trusted CA on your clients.')
    } catch (e) {
      toast(e.message, 'error')
    }
  }

  const issueAcme = async () => {
    setBusy(true)
    try {
      const r = await api.tlsAcmeIssue()
      setStatus(r.status)
      toast(
        r.applied
          ? "Let's Encrypt certificate issued and applied to the listeners."
          : `Certificate issued but could not be applied in place: ${r.apply_error || 'reload hook unavailable'}.`,
        r.applied ? 'info' : 'error',
      )
    } catch (e) {
      toast('ACME issuance failed: ' + e.message, 'error')
    } finally {
      setBusy(false)
    }
  }

  if (!status) return <div className="loading">Loading TLS status…</div>

  const info = status.info
  const expiry = info ? Math.max(0, info.expires_in_days) : null
  const expired = info ? info.expires_in_days < 0 : false
  const expiryClass = expired
    ? 'expiry-bad'
    : expiry == null
      ? ''
      : expiry < 30
        ? 'expiry-bad'
        : expiry < 90
          ? 'expiry-warn'
          : 'expiry-ok'

  const kv = (label, value, mono = false) => (
    <div className="kv-row">
      <span className="kv-label">{label}</span>
      <span className={`kv-value ${mono ? 'mono' : ''}`}>{value || '—'}</span>
    </div>
  )

  return (
    <div className="stack">
      <div className="card">
        <div className="row-between">
          <h3 style={{ margin: 0 }}>SSL / TLS certificate</h3>
          <div className="row">
            <button className="btn" onClick={() => setShowTrust(true)} disabled={!info}>
              {TrustIcon}
              Trust on devices
            </button>
            <button className="btn" onClick={download} disabled={!info}>
              {DownloadIcon}
              Download cert
            </button>
            <button className="btn ghost small" onClick={load}>
              ⟳ Refresh
            </button>
          </div>
        </div>

        {!info ? (
          <div className="empty">
            No certificate yet — generate a self-signed one below, or upload a CA-signed certificate. Until then the
            DoT/DoH/DoQ listeners cannot start.
          </div>
        ) : (
          <div className="cert-summary">
            <div className="row">
              <span className={`badge ${info.source === 'custom' ? 'badge-allowed' : 'badge-cached'}`}>
                {info.source === 'custom' ? 'CA-signed (custom)' : 'self-signed'}
              </span>
              <span
                className={`badge ${expired ? 'badge-error' : expiryClass === 'expiry-warn' ? 'badge-warn' : 'badge-allowed'}`}
              >
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
                {(info.sans || []).map((s) => (
                  <span className="chip" key={s}>
                    {s}
                  </span>
                ))}
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
            Perfect for your own devices (Android Private DNS) or a private setup. Overwrites the current self-signed
            certificate.
          </p>
          <form onSubmit={generate} className="form-grid">
            <label className="field span-2">
              <span className="field-label">Hosts / SANs (one per line)</span>
              <textarea
                className="input mono"
                rows={4}
                value={hosts}
                onChange={(e) => setHosts(e.target.value)}
                placeholder="dns.example.com&#10;localhost&#10;192.168.1.10"
              />
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
            Paste a certificate chain and its private key (e.g. from Let&apos;s Encrypt or your CA) to serve DoT/DoH/DoQ
            with a trusted cert.
          </p>
          <form onSubmit={upload} className="form-grid">
            <label className="field span-2">
              <span className="field-label">Certificate (PEM)</span>
              <textarea
                className="input mono pem-box"
                rows={6}
                value={certPEM}
                onChange={(e) => setCertPEM(e.target.value)}
                placeholder="-----BEGIN CERTIFICATE-----&#10;…"
              />
            </label>
            <label className="field span-2">
              <span className="field-label">Private key (PEM)</span>
              <textarea
                className="input mono pem-box"
                rows={6}
                value={keyPEM}
                onChange={(e) => setKeyPEM(e.target.value)}
                placeholder="-----BEGIN PRIVATE KEY-----&#10;…"
              />
            </label>
            <div className="span-2">
              <button className="btn primary" type="submit" disabled={busy || !certPEM || !keyPEM}>
                {busy ? 'Working…' : 'Upload & apply'}
              </button>
            </div>
          </form>
        </div>
      </div>

      <div className="card">
        <div className="row-between">
          <h3 style={{ margin: 0 }}>Let's Encrypt (ACME) auto-issuance</h3>
          {status.acme?.enabled && (
            <span className={`badge ${status.acme.last_error ? 'badge-error' : 'badge-allowed'}`}>
              {status.acme.challenge === 'dns-01'
                ? 'dns-01 (no open port)'
                : status.acme.running
                  ? 'challenge server on'
                  : 'configured'}
            </span>
          )}
        </div>
        <p className="dim small" style={{ marginTop: 6 }}>
          Automatically issues and renews a trusted certificate for a public hostname. By default it uses the{' '}
          <strong>HTTP-01</strong> challenge (domains must answer on port 80); set{' '}
          <code>tls.acme.dns01.provider: cloudflare</code> in the config to issue via <strong>DNS-01</strong> TXT
          records instead — no inbound port needed. Route the hostname to this machine (or through the Cloudflare
          Tunnel) first.
        </p>
        {!status.acme?.enabled ? (
          <div className="empty">
            ACME is disabled. Enable <code>tls.acme</code> (email + domains) in the config, then return here to issue
            the first certificate.
          </div>
        ) : (
          <div className="kv-grid">
            <div className="kv-row">
              <span className="kv-label">Email</span>
              <span className="kv-value">{status.acme.email}</span>
            </div>
            <div className="kv-row">
              <span className="kv-label">Domains</span>
              <span className="kv-value">{(status.acme.domains || []).join(', ') || '—'}</span>
            </div>
            <div className="kv-row">
              <span className="kv-label">CA</span>
              <span className="kv-value">
                {status.acme.staging ? "Let's Encrypt staging (test)" : "Let's Encrypt production"}
              </span>
            </div>
            <div className="kv-row">
              <span className="kv-label">Challenge</span>
              <span className="kv-value">
                {status.acme.challenge || 'http-01'}
                {status.acme.dns_provider ? ` (${status.acme.dns_provider})` : ''}
              </span>
            </div>
            {status.acme.challenge !== 'dns-01' && (
              <div className="kv-row">
                <span className="kv-label">Challenge port</span>
                <span className="kv-value">:{status.acme.challenge_port}</span>
              </div>
            )}
            {status.acme.last_success && (
              <div className="kv-row">
                <span className="kv-label">Last issued</span>
                <span className="kv-value">{fmtDate(status.acme.last_success)}</span>
              </div>
            )}
            {status.acme.next_renewal && (
              <div className="kv-row">
                <span className="kv-label">Next renewal</span>
                <span className="kv-value">{fmtDate(status.acme.next_renewal)}</span>
              </div>
            )}
            {status.acme.last_error && (
              <div className="kv-row">
                <span className="kv-label">Last error</span>
                <span className="kv-value error-text">{status.acme.last_error}</span>
              </div>
            )}
          </div>
        )}
        {status.acme?.enabled && (
          <div className="quick-actions" style={{ marginTop: 14 }}>
            <button className="btn primary" onClick={issueAcme} disabled={busy}>
              {busy ? 'Issuing…' : 'Issue / renew now'}
            </button>
          </div>
        )}
      </div>

      <div className="card hint-card">
        <h3>How the certificate is used</h3>
        <p className="dim small">
          The certificate secures the <strong>DoT (853), DoH (443) and DoQ (853)</strong> DNS listeners, and the
          dashboard itself when <code>web_tls</code> is enabled. Generating, uploading or ACME-issuing applies it
          immediately by rebinding the listeners (a sub-second interruption) — no process restart needed. For a public
          hostname, route it through the Cloudflare Tunnel and use a CA-signed or Let's Encrypt certificate so phones
          trust it without extra setup; for local use,{' '}
          <button className="btn-link" onClick={() => setShowTrust(true)} disabled={!info}>
            trust this certificate on your devices
          </button>
          .
        </p>
      </div>

      {showTrust && (
        <div className="modal-overlay" onClick={() => setShowTrust(false)}>
          <div className="modal" onClick={(e) => e.stopPropagation()}>
            <div className="modal-head">
              <div>
                <div className="modal-title">Trust this certificate</div>
                <div className="modal-sub">
                  <span className="chip">irongrid-cert.pem</span>
                  <span className="modal-date">install as a trusted CA on each client</span>
                </div>
              </div>
              <button className="modal-x" onClick={() => setShowTrust(false)} aria-label="Close">
                <XIcon size={13} />
              </button>
            </div>
            <div className="modal-body changelog">
              {TRUST_STEPS.map((t) => (
                <div key={t.os}>
                  <h4>{t.os}</h4>
                  <ol>
                    {t.steps.map((s, i) => (
                      <li key={i}>{s}</li>
                    ))}
                  </ol>
                </div>
              ))}
              <p className="modal-note">
                First <strong>download</strong> the certificate above, then follow the steps for each device. For
                Android Private DNS, use a CA-signed or Let's Encrypt certificate instead so no manual trust is needed.
              </p>
            </div>
            <div className="modal-foot">
              <div className="modal-spacer" />
              <button className="btn" onClick={() => setShowTrust(false)}>
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
