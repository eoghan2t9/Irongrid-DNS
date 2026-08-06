import React, { useState } from 'react'
import { api } from '../api'
import { useToast } from '../toast'
import SiteScanner from './SiteScanner'

const QTYPES = ['A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT', 'SOA', 'SRV', 'PTR', 'CAA', 'TLSA', 'ANY']
const SOURCES = [
  { id: 'local', label: 'Local upstreams' },
  { id: 'cloudflare', label: 'Cloudflare 1.1.1.1' },
  { id: 'google', label: 'Google 8.8.8.8' },
  { id: 'quad9', label: 'Quad9 9.9.9.9' },
]

function rcodeBadge(rcode) {
  const cls = { NOERROR: 'badge-allowed', NXDOMAIN: 'badge-warn', SERVFAIL: 'badge-error', REFUSED: 'badge-error' }[rcode] || 'badge-cached'
  return <span className={`badge ${cls}`}>{rcode}</span>
}

// ResolveTable renders one row per source for a toolsResolve response.
function ResolveTable({ results }) {
  if (!results || results.length === 0) return <div className="empty">No results.</div>
  return (
    <div className="stack" style={{ marginTop: 12 }}>
      {results.map((res) => (
        <div className="card" key={res.source} style={{ padding: 10 }}>
          <div className="row" style={{ flexWrap: 'wrap', gap: 8 }}>
            <span className="chip">{res.source}</span>
            {res.error ? (
              <span className="badge badge-error">Error</span>
            ) : (
              <>
                {rcodeBadge(res.rcode)}
                <span className="mono dim">{res.latency_ms} ms</span>
                {res.aa && <span className="badge badge-cached">AA</span>}
                {res.ad && <span className="badge badge-cached">AD</span>}
                {res.ra && <span className="badge badge-cached">RA</span>}
                <span className="dim small mono">{res.server}</span>
              </>
            )}
          </div>
          {res.error ? (
            <div className="error-text small">{res.error}</div>
          ) : res.answers.length === 0 ? (
            <div className="dim small" style={{ marginTop: 8 }}>No answers ({res.rcode})</div>
          ) : (
            <pre className="log-view" style={{ marginTop: 8 }}>{res.answers.join('\n')}</pre>
          )}
        </div>
      ))}
    </div>
  )
}

function ResolveTool() {
  const [name, setName] = useState('')
  const [type, setType] = useState('A')
  const [rd, setRd] = useState(true)
  const [doBit, setDoBit] = useState(false)
  const [cd, setCd] = useState(false)
  const [sources, setSources] = useState(['local'])
  const [busy, setBusy] = useState(false)
  const [res, setRes] = useState(null)
  const [err, setErr] = useState('')

  const toggleSource = (id) => setSources((s) => (s.includes(id) ? s.filter((x) => x !== id) : [...s, id]))

  const run = async (e) => {
    e.preventDefault()
    if (!name.trim()) return
    setBusy(true); setErr(''); setRes(null)
    try {
      setRes(await api.toolsResolve({ name: name.trim(), type, rd, do: doBit, cd, sources }))
    } catch (ex) {
      setErr(ex.message)
    }
    setBusy(false)
  }

  return (
    <div className="card">
      <h3>DNS lookup</h3>
      <p className="dim small">dig-style lookup through any combination of your upstreams and public resolvers.</p>
      <form onSubmit={run} className="form-grid">
        <input className="input" placeholder="example.com or 1.2.3.4" value={name} onChange={(e) => setName(e.target.value)} />
        <select className="input" value={type} onChange={(e) => setType(e.target.value)}>
          {QTYPES.map((t) => <option key={t}>{t}</option>)}
        </select>
        <button className="btn primary" type="submit" disabled={busy || sources.length === 0}>
          {busy ? 'Resolving…' : 'Look up'}
        </button>
      </form>
      <div className="row" style={{ marginTop: 10, flexWrap: 'wrap', gap: 10 }}>
        {SOURCES.map((s) => (
          <label className="toggle-label" key={s.id}>
            <input type="checkbox" checked={sources.includes(s.id)} onChange={() => toggleSource(s.id)} />
            {s.label}
          </label>
        ))}
        <label className="toggle-label"><input type="checkbox" checked={rd} onChange={(e) => setRd(e.target.checked)} /> RD</label>
        <label className="toggle-label"><input type="checkbox" checked={doBit} onChange={(e) => setDoBit(e.target.checked)} /> DO</label>
        <label className="toggle-label"><input type="checkbox" checked={cd} onChange={(e) => setCd(e.target.checked)} /> CD</label>
      </div>
      {err && <div className="error-banner" style={{ marginTop: 10 }}>{err}</div>}
      <ResolveTable results={res?.results} />
    </div>
  )
}

function PropagationTool() {
  const [name, setName] = useState('')
  const [type, setType] = useState('A')
  const [busy, setBusy] = useState(false)
  const [res, setRes] = useState(null)
  const [err, setErr] = useState('')

  const run = async (e) => {
    e.preventDefault()
    if (!name.trim()) return
    setBusy(true); setErr(''); setRes(null)
    try {
      setRes(await api.toolsResolve({ name: name.trim(), type, rd: true, do: false, cd: false, sources: ['cloudflare', 'google', 'quad9', 'local'] }))
    } catch (ex) {
      setErr(ex.message)
    }
    setBusy(false)
  }

  return (
    <div className="card">
      <h3>Propagation check</h3>
      <p className="dim small">Is your change live everywhere yet? Compares the answer from each public resolver plus your own upstreams.</p>
      <form onSubmit={run} className="form-grid">
        <input className="input" placeholder="example.com" value={name} onChange={(e) => setName(e.target.value)} />
        <select className="input" value={type} onChange={(e) => setType(e.target.value)}>
          {QTYPES.map((t) => <option key={t}>{t}</option>)}
        </select>
        <button className="btn" type="submit" disabled={busy}>{busy ? 'Checking…' : 'Check propagation'}</button>
      </form>
      {err && <div className="error-banner" style={{ marginTop: 10 }}>{err}</div>}
      <ResolveTable results={res?.results} />
    </div>
  )
}

function MailTool() {
  const [domain, setDomain] = useState('')
  const [busy, setBusy] = useState(false)
  const [res, setRes] = useState(null)
  const [err, setErr] = useState('')

  const run = async (e) => {
    e.preventDefault()
    if (!domain.trim()) return
    setBusy(true); setErr(''); setRes(null)
    try {
      setRes(await api.toolsMail(domain.trim()))
    } catch (ex) {
      setErr(ex.message)
    }
    setBusy(false)
  }

  return (
    <div className="card">
      <h3>Mail records</h3>
      <p className="dim small">MX, SPF, DKIM (default selector), DMARC and CAA for a domain — will email to it deliver and is it protected from spoofing?</p>
      <form onSubmit={run} className="form-grid">
        <input className="input" placeholder="example.com" value={domain} onChange={(e) => setDomain(e.target.value)} />
        <button className="btn" type="submit" disabled={busy}>{busy ? 'Checking…' : 'Check mail records'}</button>
      </form>
      {err && <div className="error-banner" style={{ marginTop: 10 }}>{err}</div>}
      {res && (
        <table className="table" style={{ marginTop: 12 }}>
          <tbody>
            <tr>
              <td className="mono" style={{ width: 60 }}>MX</td>
              <td style={{ width: 130 }}>
                {res.mx_error ? <span className="badge badge-warn">Missing</span> : <span className="badge badge-allowed">{res.mx.length} server{res.mx.length === 1 ? '' : 's'}</span>}
              </td>
              <td className="mono small dim">{res.mx.join(', ') || res.mx_error}</td>
            </tr>
            <tr>
              <td className="mono">SPF</td>
              <td>
                {res.spf_error ? <span className="badge badge-warn">Missing</span> : res.spf_ok ? <span className="badge badge-allowed">OK</span> : <span className="badge badge-warn">Issues</span>}
              </td>
              <td className="small">
                {res.spf && <div className="mono dim">{res.spf}</div>}
                {res.spf_error && <div className="dim">{res.spf_error}</div>}
                {res.spf_issues?.map((i) => <div key={i} className="error-text small">{i}</div>)}
              </td>
            </tr>
            <tr>
              <td className="mono">DKIM</td>
              <td>{res.dkim_ok ? <span className="badge badge-allowed">Present</span> : <span className="badge badge-warn">Missing</span>}</td>
              <td className="dim small mono">{res.dkim || res.dkim_error}</td>
            </tr>
            <tr>
              <td className="mono">DMARC</td>
              <td>
                {res.dmarc ? (
                  res.dmarc_policy === 'reject' ? <span className="badge badge-allowed">p={res.dmarc_policy}</span> : <span className="badge badge-warn">p={res.dmarc_policy}</span>
                ) : <span className="badge badge-warn">Missing</span>}
              </td>
              <td className="dim small mono">{res.dmarc || res.dmarc_error}</td>
            </tr>
            <tr>
              <td className="mono">CAA</td>
              <td>{res.caa.length ? <span className="badge badge-allowed">Configured</span> : <span className="badge badge-cached">Open</span>}</td>
              <td className="dim small mono">{res.caa.join(', ') || res.caa_error}</td>
            </tr>
          </tbody>
        </table>
      )}
    </div>
  )
}

function RBLTool() {
  const [ip, setIP] = useState('')
  const [busy, setBusy] = useState(false)
  const [res, setRes] = useState(null)
  const [err, setErr] = useState('')

  const run = async (e) => {
    e.preventDefault()
    if (!ip.trim()) return
    setBusy(true); setErr(''); setRes(null)
    try {
      setRes(await api.toolsRBL(ip.trim()))
    } catch (ex) {
      setErr(ex.message)
    }
    setBusy(false)
  }

  return (
    <div className="card">
      <h3>Reputation (RBL) check</h3>
      <p className="dim small">Is an IP address listed on DNS-based spam blocklists?</p>
      <form onSubmit={run} className="form-grid">
        <input className="input" placeholder="1.2.3.4" value={ip} onChange={(e) => setIP(e.target.value)} />
        <button className="btn" type="submit" disabled={busy}>{busy ? 'Checking…' : 'Check reputation'}</button>
      </form>
      {err && <div className="error-banner" style={{ marginTop: 10 }}>{err}</div>}
      {res && (
        <table className="table" style={{ marginTop: 12 }}>
          <thead>
            <tr><th>Blocklist</th><th>Status</th><th>Detail</th></tr>
          </thead>
          <tbody>
            {res.checks.map((c) => (
              <tr key={c.zone}>
                <td>
                  <div className="strong">{c.rbl}</div>
                  <div className="dim small mono">{c.zone}</div>
                </td>
                <td>
                  {c.error ? <span className="badge badge-error">Error</span>
                    : c.listed ? <span className="badge badge-blocked">Listed {c.code}</span>
                    : <span className="badge badge-allowed">Clean</span>}
                </td>
                <td className="dim small">{c.reason || c.error || ''}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  )
}

function AXFRTool() {
  const [domain, setDomain] = useState('')
  const [busy, setBusy] = useState(false)
  const [res, setRes] = useState(null)
  const [err, setErr] = useState('')

  const run = async (e) => {
    e.preventDefault()
    if (!domain.trim()) return
    setBusy(true); setErr(''); setRes(null)
    try {
      setRes(await api.toolsAXFR(domain.trim()))
    } catch (ex) {
      setErr(ex.message)
    }
    setBusy(false)
  }

  return (
    <div className="card">
      <h3>Zone transfer (AXFR) check</h3>
      <p className="dim small">Would any of this domain's nameservers hand over its full zone to anyone who asks?</p>
      <form onSubmit={run} className="form-grid">
        <input className="input" placeholder="example.com" value={domain} onChange={(e) => setDomain(e.target.value)} />
        <button className="btn" type="submit" disabled={busy}>{busy ? 'Checking…' : 'Check AXFR'}</button>
      </form>
      {err && <div className="error-banner" style={{ marginTop: 10 }}>{err}</div>}
      {res && (
        <>
          {res.note && <div className="info-banner" style={{ marginTop: 10 }}>{res.note}</div>}
          <table className="table" style={{ marginTop: 12 }}>
            <thead>
              <tr><th>Nameserver</th><th>Address</th><th>Result</th></tr>
            </thead>
            <tbody>
              {res.nameservers.map((n, i) => (
                <tr key={i}>
                  <td className="mono">{n.host}</td>
                  <td className="mono dim">{n.address || '—'}</td>
                  <td>
                    {n.error ? <span className="badge badge-warn">Refused / error</span>
                      : n.axfr ? <span className="badge badge-blocked">Vulnerable — {n.records} records leaked</span>
                      : <span className="badge badge-allowed">Safe</span>}
                    {n.error && <div className="dim small">{n.error}</div>}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </>
      )}
    </div>
  )
}

function SubdomainTool() {
  const toast = useToast()
  const [domain, setDomain] = useState('')
  const [busy, setBusy] = useState(false)
  const [res, setRes] = useState(null)
  const [err, setErr] = useState('')
  const [allowed, setAllowed] = useState({})

  const run = async (e) => {
    e.preventDefault()
    if (!domain.trim()) return
    setBusy(true); setErr(''); setRes(null); setAllowed({})
    try {
      setRes(await api.toolsSubdomains(domain.trim()))
    } catch (ex) {
      setErr(ex.message)
    }
    setBusy(false)
  }

  const allowOne = async (d) => {
    try {
      await api.addFilterEntry('whitelist', d)
      setAllowed((s) => ({ ...s, [d]: true }))
      toast(`Allowed "${d}"`)
    } catch (ex) {
      toast('Failed to allow: ' + ex.message, 'error')
    }
  }

  const allowAll = async () => {
    const blocked = (res?.domains || []).filter((x) => x.blocked && !allowed[x.domain]).map((x) => x.domain)
    const ok = []
    for (const d of blocked) {
      try {
        await api.addFilterEntry('whitelist', d)
        ok.push(d)
      } catch (ex) {
        toast(`Failed to allow "${d}": ` + ex.message, 'error')
      }
    }
    if (ok.length) toast(`Allowed ${ok.length} blocked subdomain${ok.length === 1 ? '' : 's'}`)
    setAllowed((s) => {
      const n = { ...s }
      ok.forEach((d) => { n[d] = true })
      return n
    })
  }

  return (
    <div className="card">
      <h3>Subdomain audit</h3>
      <p className="dim small">Finds a domain's subdomains via certificate transparency (crt.sh) and flags the ones your blocklists cover — often the source of a "half-broken" site.</p>
      <form onSubmit={run} className="form-grid">
        <input className="input" placeholder="example.com" value={domain} onChange={(e) => setDomain(e.target.value)} />
        <button className="btn" type="submit" disabled={busy}>{busy ? 'Scanning…' : 'Audit subdomains'}</button>
      </form>
      {err && <div className="error-banner" style={{ marginTop: 10 }}>{err}</div>}
      {res && (
        <>
          <div className="row-between" style={{ marginTop: 12 }}>
            <div className="dim small">
              {res.total} subdomains found,{' '}
              <span style={{ color: res.blocked ? 'var(--rose)' : undefined }}>{res.blocked} blocked</span>
              {res.truncated && ' · list truncated'}
            </div>
            {res.blocked > 0 && (
              <button className="btn small" onClick={allowAll}>Allow all blocked</button>
            )}
          </div>
          <div style={{ maxHeight: 360, overflowY: 'auto', marginTop: 10 }}>
            <table className="table">
              <thead>
                <tr><th>Subdomain</th><th>Status</th><th>Blocked by</th><th className="action-col"></th></tr>
              </thead>
              <tbody>
                {res.domains.map((x) => {
                  const already = allowed[x.domain]
                  return (
                    <tr key={x.domain} className={x.blocked ? '' : 'row-dim'}>
                      <td className="entry-cell" title={x.domain}>{x.domain}</td>
                      <td>
                        <span className={`badge ${x.blocked ? 'badge-blocked' : 'badge-allowed'}`}>
                          {x.blocked ? 'Blocked' : 'Allowed'}
                        </span>
                      </td>
                      <td className="dim small">{x.blocked ? (x.list || 'blocklist') : ''}</td>
                      <td className="action-col">
                        {x.blocked && !already && <button className="btn small" onClick={() => allowOne(x.domain)}>Allow</button>}
                        {x.blocked && already && <button className="btn small" disabled>✓ Allowed</button>}
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        </>
      )}
    </div>
  )
}

export default function Tools() {
  return (
    <div className="stack">
      <div className="grid-2">
        <ResolveTool />
        <PropagationTool />
      </div>
      <div className="grid-2">
        <MailTool />
        <RBLTool />
      </div>
      <div className="grid-2">
        <AXFRTool />
        <SubdomainTool />
      </div>
      <SiteScanner />
    </div>
  )
}
