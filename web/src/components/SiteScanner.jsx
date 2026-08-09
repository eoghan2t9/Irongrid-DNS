import { useEffect, useState } from 'react'
import { api } from '../api'
import { useToast } from '../toast'

// SiteScanner scans a page's HTML for every domain it references and flags the
// ones the current blocklists are blocking, so a broken site can be fixed by
// whitelisting the offending domains. Shared by the Lists and Tools pages.
//
// It keeps its own copy of the allow list so rows that are already whitelisted
// (from a previous scan or elsewhere) show as ✓ Allowed and are excluded from
// "Allow all". onAllowed fires after any successful whitelist add so a parent
// page (the Lists page) can reload its own lists.
export default function SiteScanner({ onAllowed }) {
  const toast = useToast()
  const [site, setSite] = useState('')
  const [busy, setBusy] = useState(false)
  const [result, setResult] = useState(null)
  const [error, setError] = useState('')
  const [allowed, setAllowed] = useState({})
  const [whitelist, setWhitelist] = useState([])

  const loadWhitelist = async () => {
    try {
      const w = await api.getFilterList('whitelist')
      setWhitelist(w.whitelist || [])
    } catch {
      /* the scanner still works without the allow list; just no ✓ state */
    }
  }

  useEffect(() => { loadWhitelist() }, [])

  const scanSite = async (e) => {
    e.preventDefault()
    if (!site.trim()) return
    setBusy(true)
    setError('')
    setResult(null)
    setAllowed({})
    // Refresh the allow list so rows already whitelisted elsewhere (e.g. the
    // Lists page's own Add-entry form) show as ✓ Allowed right away.
    loadWhitelist()
    try {
      setResult(await api.siteCheck(site.trim()))
    } catch (err) {
      setError(err.message)
    }
    setBusy(false)
  }

  const allowSiteDomain = async (d) => {
    try {
      await api.addFilterEntry('whitelist', d)
      setAllowed((s) => ({ ...s, [d]: true }))
      toast(`Allowed "${d}"`)
      loadWhitelist()
      if (onAllowed) onAllowed()
    } catch (e) {
      toast('Failed to allow: ' + e.message, 'error')
    }
  }

  const allowAllSiteDomains = async () => {
    const ok = []
    for (const d of blockedDomains) {
      try {
        await api.addFilterEntry('whitelist', d)
        ok.push(d)
      } catch (e) {
        toast(`Failed to allow "${d}": ` + e.message, 'error')
      }
    }
    // Only the successfully added domains get marked allowed — a partial
    // failure must not paint the failed rows as fixed.
    if (ok.length) {
      toast(`Allowed ${ok.length} blocked domain${ok.length === 1 ? '' : 's'}`)
    }
    setAllowed((s) => {
      const n = { ...s }
      ok.forEach((d) => { n[d] = true })
      return n
    })
    loadWhitelist()
    if (onAllowed) onAllowed()
  }

  // Domains still blocked that we haven't whitelisted yet (this scan or in the
  // loaded allow list) — what "Allow all" and the per-row button act on.
  const blockedDomains = result
    ? result.domains
        .filter((x) => x.blocked && !allowed[x.domain] && !whitelist.includes(x.domain))
        .map((x) => x.domain)
    : []
  // Blocked first, then alphabetical, so the problem rows sit on top.
  const sortedDomains = result
    ? [...result.domains].sort(
        (a, b) => (b.blocked ? 1 : 0) - (a.blocked ? 1 : 0) || a.domain.localeCompare(b.domain)
      )
    : []

  return (
    <div className="card">
      <h3>Fix a broken site</h3>
      <p className="dim small">
        A page can break when one of the domains it loads is blocked. Enter a URL and Irongrid
        scans its HTML for every domain it references, then flags the ones your blocklists are
        blocking so you can whitelist them.
      </p>
      <form onSubmit={scanSite} className="form-grid">
        <input
          className="input"
          placeholder="example.com or https://example.com"
          value={site}
          onChange={(e) => setSite(e.target.value)}
        />
        <button className="btn primary" type="submit" disabled={busy}>
          {busy ? 'Scanning…' : 'Scan site'}
        </button>
      </form>
      {error && <div className="error-banner" style={{ marginTop: 12 }}>{error}</div>}
      {result && (
        <>
          <div className="row-between" style={{ marginTop: 12 }}>
            <div className="dim small">
              {result.title && <span className="strong" style={{ color: 'var(--text)' }}>{result.title}</span>}
              {' — '}<span className="mono">{result.final_url}</span>
              <br />
              {result.total} domains found,{' '}
              <span style={{ color: result.blocked_count ? 'var(--rose)' : undefined }}>
                {result.blocked_count} blocked
              </span>
              {result.truncated && ' · page truncated at 2 MiB'}
              {' · '}{result.fetch_ms} ms
            </div>
            {blockedDomains.length > 0 && (
              <button className="btn small" onClick={allowAllSiteDomains}>
                Allow all {blockedDomains.length} blocked
              </button>
            )}
          </div>
          <div style={{ maxHeight: 360, overflowY: 'auto', marginTop: 10 }}>
            <table className="table">
              <thead>
                <tr>
                  <th>Domain</th>
                  <th>Status</th>
                  <th>Blocked by</th>
                  <th className="action-col"></th>
                </tr>
              </thead>
              <tbody>
                {sortedDomains.map((x) => {
                  const already = allowed[x.domain] || whitelist.includes(x.domain)
                  return (
                    <tr key={x.domain} className={x.blocked ? '' : 'row-dim'}>
                      <td className="entry-cell" title={x.domain}>{x.domain}</td>
                      <td>
                        <span className={`badge ${x.blocked ? 'badge-blocked' : 'badge-allowed'}`}>
                          {x.blocked ? 'Blocked' : 'Allowed'}
                        </span>
                      </td>
                      <td className="dim small">{x.blocked ? (x.list || x.reason || 'blocklist') : ''}</td>
                      <td className="action-col">
                        {x.blocked && !already && (
                          <button className="btn small" onClick={() => allowSiteDomain(x.domain)}>Allow</button>
                        )}
                        {x.blocked && already && (
                          <button className="btn small" disabled>✓ Allowed</button>
                        )}
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
