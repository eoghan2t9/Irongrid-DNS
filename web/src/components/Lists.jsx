import React, { useEffect, useState, useCallback } from 'react'
import { api } from '../api'

export default function Lists() {
  const [whitelist, setWhitelist] = useState([])
  const [blacklist, setBlacklist] = useState([])
  const [entry, setEntry] = useState('')
  const [kind, setKind] = useState('whitelist')
  const [checkName, setCheckName] = useState('')
  const [checkResult, setCheckResult] = useState(null)
  const [msg, setMsg] = useState('')

  const load = useCallback(async () => {
    const [w, b] = await Promise.all([api.getFilterList('whitelist'), api.getFilterList('blacklist')])
    setWhitelist(w.whitelist || [])
    setBlacklist(b.blacklist || [])
  }, [])

  useEffect(() => { load() }, [load])

  const add = async (e) => {
    e.preventDefault()
    const value = entry.trim()
    if (!value) return
    await api.addFilterEntry(kind, value)
    setEntry('')
    setMsg(`Added "${value}" to ${kind}`)
    load()
  }

  const remove = async (k, value) => {
    await api.deleteFilterEntry(k, value)
    load()
  }

  const check = async (e) => {
    e.preventDefault()
    if (!checkName) return
    try {
      const r = await api.checkFilter(checkName)
      setCheckResult(r)
    } catch (err) {
      setCheckResult({ error: err.message })
    }
  }

  const renderList = (k, items) => (
    <div className="card">
      <h3>{k === 'whitelist' ? 'Allow list — always resolves' : 'Block list — always blocked'}</h3>
      <p className="dim small">
        {k === 'whitelist'
          ? 'Domains here override every blocklist. Use it to unblock false positives.'
          : 'Manual deny entries with the same syntax as blocklists (domains, wildcards, IPs).'}
      </p>
      {items.length === 0 ? (
        <div className="empty">Nothing here yet.</div>
      ) : (
        <ul className="tag-list">
          {items.map((it) => (
            <li className="tag" key={it}>
              <span className="mono">{it}</span>
              <button className="tag-x" onClick={() => remove(k, it)} title="Remove">✕</button>
            </li>
          ))}
        </ul>
      )}
    </div>
  )

  return (
    <div className="stack">
      {msg && <div className="info-banner">{msg}</div>}

      <div className="card">
        <h3>Add entry</h3>
        <form onSubmit={add} className="form-grid">
          <select className="input" value={kind} onChange={(e) => setKind(e.target.value)}>
            <option value="whitelist">Allow list</option>
            <option value="blacklist">Block list</option>
          </select>
          <input
            className="input"
            placeholder="example.com, *.ads.net, or 1.2.3.4"
            value={entry}
            onChange={(e) => setEntry(e.target.value)}
          />
          <button className="btn primary" type="submit">Add</button>
        </form>
      </div>

      <div className="card">
        <h3>Test a domain or IP</h3>
        <form onSubmit={check} className="form-grid">
          <input
            className="input"
            placeholder="e.g. ads.example.com"
            value={checkName}
            onChange={(e) => setCheckName(e.target.value)}
          />
          <button className="btn" type="submit">Check</button>
        </form>
        {checkResult && (
          <div className={`check-result ${checkResult.blocked ? 'check-blocked' : 'check-allowed'}`}>
            <div className="strong">
              {checkResult.domain} → {checkResult.blocked ? 'BLOCKED' : checkResult.error ? 'ERROR' : 'ALLOWED'}
            </div>
            {checkResult.reason && <div className="dim small">{checkResult.reason}</div>}
          </div>
        )}
      </div>

      <div className="grid-2">
        {renderList('whitelist', whitelist)}
        {renderList('blacklist', blacklist)}
      </div>
    </div>
  )
}
