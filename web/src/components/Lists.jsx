import React, { useEffect, useState, useCallback } from 'react'
import { api } from '../api'
import { useToast } from '../toast'

const PAGE_SIZE = 50

// ListCard renders one allow/block table with client-side pagination so the
// page stays fast as the lists grow over time.
function ListCard({ k, items, onRemove }) {
  const [page, setPage] = useState(0)
  const total = items.length
  const pages = Math.max(1, Math.ceil(total / PAGE_SIZE))
  // Clamp in case the list shrank (e.g. an entry was removed) — the current
  // page may no longer exist.
  const cur = Math.min(page, pages - 1)
  const start = cur * PAGE_SIZE
  const slice = items.slice(start, start + PAGE_SIZE)
  const isAllow = k === 'whitelist'

  return (
    <div className="card">
      <div className="row-between">
        <h3 style={{ margin: 0 }}>
          {isAllow ? 'Allow list — always resolves' : 'Block list — always blocked'}
        </h3>
        <span className="chip">{total.toLocaleString()} entries</span>
      </div>
      <p className="dim small">
        {isAllow
          ? 'Domains here override every blocklist. Use it to unblock false positives.'
          : 'Manual deny entries with the same syntax as blocklists (domains, wildcards, IPs).'}
      </p>
      {total === 0 ? (
        <div className="empty">Nothing here yet.</div>
      ) : (
        <>
          <ul className="tag-list">
            {slice.map((it) => (
              <li className="tag" key={it}>
                <span className="mono">{it}</span>
                <button className="tag-x" onClick={() => onRemove(k, it)} title="Remove" aria-label={`Remove ${it}`}>✕</button>
              </li>
            ))}
          </ul>
          {pages > 1 && (
            <div className="pager">
              <button className="btn small" disabled={cur === 0} onClick={() => setPage(cur - 1)}>
                ← Prev
              </button>
              <span className="dim small">Page {cur + 1} / {pages}</span>
              <button className="btn small" disabled={cur >= pages - 1} onClick={() => setPage(cur + 1)}>
                Next →
              </button>
            </div>
          )}
        </>
      )}
    </div>
  )
}

export default function Lists() {
  const toast = useToast()
  const [whitelist, setWhitelist] = useState([])
  const [blacklist, setBlacklist] = useState([])
  const [whitelistPresets, setWhitelistPresets] = useState([])
  const [presetSearch, setPresetSearch] = useState('')
  const [entry, setEntry] = useState('')
  const [kind, setKind] = useState('whitelist')
  const [checkName, setCheckName] = useState('')
  const [checkResult, setCheckResult] = useState(null)

  const load = useCallback(async () => {
    const [w, b] = await Promise.all([api.getFilterList('whitelist'), api.getFilterList('blacklist')])
    setWhitelist(w.whitelist || [])
    setBlacklist(b.blacklist || [])
  }, [])

  useEffect(() => { load() }, [load])

  useEffect(() => {
    api.catalog()
      .then((c) => setWhitelistPresets(c.whitelists || []))
      .catch(() => {})
  }, [])

  const addPreset = async (p) => {
    const existing = new Set(whitelist)
    const fresh = (p.domains || []).filter((d) => !existing.has(d))
    if (fresh.length === 0) { toast(`"${p.name}" domains are already on the allow list.`); return }
    try {
      for (const d of fresh) await api.addFilterEntry('whitelist', d)
      toast(`Added ${fresh.length} domains from "${p.name}" to the allow list.`)
      load()
    } catch (e) {
      toast('Failed to add preset: ' + e.message, 'error')
    }
  }

  const add = async (e) => {
    e.preventDefault()
    const value = entry.trim()
    if (!value) return
    try {
      await api.addFilterEntry(kind, value)
      setEntry('')
      toast(`Added "${value}" to ${kind}`)
      load()
    } catch (err) {
      toast('Failed to add: ' + err.message, 'error')
    }
  }

  const remove = async (k, value) => {
    try {
      await api.deleteFilterEntry(k, value)
      load()
    } catch (e) {
      toast('Failed to remove: ' + e.message, 'error')
    }
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

  return (
    <div className="stack">
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

      {whitelistPresets.length > 0 && (() => {
        const q = presetSearch.trim().toLowerCase()
        const filtered = whitelistPresets.filter((p) => {
          if (!q) return true
          return p.name.toLowerCase().includes(q) || (p.description || '').toLowerCase().includes(q)
        })
        return (
          <div className="card">
            <h3>Pre-made allow lists</h3>
            <p className="dim small">One click adds a curated set of domains to the Allow list (they override every blocklist).</p>
            <div className="preset-filters">
              <input
                className="input"
                placeholder="Search name or description…"
                value={presetSearch}
                onChange={(e) => setPresetSearch(e.target.value)}
              />
            </div>
            <div className="preset-list">
              {filtered.map((p) => {
                const domains = p.domains || []
                const allAdded = domains.length > 0 && domains.every((d) => whitelist.includes(d))
                return (
                  <div className={`preset-row ${allAdded ? 'added' : ''}`} key={p.id}>
                    <div className="preset-info">
                      <div className="preset-name">
                        {p.name}
                        <span className="chip">{domains.length} domains</span>
                      </div>
                      {p.description && <div className="preset-desc">{p.description}</div>}
                    </div>
                    <button className="btn small" disabled={allAdded} onClick={() => addPreset(p)}>
                      {allAdded ? '✓ Added' : '+ Add'}
                    </button>
                  </div>
                )
              })}
              {filtered.length === 0 && <div className="empty">No presets match "{presetSearch}".</div>}
            </div>
          </div>
        )
      })()}

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
        <ListCard k="whitelist" items={whitelist} onRemove={remove} />
        <ListCard k="blacklist" items={blacklist} onRemove={remove} />
      </div>
    </div>
  )
}
