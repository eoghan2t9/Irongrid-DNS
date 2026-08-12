import { useEffect, useState, useCallback } from 'react'
import { api } from '../api'
import { useToast } from '../toast'
import { EmptyState } from './ui'

const PRESETS = [
  { name: 'OISD Big (comprehensive)', url: 'https://big.oisd.nl/', enabled: true },
  { name: 'StevenBlack hosts', url: 'https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts', enabled: true },
  {
    name: 'AdGuard DNS filter',
    url: 'https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt',
    enabled: true,
  },
  { name: 'EasyList', url: 'https://easylist.to/easylist/easylist.txt', enabled: true },
]

const fmtWhen = (t) => (t ? new Date(t).toLocaleString([], { hour12: false }) : 'never')

export default function Blocklists() {
  const toast = useToast()
  const [lists, setLists] = useState([])
  const [presets, setPresets] = useState([])
  const [busy, setBusy] = useState(false)
  const [adding, setAdding] = useState(false)
  const [form, setForm] = useState({ id: '', name: '', url: '', enabled: true })
  const [search, setSearch] = useState('')
  const [category, setCategory] = useState('all')

  const load = useCallback(async () => {
    const res = await api.lists()
    setLists(res.lists || [])
  }, [])

  useEffect(() => {
    load()
  }, [load])

  useEffect(() => {
    api
      .catalog()
      .then((c) => setPresets(c.blocklists || []))
      .catch(() => {
        /* keep hardcoded PRESETS fallback */
      })
  }, [])

  const toggle = async (id, enabled) => {
    const l = lists.find((x) => x.spec.id === id)
    try {
      await api.updateList(id, { id: l.spec.id, name: l.spec.name, url: l.spec.url, enabled })
      load()
    } catch (e) {
      toast('Failed to update: ' + e.message, 'error')
    }
  }

  const remove = async (id) => {
    if (!confirm('Remove this blocklist?')) return
    try {
      await api.deleteList(id)
      load()
    } catch (e) {
      toast('Failed to remove: ' + e.message, 'error')
    }
  }

  const refreshAll = async () => {
    setBusy(true)
    try {
      await api.refreshLists()
      toast('All lists updated')
    } catch (e) {
      toast('Update failed: ' + e.message, 'error')
    }
    setBusy(false)
    load()
  }

  const addPreset = async (p) => {
    if (lists.some((l) => l.spec.id === p.id)) return
    setBusy(true)
    try {
      await api.addList({ id: p.id, name: p.name, url: p.url, enabled: true })
      await api.refreshList(p.id)
      toast(`Added "${p.name}"`)
      load()
    } catch (e) {
      toast('Failed: ' + e.message, 'error')
    }
    setBusy(false)
  }

  const submit = async (e) => {
    e.preventDefault()
    if (!form.id || !form.url) {
      toast('ID and URL are required', 'error')
      return
    }
    try {
      await api.addList(form)
      setAdding(false)
      setForm({ id: '', name: '', url: '', enabled: true })
      await api.refreshList(form.id)
      toast('List added and loaded')
      load()
    } catch (err) {
      toast('Failed: ' + err.message, 'error')
    }
  }

  return (
    <div className="stack">
      <div className="card">
        <div className="row-between">
          <h3>
            Active blocklists ({lists.filter((l) => l.spec.enabled).length}/{lists.length})
          </h3>
          <div className="row">
            <button className="btn ghost" onClick={load} aria-label="Refresh blocklist status">
              ⟳
            </button>
            <button className="btn" onClick={refreshAll} disabled={busy}>
              {busy ? 'Updating…' : 'Update all'}
            </button>
            <button className="btn primary" onClick={() => setAdding(!adding)}>
              {adding ? 'Cancel' : '+ Add list'}
            </button>
          </div>
        </div>
      </div>

      {adding && (
        <div className="card">
          <h3>Add blocklist</h3>
          <form onSubmit={submit} className="form-grid">
            <input
              className="input"
              placeholder="ID (e.g. oisd)"
              value={form.id}
              onChange={(e) => setForm({ ...form, id: e.target.value })}
            />
            <input
              className="input"
              placeholder="Name (e.g. OISD Big)"
              value={form.name}
              onChange={(e) => setForm({ ...form, name: e.target.value })}
            />
            <input
              className="input span-2"
              placeholder="URL or file:// path"
              value={form.url}
              onChange={(e) => setForm({ ...form, url: e.target.value })}
            />
            <button className="btn primary" type="submit">
              Add &amp; fetch
            </button>
          </form>
          <p className="field-hint" style={{ marginTop: -4 }}>
            All lists share the auto-update interval set in Settings → Filtering.
          </p>
          <div className="presets">
            <span className="dim">Quick add:</span>
            {(presets.length ? presets : PRESETS).map((p) => (
              <button
                key={p.url}
                className="btn ghost small"
                title={p.description || p.name}
                onClick={() =>
                  setForm({
                    id: p.id || slug(p.name),
                    name: p.name,
                    url: p.url,
                    enabled: true,
                  })
                }
              >
                {p.name.split(' ')[0]}
              </button>
            ))}
          </div>
        </div>
      )}

      {(presets.length ? presets : PRESETS).length > 0 &&
        (() => {
          const all = presets.length ? presets : PRESETS
          const categories = ['all', ...Array.from(new Set(all.map((p) => p.category).filter(Boolean))).sort()]
          const q = search.trim().toLowerCase()
          const filtered = all.filter((p) => {
            if (category !== 'all' && p.category !== category) return false
            if (!q) return true
            return p.name.toLowerCase().includes(q) || (p.description || '').toLowerCase().includes(q)
          })
          return (
            <div className="card">
              <h3>Pre-made blocklists</h3>
              <p className="dim small">
                One click adds a curated blocklist and starts fetching it. Already-added lists are skipped.
              </p>
              <div className="preset-filters">
                <input
                  className="input"
                  placeholder="Search name or description…"
                  value={search}
                  onChange={(e) => setSearch(e.target.value)}
                />
                {categories.length > 1 && (
                  <div className="filter-chips">
                    {categories.map((c) => (
                      <button
                        key={c}
                        className={`btn small ghost ${category === c ? 'active' : ''}`}
                        onClick={() => setCategory(c)}
                      >
                        {c}
                      </button>
                    ))}
                  </div>
                )}
              </div>
              <div className="preset-list">
                {filtered.map((p) => {
                  const id = p.id || slug(p.name)
                  const added = lists.some((l) => l.spec.id === id)
                  return (
                    <div className={`preset-row ${added ? 'added' : ''}`} key={p.url}>
                      <div className="preset-info">
                        <div className="preset-name">
                          {p.name}
                          {p.category && <span className="chip">{p.category}</span>}
                        </div>
                        {p.description && <div className="preset-desc">{p.description}</div>}
                      </div>
                      <button className="btn small" disabled={added} onClick={() => addPreset({ ...p, id })}>
                        {added ? '✓ Added' : '+ Add'}
                      </button>
                    </div>
                  )
                })}
                {filtered.length === 0 && <div className="empty">No presets match "{search}".</div>}
              </div>
            </div>
          )
        })()}

      <div className="card table-card">
        {lists.length === 0 ? (
          <EmptyState
            icon={
              <svg
                width="20"
                height="20"
                viewBox="0 0 24 24"
                fill="none"
                stroke="currentColor"
                strokeWidth="1.8"
                strokeLinecap="round"
                strokeLinejoin="round"
                aria-hidden="true"
              >
                <path d="M12 2 20 6v6c0 5-3.5 8.5-8 10-4.5-1.5-8-5-8-10V6z" />
              </svg>
            }
            title="No blocklists configured"
            body="Ad blocking starts with a curated list — pick one above or paste your own URL, and Irongrid fetches it on a schedule."
            action="Add a blocklist"
            onAction={() => setAdding(true)}
          />
        ) : (
          <table className="table">
            <thead>
              <tr>
                <th>Enabled</th>
                <th>Name / ID</th>
                <th>Source</th>
                <th>Rules</th>
                <th>Last updated</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {lists.map((l) => {
                const s = l.spec
                return (
                  <tr key={s.id} className={s.enabled ? '' : 'row-dim'}>
                    <td>
                      <label className="switch">
                        <input
                          type="checkbox"
                          checked={s.enabled}
                          onChange={(e) => toggle(s.id, e.target.checked)}
                          aria-label={`Enable ${s.name || s.id}`}
                        />
                        <span className="slider" />
                      </label>
                    </td>
                    <td>
                      <div className="strong">{s.name || s.id}</div>
                      <div className="dim small mono">{s.id}</div>
                    </td>
                    <td className="mono small" title={s.url}>
                      {truncate(s.url, 42)}
                    </td>
                    <td className="mono">{l.rule_count ?? 0}</td>
                    <td className="dim small">{fmtWhen(l.last_fetched)}</td>
                    <td>
                      <div className="row">
                        <button
                          className="btn ghost small"
                          onClick={() =>
                            api
                              .refreshList(s.id)
                              .then(load)
                              .catch((e) => toast(`Failed to update "${s.name || s.id}": ` + e.message, 'error'))
                          }
                        >
                          Update
                        </button>
                        <button
                          className="btn danger ghost small"
                          onClick={() => remove(s.id)}
                          aria-label={`Remove ${s.name || s.id}`}
                        >
                          ✕
                        </button>
                      </div>
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        )}
      </div>

      <div className="card hint-card">
        <h3>Supported formats</h3>
        <p className="dim">
          Hosts files (<code>0.0.0.0 domain</code>), Adblock syntax (<code>||domain^</code>, <code>@@||allow^</code>),
          plain domains, wildcards (<code>*.domain</code>), and bare IP rules. Whitelist exceptions inside lists are
          honoured, and the Allow list in the next tab always overrides blocklists.
        </p>
      </div>
    </div>
  )
}

const slug = (s) =>
  s
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-|-$/g, '')
    .slice(0, 40)
const truncate = (s, n) => (s && s.length > n ? s.slice(0, n) + '…' : s)
