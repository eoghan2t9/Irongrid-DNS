import React, { useEffect, useState, useCallback } from 'react'
import { api } from '../api'

const PRESETS = [
  { name: 'OISD Big (comprehensive)', url: 'https://big.oisd.nl/', enabled: true, auto_update_hours: 24 },
  { name: 'StevenBlack hosts', url: 'https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts', enabled: true, auto_update_hours: 168 },
  { name: 'AdGuard DNS filter', url: 'https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt', enabled: true, auto_update_hours: 168 },
  { name: 'EasyList', url: 'https://easylist.to/easylist/easylist.txt', enabled: true, auto_update_hours: 168 },
]

const fmtWhen = (t) => (t ? new Date(t).toLocaleString([], { hour12: false }) : 'never')

export default function Blocklists() {
  const [lists, setLists] = useState([])
  const [busy, setBusy] = useState(false)
  const [adding, setAdding] = useState(false)
  const [form, setForm] = useState({ id: '', name: '', url: '', enabled: true, auto_update_hours: 24 })
  const [msg, setMsg] = useState('')

  const load = useCallback(async () => {
    const res = await api.lists()
    setLists(res.lists || [])
  }, [])

  useEffect(() => { load() }, [load])

  const toggle = async (id, enabled) => {
    const l = lists.find((x) => x.spec.id === id)
    await api.updateList(id, { id: l.spec.id, name: l.spec.name, url: l.spec.url, enabled, auto_update_hours: hoursOf(l.spec.auto_update) })
    load()
  }

  const remove = async (id) => {
    if (!confirm('Remove this blocklist?')) return
    await api.deleteList(id)
    load()
  }

  const refreshAll = async () => {
    setBusy(true); setMsg('Updating lists…')
    try {
      await api.refreshLists()
      setMsg('All lists updated')
    } catch (e) { setMsg('Update failed: ' + e.message) }
    setBusy(false)
    load()
  }

  const submit = async (e) => {
    e.preventDefault()
    if (!form.id || !form.url) { setMsg('ID and URL are required'); return }
    try {
      await api.addList(form)
      setAdding(false)
      setForm({ id: '', name: '', url: '', enabled: true, auto_update_hours: 24 })
      setMsg('List added — fetching content…')
      await api.refreshList(form.id)
      setMsg('List added and loaded')
      load()
    } catch (err) { setMsg('Failed: ' + err.message) }
  }

  return (
    <div className="stack">
      {msg && <div className="info-banner">{msg}</div>}

      <div className="card">
        <div className="row-between">
          <h3>Active blocklists ({lists.filter((l) => l.spec.enabled).length}/{lists.length})</h3>
          <div className="row">
            <button className="btn ghost" onClick={load}>⟳</button>
            <button className="btn" onClick={refreshAll} disabled={busy}>{busy ? 'Updating…' : 'Update all'}</button>
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
            <input className="input" placeholder="ID (e.g. oisd)" value={form.id} onChange={(e) => setForm({ ...form, id: e.target.value })} />
            <input className="input" placeholder="Name (e.g. OISD Big)" value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} />
            <input className="input span-2" placeholder="URL or file:// path" value={form.url} onChange={(e) => setForm({ ...form, url: e.target.value })} />
            <label className="input-label">Auto update
              <select className="input" value={form.auto_update_hours} onChange={(e) => setForm({ ...form, auto_update_hours: +e.target.value })}>
                <option value={0}>Never</option>
                <option value={6}>Every 6 hours</option>
                <option value={24}>Daily</option>
                <option value={168}>Weekly</option>
              </select>
            </label>
            <button className="btn primary" type="submit">Add &amp; fetch</button>
          </form>
          <div className="presets">
            <span className="dim">Quick add:</span>
            {PRESETS.map((p) => (
              <button
                key={p.url}
                className="btn ghost small"
                onClick={() => setForm({ id: slug(p.name), name: p.name, url: p.url, enabled: true, auto_update_hours: p.auto_update_hours })}
              >
                {p.name.split(' ')[0]}
              </button>
            ))}
          </div>
        </div>
      )}

      <div className="card table-card">
        <table className="table">
          <thead>
            <tr>
              <th>Enabled</th>
              <th>Name / ID</th>
              <th>Source</th>
              <th>Rules</th>
              <th>Last updated</th>
              <th>Auto</th>
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
                      <input type="checkbox" checked={s.enabled} onChange={(e) => toggle(s.id, e.target.checked)} />
                      <span className="slider" />
                    </label>
                  </td>
                  <td>
                    <div className="strong">{s.name || s.id}</div>
                    <div className="dim small mono">{s.id}</div>
                  </td>
                  <td className="mono small" title={s.url}>{truncate(s.url, 42)}</td>
                  <td className="mono">{l.rule_count ?? 0}</td>
                  <td className="dim small">{fmtWhen(l.last_fetched)}</td>
                  <td>{s.auto_update > 0 ? `${hoursOf(s.auto_update)}h` : '—'}</td>
                  <td>
                    <div className="row">
                      <button className="btn ghost small" onClick={() => api.refreshList(s.id).then(load)}>Update</button>
                      <button className="btn danger ghost small" onClick={() => remove(s.id)}>✕</button>
                    </div>
                  </td>
                </tr>
              )
            })}
            {lists.length === 0 && (
              <tr><td colSpan={7} className="empty">No blocklists configured. Add one to start blocking.</td></tr>
            )}
          </tbody>
        </table>
      </div>

      <div className="card hint-card">
        <h3>Supported formats</h3>
        <p className="dim">
          Hosts files (<code>0.0.0.0 domain</code>), Adblock syntax (<code>||domain^</code>, <code>@@||allow^</code>),
          plain domains, wildcards (<code>*.domain</code>), and bare IP rules. Whitelist exceptions inside lists are honoured,
          and the Allow list in the next tab always overrides blocklists.
        </p>
      </div>
    </div>
  )
}

const hoursOf = (v) => (v ? Math.round(v / 3.6e12) : 0) // nanoseconds -> hours
const slug = (s) => s.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '').slice(0, 40)
const truncate = (s, n) => (s && s.length > n ? s.slice(0, n) + '…' : s)
