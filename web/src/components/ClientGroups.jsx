import { useEffect, useState, useCallback } from 'react'
import { api } from '../api'
import { useToast } from '../toast-context'
import { LineListField } from './ui'

// ClientGroups is a dedicated page for per-client policy — split out of the
// Settings mega-form for the same reason as Rewrites. Round-trips the whole
// config object on save; there's no dedicated client-groups endpoint.
export default function ClientGroups() {
  const toast = useToast()
  const [cfg, setCfg] = useState(null)
  const [groups, setGroups] = useState([])
  const [dirty, setDirty] = useState(false)
  const [saving, setSaving] = useState(false)

  const load = useCallback(async () => {
    try {
      const c = await api.config()
      setCfg(c)
      setGroups(c.client_groups || [])
      setDirty(false)
    } catch (e) {
      toast('Failed to load configuration: ' + e.message, 'error')
    }
  }, [toast])

  useEffect(() => {
    load()
  }, [load])

  const setGroup = (i, patch) => {
    setGroups((prev) => prev.map((g, x) => (x === i ? { ...g, ...patch } : g)))
    setDirty(true)
  }
  const addGroup = () => {
    setGroups((prev) => [
      ...prev,
      { id: '', name: '', enabled: true, cidrs: [], blocklists: [], whitelist: [], blacklist: [], upstreams: [] },
    ])
    setDirty(true)
  }
  const removeGroup = (i) => {
    setGroups((prev) => prev.filter((_, x) => x !== i))
    setDirty(true)
  }

  const save = async () => {
    setSaving(true)
    try {
      await api.saveConfig({ ...cfg, client_groups: groups })
      toast('Client groups saved and applied live.')
      await load()
    } catch (e) {
      toast('Save failed: ' + e.message, 'error')
    } finally {
      setSaving(false)
    }
  }

  if (!cfg) return <div className="loading">Loading…</div>

  const field = (label, hint, input) => (
    <label className="field">
      <span className="field-label">{label}</span>
      {input}
      {hint && <span className="field-hint">{hint}</span>}
    </label>
  )

  return (
    <div className="stack">
      <div className="card">
        <div className="row-between">
          <h3 style={{ margin: 0 }}>Client groups</h3>
          <div className="row">
            {dirty && <span className="dim small">unsaved changes</span>}
            <button className="btn primary" onClick={save} disabled={saving || !dirty}>
              {saving ? 'Saving…' : 'Save & apply'}
            </button>
          </div>
        </div>
        <p className="dim small">
          Apply a different policy to specific devices/subnets — e.g. a kids' device group with stricter blocklists, or
          an IoT VLAN pinned to specific upstreams. The first matching group wins; clients matching none use the global
          filtering and upstreams in Settings. Leave "Blocklist IDs" empty to use every enabled global blocklist.
          Applied live — no restart needed.
        </p>
      </div>

      <div className="card">
        {groups.length === 0 && (
          <div className="empty">No client groups yet — every client uses the global policy.</div>
        )}
        {groups.map((g, i) => (
          <div className="blocklist-row" key={i}>
            <div className="list-row">
              <input
                className="input"
                placeholder="id (e.g. kids)"
                value={g.id || ''}
                onChange={(e) => setGroup(i, { id: e.target.value })}
              />
              <input
                className="input"
                placeholder="Name"
                value={g.name || ''}
                onChange={(e) => setGroup(i, { name: e.target.value })}
              />
              <label className="switch" title="Enabled">
                <input
                  type="checkbox"
                  checked={!!g.enabled}
                  onChange={(e) => setGroup(i, { enabled: e.target.checked })}
                  aria-label={`Enable group ${g.name || g.id || i + 1}`}
                />
                <span className="slider" />
              </label>
              <button
                className="btn small danger"
                type="button"
                onClick={() => removeGroup(i)}
                aria-label={`Remove group ${g.name || g.id || i + 1}`}
              >
                ✕
              </button>
            </div>
            <div className="form-grid">
              {field(
                'Client CIDRs / IPs',
                'one per line, e.g. 192.168.1.50 or 10.0.5.0/24',
                <LineListField value={g.cidrs} onChange={(v) => setGroup(i, { cidrs: v })} rows={2} />,
              )}
              {field(
                'Blocklist IDs',
                'one per line; empty = all enabled global blocklists',
                <LineListField value={g.blocklists} onChange={(v) => setGroup(i, { blocklists: v })} rows={2} />,
              )}
              {field(
                'Extra whitelist',
                'one per line, added to the global whitelist',
                <LineListField value={g.whitelist} onChange={(v) => setGroup(i, { whitelist: v })} rows={2} />,
              )}
              {field(
                'Extra blacklist',
                'one per line, added to the global blacklist',
                <LineListField value={g.blacklist} onChange={(v) => setGroup(i, { blacklist: v })} rows={2} />,
              )}
              {field(
                'Upstream override',
                'one per line, e.g. udp://1.1.1.1:53 or recursive://; empty = use the global upstreams in Settings',
                <LineListField value={g.upstreams} onChange={(v) => setGroup(i, { upstreams: v })} rows={2} />,
              )}
            </div>
          </div>
        ))}
        <div className="quick-actions" style={{ marginTop: 12 }}>
          <button className="btn small" type="button" onClick={addGroup}>
            + Add group
          </button>
        </div>
      </div>
    </div>
  )
}
