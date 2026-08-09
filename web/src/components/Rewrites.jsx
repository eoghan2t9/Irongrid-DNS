import { useEffect, useState, useCallback } from 'react'
import { api } from '../api'
import { useToast } from '../toast'

// Rewrites is a dedicated page for local DNS records — split out of the
// Settings mega-form since it's a full list-editing UI in its own right.
// It still round-trips the whole config object on save (there's no
// dedicated rewrites endpoint), same as Settings itself.
export default function Rewrites() {
  const toast = useToast()
  const [cfg, setCfg] = useState(null)
  const [rewrites, setRewrites] = useState([])
  const [dirty, setDirty] = useState(false)
  const [saving, setSaving] = useState(false)

  const load = useCallback(async () => {
    try {
      const c = await api.config()
      setCfg(c)
      setRewrites(c.rewrites || [])
      setDirty(false)
    } catch (e) {
      toast('Failed to load configuration: ' + e.message, 'error')
    }
  }, [toast])

  useEffect(() => { load() }, [load])

  const setRewrite = (i, patch) => {
    setRewrites((prev) => prev.map((r, x) => (x === i ? { ...r, ...patch } : r)))
    setDirty(true)
  }
  const addRewrite = () => {
    setRewrites((prev) => [...prev, { domain: '', type: 'A', value: '', ttl: 300 }])
    setDirty(true)
  }
  const removeRewrite = (i) => {
    setRewrites((prev) => prev.filter((_, x) => x !== i))
    setDirty(true)
  }

  const save = async () => {
    setSaving(true)
    try {
      await api.saveConfig({ ...cfg, rewrites })
      toast('Local DNS records saved and applied live.')
      await load()
    } catch (e) {
      toast('Save failed: ' + e.message, 'error')
    } finally {
      setSaving(false)
    }
  }

  if (!cfg) return <div className="loading">Loading…</div>

  return (
    <div className="stack">
      <div className="card">
        <div className="row-between">
          <h3 style={{ margin: 0 }}>Local DNS records</h3>
          <div className="row">
            {dirty && <span className="dim small">unsaved changes</span>}
            <button className="btn primary" onClick={save} disabled={saving || !dirty}>
              {saving ? 'Saving…' : 'Save & apply'}
            </button>
          </div>
        </div>
        <p className="dim small">
          Answer a domain yourself instead of forwarding it — e.g. <code>nas.home</code> → <code>192.168.1.10</code>.
          Takes priority over blocklists and the cache. Domain may start with <code>*.</code> to cover a whole
          subtree; a CNAME rule answers any query type. Applied live — no restart needed.
        </p>
      </div>

      <div className="card">
        {rewrites.length === 0 && <div className="empty">No local DNS records yet.</div>}
        {rewrites.map((rw, i) => (
          <div className="blocklist-row" key={i}>
            <div className="list-row">
              <input
                className="input mono"
                placeholder="domain (e.g. nas.home or *.internal.example.com)"
                value={rw.domain || ''}
                onChange={(e) => setRewrite(i, { domain: e.target.value })}
              />
              <select className="input" value={rw.type || 'A'} onChange={(e) => setRewrite(i, { type: e.target.value })} aria-label="Record type">
                <option value="A">A</option>
                <option value="AAAA">AAAA</option>
                <option value="CNAME">CNAME</option>
              </select>
            </div>
            <div className="list-row">
              <input
                className="input mono"
                placeholder="value (IP or hostname)"
                value={rw.value || ''}
                onChange={(e) => setRewrite(i, { value: e.target.value })}
              />
              <input
                className="input"
                type="number"
                placeholder="TTL (s)"
                value={rw.ttl || 300}
                onChange={(e) => setRewrite(i, { ttl: Number(e.target.value) })}
                aria-label="TTL in seconds"
              />
              <button className="btn small danger" type="button" onClick={() => removeRewrite(i)} aria-label={`Remove ${rw.domain || 'this record'}`}>✕</button>
            </div>
          </div>
        ))}
        <div className="quick-actions" style={{ marginTop: 12 }}>
          <button className="btn small" type="button" onClick={addRewrite}>+ Add record</button>
        </div>
      </div>
    </div>
  )
}
