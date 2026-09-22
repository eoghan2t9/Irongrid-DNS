import { useEffect, useState, useCallback } from 'react'
import { api } from '../api'
import { useToast } from '../toast-context'
import { XIcon } from './ui'

// Users is the dashboard/API account management page — split out the same
// way ClientGroups/Rewrites are, round-tripping the whole config object on
// save (there's no dedicated users endpoint). A password field left blank
// keeps the existing hash on an edit; a brand-new row requires one.
export default function Users({ currentUsername, onSessionInvalidated }) {
  const toast = useToast()
  const [cfg, setCfg] = useState(null)
  const [users, setUsers] = useState([])
  const [dirty, setDirty] = useState(false)
  const [saving, setSaving] = useState(false)

  const load = useCallback(async () => {
    try {
      const c = await api.config()
      setCfg(c)
      setUsers(c.web?.users || [])
      setDirty(false)
    } catch (e) {
      toast('Failed to load configuration: ' + e.message, 'error')
    }
  }, [toast])

  useEffect(() => {
    load()
  }, [load])

  const setUser = (i, patch) => {
    setUsers((prev) => prev.map((u, x) => (x === i ? { ...u, ...patch } : u)))
    setDirty(true)
  }
  const addUser = () => {
    setUsers((prev) => [...prev, { id: '', username: '', password: '', role: 'viewer' }])
    setDirty(true)
  }
  const removeUser = (i) => {
    setUsers((prev) => prev.filter((_, x) => x !== i))
    setDirty(true)
  }

  const adminCount = users.filter((u) => u.role === 'admin').length
  // The server rejects a save that would leave zero admins regardless — this
  // is just an earlier, friendlier warning so the mistake is obvious before
  // a round trip (disables removing or demoting the sole remaining admin).
  const isLastAdmin = (i) => users[i].role === 'admin' && adminCount <= 1

  const save = async () => {
    setSaving(true)
    try {
      const changedOwnAccount = users.some(
        (u) => u.id && u.username === currentUsername && (u.password || u.role !== 'admin'),
      )
      await api.saveConfig({ ...cfg, web: { ...cfg.web, users } })
      // Any Users change rotates the session secret server-side, signing
      // every session out — including this one, always. See save flow in
      // handlers_config.go (rotateSecretIfUsersChanged).
      if (onSessionInvalidated) {
        onSessionInvalidated(
          changedOwnAccount
            ? 'Your account changed — all sessions were signed out. Please sign in again.'
            : 'Users changed — all sessions were signed out. Please sign in again.',
        )
        return
      }
      toast('Users saved and applied live.')
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
          <h3 style={{ margin: 0 }}>Users</h3>
          <div className="row">
            {dirty && <span className="dim small">unsaved changes</span>}
            <button className="btn primary" onClick={save} disabled={saving || !dirty}>
              {saving ? 'Saving…' : 'Save & apply'}
            </button>
          </div>
        </div>
        <p className="dim small">
          Dashboard and API accounts. <strong>Admin</strong> can do everything, including managing users.{' '}
          <strong>Viewer</strong> can see everything but can't change anything (read-only, like a read-only API token).
          Saving any change here signs every logged-in session out, including this one — sign back in afterward with the
          account you want to use.
        </p>
      </div>

      <div className="card">
        {users.length === 0 && <div className="empty">No users — add at least one admin account.</div>}
        {users.map((u, i) => (
          <div className="blocklist-row" key={i}>
            <div className="list-row">
              <input
                className="input"
                placeholder="Username"
                value={u.username || ''}
                onChange={(e) => setUser(i, { username: e.target.value })}
              />
              <input
                className="input"
                type="password"
                placeholder={u.id ? 'leave blank to keep current password' : 'Password (required)'}
                value={u.password || ''}
                onChange={(e) => setUser(i, { password: e.target.value })}
                autoComplete="new-password"
              />
              <select
                className="input"
                value={u.role || 'viewer'}
                onChange={(e) => setUser(i, { role: e.target.value })}
                disabled={isLastAdmin(i)}
                title={isLastAdmin(i) ? "Can't demote the last admin account" : undefined}
                aria-label={`Role for ${u.username || 'new user'}`}
              >
                <option value="admin">Admin</option>
                <option value="viewer">Viewer</option>
              </select>
              <button
                className="btn small danger"
                type="button"
                onClick={() => removeUser(i)}
                disabled={isLastAdmin(i)}
                title={isLastAdmin(i) ? "Can't remove the last admin account" : 'Remove user'}
                aria-label={`Remove user ${u.username || i + 1}`}
              >
                <XIcon size={12} />
              </button>
            </div>
          </div>
        ))}
        <div className="quick-actions" style={{ marginTop: 12 }}>
          <button className="btn small" type="button" onClick={addUser}>
            + Add user
          </button>
        </div>
      </div>
    </div>
  )
}
