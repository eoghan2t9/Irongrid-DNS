import React, { useEffect, useState, useCallback } from 'react'
import { api, setAuthHandler, setCredentials, restoreCredentials, hasCredentials, clearCredentials } from './api'
import Dashboard from './components/Dashboard'
import QueryLog from './components/QueryLog'
import Blocklists from './components/Blocklists'
import Lists from './components/Lists'
import Tunnel from './components/Tunnel'
import Settings from './components/Settings'
import Tls from './components/Tls'
import UpdateChecker from './components/UpdateChecker'
import Changelog from './components/Changelog'

const NAV = [
  { id: 'dashboard', label: 'Dashboard', icon: '◧' },
  { id: 'log', label: 'Query Log', icon: '≡' },
  { id: 'blocklists', label: 'Blocklists', icon: '▤' },
  { id: 'lists', label: 'Allow / Block', icon: '✓' },
  { id: 'tls', label: 'SSL / TLS', icon: '🔒' },
  { id: 'tunnel', label: 'Tunnel', icon: '↗' },
  { id: 'changelog', label: 'Changelog', icon: '✦' },
  { id: 'settings', label: 'Settings', icon: '⚙' },
]

export default function App() {
  const [view, setView] = useState('dashboard')
  const [status, setStatus] = useState(null)
  const [authed, setAuthed] = useState(hasCredentials())
  const [showLogin, setShowLogin] = useState(!hasCredentials())
  const [navOpen, setNavOpen] = useState(false)
  const [loginNotice, setLoginNotice] = useState('')

  const navigate = (id) => {
    setView(id)
    setNavOpen(false)
  }

  const refreshStatus = useCallback(async () => {
    try {
      const s = await api.status()
      setStatus(s)
      setAuthed(true)
    } catch (e) {
      /* not authed yet */
    }
  }, [])

  useEffect(() => {
    setAuthHandler(() => setShowLogin(true))
    restoreCredentials()
    if (hasCredentials()) refreshStatus()
  }, [refreshStatus])

  const handleLogin = async (user, pass) => {
    setCredentials(user, pass)
    // Direct call so a wrong password surfaces an error on the login form.
    await api.status()
    setAuthed(true)
    setShowLogin(false)
    setLoginNotice('')
  }

  // Best-effort server-side cookie clear, then drop local credentials.
  const handleLogout = async () => {
    try {
      await api.logout()
    } catch {
      /* cookie may already be invalid — local clear still logs out */
    }
    clearCredentials()
    setAuthed(false)
    setShowLogin(true)
  }

  // Called by Settings after a successful password/username change: the server
  // rotated the session secret (or the cookie is now bound to the wrong
  // username), so every old session cookie — including this one — is dead.
  // Sign out locally and ask the user to sign in again.
  const handleSessionInvalidated = (message) => {
    clearCredentials()
    setAuthed(false)
    setLoginNotice(message || 'Your sign-in details changed — all sessions were signed out. Please sign in again.')
    setShowLogin(true)
  }

  if (showLogin) return <Login onLogin={handleLogin} notice={loginNotice} />

  return (
    <div className="shell">
      <aside className={`sidebar ${navOpen ? 'open' : ''}`}>
        <div className="brand">
          <div className="brand-mark">◈</div>
          <div>
            <div className="brand-name">Irongrid DNS</div>
            <div className="brand-sub">self-hosted · private</div>
          </div>
        </div>
        <nav className="nav">
          {NAV.map((n) => (
            <button
              key={n.id}
              className={`nav-item ${view === n.id ? 'active' : ''}`}
              onClick={() => {
                navigate(n.id)
                setNavOpen(false)
              }}
            >
              <span className="nav-icon">{n.icon}</span>
              {n.label}
            </button>
          ))}
        </nav>
        <div className="sidebar-foot">
          {status && (
            <>
              <div className="status-row">
                <span className={`dot ${status.cache_ok ? 'ok' : 'bad'}`} />
                Cache: {status.cache_ok ? 'online' : 'offline'}
              </div>
              <div className="status-row">
                <span className={`dot ${status.tunnel?.running ? 'ok' : 'idle'}`} />
                Tunnel: {status.tunnel?.running ? 'running' : 'stopped'}
              </div>
              <div className="status-row subtle">{status.version}</div>
            </>
          )}
        </div>
      </aside>
      {navOpen && <div className="sidebar-backdrop" onClick={() => setNavOpen(false)} />}
      <main className="main">
        <header className="topbar">
          <div className="topbar-left">
            <button className="menu-btn" onClick={() => setNavOpen(true)} aria-label="Open navigation">
              ☰
            </button>
            <div className="topbar-title">{NAV.find((n) => n.id === view)?.label}</div>
          </div>
          <div className="topbar-actions">
            <UpdateChecker onNavigate={navigate} />
            <button className="btn ghost small" onClick={refreshStatus}>
              ⟳ Refresh
            </button>
            <button className="btn ghost small danger" onClick={handleLogout} title="Sign out">
              ⏻ Log out
            </button>
          </div>
        </header>
        <div className="content">
          {view === 'dashboard' && <Dashboard onNavigate={navigate} />}
          {view === 'log' && <QueryLog />}
          {view === 'blocklists' && <Blocklists />}
          {view === 'lists' && <Lists />}
          {view === 'tls' && <Tls />}
          {view === 'tunnel' && <Tunnel />}
          {view === 'changelog' && <Changelog />}
          {view === 'settings' && <Settings onSessionInvalidated={handleSessionInvalidated} />}
        </div>
      </main>
    </div>
  )
}

function Login({ onLogin, notice }) {
  const [user, setUser] = useState('admin')
  const [pass, setPass] = useState('')
  const [err, setErr] = useState('')

  const submit = async (e) => {
    e.preventDefault()
    try {
      await onLogin(user, pass)
    } catch {
      setErr('Invalid credentials')
    }
  }

  return (
    <div className="login-wrap">
      <form className="login-card" onSubmit={submit}>
        <div className="login-logo">◈</div>
        <h1>Irongrid DNS</h1>
        <p className="login-sub">Sign in to manage your DNS blocker</p>
        {notice && <div className="info-banner">{notice}</div>}
        <input
          className="input"
          placeholder="Username"
          value={user}
          onChange={(e) => setUser(e.target.value)}
          autoFocus
        />
        <input
          className="input"
          placeholder="Password"
          type="password"
          value={pass}
          onChange={(e) => setPass(e.target.value)}
        />
        {err && <div className="error-text">{err}</div>}
        <button className="btn primary block" type="submit">
          Sign in
        </button>
      </form>
    </div>
  )
}
