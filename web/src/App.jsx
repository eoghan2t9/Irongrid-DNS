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

// Each view maps to a real URL path (/blocklists, /tls, …) so the browser
// back/forward buttons work and links are shareable. The web server serves
// index.html as the SPA fallback for these paths.
const VALID_VIEWS = NAV.map((n) => n.id)
const viewFromPath = () => {
  const p = window.location.pathname.replace(/^\/+|\/+$/g, '')
  return VALID_VIEWS.includes(p) ? p : 'dashboard'
}

export default function App() {
  const [view, setView] = useState(viewFromPath)
  const [status, setStatus] = useState(null)
  const [authed, setAuthed] = useState(hasCredentials())
  const [showLogin, setShowLogin] = useState(!hasCredentials())
  const [navOpen, setNavOpen] = useState(false)
  const [loginNotice, setLoginNotice] = useState('')
  // True while the saved session is being verified on mount. Until it
  // resolves we render a branded splash instead of the login form or the
  // dashboard, so a refresh never flashes one over the other.
  const [initializing, setInitializing] = useState(true)

  const navigate = (id) => {
    setView(id)
    setNavOpen(false)
    // Keep the URL in sync so back/forward navigate between views. Avoid
    // pushing a duplicate entry when the path already matches (e.g. the
    // topbar title click on the same view).
    const path = id === 'dashboard' ? '/' : '/' + id
    if (window.location.pathname !== path) {
      window.history.pushState(null, '', path)
    }
  }

  // Back/forward: the URL changed without a pushState from us.
  useEffect(() => {
    const onPop = () => setView(viewFromPath())
    window.addEventListener('popstate', onPop)
    return () => window.removeEventListener('popstate', onPop)
  }, [])

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
    setAuthHandler(() => {
      setShowLogin(true)
      setInitializing(false)
    })
    restoreCredentials()
    if (hasCredentials()) {
      // Verify the saved session before revealing the app; the splash stays
      // up until the check resolves (or the 401 handler flips to login).
      refreshStatus().finally(() => setInitializing(false))
      // Bound the check: fetch has no timeout, so if the API stalls the
      // splash must still settle (revealing the app; a later 401 still
      // flips to login via the auth handler) instead of spinning forever.
      const t = setTimeout(() => setInitializing(false), 10000)
      return () => clearTimeout(t)
    }
    // No saved credentials: showLogin is already true from the initial state.
    setInitializing(false)
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

  if (initializing) return <Splash />
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
            <button className="btn ghost small danger icon" onClick={handleLogout} title="Sign out">
              <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.4" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
                <path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4" />
                <polyline points="16 17 21 12 16 7" />
                <line x1="21" y1="12" x2="9" y2="12" />
              </svg>
              Log out
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

function Splash() {
  return (
    <div className="login-wrap">
      <div className="login-card splash-card" role="status" aria-live="polite">
        <div className="login-logo logo-spin">◈</div>
        <h1>Irongrid DNS</h1>
        <p className="login-sub">Loading…</p>
      </div>
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
          name="username"
          autoComplete="username"
          autoCapitalize="none"
          autoCorrect="off"
          spellCheck={false}
          value={user}
          onChange={(e) => setUser(e.target.value)}
          autoFocus
        />
        <input
          className="input"
          placeholder="Password"
          type="password"
          name="password"
          autoComplete="current-password"
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
