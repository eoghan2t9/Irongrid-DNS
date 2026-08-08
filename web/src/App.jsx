import React, { useEffect, useState, useCallback, lazy, Suspense } from 'react'
import { api, setAuthHandler, setCredentials, restoreCredentials, hasCredentials, clearCredentials } from './api'
// Dashboard and UpdateChecker stay in the initial bundle: Dashboard is the
// landing view (the first paint needs it eagerly) and UpdateChecker is tiny
// and rendered in the topbar on every view. Every other view lazy-loads its
// own chunk on first visit, so the initial payload stays small.
import Dashboard from './components/Dashboard'
import UpdateChecker from './components/UpdateChecker'
const QueryLog = lazy(() => import('./components/QueryLog'))
const Blocklists = lazy(() => import('./components/Blocklists'))
const Lists = lazy(() => import('./components/Lists'))
const Rewrites = lazy(() => import('./components/Rewrites'))
const Tools = lazy(() => import('./components/Tools'))
const ClientGroups = lazy(() => import('./components/ClientGroups'))
const Tunnel = lazy(() => import('./components/Tunnel'))
const Settings = lazy(() => import('./components/Settings'))
const Tls = lazy(() => import('./components/Tls'))
const Changelog = lazy(() => import('./components/Changelog'))

// navSvg wraps every nav icon in the same stroke-only SVG shell (matching
// the logout icon below) so they inherit color via currentColor — no glyph
// can render as a colorful emoji regardless of the viewer's font/platform,
// unlike the previous Unicode symbols (a lock emoji kept rendering in color
// even with the U+FE0E text-presentation selector on some browsers).
function navSvg(children) {
  return (
    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      {children}
    </svg>
  )
}

const NAV = [
  {
    id: 'dashboard', label: 'Dashboard',
    icon: navSvg(<><rect x="3" y="3" width="7" height="7" rx="1" /><rect x="14" y="3" width="7" height="7" rx="1" /><rect x="3" y="14" width="7" height="7" rx="1" /><rect x="14" y="14" width="7" height="7" rx="1" /></>),
  },
  {
    id: 'log', label: 'Query Log',
    icon: navSvg(<><line x1="8" y1="6" x2="21" y2="6" /><line x1="8" y1="12" x2="21" y2="12" /><line x1="8" y1="18" x2="21" y2="18" /><line x1="3" y1="6" x2="3.01" y2="6" /><line x1="3" y1="12" x2="3.01" y2="12" /><line x1="3" y1="18" x2="3.01" y2="18" /></>),
  },
  {
    id: 'blocklists', label: 'Blocklists',
    icon: navSvg(<path d="M12 2 20 6v6c0 5-3.5 8.5-8 10-4.5-1.5-8-5-8-10V6z" />),
  },
  {
    id: 'lists', label: 'Allow / Block',
    icon: navSvg(<><circle cx="12" cy="12" r="9" /><path d="M8 12.5l2.5 2.5 5.5-6" /></>),
  },
  {
    id: 'rewrites', label: 'Local DNS',
    icon: navSvg(<><path d="M12 21s-7-6.5-7-11a7 7 0 1 1 14 0c0 4.5-7 11-7 11z" /><circle cx="12" cy="10" r="2.5" /></>),
  },
  {
    id: 'tools', label: 'DNS Tools',
    icon: navSvg(<path d="M14.7 6.3a1 1 0 0 0 0 1.4l1.6 1.6a1 1 0 0 0 1.4 0l3.77-3.77a6 6 0 0 1-7.94 7.94l-6.91 6.91a2.12 2.12 0 0 1-3-3l6.91-6.91a6 6 0 0 1 7.94-7.94l-3.76 3.76z" />),
  },
  {
    id: 'client-groups', label: 'Client Groups',
    icon: navSvg(<><circle cx="9" cy="8" r="3" /><path d="M2.5 20c0-3.3 3-5.5 6.5-5.5s6.5 2.2 6.5 5.5" /><circle cx="17" cy="8.5" r="2.2" /><path d="M15.7 13.3c2.3.5 4.1 2.2 4.1 4.7" /></>),
  },
  {
    id: 'tls', label: 'SSL / TLS',
    icon: navSvg(<><rect x="5" y="11" width="14" height="9" rx="1.5" /><path d="M8 11V8a4 4 0 0 1 8 0v3" /></>),
  },
  {
    id: 'tunnel', label: 'Tunnel',
    icon: navSvg(<><line x1="6" y1="18" x2="18" y2="6" /><polyline points="9 6 18 6 18 15" /></>),
  },
  {
    id: 'changelog', label: 'Changelog',
    icon: navSvg(<><circle cx="12" cy="12" r="9" /><polyline points="12 7 12 12 15.5 14" /></>),
  },
  {
    id: 'settings', label: 'Settings',
    icon: navSvg(<><circle cx="12" cy="12" r="3" /><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 1 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82A1.65 1.65 0 0 0 3 13.09H3a2 2 0 1 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 1 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 1 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z" /></>),
  },
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
          {/* Suspense shows the spinner while a lazy view's chunk is being
              fetched; the shell (sidebar/topbar) stays rendered, so switching
              views never blanks the page or causes a layout jump. The error
              boundary turns a failed chunk fetch (flaky network mid-
              navigation) into a friendly reload button instead of a blank
              screen — React.lazy caches the rejection, so retrying in place
              can't re-fetch; a page reload is the honest recovery. */}
          <ViewErrorBoundary>
            <Suspense fallback={<ViewLoading />}>
              {view === 'dashboard' && <Dashboard onNavigate={navigate} />}
              {view === 'log' && <QueryLog />}
              {view === 'blocklists' && <Blocklists />}
              {view === 'lists' && <Lists />}
              {view === 'rewrites' && <Rewrites />}
              {view === 'tools' && <Tools />}
              {view === 'client-groups' && <ClientGroups />}
              {view === 'tls' && <Tls />}
              {view === 'tunnel' && <Tunnel />}
              {view === 'changelog' && <Changelog />}
              {view === 'settings' && <Settings onSessionInvalidated={handleSessionInvalidated} />}
            </Suspense>
          </ViewErrorBoundary>
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

// Shown briefly while a lazy-loaded view's chunk downloads. It keeps the
// content area's height stable so the shell doesn't jump between views.
function ViewLoading() {
  return (
    <div className="view-loading" role="status" aria-live="polite">
      <span className="view-spinner" />
    </div>
  )
}

// Catches render errors in the view area — most importantly a failed lazy
// chunk load, which would otherwise unmount the whole app to a blank screen.
class ViewErrorBoundary extends React.Component {
  constructor(props) {
    super(props)
    this.state = { failed: false }
  }
  static getDerivedStateFromError() {
    return { failed: true }
  }
  componentDidCatch(err) {
    console.error('view render error:', err)
  }
  render() {
    if (this.state.failed) {
      return (
        <div className="view-loading view-error" role="alert">
          <div>This view failed to load.</div>
          <button className="btn ghost small" onClick={() => window.location.reload()}>
            Reload
          </button>
        </div>
      )
    }
    return this.props.children
  }
}

function Login({ onLogin, notice }) {
  const [user, setUser] = useState('admin')
  const [pass, setPass] = useState('')
  const [err, setErr] = useState('')

  const submit = async (e) => {
    e.preventDefault()
    try {
      await onLogin(user, pass)
    } catch (err) {
      // A plain 401 throws the sentinel message "unauthorized" — keep the
      // friendlier generic copy for that case, but surface anything more
      // specific (e.g. the login-lockout message) as-is.
      setErr(err.message && err.message !== 'unauthorized' ? err.message : 'Invalid credentials')
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
