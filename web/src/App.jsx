import React, { useEffect, useState, useCallback, useMemo, useRef, lazy, Suspense } from 'react'
import { api, setAuthHandler, setCredentials, restoreCredentials, hasCredentials, clearCredentials } from './api'
import { Kbd, Logo } from './components/ui'
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
const Dhcp = lazy(() => import('./components/Dhcp'))
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
    <svg
      width="15"
      height="15"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
    >
      {children}
    </svg>
  )
}

// NAV is grouped into labelled sections so newcomers can find features by
// what they do, not by name. Each entry carries a plain-English desc used
// for the topbar subtitle and the sidebar hover tooltip, plus search
// keywords that power the ⌘K command palette (so “adblock” finds Blocklists
// even though the label is different).
const NAV = [
  {
    id: 'dashboard',
    label: 'Dashboard',
    section: 'Overview',
    desc: 'Live overview of your network\u2019s DNS traffic and health',
    keywords: ['home', 'overview', 'stats', 'status'],
    icon: navSvg(
      <>
        <rect x="3" y="3" width="7" height="7" rx="1" />
        <rect x="14" y="3" width="7" height="7" rx="1" />
        <rect x="3" y="14" width="7" height="7" rx="1" />
        <rect x="14" y="14" width="7" height="7" rx="1" />
      </>,
    ),
  },
  {
    id: 'log',
    label: 'Query Log',
    section: 'Overview',
    desc: 'Every DNS query your server answered — searchable and filterable',
    keywords: ['history', 'queries', 'entries', 'search'],
    icon: navSvg(
      <>
        <line x1="8" y1="6" x2="21" y2="6" />
        <line x1="8" y1="12" x2="21" y2="12" />
        <line x1="8" y1="18" x2="21" y2="18" />
        <line x1="3" y1="6" x2="3.01" y2="6" />
        <line x1="3" y1="12" x2="3.01" y2="12" />
        <line x1="3" y1="18" x2="3.01" y2="18" />
      </>,
    ),
  },
  {
    id: 'blocklists',
    label: 'Blocklists',
    section: 'Ad blocking',
    desc: 'Choose curated lists that block ads, trackers and malware',
    keywords: ['ads', 'adblock', 'filter', 'trackers', 'lists', 'oisd', 'easylist'],
    icon: navSvg(<path d="M12 2 20 6v6c0 5-3.5 8.5-8 10-4.5-1.5-8-5-8-10V6z" />),
  },
  {
    id: 'lists',
    label: 'Allow / Block',
    section: 'Ad blocking',
    desc: 'Always-allow or always-block specific domains yourself',
    keywords: ['allow', 'block', 'whitelist', 'blacklist', 'deny', 'unblock'],
    icon: navSvg(
      <>
        <circle cx="12" cy="12" r="9" />
        <path d="M8 12.5l2.5 2.5 5.5-6" />
      </>,
    ),
  },
  {
    id: 'rewrites',
    label: 'Local DNS',
    section: 'Ad blocking',
    desc: 'Answer local names yourself, like printer.lan or media-server.local',
    keywords: ['local', 'hosts', 'lan', 'records', 'rewrite'],
    icon: navSvg(
      <>
        <path d="M12 21s-7-6.5-7-11a7 7 0 1 1 14 0c0 4.5-7 11-7 11z" />
        <circle cx="12" cy="10" r="2.5" />
      </>,
    ),
  },
  {
    id: 'tools',
    label: 'DNS Tools',
    section: 'Diagnostics',
    desc: 'Look up records, check mail servers, and audit a domain',
    keywords: ['dig', 'lookup', 'diagnose', 'resolve', 'mx', 'whois'],
    icon: navSvg(
      <path d="M14.7 6.3a1 1 0 0 0 0 1.4l1.6 1.6a1 1 0 0 0 1.4 0l3.77-3.77a6 6 0 0 1-7.94 7.94l-6.91 6.91a2.12 2.12 0 0 1-3-3l6.91-6.91a6 6 0 0 1 7.94-7.94l-3.76 3.76z" />,
    ),
  },
  {
    id: 'client-groups',
    label: 'Client Groups',
    section: 'Network',
    desc: 'Give different devices different rules — kids, guests, IoT',
    keywords: ['devices', 'kids', 'lan', 'rules', 'group'],
    icon: navSvg(
      <>
        <circle cx="9" cy="8" r="3" />
        <path d="M2.5 20c0-3.3 3-5.5 6.5-5.5s6.5 2.2 6.5 5.5" />
        <circle cx="17" cy="8.5" r="2.2" />
        <path d="M15.7 13.3c2.3.5 4.1 2.2 4.1 4.7" />
      </>,
    ),
  },
  {
    id: 'dhcp',
    label: 'DHCP',
    section: 'Network',
    desc: 'Hand out addresses and names to devices on your network',
    keywords: ['leases', 'ip', 'addresses', 'pool', 'reservations'],
    icon: navSvg(
      <>
        <path d="M12 21s-7-6.5-7-11a7 7 0 1 1 14 0c0 4.5-7 11-7 11z" />
        <circle cx="12" cy="10" r="2.5" />
        <path d="M8 10h8M10.5 12.5l3-3" />
      </>,
    ),
  },
  {
    id: 'tls',
    label: 'SSL / TLS',
    section: 'Server',
    desc: 'Certificates that keep your DNS and dashboard encrypted',
    keywords: ['certificate', 'https', 'ssl', 'acme', 'letsencrypt', 'lets encrypt'],
    icon: navSvg(
      <>
        <rect x="5" y="11" width="14" height="9" rx="1.5" />
        <path d="M8 11V8a4 4 0 0 1 8 0v3" />
      </>,
    ),
  },
  {
    id: 'tunnel',
    label: 'Tunnel',
    section: 'Server',
    desc: 'Reach your server from anywhere via a Cloudflare tunnel',
    keywords: ['cloudflare', 'remote', 'cloudflared', 'expose'],
    icon: navSvg(
      <>
        <line x1="6" y1="18" x2="18" y2="6" />
        <polyline points="9 6 18 6 18 15" />
      </>,
    ),
  },
  {
    id: 'changelog',
    label: 'Changelog',
    section: 'System',
    desc: 'What\u2019s new in each Irongrid release',
    keywords: ['updates', 'release notes', 'whats new'],
    icon: navSvg(
      <>
        <circle cx="12" cy="12" r="9" />
        <polyline points="12 7 12 12 15.5 14" />
      </>,
    ),
  },
  {
    id: 'settings',
    label: 'Settings',
    section: 'System',
    desc: 'Every option — listeners, cache, security and more',
    keywords: ['preferences', 'config', 'options', 'security'],
    icon: navSvg(
      <>
        <circle cx="12" cy="12" r="3" />
        <path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 1 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82A1.65 1.65 0 0 0 3 13.09H3a2 2 0 1 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 1 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 1 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z" />
      </>,
    ),
  },
]

// Each view maps to a real URL path (/blocklists, /tls, …) so the browser
// back/forward buttons work and links are shareable. The web server serves
// index.html as the SPA fallback for these paths.
const VALID_VIEWS = NAV.map((n) => n.id)
// Section order for the sidebar grouping, derived from the first appearance
// of each section label in NAV so the nav stays the single source of truth.
const NAV_SECTIONS = [...new Set(NAV.map((n) => n.section))]
const viewFromPath = () => {
  const p = window.location.pathname.replace(/^\/+|\/+$/g, '')
  return VALID_VIEWS.includes(p) ? p : 'dashboard'
}

// The palette trigger shows the platform-appropriate modifier (⌘K on Mac,
// Ctrl+K elsewhere) so the hint matches the user's muscle memory.
const IS_MAC = typeof navigator !== 'undefined' && /Mac|iPhone|iPad/.test(navigator.userAgent || '')

// Apply the persisted theme before the first paint so a returning light-mode
// user never sees a dark flash; the effect below keeps it in sync after that.
// Only 'light' is honoured — anything else (unset, corrupted) means dark, so
// the toggle never renders the wrong icon against the real palette.
try {
  document.documentElement.dataset.theme = localStorage.getItem('irongrid_theme') === 'light' ? 'light' : 'dark'
} catch {
  /* private mode — dark default */
}

const SunIcon = (
  <svg
    width="13"
    height="13"
    viewBox="0 0 24 24"
    fill="none"
    stroke="currentColor"
    strokeWidth="2"
    strokeLinecap="round"
    strokeLinejoin="round"
    aria-hidden="true"
  >
    <circle cx="12" cy="12" r="4.5" />
    <path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4" />
  </svg>
)

const MoonIcon = (
  <svg
    width="13"
    height="13"
    viewBox="0 0 24 24"
    fill="none"
    stroke="currentColor"
    strokeWidth="2"
    strokeLinecap="round"
    strokeLinejoin="round"
    aria-hidden="true"
  >
    <path d="M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8z" />
  </svg>
)

export default function App() {
  const [view, setView] = useState(viewFromPath)
  const [status, setStatus] = useState(null)
  const [showLogin, setShowLogin] = useState(!hasCredentials())
  const [navOpen, setNavOpen] = useState(false)
  const [loginNotice, setLoginNotice] = useState('')
  // True while the saved session is being verified on mount. Until it
  // resolves we render a branded splash instead of the login form or the
  // dashboard, so a refresh never flashes one over the other.
  const [initializing, setInitializing] = useState(true)
  // ⌘K command palette + the ? shortcuts cheat sheet.
  const [paletteOpen, setPaletteOpen] = useState(false)
  const [shortcutsOpen, setShortcutsOpen] = useState(false)
  // The topbar Search button — the palette returns focus here on close so
  // keyboard users don't get dropped on the page background.
  const paletteTriggerRef = useRef(null)
  const closePalette = useCallback(() => {
    setPaletteOpen(false)
    paletteTriggerRef.current && paletteTriggerRef.current.focus()
  }, [])
  // Light/dark theme, persisted per browser. The module-level pre-paint
  // apply above already normalised the stored value onto <html data-theme>,
  // so this just reads it back — no duplicate localStorage access.
  const [theme, setTheme] = useState(() => document.documentElement.dataset.theme || 'dark')
  useEffect(() => {
    document.documentElement.dataset.theme = theme
  }, [theme])
  const toggleTheme = () => {
    setTheme((t) => {
      const next = t === 'dark' ? 'light' : 'dark'
      try {
        localStorage.setItem('irongrid_theme', next)
      } catch {
        /* private mode */
      }
      return next
    })
  }
  // Collapsed sidebar sections (persisted per browser; see toggleSection).
  const [collapsedSections, setCollapsedSections] = useState(() => {
    try {
      return new Set((localStorage.getItem('irongrid_nav_collapsed') || '').split(',').filter(Boolean))
    } catch {
      return new Set()
    }
  })

  const navigate = (id) => {
    // Navigating always expands the destination section, so collapsing the
    // current section is safe — you can never strand yourself in a hidden
    // nav group (and the toggle keeps working even on the active section).
    const sec = NAV.find((n) => n.id === id.split('?')[0])?.section
    if (sec) {
      setCollapsedSections((prev) => {
        if (!prev.has(sec)) return prev
        const next = new Set(prev)
        next.delete(sec)
        try {
          localStorage.setItem('irongrid_nav_collapsed', [...next].join(','))
        } catch {
          /* private mode */
        }
        return next
      })
    }
    // id may carry a query string (e.g. 'log?client=1.2.3.4' when the
    // dashboard deep-links into a filtered query log); the view is the path
    // part and the query rides along in the URL so the target view can read
    // it on mount (and refresh/re-share keeps the filter).
    const [base, query] = id.split('?')
    setView(base)
    setNavOpen(false)
    // Keep the URL in sync so back/forward navigate between views. Avoid
    // pushing a duplicate entry when the path already matches (e.g. the
    // topbar title click on the same view).
    const path = (base === 'dashboard' ? '/' : '/' + base) + (query ? '?' + query : '')
    if (window.location.pathname + window.location.search !== path) {
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
    } catch {
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
    setShowLogin(true)
  }

  // Called by Settings after a successful password/username change: the server
  // rotated the session secret (or the cookie is now bound to the wrong
  // username), so every old session cookie — including this one — is dead.
  // Sign out locally and ask the user to sign in again.
  const handleSessionInvalidated = (message) => {
    clearCredentials()
    setLoginNotice(message || 'Your sign-in details changed — all sessions were signed out. Please sign in again.')
    setShowLogin(true)
  }

  // Global keyboard shortcuts: ⌘K / Ctrl+K opens the command palette, ? shows
  // the shortcut help, / focuses the query-log search when that page is open,
  // Esc closes any overlay. Typing in a field never hijacks keys.
  useEffect(() => {
    const onKey = (e) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault()
        setShortcutsOpen(false)
        setPaletteOpen((o) => !o)
        return
      }
      if (e.key === 'Escape') {
        if (paletteOpen) {
          closePalette()
        } else {
          setShortcutsOpen(false)
        }
        return
      }
      const typing = ['INPUT', 'TEXTAREA', 'SELECT'].includes(document.activeElement?.tagName)
      if (typing || paletteOpen) return
      if (e.key === '?') {
        setShortcutsOpen((o) => !o)
      } else if (e.key === '/' && view === 'log') {
        e.preventDefault()
        window.dispatchEvent(new CustomEvent('irongrid:focus-log-search'))
      }
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [view, paletteOpen, closePalette])

  // Sidebar sections collapse for advanced users who want a compact nav;
  // newcomers see everything expanded by default. The active view's section
  // never stays collapsed, so you can't strand yourself.
  const toggleSection = (sec) => {
    setCollapsedSections((prev) => {
      const next = new Set(prev)
      if (next.has(sec)) next.delete(sec)
      else next.add(sec)
      try {
        localStorage.setItem('irongrid_nav_collapsed', [...next].join(','))
      } catch {
        /* private mode */
      }
      return next
    })
  }

  // The command palette's action rows — pages come from NAV, these are the
  // one-off things you might want to do from anywhere.
  const paletteActions = [
    {
      key: 'goto-blocklists',
      label: 'Manage blocklists',
      to: 'blocklists',
      desc: 'Add or update curated blocklists',
      run: () => navigate('blocklists'),
    },
    { key: 'goto-log', label: 'View query log', to: 'log', desc: 'Browse every DNS query', run: () => navigate('log') },
    {
      key: 'goto-lists',
      label: 'Allow-list a domain',
      to: 'lists',
      desc: 'Unblock a false positive',
      run: () => navigate('lists'),
    },
    {
      key: 'goto-dhcp',
      label: 'Set up DHCP',
      to: 'dhcp',
      desc: 'Serve addresses and names to your LAN',
      run: () => navigate('dhcp'),
    },
    {
      key: 'refresh',
      label: 'Refresh everything',
      desc: 'Re-fetch status and dashboard stats',
      run: () => {
        refreshStatus()
        window.dispatchEvent(new CustomEvent('irongrid:refresh-dashboard'))
      },
    },
    { key: 'logout', label: 'Log out', desc: 'Sign out of this dashboard', run: () => handleLogout() },
  ]

  if (initializing) return <Splash />
  if (showLogin) return <Login onLogin={handleLogin} notice={loginNotice} theme={theme} onToggleTheme={toggleTheme} />

  return (
    <div className="shell">
      <aside className={`sidebar ${navOpen ? 'open' : ''}`}>
        {' '}
        <div className="brand">
          <div className="brand-mark">
            <Logo size={17} />
          </div>
          <div>
            <div className="brand-name">Irongrid DNS</div>
            <div className="brand-sub">self-hosted · private</div>
          </div>
        </div>
        <nav className="nav">
          {NAV_SECTIONS.map((sec) => {
            const isCollapsed = collapsedSections.has(sec)
            return (
              <div className="nav-group" key={sec}>
                <button
                  type="button"
                  className={`nav-section ${isCollapsed ? 'collapsed' : ''}`}
                  onClick={() => toggleSection(sec)}
                  aria-expanded={!isCollapsed}
                  title={isCollapsed ? `Show ${sec}` : `Hide ${sec}`}
                >
                  {sec}
                  <svg
                    className="nav-chevron"
                    viewBox="0 0 24 24"
                    fill="none"
                    stroke="currentColor"
                    strokeWidth="2.4"
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    aria-hidden="true"
                  >
                    <polyline points="6 9 12 15 18 9" />
                  </svg>
                </button>
                {!isCollapsed &&
                  NAV.filter((n) => n.section === sec).map((n) => (
                    <button
                      key={n.id}
                      className={`nav-item ${view === n.id ? 'active' : ''}`}
                      title={n.desc}
                      onClick={() => {
                        navigate(n.id)
                        setNavOpen(false)
                      }}
                    >
                      <span className="nav-icon">{n.icon}</span>
                      {n.label}
                    </button>
                  ))}
              </div>
            )
          })}
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
          {/* Row one: page title + description, with the full width to
              itself so a long view name or subtitle never competes with
              the action buttons for space. */}
          <div className="topbar-main">
            <button className="menu-btn" onClick={() => setNavOpen(true)} aria-label="Open navigation">
              ☰
            </button>
            <div>
              <div className="topbar-title">{NAV.find((n) => n.id === view)?.label}</div>
              <div className="topbar-sub">{NAV.find((n) => n.id === view)?.desc}</div>
            </div>
          </div>
          {/* Row two: the action cluster (Updates / Refresh / Log out) on
              its own strip, right-aligned, so neither row squashes the
              other. */}
          <div className="topbar-actions">
            {' '}
            <button
              className="btn ghost small theme-btn"
              onClick={toggleTheme}
              title={theme === 'dark' ? 'Switch to light theme' : 'Switch to dark theme'}
              aria-label={theme === 'dark' ? 'Switch to light theme' : 'Switch to dark theme'}
            >
              <span key={theme} className="theme-icon">
                {theme === 'dark' ? SunIcon : MoonIcon}
              </span>
            </button>
            <button
              className="btn ghost small palette-trigger"
              ref={paletteTriggerRef}
              onClick={() => setPaletteOpen(true)}
              aria-haspopup="dialog"
            >
              <svg
                width="13"
                height="13"
                viewBox="0 0 24 24"
                fill="none"
                stroke="currentColor"
                strokeWidth="2"
                strokeLinecap="round"
                aria-hidden="true"
              >
                <circle cx="11" cy="11" r="7" />
                <line x1="21" y1="21" x2="16.5" y2="16.5" />
              </svg>
              <span className="palette-trigger-label">Search</span>
              <Kbd>{IS_MAC ? '⌘K' : 'Ctrl K'}</Kbd>
            </button>
            <UpdateChecker onNavigate={navigate} />
            <button className="btn ghost small" onClick={refreshStatus}>
              ⟳ Refresh
            </button>
            <button className="btn ghost small danger icon" onClick={handleLogout} title="Sign out">
              <svg
                width="12"
                height="12"
                viewBox="0 0 24 24"
                fill="none"
                stroke="currentColor"
                strokeWidth="2.4"
                strokeLinecap="round"
                strokeLinejoin="round"
                aria-hidden="true"
              >
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
              {/* key={view} replays a short entrance animation on every
                  switch so views feel like they flow into place rather
                  than snapping. */}
              <div key={view} className="view-transition">
                {view === 'dashboard' && <Dashboard onNavigate={navigate} />}
                {view === 'log' && <QueryLog />}
                {view === 'blocklists' && <Blocklists />}
                {view === 'lists' && <Lists />}
                {view === 'rewrites' && <Rewrites />}
                {view === 'tools' && <Tools />}
                {view === 'client-groups' && <ClientGroups />}
                {view === 'tls' && <Tls />}
                {view === 'tunnel' && <Tunnel />}
                {view === 'dhcp' && <Dhcp />}
                {view === 'changelog' && <Changelog />}
                {view === 'settings' && <Settings onSessionInvalidated={handleSessionInvalidated} />}
              </div>
            </Suspense>
          </ViewErrorBoundary>
        </div>
      </main>
      <CommandPalette open={paletteOpen} onClose={closePalette} onNavigate={navigate} actions={paletteActions} />
      <ShortcutsHelp open={shortcutsOpen} onClose={() => setShortcutsOpen(false)} />
    </div>
  )
}

function Splash() {
  return (
    <div className="login-wrap">
      <div className="login-card splash-card" role="status" aria-live="polite">
        <div className="login-logo splash-logo">
          <Logo size={24} />
          <span className="splash-ring" aria-hidden="true" />
        </div>
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

// The bolt icon marks palette action rows (as opposed to pages).
const ACT_ICON = (
  <svg
    width="15"
    height="15"
    viewBox="0 0 24 24"
    fill="none"
    stroke="currentColor"
    strokeWidth="2"
    strokeLinecap="round"
    strokeLinejoin="round"
    aria-hidden="true"
  >
    <polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2" />
  </svg>
)

// CommandPalette is the ⌘K quick-switcher: type to filter every page plus a
// few global actions, ↑/↓ to move, ↵ to run. Newcomers discover it via the
// Search button in the topbar; advanced users live in it.
function CommandPalette({ open, onClose, onNavigate, actions }) {
  const [q, setQ] = useState('')
  const [idx, setIdx] = useState(0)
  const inputRef = useRef(null)
  const panelRef = useRef(null)

  // Reset the query and refocus every time the palette opens.
  useEffect(() => {
    if (!open) return
    setQ('')
    setIdx(0)
    const t = setTimeout(() => inputRef.current && inputRef.current.focus(), 20)
    return () => clearTimeout(t)
  }, [open])

  const results = useMemo(() => {
    const query = q.trim().toLowerCase()
    const match = (s) => !query || (s || '').toLowerCase().includes(query)
    const views = NAV.filter(
      (n) => match(n.label) || match(n.desc) || match(n.section) || (n.keywords || []).some(match),
    ).map((n) => ({
      type: 'Pages',
      key: n.id,
      label: n.label,
      hint: n.section,
      icon: n.icon,
      run: () => {
        onNavigate(n.id)
        onClose()
      },
    }))
    // Actions that merely navigate to a page are dropped when that page is
    // already in the results — no duplicate rows for the same destination.
    const viewIds = new Set(views.map((v) => v.key))
    const acts = actions
      .filter((a) => !a.to || !viewIds.has(a.to))
      .filter((a) => match(a.label) || match(a.desc))
      .map((a) => ({
        type: 'Actions',
        key: a.key,
        label: a.label,
        hint: 'Action',
        icon: ACT_ICON,
        run: () => {
          a.run()
          onClose()
        },
      }))
    return [...views, ...acts]
  }, [q, actions, onNavigate, onClose])

  // Keep the highlight in range whenever the filter shrinks the list.
  useEffect(() => {
    setIdx(0)
  }, [q])

  if (!open) return null
  const flat = results
  const cur = Math.min(idx, Math.max(flat.length - 1, 0))
  const groups = []
  for (const r of flat) {
    const last = groups[groups.length - 1]
    if (!last || last.type !== r.type) groups.push({ type: r.type, items: [r] })
    else last.items.push(r)
  }

  const onKeyDown = (e) => {
    if (e.key === 'ArrowDown') {
      e.preventDefault()
      setIdx((i) => Math.min(i + 1, flat.length - 1))
    } else if (e.key === 'ArrowUp') {
      e.preventDefault()
      setIdx((i) => Math.max(i - 1, 0))
    } else if (e.key === 'Enter') {
      e.preventDefault()
      flat[cur] && flat[cur].run()
    } else if (e.key === 'Escape') {
      onClose()
    }
  }

  // Minimal focus trap: Tab cycles inside the dialog (input ⇄ rows) instead
  // of escaping to the page behind the overlay.
  const onPanelKeyDown = (e) => {
    if (e.key !== 'Tab' || !panelRef.current) return
    const els = Array.from(panelRef.current.querySelectorAll('.palette-input, [role="option"]')).filter(
      (el) => !el.disabled,
    )
    if (els.length < 2) return
    const first = els[0]
    const last = els[els.length - 1]
    if (e.shiftKey && document.activeElement === first) {
      e.preventDefault()
      last.focus()
    } else if (!e.shiftKey && document.activeElement === last) {
      e.preventDefault()
      first.focus()
    }
  }

  return (
    <div className="palette-overlay" onClick={onClose} role="presentation">
      <div
        className="palette"
        role="dialog"
        aria-modal="true"
        aria-label="Search"
        ref={panelRef}
        onClick={(e) => e.stopPropagation()}
        onKeyDown={onPanelKeyDown}
      >
        <div className="palette-input-wrap">
          <svg
            width="16"
            height="16"
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            strokeWidth="2"
            strokeLinecap="round"
            aria-hidden="true"
          >
            <circle cx="11" cy="11" r="7" />
            <line x1="21" y1="21" x2="16.5" y2="16.5" />
          </svg>
          <input
            ref={inputRef}
            className="palette-input"
            placeholder="Search pages and actions…"
            value={q}
            onChange={(e) => setQ(e.target.value)}
            onKeyDown={onKeyDown}
            role="combobox"
            aria-expanded="true"
            aria-controls="palette-list"
            aria-activedescendant={flat[cur] ? `palette-${flat[cur].key}` : undefined}
          />
          <Kbd>esc</Kbd>
        </div>
        <div className="palette-list" id="palette-list" role="listbox">
          {flat.length === 0 ? (
            <div className="palette-empty">No matches for “{q}”.</div>
          ) : (
            groups.map((g) => (
              <div key={g.type}>
                <div className="palette-group-title">{g.type}</div>
                {g.items.map((r) => {
                  const gi = flat.indexOf(r)
                  const active = gi === cur
                  return (
                    <button
                      key={r.key}
                      type="button"
                      id={`palette-${r.key}`}
                      role="option"
                      aria-selected={active}
                      className={`palette-row ${active ? 'active' : ''}`}
                      onMouseMove={() => setIdx(gi)}
                      onClick={() => r.run()}
                    >
                      <span className="palette-icon">{r.icon}</span>
                      <span className="palette-label">{r.label}</span>
                      <span className="palette-hint">{r.hint}</span>
                    </button>
                  )
                })}
              </div>
            ))
          )}
        </div>
        <div className="palette-foot">
          <span>↑↓ navigate</span>
          <span>↵ run</span>
          <span>esc close</span>
          <span className="ml-auto">
            {flat.length} result{flat.length === 1 ? '' : 's'}
          </span>
        </div>
      </div>
    </div>
  )
}

// ShortcutsHelp is the ? cheat sheet: a compact modal listing every global
// keyboard shortcut with its key chips.
function ShortcutsHelp({ open, onClose }) {
  if (!open) return null
  const rows = [
    { keys: [<Kbd key="k1">Ctrl</Kbd>, <Kbd key="k2">K</Kbd>], what: 'Open search / command palette (⌘ on Mac)' },
    { keys: [<Kbd key="s1">/</Kbd>], what: 'Jump to the query-log search' },
    { keys: [<Kbd key="s2">?</Kbd>], what: 'Show or hide this help' },
    { keys: [<Kbd key="s3">esc</Kbd>], what: 'Close dialogs and overlays' },
  ]
  return (
    <div className="modal-overlay" onClick={onClose}>
      <div
        className="modal"
        role="dialog"
        aria-modal="true"
        aria-label="Keyboard shortcuts"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="modal-head">
          <div>
            <div className="modal-title">Keyboard shortcuts</div>
            <div className="modal-sub">
              <span className="modal-note">Every shortcut has a clickable button too</span>
            </div>
          </div>
          <button className="modal-x" onClick={onClose} aria-label="Close">
            ✕
          </button>
        </div>
        <div className="modal-body">
          <div className="shortcuts">
            {rows.map((r, i) => (
              <div className="shortcut-row" key={i}>
                <span className="shortcut-keys">{r.keys}</span>
                <span>{r.what}</span>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  )
}

function Login({ onLogin, notice, theme, onToggleTheme }) {
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
      <button
        className="btn ghost theme-btn login-theme-btn"
        onClick={onToggleTheme}
        title={theme === 'dark' ? 'Switch to light theme' : 'Switch to dark theme'}
        aria-label={theme === 'dark' ? 'Switch to light theme' : 'Switch to dark theme'}
      >
        <span key={theme} className="theme-icon">
          {theme === 'dark' ? SunIcon : MoonIcon}
        </span>
      </button>
      <form className="login-card" onSubmit={submit}>
        <div className="login-logo">
          <Logo size={24} />
        </div>
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
        <p className="login-foot">Irongrid DNS · self-hosted · private by default</p>
      </form>
    </div>
  )
}
