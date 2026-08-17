import { useEffect, useRef, useState } from 'react'

// Shared UI primitives used across views. Kept dependency-free on purpose so
// any component can import them without pulling in extra chunks.

// EmptyState is the friendly "nothing here yet" treatment: a soft icon, a
// one-line title, a plain-English explanation, and an optional action button
// that moves the operator forward instead of leaving them staring at a dash.
// Color is never the only signal, so every state carries words too.
export function EmptyState({ icon, title, body, action, onAction, children, compact }) {
  return (
    <div className={`empty-state${compact ? ' empty-state-compact' : ''}`}>
      {icon && (
        <div className="empty-state-icon" aria-hidden="true">
          {icon}
        </div>
      )}
      {title && <div className="empty-state-title">{title}</div>}
      {body && <div className="empty-state-body">{body}</div>}
      {action && (
        <button className="btn small" type="button" onClick={onAction}>
          {action}
        </button>
      )}
      {children}
    </div>
  )
}

// Kbd renders a keyboard key as a small chip (⌘K hints, shortcut lists).
export function Kbd({ children }) {
  return <kbd className="kbd">{children}</kbd>
}

// Logo is the Irongrid mark: a rounded square with a signal dot — the same
// shape family as the dashboard nav icon. It inherits currentColor so it
// works at any size on any surface (sidebar brand, login card, splash).
export function Logo({ size = 20 }) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
    >
      <rect x="3" y="3" width="18" height="18" rx="5" />
      <circle cx="12" cy="12" r="4.5" fill="currentColor" stroke="none" />
    </svg>
  )
}

// Small stroke-only icon set, matching Logo/navSvg's grammar (24x24 view,
// currentColor stroke, weight 2, round caps/joins) so every icon in the app
// shares one hand — including the close/check/warning marks that used to be
// plain Unicode glyphs, which render as colorful platform emoji on some
// devices and don't share a weight with the rest of the icon system.
function iconShell(size, style, children) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
      style={style}
    >
      {children}
    </svg>
  )
}
export function CheckIcon({ size = 14, style }) {
  return iconShell(size, style, <polyline points="20 6 9 17 4 12" />)
}
export function XIcon({ size = 14, style }) {
  return iconShell(
    size,
    style,
    <>
      <line x1="18" y1="6" x2="6" y2="18" />
      <line x1="6" y1="6" x2="18" y2="18" />
    </>
  )
}
export function AlertIcon({ size = 14, style }) {
  return iconShell(
    size,
    style,
    <>
      <path d="M10.29 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0Z" />
      <line x1="12" y1="9" x2="12" y2="13" />
      <line x1="12" y1="17" x2="12.01" y2="17" />
    </>
  )
}
export function MenuIcon({ size = 18, style }) {
  return iconShell(
    size,
    style,
    <>
      <line x1="3" y1="6" x2="21" y2="6" />
      <line x1="3" y1="12" x2="21" y2="12" />
      <line x1="3" y1="18" x2="21" y2="18" />
    </>
  )
}

// LineListField edits a string array as a one-entry-per-line textarea (the
// pattern behind Settings' honeypot/allowlist/blacklist fields and Client
// Groups' CIDR/upstream fields). It keeps a local draft while typing and
// only normalises (trim each line, drop empties) on blur — normalising on
// every keystroke would strip the trailing newline the moment Enter is
// pressed, so the field would appear to ignore the return key entirely.
// External changes to value (config save/reload, another field touching the
// same list) replace the draft, but never mid-typing.
export function LineListField({ value, onChange, placeholder, rows = 3, className = 'input mono', style }) {
  const [draft, setDraft] = useState(() => (value || []).join('\n'))
  const lastCommitted = useRef((value || []).join('\n'))

  useEffect(() => {
    const joined = (value || []).join('\n')
    if (joined !== lastCommitted.current) {
      lastCommitted.current = joined
      setDraft(joined)
    }
  }, [value])

  const commit = () => {
    const normalized = draft
      .split('\n')
      .map((s) => s.trim())
      .filter(Boolean)
    const joined = normalized.join('\n')
    if (joined !== lastCommitted.current) {
      lastCommitted.current = joined
      onChange(normalized)
    }
    // Clean the draft up (drop the trailing newline / stray spaces) so the
    // field looks the same after blur as it would after a reload.
    setDraft(joined)
  }

  return (
    <textarea
      className={className}
      rows={rows}
      style={style}
      placeholder={placeholder}
      value={draft}
      onChange={(e) => setDraft(e.target.value)}
      onBlur={commit}
    />
  )
}
