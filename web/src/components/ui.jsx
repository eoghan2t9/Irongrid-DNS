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
