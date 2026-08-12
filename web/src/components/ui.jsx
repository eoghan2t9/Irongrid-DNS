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
