import React, { createContext, useCallback, useContext, useRef, useState } from 'react'

const ToastContext = createContext(null)

// ToastProvider renders a fixed-position, auto-dismissing stack of status
// messages. Mounted once at the app root so any page can report a
// transient action result (saved, added, failed…) without it scrolling out
// of view on a long page — the old pattern of an inline banner at the top
// of the page meant a message could land off-screen from wherever the
// triggering button was.
export function ToastProvider({ children }) {
  const [toasts, setToasts] = useState([])
  const idRef = useRef(0)

  const dismiss = useCallback((id) => {
    setToasts((prev) => prev.filter((t) => t.id !== id))
  }, [])

  // toast(message, type): type 'info' (default) or 'error'. Errors stay up
  // longer since they're more likely to need reading closely, but both are
  // dismissible early by clicking.
  const toast = useCallback((message, type = 'info') => {
    const id = ++idRef.current
    setToasts((prev) => [...prev, { id, message, type }])
    setTimeout(() => dismiss(id), type === 'error' ? 7000 : 4000)
    return id
  }, [dismiss])

  return (
    <ToastContext.Provider value={toast}>
      {children}
      <div className="toast-stack" role="status" aria-live="polite">
        {toasts.map((t) => (
          <div
            key={t.id}
            className={`toast toast-${t.type}`}
            onClick={() => dismiss(t.id)}
            role="button"
            tabIndex={0}
            aria-label="Dismiss notification"
            onKeyDown={(e) => e.key === 'Enter' && dismiss(t.id)}
          >
            {t.message}
          </div>
        ))}
      </div>
    </ToastContext.Provider>
  )
}

// useToast returns a toast(message, type) function. Must be called from
// inside a ToastProvider (mounted once in main.jsx around <App />).
export function useToast() {
  const toast = useContext(ToastContext)
  if (!toast) throw new Error('useToast must be used within a ToastProvider')
  return toast
}
