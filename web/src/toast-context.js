import { createContext, useContext } from 'react'

// Shared between ToastProvider (toast.jsx) and useToast, so the provider
// file only exports components and stays fast-refresh friendly.
export const ToastContext = createContext(null)

// useToast returns a toast(message, type) function. Must be called from
// inside a ToastProvider (mounted once in main.jsx around <App />).
export function useToast() {
  const toast = useContext(ToastContext)
  if (!toast) throw new Error('useToast must be used within a ToastProvider')
  return toast
}
