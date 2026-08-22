import { describe, it, expect, beforeEach, vi } from 'vitest'
import { api, setAuthHandler, setCredentials, clearCredentials, hasCredentials, restoreCredentials } from './api'

describe('api credentials', () => {
  beforeEach(() => {
    localStorage.clear()
    clearCredentials()
    setAuthHandler(null)
  })

  it('keeps the password in memory only, the username in localStorage', () => {
    setCredentials('admin', 's3cret')
    expect(hasCredentials()).toBe(true)
    expect(localStorage.getItem('irongrid_user')).toBe('admin')
    expect(localStorage.getItem('irongrid_pass')).toBeNull()
  })

  it('restoreCredentials rehydrates the user with an empty password (the session cookie covers auth)', () => {
    localStorage.setItem('irongrid_user', 'admin')
    expect(restoreCredentials()).toEqual({ user: 'admin', pass: '' })
    expect(hasCredentials()).toBe(true)
  })

  it('clearCredentials drops both memory and localStorage', () => {
    setCredentials('admin', 's3cret')
    clearCredentials()
    expect(hasCredentials()).toBe(false)
    expect(localStorage.getItem('irongrid_user')).toBeNull()
  })
})

describe('api request', () => {
  beforeEach(() => {
    localStorage.clear()
    clearCredentials()
    setAuthHandler(null)
    vi.restoreAllMocks()
  })

  it('sends a Basic auth header when credentials are in memory', async () => {
    setCredentials('admin', 's3cret')
    globalThis.fetch = vi.fn().mockResolvedValue({ status: 200, ok: true, json: async () => ({ ok: true }) })
    await api.status()
    const [url, opts] = globalThis.fetch.mock.calls[0]
    expect(url).toBe('/api/status')
    expect(opts.headers.Authorization).toBe('Basic ' + btoa('admin:s3cret'))
  })

  it('does not send an auth header for a reloaded (cookie-only) session', async () => {
    localStorage.setItem('irongrid_user', 'admin')
    restoreCredentials() // pass is '' after a reload
    globalThis.fetch = vi.fn().mockResolvedValue({ status: 200, ok: true, json: async () => ({}) })
    await api.status()
    expect(globalThis.fetch.mock.calls[0][1].headers.Authorization).toBeUndefined()
  })

  it('passes cache control options through for restart polling', async () => {
    globalThis.fetch = vi.fn().mockResolvedValue({ status: 200, ok: true, json: async () => ({}) })
    await api.status({ cache: 'no-store' })
    expect(globalThis.fetch.mock.calls[0][1].cache).toBe('no-store')
  })

  it('throws "unauthorized" and fires the auth handler on 401', async () => {
    const onAuth = vi.fn()
    setAuthHandler(onAuth)
    globalThis.fetch = vi.fn().mockResolvedValue({ status: 401, ok: false, json: async () => ({}) })
    await expect(api.status()).rejects.toThrow('unauthorized')
    expect(onAuth).toHaveBeenCalledTimes(1)
  })

  it('surfaces the server error message on a non-OK response', async () => {
    globalThis.fetch = vi
      .fn()
      .mockResolvedValue({ status: 400, ok: false, json: async () => ({ error: 'bad request' }) })
    await expect(api.status()).rejects.toThrow('bad request')
  })

  it('retries once when the pooled connection is stale, then succeeds', async () => {
    globalThis.fetch = vi
      .fn()
      .mockRejectedValueOnce(new TypeError('Failed to fetch'))
      .mockResolvedValueOnce({ status: 200, ok: true, json: async () => ({ ok: true }) })
    await expect(api.status()).resolves.toEqual({ ok: true })
    expect(globalThis.fetch).toHaveBeenCalledTimes(2)
  })
})
