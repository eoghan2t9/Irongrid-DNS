let credentials = null // { user, pass }
let onUnauthorized = null

// authHeader returns the Basic auth header for the in-memory credentials, or
// null when there is no usable password. After a page reload the password is
// gone from memory — the signed irongrid_session cookie (set on login) keeps
// the user authenticated instead, so we don't send a broken empty-password
// header that would 401 before the cookie is considered.
function authHeader() {
  if (!credentials || !credentials.user || !credentials.pass) return null
  return 'Basic ' + btoa(`${credentials.user}:${credentials.pass}`)
}

export function setAuthHandler(fn) { onUnauthorized = fn }
export function setCredentials(user, pass) {
  credentials = { user, pass }
  localStorage.setItem('irongrid_user', user)
}
export function hasCredentials() {
  return !!credentials || !!localStorage.getItem('irongrid_user')
}
// clearCredentials forgets the in-memory credentials and the persisted
// username. Used by logout and when the server rotates the session secret
// after a password change.
export function clearCredentials() {
  credentials = null
  localStorage.removeItem('irongrid_user')
}
export function restoreCredentials() {
  const user = localStorage.getItem('irongrid_user')
  // Password lives only in memory (Basic auth); the session cookie covers
  // reloads, so an empty pass here is expected and fine.
  if (user) credentials = { user, pass: '' }
  return credentials
}

async function request(path, options = {}) {
  const headers = { ...(options.headers || {}) }
  const auth = authHeader()
  if (auth) headers.Authorization = auth
  let resp
  try {
    resp = await fetch(path, { ...options, headers })
  } catch (err) {
    // A raw fetch() throw ("Failed to fetch") is a connection-level failure,
    // not an HTTP error — most often the browser's pooled HTTP/2 connection
    // going stale while the tab was backgrounded (minimised, laptop sleep,
    // phone screen off). The browser opens a fresh connection on the very
    // next attempt, so one silent retry clears up the vast majority of these
    // instead of surfacing a one-off blip as a hard error.
    resp = await fetch(path, { ...options, headers })
  }
  if (resp.status === 401) {
    if (onUnauthorized) onUnauthorized()
    throw new Error('unauthorized')
  }
  if (!resp.ok) {
    const body = await resp.json().catch(() => ({}))
    throw new Error(body.error || `HTTP ${resp.status}`)
  }
  return resp.json()
}

export const api = {
  status: () => request('/api/status'),
  logout: () => request('/api/logout', { method: 'POST' }),
  stats: () => request('/api/stats'),
  log: (params = {}) => {
    const q = new URLSearchParams()
    Object.entries(params).forEach(([k, v]) => { if (v) q.set(k, v) })
    return request('/api/log?' + q.toString())
  },
  clearLog: () => request('/api/log', { method: 'DELETE' }),
  lists: () => request('/api/lists'),
  catalog: () => request('/api/lists/catalog'),
  addList: (body) => request('/api/lists', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) }),
  updateList: (id, body) => request(`/api/lists/${encodeURIComponent(id)}`, { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) }),
  deleteList: (id) => request(`/api/lists/${encodeURIComponent(id)}`, { method: 'DELETE' }),
  refreshLists: () => request('/api/lists/refresh', { method: 'POST' }),
  refreshList: (id) => request(`/api/lists/${encodeURIComponent(id)}/fetch`, { method: 'POST' }),
  getFilterList: (kind) => request(`/api/filter/${kind}`),
  addFilterEntry: (kind, entry) => request(`/api/filter/${kind}`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ entry }) }),
  deleteFilterEntry: (kind, entry) => request('/api/filter/delete', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ kind, entry }) }),
  checkFilter: (entry) => request('/api/filter/check', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ entry }) }),
  flushCache: () => request('/api/cache/flush', { method: 'POST' }),
  tunnelStatus: () => request('/api/tunnel/status'),
  tunnelStart: (body) => request('/api/tunnel/start', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) }),
  tunnelStop: () => request('/api/tunnel/stop', { method: 'POST' }),
  tunnelLog: () => request('/api/tunnel/log'),
  config: () => request('/api/config'),
  saveConfig: (cfg) => request('/api/config', { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(cfg) }),
  reloadConfig: () => request('/api/config/reload', { method: 'POST' }),
  diagDNS: (name, type) => request(`/api/diag/dns?name=${encodeURIComponent(name)}&type=${encodeURIComponent(type)}`),
  updateCheck: () => request('/api/update/check'),
  updateChangelog: () => request('/api/update/changelog'),
  updateInstall: () => request('/api/update/install', { method: 'POST' }),
  tlsStatus: () => request('/api/tls'),
  tlsGenerate: (body) => request('/api/tls/generate', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) }),
  tlsUpload: (body) => request('/api/tls/upload', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) }),
  tlsAcmeIssue: () => request('/api/tls/acme/issue', { method: 'POST' }),
  tlsCertDownload: async () => {
    // Raw fetch so we can return a blob (the auth header is attached the
    // same way as request() does; after a reload the session cookie covers it).
    const headers = {}
    const auth = authHeader()
    if (auth) headers.Authorization = auth
    const resp = await fetch('/api/tls/cert', { headers })
    if (resp.status === 401) {
      if (onUnauthorized) onUnauthorized()
      throw new Error('unauthorized')
    }
    if (!resp.ok) throw new Error(`HTTP ${resp.status}`)
    return resp.blob()
  },
}

