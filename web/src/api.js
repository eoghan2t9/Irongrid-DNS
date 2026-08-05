let credentials = null // { user, pass }
let onUnauthorized = null

export function setAuthHandler(fn) { onUnauthorized = fn }
export function setCredentials(user, pass) {
  credentials = { user, pass }
  localStorage.setItem('irongrid_user', user)
}
export function hasCredentials() {
  return !!credentials || !!localStorage.getItem('irongrid_user')
}
export function restoreCredentials() {
  const user = localStorage.getItem('irongrid_user')
  if (user) credentials = { user, pass: '' }
  return credentials
}

async function request(path, options = {}) {
  const headers = { ...(options.headers || {}) }
  if (credentials) {
    headers.Authorization = 'Basic ' + btoa(`${credentials.user}:${credentials.pass}`)
  }
  const resp = await fetch(path, { ...options, headers })
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
}
