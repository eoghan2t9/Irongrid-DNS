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

export function setAuthHandler(fn) {
  onUnauthorized = fn
}
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

// REQUEST_TIMEOUT_MS bounds every request so a stalled backend (a stuck
// upstream resolve, a hung AXFR) fails fast instead of leaving the caller's
// promise pending forever.
const REQUEST_TIMEOUT_MS = 30000

// timedFetch wraps fetch with an AbortController-based timeout. A timeout
// abort is turned into a distinctly-messaged Error so callers (the stale-
// connection retry below) can tell "the network hiccuped" from "the server
// really is stuck" and only retry the former.
async function timedFetch(path, options, timeoutMs = REQUEST_TIMEOUT_MS) {
  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), timeoutMs)
  try {
    return await fetch(path, { ...options, signal: controller.signal })
  } catch (err) {
    if (err.name === 'AbortError') throw new Error(`Request timed out after ${timeoutMs / 1000}s`)
    throw err
  } finally {
    clearTimeout(timer)
  }
}

// fetchWithAuthRetry attaches the Basic auth header (when present) and
// performs the fetch, retrying once on a connection-level failure. A raw
// fetch() throw ("Failed to fetch") is most often the browser's pooled
// HTTP/2 connection going stale while the tab was backgrounded (minimised,
// laptop sleep, phone screen off); the browser opens a fresh connection on
// the very next attempt, so one silent retry clears up the vast majority of
// these instead of surfacing a one-off blip as a hard error. A genuine
// timeout is not retried — it already waited the full budget once.
async function fetchWithAuthRetry(path, options = {}) {
  const headers = { ...(options.headers || {}) }
  const auth = authHeader()
  if (auth) headers.Authorization = auth
  try {
    return await timedFetch(path, { ...options, headers })
  } catch (err) {
    if (err.message && err.message.startsWith('Request timed out')) throw err
    return await timedFetch(path, { ...options, headers })
  }
}

async function request(path, options = {}) {
  const resp = await fetchWithAuthRetry(path, options)
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

// requestBlob is request()'s counterpart for binary downloads (CSV/zip/cert
// exports): same auth header, timeout and stale-connection retry, but
// resolves to a Blob instead of parsed JSON. Shared by every download
// endpoint below instead of each hand-rolling the same fetch/401/retry
// sequence.
async function requestBlob(path, options = {}) {
  const resp = await fetchWithAuthRetry(path, options)
  if (resp.status === 401) {
    if (onUnauthorized) onUnauthorized()
    throw new Error('unauthorized')
  }
  if (!resp.ok) {
    const body = await resp.json().catch(() => ({}))
    throw new Error(body.error || `HTTP ${resp.status}`)
  }
  return resp.blob()
}

export const api = {
  status: (options = {}) => request('/api/status', options),
  logout: () => request('/api/logout', { method: 'POST' }),
  stats: () => request('/api/stats'),
  log: (params = {}) => {
    const q = new URLSearchParams()
    Object.entries(params).forEach(([k, v]) => {
      if (v) q.set(k, v)
    })
    return request('/api/log?' + q.toString())
  },
  clearLog: () => request('/api/log', { method: 'DELETE' }),
  hostnames: (ips) => {
    const list = (ips || []).filter(Boolean)
    if (!list.length) return Promise.resolve({ hostnames: {} })
    return request('/api/log/hostnames?ips=' + encodeURIComponent(list.join(',')))
  },
  asnInfo: (ips) => {
    const list = (ips || []).filter(Boolean)
    if (!list.length) return Promise.resolve({ asn: {} })
    return request('/api/log/asn?ips=' + encodeURIComponent(list.join(',')))
  },
  lists: () => request('/api/lists'),
  catalog: () => request('/api/lists/catalog'),
  addList: (body) =>
    request('/api/lists', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    }),
  updateList: (id, body) =>
    request(`/api/lists/${encodeURIComponent(id)}`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    }),
  deleteList: (id) => request(`/api/lists/${encodeURIComponent(id)}`, { method: 'DELETE' }),
  refreshLists: () => request('/api/lists/refresh', { method: 'POST' }),
  refreshList: (id) => request(`/api/lists/${encodeURIComponent(id)}/fetch`, { method: 'POST' }),
  getFilterList: (kind) => request(`/api/filter/${kind}`),
  addFilterEntry: (kind, entry) =>
    request(`/api/filter/${kind}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ entry }),
    }),
  deleteFilterEntry: (kind, entry) =>
    request('/api/filter/delete', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ kind, entry }),
    }),
  checkFilter: (entry) =>
    request('/api/filter/check', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ entry }),
    }),
  siteCheck: (url) =>
    request('/api/filter/site', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url }),
    }),
  toolsResolve: (body) =>
    request('/api/tools/resolve', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    }),
  toolsMail: (domain) =>
    request('/api/tools/mail', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ domain }),
    }),
  toolsRBL: (ip) =>
    request('/api/tools/rbl', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ip }),
    }),
  toolsAXFR: (domain) =>
    request('/api/tools/axfr', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ domain }),
    }),
  toolsSubdomains: (domain) =>
    request('/api/tools/subdomains', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ domain }),
    }),
  toolsFastest: () => request('/api/tools/fastest', { method: 'POST' }),
  flushCache: () => request('/api/cache/flush', { method: 'POST' }),
  warmCache: () => request('/api/cache/warm', { method: 'POST' }),
  rateBlocked: () => request('/api/rate/blocked'),
  rateUnblock: (ip) =>
    request('/api/rate/unblock', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ip }),
    }),
  geoStatus: () => request('/api/geo/status'),
  geoRefresh: () => request('/api/geo/refresh', { method: 'POST' }),
  geoBlocked: () => request('/api/geo/blocked'),
  geoUnblock: (ip) =>
    request('/api/geo/unblock', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ip }),
    }),
  geoBlockIP: (ip, prefix) =>
    request('/api/geo/blockip', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ip, prefix }),
    }),
  abuseReport: (ip) =>
    request('/api/abuse/report', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ip }),
    }),
  abuseASN: (ip) =>
    request('/api/abuse/asn', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ip }),
    }),
  abuseExport: () => requestBlob('/api/abuse/export'),
  tunnelStatus: () => request('/api/tunnel/status'),
  tunnelStart: (body) =>
    request('/api/tunnel/start', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    }),
  tunnelStop: () => request('/api/tunnel/stop', { method: 'POST' }),
  tunnelLog: () => request('/api/tunnel/log'),
  tunnelCheckCloudflaredUpdate: () => request('/api/tunnel/cloudflared-update', { method: 'POST' }),
  dhcpLeases: () => request('/api/dhcp/leases'),
  config: () => request('/api/config'),
  saveConfig: (cfg) =>
    request('/api/config', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(cfg),
    }),
  reloadConfig: () => request('/api/config/reload', { method: 'POST' }),
  configBackup: (passphrase) =>
    // The passphrase (if any) rides in a header, not a query string, so it
    // doesn't end up in server access logs.
    requestBlob('/api/config/backup', passphrase ? { headers: { 'X-Backup-Passphrase': passphrase } } : {}),
  configRestore: (file, passphrase) => {
    // Multipart upload; the browser sets the boundary automatically, so no
    // Content-Type header is sent. passphrase is ignored server-side for a
    // plain (unencrypted) archive, so it's always safe to include it.
    const fd = new FormData()
    fd.append('file', file)
    if (passphrase) fd.append('passphrase', passphrase)
    return request('/api/config/restore', { method: 'POST', body: fd })
  },
  diagDNS: (name, type) => request(`/api/diag/dns?name=${encodeURIComponent(name)}&type=${encodeURIComponent(type)}`),
  updateCheck: () => request('/api/update/check'),
  updateChangelog: () => request('/api/update/changelog'),
  updateInstall: () => request('/api/update/install', { method: 'POST' }),
  tlsStatus: () => request('/api/tls'),
  tlsGenerate: (body) =>
    request('/api/tls/generate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    }),
  tlsUpload: (body) =>
    request('/api/tls/upload', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    }),
  tlsAcmeIssue: () => request('/api/tls/acme/issue', { method: 'POST' }),
  tlsCertDownload: () => requestBlob('/api/tls/cert'),
}
