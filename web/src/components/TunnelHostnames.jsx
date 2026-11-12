import { useCallback, useEffect, useState } from 'react'
import { api } from '../api'
import { useToast } from '../toast-context'

const REFRESH_MS = 20000

// How a hostname's DNS stands relative to the tunnel, as the server reports it.
const DNS_BADGE = {
  ok: { badge: 'badge-allowed', label: 'DNS ok' },
  proxy_off: { badge: 'badge-warn', label: 'Not proxied' },
  missing: { badge: 'badge-error', label: 'No DNS record' },
  conflict: { badge: 'badge-error', label: 'DNS conflict' },
  no_zone: { badge: 'badge-warn', label: 'Zone not found' },
  unknown: { badge: 'badge-warn', label: 'DNS unknown' },
}

const CUSTOM = '__custom__'
// How the tunnel checks the origin's TLS certificate: normally, as a named
// host (the certificate is for a public name but the tunnel dials localhost),
// or not at all (only reasonable for a hop on the same machine).
const CERT_VERIFY = 'verify'
const CERT_NAME = 'name'
const CERT_SKIP = 'skip'

const certModeOf = (o) => (o.origin_server_name ? CERT_NAME : o.no_tls_verify ? CERT_SKIP : CERT_VERIFY)

const blankForm = {
  hostname: '',
  preset: CUSTOM,
  service: '',
  path: '',
  certMode: CERT_VERIFY,
  serverName: '',
  createDns: true,
}

// TunnelHostnames lists the public hostnames on the Cloudflare tunnel, with the
// DNS record and local-origin state of each, and adds, edits and removes them.
// Changes are made on Cloudflare itself, so they take effect without
// restarting the tunnel.
export default function TunnelHostnames({ cf }) {
  const toast = useToast()
  const [data, setData] = useState(null)
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)
  const [busy, setBusy] = useState('')
  const [form, setForm] = useState(blankForm)
  const [editing, setEditing] = useState(false)
  const [removing, setRemoving] = useState(null) // { hostname, dns }

  const suggestions = cf?.suggested_origins || []
  const ready = !!cf?.api_token_set && !!cf?.tunnel_id && cf?.tunnel?.remotely_managed !== false

  const load = useCallback(async () => {
    setLoading(true)
    try {
      setData(await api.cfHostnames())
      setError('')
    } catch (e) {
      setError(e.message)
    }
    setLoading(false)
  }, [])

  useEffect(() => {
    if (!ready) return undefined
    // load sets state only after its fetch resolves, never synchronously.
    load()
    const t = setInterval(load, REFRESH_MS)
    return () => clearInterval(t)
  }, [ready, cf?.tunnel_id, load])

  const set = (patch) => setForm((f) => ({ ...f, ...patch }))

  const pickPreset = (value) => {
    if (value === CUSTOM) {
      set({ preset: CUSTOM })
      return
    }
    const s = suggestions[Number(value)]
    if (s) set({ preset: value, service: s.service, certMode: certModeOf(s), serverName: s.origin_server_name || '' })
  }

  const startEdit = (row) => {
    const idx = suggestions.findIndex((s) => s.service === row.service)
    setEditing(true)
    setForm({
      hostname: row.hostname,
      preset: idx >= 0 ? String(idx) : CUSTOM,
      service: row.service,
      path: row.path || '',
      certMode: certModeOf(row),
      serverName: row.origin_server_name || '',
      createDns: row.dns?.state !== 'ok',
    })
    document.getElementById('tunnel-hostname-form')?.scrollIntoView?.({ behavior: 'smooth', block: 'center' })
  }

  const cancelEdit = () => {
    setEditing(false)
    setForm(blankForm)
  }

  const save = async (e) => {
    e.preventDefault()
    setBusy('save')
    try {
      const res = await api.cfSaveHostname(
        {
          hostname: form.hostname.trim(),
          service: form.service.trim(),
          path: form.path.trim(),
          no_tls_verify: form.certMode === CERT_SKIP,
          origin_server_name: form.certMode === CERT_NAME ? form.serverName.trim() : '',
          create_dns: form.createDns,
        },
        editing,
      )
      if (res.dns_error) toast(`Saved, but the DNS record failed: ${res.dns_error}`, 'error')
      else if (res.dns?.state === 'conflict') toast(`Saved. DNS was left alone: ${res.dns.detail}`, 'error')
      else if (res.dns?.state === 'no_zone') toast(`Saved. ${res.dns.detail}`, 'error')
      else toast(editing ? 'Hostname updated' : 'Hostname added')
      cancelEdit()
      await load()
    } catch (err) {
      toast(err.message, 'error')
    }
    setBusy('')
  }

  const syncDns = async (row, overwrite) => {
    if (overwrite && !confirm(`Re-point ${row.hostname} at this tunnel?\n\nIts current CNAME record will be changed.`))
      return
    setBusy('dns:' + row.hostname)
    try {
      const res = await api.cfSyncDNS(row.hostname, overwrite)
      if (res.dns?.state === 'ok') toast(`DNS for ${row.hostname} now routes to the tunnel`)
      else toast(res.dns?.detail || 'DNS was not changed', 'error')
      await load()
    } catch (err) {
      toast(err.message, 'error')
    }
    setBusy('')
  }

  const confirmRemove = async () => {
    const { hostname, dns } = removing
    setBusy('rm:' + hostname)
    try {
      const res = await api.cfRemoveHostname(hostname, dns)
      if (res.dns_error) toast(`Removed, but its DNS record could not be deleted: ${res.dns_error}`, 'error')
      else toast(dns && res.dns_removed ? `Removed ${hostname} and its DNS record` : `Removed ${hostname}`)
      setRemoving(null)
      await load()
    } catch (err) {
      toast(err.message, 'error')
    }
    setBusy('')
  }

  let guidance = ''
  if (!cf) guidance = 'Loading…'
  else if (!cf.api_token_set) guidance = 'Connect a Cloudflare account above to manage this tunnel’s hostnames.'
  else if (!cf.tunnel_id) guidance = 'Pick or create a named tunnel above first.'
  else if (cf.tunnel && cf.tunnel.remotely_managed === false)
    guidance = 'This tunnel uses a local config file; switch to a remotely-managed tunnel to manage hostnames here.'

  const rows = data?.hostnames || []

  return (
    <div className="card">
      <div className="row-between">
        <h3>Public hostnames</h3>
        {ready && (
          <button className="btn small" type="button" onClick={load} disabled={loading}>
            ⟳ {loading ? 'Checking…' : 'Refresh'}
          </button>
        )}
      </div>

      {guidance && <div className="dim">{guidance}</div>}
      {ready && (
        <>
          <p className="dim small">
            Names that reach this server through the tunnel, stored on Cloudflare — adding or removing one takes effect
            immediately, with no restart. Unmatched requests get{' '}
            <span className="mono">{data?.catch_all || 'http_status:404'}</span>.
          </p>
          {error && <div className="error-text">{error}</div>}
          {data?.dns_denied_zones?.length > 0 && (
            <div className="error-text">
              Cloudflare is denying the API token access to DNS records in{' '}
              <strong>{data.dns_denied_zones.join(', ')}</strong>. The token can see the zone, but its DNS permission
              doesn&apos;t cover it: in Cloudflare, edit the token connected above and, under <em>Zone Resources</em>,
              include {data.dns_denied_zones.length > 1 ? 'these zones' : 'this zone'} (or All zones) for{' '}
              <strong>Zone → DNS → Edit</strong>. If you edited a different token, use <strong>Replace token</strong>{' '}
              above. This list rechecks every few seconds.
            </div>
          )}
          {data?.dns_error && (
            <div className="error-text">
              DNS status is incomplete: {data.dns_error}. The API token needs <strong>Zone → Zone → Read</strong> and{' '}
              <strong>Zone → DNS → Edit</strong>.
            </div>
          )}
          {data?.dns_via_acme && (
            <div className="dim small">
              DNS records were handled with the Cloudflare token from your certificate (ACME) settings, because the
              tunnel API token has no DNS access.
            </div>
          )}
          {data && rows.length === 0 && !error && <div className="dim small">No hostnames yet — add one below.</div>}

          {rows.length > 0 && (
            <div className="table-scroll">
              <table className="table">
                <thead>
                  <tr>
                    <th>Hostname</th>
                    <th>Origin</th>
                    <th>DNS</th>
                    <th />
                  </tr>
                </thead>
                <tbody>
                  {rows.map((row) => {
                    const d = DNS_BADGE[row.dns?.state] || DNS_BADGE.unknown
                    const canFix = row.dns?.state === 'missing' || row.dns?.state === 'proxy_off'
                    const canRepoint = row.dns?.state === 'conflict' && (row.dns.detail || '').startsWith('a CNAME')
                    return (
                      <tr key={row.hostname + (row.path || '')}>
                        <td>
                          <span className="mono">{row.hostname}</span>
                        </td>
                        <td>
                          <span className="row" style={{ gap: 6, alignItems: 'center' }}>
                            {row.origin_reachable !== null && row.origin_reachable !== undefined && (
                              <span
                                className={`dot ${row.origin_reachable ? 'ok' : 'bad'}`}
                                title={
                                  row.origin_reachable
                                    ? 'Accepting connections on this server'
                                    : 'Nothing is listening on this local origin'
                                }
                              />
                            )}
                            <span className="mono">{row.service}</span>
                            {row.path && <span className="dim small">path {row.path}</span>}
                            {row.origin_server_name && (
                              <span className="chip" title="The tunnel verifies the origin's certificate as this name">
                                verified as {row.origin_server_name}
                              </span>
                            )}
                            {row.no_tls_verify && <span className="chip">TLS not verified</span>}
                          </span>
                        </td>
                        <td>
                          <span className={`badge ${d.badge}`} title={row.dns?.detail || undefined}>
                            {d.label}
                          </span>
                        </td>
                        <td style={{ textAlign: 'right' }}>
                          <span className="row" style={{ gap: 6, justifyContent: 'flex-end' }}>
                            {canFix && (
                              <button
                                className="btn tiny"
                                type="button"
                                onClick={() => syncDns(row, false)}
                                disabled={!!busy}
                              >
                                Fix DNS
                              </button>
                            )}
                            {canRepoint && (
                              <button
                                className="btn tiny"
                                type="button"
                                onClick={() => syncDns(row, true)}
                                disabled={!!busy}
                              >
                                Re-point DNS
                              </button>
                            )}
                            <button className="btn tiny" type="button" onClick={() => startEdit(row)} disabled={!!busy}>
                              Edit
                            </button>
                            <button
                              className="btn tiny danger"
                              type="button"
                              onClick={() => setRemoving({ hostname: row.hostname, dns: true })}
                              disabled={!!busy}
                            >
                              Remove
                            </button>
                          </span>
                        </td>
                      </tr>
                    )
                  })}
                </tbody>
              </table>
            </div>
          )}

          {removing && (
            <div className="info-banner" role="alertdialog" aria-label="Confirm removal" style={{ marginTop: 12 }}>
              <div>
                Remove <strong className="mono">{removing.hostname}</strong> from the tunnel?
              </div>
              <label className="row dim small" style={{ gap: 6, margin: '8px 0' }}>
                <input
                  type="checkbox"
                  checked={removing.dns}
                  onChange={(e) => setRemoving({ ...removing, dns: e.target.checked })}
                />
                Also delete its DNS record (only if it points at this tunnel)
              </label>
              <div className="row" style={{ gap: 8 }}>
                <button
                  className="btn danger small"
                  type="button"
                  onClick={confirmRemove}
                  disabled={busy === 'rm:' + removing.hostname}
                >
                  Remove
                </button>
                <button className="btn small" type="button" onClick={() => setRemoving(null)}>
                  Cancel
                </button>
              </div>
            </div>
          )}

          <h4 id="tunnel-hostname-form" style={{ marginTop: 18 }}>
            {editing ? `Edit ${form.hostname}` : 'Add a hostname'}
          </h4>
          <form onSubmit={save} className="form-grid">
            <input
              className="input"
              placeholder="dns.example.com"
              aria-label="Hostname"
              value={form.hostname}
              onChange={(e) => set({ hostname: e.target.value })}
              disabled={editing}
            />
            <label className="input-label">
              Send to
              <select
                className="input"
                aria-label="Origin preset"
                value={form.preset}
                onChange={(e) => pickPreset(e.target.value)}
              >
                {suggestions.map((s, i) => (
                  <option key={s.service} value={String(i)}>
                    {s.label} — {s.service}
                  </option>
                ))}
                <option value={CUSTOM}>Custom origin…</option>
              </select>
            </label>
            {form.preset === CUSTOM && (
              <input
                className="input span-2"
                placeholder="https://localhost:443"
                aria-label="Origin URL"
                value={form.service}
                onChange={(e) => set({ service: e.target.value })}
              />
            )}
            <input
              className="input"
              placeholder="Path filter (optional), e.g. ^/dns-query"
              aria-label="Path filter"
              value={form.path}
              onChange={(e) => set({ path: e.target.value })}
            />
            {(form.service.trim().startsWith('https://') || form.certMode !== CERT_VERIFY) && (
              <label className="input-label">
                Origin certificate
                <select
                  className="input"
                  aria-label="Origin certificate"
                  value={form.certMode}
                  onChange={(e) => set({ certMode: e.target.value })}
                >
                  <option value={CERT_VERIFY}>Verify normally</option>
                  <option value={CERT_NAME}>Verify as a specific name…</option>
                  <option value={CERT_SKIP}>Don&apos;t verify (same-machine hop only)</option>
                </select>
              </label>
            )}
            {form.certMode === CERT_NAME && (
              <input
                className="input"
                placeholder="adguard2.example.com"
                aria-label="Certificate name"
                value={form.serverName}
                onChange={(e) => set({ serverName: e.target.value })}
              />
            )}
            <div className="row" style={{ gap: 16, flexWrap: 'wrap' }}>
              <label className="row dim small" style={{ gap: 6 }}>
                <input
                  type="checkbox"
                  checked={form.createDns}
                  onChange={(e) => set({ createDns: e.target.checked })}
                />
                Create / fix the DNS record
              </label>
            </div>
            <div className="row">
              <button
                className="btn primary"
                type="submit"
                disabled={
                  !form.hostname.trim() ||
                  !form.service.trim() ||
                  (form.certMode === CERT_NAME && !form.serverName.trim()) ||
                  busy === 'save'
                }
              >
                {busy === 'save' ? 'Saving…' : editing ? 'Save changes' : 'Add hostname'}
              </button>
              {editing && (
                <button className="btn" type="button" onClick={cancelEdit}>
                  Cancel
                </button>
              )}
            </div>
          </form>
          <p className="dim small">
            For Android Private DNS, point a hostname at your DoH origin, then set Private DNS to that hostname.
            Skipping TLS verification only applies to the hop from the tunnel to this server on the same machine.
          </p>
        </>
      )}
    </div>
  )
}
