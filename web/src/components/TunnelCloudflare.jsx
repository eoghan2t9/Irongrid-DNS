import { useCallback, useEffect, useState } from 'react'
import { api } from '../api'
import { useToast } from '../toast-context'

// Cloudflare's own words for a tunnel's health, mapped onto our badges.
const HEALTH = {
  healthy: { badge: 'badge-allowed', label: 'Healthy' },
  degraded: { badge: 'badge-warn', label: 'Degraded' },
  down: { badge: 'badge-error', label: 'Down' },
  inactive: { badge: 'badge-warn', label: 'Inactive' },
}

const fmtDate = (iso) =>
  iso ? new Date(iso).toLocaleDateString([], { year: 'numeric', month: 'short', day: 'numeric' }) : ''

function Health({ status }) {
  const h = HEALTH[status] || { badge: 'badge-warn', label: status || 'Unknown' }
  return <span className={`badge ${h.badge}`}>{h.label}</span>
}

// TunnelCloudflare connects a Cloudflare API token and manages which tunnel
// this server runs: pick an existing one, create a new one, or delete an
// unused one. cf is the /api/tunnel/cf/status document owned by the page.
export default function TunnelCloudflare({ cf, reload, tunnelRunning }) {
  const toast = useToast()
  const [token, setToken] = useState('')
  const [accountId, setAccountId] = useState('')
  const [askAccount, setAskAccount] = useState(false)
  const [replacing, setReplacing] = useState(false)
  const [busy, setBusy] = useState('')
  const [tunnels, setTunnels] = useState(null)
  const [tunnelsError, setTunnelsError] = useState('')
  const [newName, setNewName] = useState('')
  const [useNew, setUseNew] = useState(true)

  const connected = !!cf?.api_token_set

  const loadTunnels = useCallback(async () => {
    try {
      const r = await api.cfTunnels()
      setTunnels(r.tunnels || [])
      setTunnelsError('')
    } catch (e) {
      setTunnels(null)
      setTunnelsError(e.message)
    }
  }, [])

  useEffect(() => {
    // loadTunnels sets state only after its fetch resolves, never synchronously.
    if (connected) loadTunnels()
  }, [connected, cf?.tunnel_id, loadTunnels])

  const refresh = async () => {
    await reload()
    await loadTunnels()
  }

  const connect = async (e) => {
    e.preventDefault()
    setBusy('connect')
    try {
      await api.cfSetCredentials({ api_token: token.trim(), account_id: accountId.trim() })
      toast('Cloudflare account connected')
      setToken('')
      setAccountId('')
      setAskAccount(false)
      setReplacing(false)
      await refresh()
    } catch (err) {
      if (/several accounts/i.test(err.message)) setAskAccount(true)
      toast(err.message, 'error')
    }
    setBusy('')
  }

  const disconnect = async () => {
    if (!confirm('Disconnect the Cloudflare account? Hostnames and DNS already on Cloudflare are not touched.')) return
    setBusy('disconnect')
    try {
      await api.cfSetCredentials({ api_token: '' })
      toast('Cloudflare account disconnected')
      setTunnels(null)
      await reload()
    } catch (err) {
      toast(err.message, 'error')
    }
    setBusy('')
  }

  const switchTunnel = async (t) => {
    setBusy('use:' + t.id)
    try {
      await api.cfSelectTunnel(t.id)
      toast(`Now using “${t.name}”`)
      await refresh()
    } catch (err) {
      toast(err.message, 'error')
    }
    setBusy('')
  }

  const removeTunnel = async (t) => {
    if (
      !confirm(
        `Delete the tunnel “${t.name}” from Cloudflare?\n\nThis cannot be undone. Cloudflare refuses while a connector is attached.`,
      )
    )
      return
    setBusy('del:' + t.id)
    try {
      await api.cfDeleteTunnel(t.id)
      toast(`Deleted “${t.name}”`)
      await loadTunnels()
    } catch (err) {
      toast(err.message, 'error')
    }
    setBusy('')
  }

  const createTunnel = async (e) => {
    e.preventDefault()
    setBusy('create')
    try {
      await api.cfCreateTunnel({ name: newName.trim(), select: useNew })
      toast(useNew ? 'Tunnel created and selected' : 'Tunnel created')
      setNewName('')
      await refresh()
    } catch (err) {
      toast(err.message, 'error')
    }
    setBusy('')
  }

  const connectForm = (
    <form onSubmit={connect} className="form-grid">
      <input
        className="input span-2"
        type="password"
        autoComplete="off"
        placeholder="Cloudflare API token"
        aria-label="Cloudflare API token"
        value={token}
        onChange={(e) => setToken(e.target.value)}
      />
      {askAccount && (
        <input
          className="input span-2"
          placeholder="Account ID (this token can see several accounts)"
          aria-label="Cloudflare account ID"
          value={accountId}
          onChange={(e) => setAccountId(e.target.value)}
        />
      )}
      <div className="row">
        <button className="btn primary" type="submit" disabled={!token.trim() || busy === 'connect'}>
          {busy === 'connect' ? 'Checking…' : 'Connect'}
        </button>
        {replacing && (
          <button className="btn" type="button" onClick={() => setReplacing(false)}>
            Cancel
          </button>
        )}
      </div>
    </form>
  )

  return (
    <div className="card">
      <div className="row-between">
        <h3>Cloudflare account</h3>
        {connected && (
          <span className="row" style={{ gap: 8 }}>
            <button className="btn small" type="button" onClick={() => setReplacing((r) => !r)}>
              Replace token
            </button>
            <button className="btn small danger" type="button" onClick={disconnect} disabled={busy === 'disconnect'}>
              Disconnect
            </button>
          </span>
        )}
      </div>

      {!cf && <div className="dim small">Loading…</div>}

      {cf && !connected && (
        <>
          <p className="dim">
            Connect a Cloudflare API token to manage this tunnel from here: pick or create the tunnel, add public
            hostnames and have their DNS records created for you. Create the token in Cloudflare under{' '}
            <em>My Profile → API Tokens</em> with these permissions:
          </p>
          <ul className="dim small">
            <li>
              <strong>Account → Cloudflare Tunnel → Edit</strong>
            </li>
            <li>
              <strong>Zone → DNS → Edit</strong> and <strong>Zone → Zone → Read</strong> (for the domains you will use)
            </li>
          </ul>
          {connectForm}
          <p className="dim small">
            The token is stored in Irongrid&apos;s config file and is never shown again or sent back to this page.
          </p>
        </>
      )}

      {connected && (
        <>
          <div className="dim small">
            Connected to account <span className="mono">{cf.account_id || '—'}</span>
          </div>
          {replacing && <div style={{ marginTop: 12 }}>{connectForm}</div>}
          {cf.error && (
            <div className="error-text" style={{ marginTop: 8 }}>
              {cf.permission
                ? 'Cloudflare is refusing this token — it may have been revoked or lack a permission. Replace it above. '
                : ''}
              {cf.error}
            </div>
          )}

          {cf.tunnel ? (
            <div style={{ marginTop: 12 }}>
              <div className="row" style={{ gap: 10, alignItems: 'center' }}>
                <strong>{cf.tunnel.name}</strong>
                <Health status={cf.tunnel.status} />
                <span className="dim small">
                  {cf.tunnel.connections.length} connector connection{cf.tunnel.connections.length === 1 ? '' : 's'}
                  {cf.tunnel.connections.length > 0 &&
                    ' · ' + [...new Set(cf.tunnel.connections.map((c) => c.colo))].join(', ')}
                </span>
              </div>
              {!cf.tunnel.remotely_managed && (
                <div className="error-text" style={{ marginTop: 6 }}>
                  This tunnel is configured by a local config file, so its hostnames can&apos;t be managed from here.
                  Pick or create a remotely-managed tunnel below.
                </div>
              )}
            </div>
          ) : (
            !cf.error && (
              <div className="dim" style={{ marginTop: 12 }}>
                No named tunnel is selected yet. Pick one below or create a new one.
              </div>
            )
          )}

          <h4 style={{ marginTop: 18 }}>Tunnels on this account</h4>
          {tunnelsError && <div className="error-text">{tunnelsError}</div>}
          {tunnels && tunnels.length === 0 && <div className="dim small">No tunnels yet.</div>}
          {tunnels && tunnels.length > 0 && (
            <div className="table-scroll">
              <table className="table">
                <thead>
                  <tr>
                    <th>Name</th>
                    <th>Status</th>
                    <th>Connectors</th>
                    <th>Created</th>
                    <th />
                  </tr>
                </thead>
                <tbody>
                  {tunnels.map((t) => (
                    <tr key={t.id}>
                      <td>
                        {t.name}
                        {!t.remotely_managed && <span className="dim small"> (local config)</span>}
                      </td>
                      <td>
                        <Health status={t.status} />
                      </td>
                      <td>{t.connections.length}</td>
                      <td>{fmtDate(t.created_at)}</td>
                      <td style={{ textAlign: 'right' }}>
                        {t.selected ? (
                          <span className="badge badge-cached">In use</span>
                        ) : (
                          <span className="row" style={{ gap: 6, justifyContent: 'flex-end' }}>
                            <button
                              className="btn tiny"
                              type="button"
                              onClick={() => switchTunnel(t)}
                              disabled={tunnelRunning || !!busy}
                              title={tunnelRunning ? 'Stop the tunnel before switching' : undefined}
                            >
                              Use
                            </button>
                            <button
                              className="btn tiny danger"
                              type="button"
                              onClick={() => removeTunnel(t)}
                              disabled={!!busy}
                            >
                              Delete
                            </button>
                          </span>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
          {tunnelRunning && (
            <div className="dim small" style={{ marginTop: 6 }}>
              The tunnel is running — stop it to switch to a different one.
            </div>
          )}

          <form onSubmit={createTunnel} className="row" style={{ gap: 8, marginTop: 14, flexWrap: 'wrap' }}>
            <input
              className="input"
              placeholder="New tunnel name"
              aria-label="New tunnel name"
              value={newName}
              onChange={(e) => setNewName(e.target.value)}
            />
            <label className="row dim small" style={{ gap: 6 }}>
              <input type="checkbox" checked={useNew} onChange={(e) => setUseNew(e.target.checked)} />
              Use it for this server
            </label>
            <button className="btn" type="submit" disabled={!newName.trim() || !!busy || (useNew && tunnelRunning)}>
              {busy === 'create' ? 'Creating…' : 'Create tunnel'}
            </button>
          </form>
        </>
      )}
    </div>
  )
}
