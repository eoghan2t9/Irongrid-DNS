import { useEffect, useState, useCallback } from 'react'
import { api } from '../api'
import { useToast } from '../toast-context'
import { LineListField, XIcon } from './ui'
import { PIA_REGIONS, NORDVPN_COUNTRIES } from '../vpnRegions'

const emptyVPN = () => ({
  enabled: false,
  providers: { nordvpn: { token: '' }, pia: { username: '', password: '' } },
  profiles: [],
  routes: [],
})

// VPN is a dedicated page for domain-based split-tunnel VPN routing:
// selected domains' resolved answers are routed through a dedicated
// WireGuard tunnel to a NordVPN or PIA server instead of the host's normal
// default route (e.g. only bbc.co.uk through a UK server so iPlayer works
// while traveling). Round-trips the whole config object on save, like
// ClientGroups — there's no dedicated profiles/routes endpoint, only a
// read-only /api/vpn/status for live connection state.
export default function VPN() {
  const toast = useToast()
  const [cfg, setCfg] = useState(null)
  const [vpn, setVpnState] = useState(emptyVPN())
  const [status, setStatus] = useState([])
  const [dirty, setDirty] = useState(false)
  const [saving, setSaving] = useState(false)

  const load = useCallback(async () => {
    try {
      const c = await api.config()
      setCfg(c)
      setVpnState({ ...emptyVPN(), ...(c.vpn || {}) })
      setDirty(false)
    } catch (e) {
      toast('Failed to load configuration: ' + e.message, 'error')
    }
  }, [toast])

  useEffect(() => {
    load()
  }, [load])

  useEffect(() => {
    let cancelled = false
    const poll = async () => {
      try {
        const s = await api.vpnStatus()
        if (!cancelled) setStatus(Array.isArray(s) ? s : [])
      } catch {
        // Status is best-effort — a transient failure just keeps the last
        // known list on screen instead of showing an error toast.
      }
    }
    poll()
    const id = setInterval(poll, 5000)
    return () => {
      cancelled = true
      clearInterval(id)
    }
  }, [])

  const patch = (p) => {
    setVpnState((prev) => ({ ...prev, ...p }))
    setDirty(true)
  }
  const patchProvider = (provider, p) => {
    setVpnState((prev) => ({
      ...prev,
      providers: { ...prev.providers, [provider]: { ...prev.providers[provider], ...p } },
    }))
    setDirty(true)
  }

  const setProfile = (i, p) => {
    setVpnState((prev) => ({ ...prev, profiles: prev.profiles.map((x, idx) => (idx === i ? { ...x, ...p } : x)) }))
    setDirty(true)
  }
  const addProfile = () => {
    setVpnState((prev) => ({ ...prev, profiles: [...prev.profiles, { id: '', provider: 'pia', region: '' }] }))
    setDirty(true)
  }
  const removeProfile = (i) => {
    setVpnState((prev) => ({ ...prev, profiles: prev.profiles.filter((_, idx) => idx !== i) }))
    setDirty(true)
  }

  const setRoute = (i, p) => {
    setVpnState((prev) => ({ ...prev, routes: prev.routes.map((x, idx) => (idx === i ? { ...x, ...p } : x)) }))
    setDirty(true)
  }
  const addRoute = () => {
    setVpnState((prev) => ({ ...prev, routes: [...prev.routes, { profile: prev.profiles[0]?.id || '', domains: [] }] }))
    setDirty(true)
  }
  const removeRoute = (i) => {
    setVpnState((prev) => ({ ...prev, routes: prev.routes.filter((_, idx) => idx !== i) }))
    setDirty(true)
  }

  const save = async () => {
    setSaving(true)
    try {
      await api.saveConfig({ ...cfg, vpn })
      toast('VPN routing saved — reconnecting affected tunnels in the background.')
      await load()
    } catch (e) {
      toast('Save failed: ' + e.message, 'error')
    } finally {
      setSaving(false)
    }
  }

  if (!cfg) return <div className="loading">Loading…</div>

  const field = (label, hint, input) => (
    <label className="field">
      <span className="field-label">{label}</span>
      {input}
      {hint && <span className="field-hint">{hint}</span>}
    </label>
  )

  return (
    <div className="stack">
      <div className="card">
        <div className="row-between">
          <h3 style={{ margin: 0, display: 'flex', alignItems: 'center', gap: 10 }}>
            VPN split-tunnel routing
            {vpn.enabled && vpn.profiles.length > 0 && (
              <span
                className={`badge ${
                  status.length === 0
                    ? 'badge-error'
                    : status.length === vpn.profiles.length
                      ? 'badge-allowed'
                      : 'badge-warn'
                }`}
              >
                {status.length}/{vpn.profiles.length} connected
              </span>
            )}
          </h3>
          <div className="row">
            {dirty && <span className="dim small">unsaved changes</span>}
            <button className="btn primary" onClick={save} disabled={saving || !dirty}>
              {saving ? 'Saving…' : 'Save & apply'}
            </button>
          </div>
        </div>
        <p className="dim small">
          Route specific domains through a dedicated WireGuard tunnel to a NordVPN or PIA server instead of your normal
          connection — e.g. only bbc.co.uk/bbci.co.uk through a UK server so iPlayer works while traveling, with
          everything else unaffected. Requires this box to be your network's gateway (or at least in the forwarding
          path) and root/CAP_NET_ADMIN, plus the <span className="mono">ip</span>, <span className="mono">wg</span> and{' '}
          <span className="mono">nft</span> binaries. Linux only.
        </p>
        <div className="form-grid">
          <label className="field">
            <span className="field-label">Enabled</span>
            <label className="switch">
              <input type="checkbox" checked={!!vpn.enabled} onChange={(e) => patch({ enabled: e.target.checked })} />
              <span className="slider" />
            </label>
          </label>
        </div>
        {vpn.enabled && vpn.profiles.length === 0 && (
          <p className="info-banner" style={{ marginTop: 12 }}>
            Enabled, but no profile is configured yet — provider credentials alone don't connect anything. Add a profile
            below (id, provider, region), then a route pointing at it, and save.
          </p>
        )}
        {vpn.enabled && vpn.profiles.length > 0 && vpn.routes.length === 0 && (
          <p className="info-banner" style={{ marginTop: 12 }}>
            No routes yet — even once a profile connects, no domains will be sent through it until you add a route
            below.
          </p>
        )}
      </div>

      {status.length > 0 && (
        <div className="card">
          <h3>Connected tunnels</h3>
          <table className="table">
            <thead>
              <tr>
                <th>Profile</th>
                <th>Provider</th>
                <th>Region</th>
                <th>Interface</th>
                <th>Endpoint</th>
                <th>Up since</th>
              </tr>
            </thead>
            <tbody>
              {status.map((s) => (
                <tr key={s.id}>
                  <td className="mono">{s.id}</td>
                  <td>{s.provider}</td>
                  <td>{s.region}</td>
                  <td className="mono">{s.iface}</td>
                  <td className="mono">{s.endpoint}</td>
                  <td>{s.up_since ? new Date(s.up_since).toLocaleString() : ''}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      <div className="card">
        <h3>Provider credentials</h3>
        <div className="form-grid">
          {field(
            'NordVPN token',
            'nordvpn.com -> Account -> "Set up NordVPN manually"',
            <input
              className="input mono"
              type="password"
              value={vpn.providers.nordvpn.token || ''}
              onChange={(e) => patchProvider('nordvpn', { token: e.target.value })}
            />,
          )}
          {field(
            'PIA username',
            'your regular PIA account login',
            <input
              className="input"
              value={vpn.providers.pia.username || ''}
              onChange={(e) => patchProvider('pia', { username: e.target.value })}
            />,
          )}
          {field(
            'PIA password',
            '',
            <input
              className="input"
              type="password"
              value={vpn.providers.pia.password || ''}
              onChange={(e) => patchProvider('pia', { password: e.target.value })}
            />,
          )}
        </div>
      </div>

      <div className="card">
        <div className="row-between">
          <h3 style={{ margin: 0 }}>Profiles</h3>
        </div>
        <p className="dim small">
          One WireGuard tunnel to a specific provider region/server. Multiple routes can share a profile.
        </p>
        {vpn.profiles.length === 0 && <div className="empty">No profiles yet.</div>}
        {vpn.profiles.map((p, i) => {
          const live = status.find((s) => s.id === p.id)
          return (
            <div className="list-row" key={i}>
              <span
                className={`dot ${live ? 'ok' : 'bad'}`}
                title={live ? `Connected — ${live.endpoint}` : 'Not connected'}
                style={{ flexShrink: 0 }}
              />
              <input
                className="input"
                placeholder="id (e.g. uk-streaming)"
                value={p.id || ''}
                onChange={(e) => setProfile(i, { id: e.target.value })}
              />
              <select
                className="input"
                value={p.provider || 'pia'}
                onChange={(e) => setProfile(i, { provider: e.target.value })}
              >
                <option value="pia">PIA</option>
                <option value="nordvpn">NordVPN</option>
              </select>
              <input
                className="input mono"
                list={p.provider === 'nordvpn' ? 'nordvpn-countries' : 'pia-regions'}
                placeholder={p.provider === 'nordvpn' ? 'country code, e.g. gb' : 'PIA region, e.g. uk_london'}
                value={p.region || ''}
                onChange={(e) => setProfile(i, { region: e.target.value })}
              />
              <button
                className="btn small danger"
                type="button"
                onClick={() => removeProfile(i)}
                aria-label={`Remove profile ${p.id || i + 1}`}
              >
                <XIcon size={12} />
              </button>
            </div>
          )
        })}
        <div className="quick-actions" style={{ marginTop: 12 }}>
          <button className="btn small" type="button" onClick={addProfile}>
            + Add profile
          </button>
        </div>
      </div>

      <div className="card">
        <div className="row-between">
          <h3 style={{ margin: 0 }}>Routes</h3>
        </div>
        <p className="dim small">Every domain listed (and its subdomains) routes through its profile's tunnel.</p>
        {vpn.routes.length === 0 && (
          <div className="empty">No routes yet — no traffic is redirected even if a profile is connected.</div>
        )}
        {vpn.routes.map((rt, i) => (
          <div className="blocklist-row" key={i}>
            <div className="list-row">
              <select
                className="input"
                value={rt.profile || ''}
                onChange={(e) => setRoute(i, { profile: e.target.value })}
              >
                <option value="">select a profile…</option>
                {vpn.profiles.map((p) => (
                  <option key={p.id} value={p.id}>
                    {p.id}
                  </option>
                ))}
              </select>
              <button
                className="btn small danger"
                type="button"
                onClick={() => removeRoute(i)}
                aria-label={`Remove route ${i + 1}`}
              >
                <XIcon size={12} />
              </button>
            </div>
            <div className="form-grid">
              {field(
                'Domains',
                'one per line, e.g. bbc.co.uk — matches the domain and every subdomain',
                <LineListField value={rt.domains} onChange={(v) => setRoute(i, { domains: v })} rows={3} />,
              )}
            </div>
          </div>
        ))}
        <div className="quick-actions" style={{ marginTop: 12 }}>
          <button className="btn small" type="button" onClick={addRoute}>
            + Add route
          </button>
        </div>
      </div>

      <datalist id="pia-regions">
        {PIA_REGIONS.map((r) => (
          <option key={r.id} value={r.id}>
            {r.name}
          </option>
        ))}
      </datalist>
      <datalist id="nordvpn-countries">
        {NORDVPN_COUNTRIES.map((c) => (
          <option key={c.code} value={c.code}>
            {c.name}
          </option>
        ))}
      </datalist>
    </div>
  )
}
