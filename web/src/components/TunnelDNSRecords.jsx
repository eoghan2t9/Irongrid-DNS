import { useCallback, useEffect, useState } from 'react'
import { api } from '../api'
import { useToast } from '../toast-context'

const STATE_BADGE = {
  ok: { badge: 'badge-allowed', label: 'Correct' },
  missing: { badge: 'badge-warn', label: 'Missing' },
  differs: { badge: 'badge-warn', label: 'Out of date' },
  conflict: { badge: 'badge-error', label: 'Conflict' },
  extra: { badge: 'badge-cached', label: 'Not needed' },
}

const ACTION_LABEL = { create: 'Create', update: 'Update', delete: 'Remove', none: '—' }

const fmtTime = (iso) => (iso ? new Date(iso).toLocaleString([], { hour12: false }) : '')

const draftFrom = (plan) => ({
  host: plan?.settings?.host || '',
  autoSync: !!plan?.settings?.auto_sync,
  ipv4: plan?.settings?.ipv4 || '',
  ipv6: plan?.settings?.ipv6 || '',
  skipHttps: !!plan?.settings?.skip_https,
})

// TunnelDNSRecords shows the public DNS records this server's encrypted
// protocols need (the hostname's addresses, SVCB records that let clients
// discover DoH / DoT / DoQ, and an HTTPS record), compares them with
// Cloudflare, and applies the difference on request. Optionally it keeps them
// in step in the background; that never deletes anything.
export default function TunnelDNSRecords({ cf }) {
  const toast = useToast()
  const [plan, setPlan] = useState(null)
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)
  const [busy, setBusy] = useState('')
  const [draft, setDraft] = useState(draftFrom(null))
  const [advanced, setAdvanced] = useState(false)
  const [prune, setPrune] = useState(false)

  const ready = !!cf?.api_token_set

  const adopt = useCallback((p) => {
    setPlan(p)
    setDraft(draftFrom(p))
  }, [])

  const load = useCallback(async () => {
    setLoading(true)
    try {
      adopt(await api.cfDNSPlan())
      setError('')
    } catch (e) {
      setError(e.message)
    }
    setLoading(false)
  }, [adopt])

  useEffect(() => {
    // load sets state only after its fetch resolves, never synchronously.
    if (ready) load()
  }, [ready, load])

  const set = (patch) => setDraft((d) => ({ ...d, ...patch }))

  const saveSettings = async (e) => {
    e.preventDefault()
    setBusy('save')
    try {
      const res = await api.cfDNSSettings({
        host: draft.host.trim(),
        auto_sync: draft.autoSync,
        ipv4: draft.ipv4.trim(),
        ipv6: draft.ipv6.trim(),
        skip_https: draft.skipHttps,
      })
      if (res.items) adopt(res)
      else await load()
      setError('')
      toast('DNS settings saved')
    } catch (err) {
      toast(err.message, 'error')
    }
    setBusy('')
  }

  const counts = plan?.counts || {}
  const pending = (counts.create || 0) + (counts.update || 0)
  const removable = counts.delete || 0
  const todo = pending + (prune ? removable : 0)

  const apply = async () => {
    const parts = []
    if (counts.create) parts.push(`${counts.create} to create`)
    if (counts.update) parts.push(`${counts.update} to update`)
    if (prune && removable) parts.push(`${removable} to remove`)
    if (!confirm(`Apply these changes in ${plan.zone || 'your Cloudflare zone'}?\n\n${parts.join(', ')}.`)) return
    setBusy('apply')
    try {
      const res = await api.cfDNSApply(prune)
      adopt(res.plan)
      const failed = (res.results || []).filter((r) => !r.ok)
      const done = (res.results || []).length - failed.length
      if (failed.length)
        toast(
          `${done} applied, ${failed.length} failed: ${failed[0].type} ${failed[0].name}: ${failed[0].error}`,
          'error',
        )
      else toast(`${done} DNS record${done === 1 ? '' : 's'} applied`)
      setPrune(false)
    } catch (err) {
      toast(err.message, 'error')
    }
    setBusy('')
  }

  let status = null
  if (plan && !plan.needs_host && !plan.error && plan.items?.length) {
    if (plan.in_sync) status = { badge: 'badge-allowed', label: 'In sync' }
    else if (counts.conflict) status = { badge: 'badge-error', label: 'Needs attention' }
    else status = { badge: 'badge-warn', label: `${pending} change${pending === 1 ? '' : 's'} to apply` }
  }

  return (
    <div className="card">
      <div className="row-between">
        <h3>DNS records for your protocols</h3>
        <span className="row" style={{ gap: 8, alignItems: 'center' }}>
          {status && <span className={`badge ${status.badge}`}>{status.label}</span>}
          {ready && (
            <button className="btn small" type="button" onClick={load} disabled={loading}>
              ⟳ {loading ? 'Checking…' : 'Re-check'}
            </button>
          )}
        </span>
      </div>

      {!ready && <div className="dim">Connect a Cloudflare account above to publish these records.</div>}

      {ready && (
        <>
          <p className="dim small">
            Clients find your encrypted DNS through public DNS records: the hostname&apos;s addresses, discovery records
            that say which protocols and ports are offered, and an HTTPS record. They are worked out from the listeners
            you have enabled, and the addresses are DNS-only because DoT and DoQ can&apos;t go through Cloudflare&apos;s
            proxy.
          </p>
          {error && <div className="error-text">{error}</div>}

          {plan && (
            <>
              <div className="row" style={{ gap: 8, flexWrap: 'wrap', marginBottom: 8 }}>
                {plan.protocols.map((p) => (
                  <span className="chip" key={p.name}>
                    {p.name} :{p.port}
                    {p.path ? ` ${p.path}` : ''}
                  </span>
                ))}
                {plan.protocols.length === 0 && <span className="dim small">No encrypted protocol is enabled.</span>}
              </div>

              <form onSubmit={saveSettings} className="form-grid">
                <input
                  className="input"
                  aria-label="Hostname to publish"
                  placeholder={plan.host_default || 'dns.example.com'}
                  value={draft.host}
                  onChange={(e) => set({ host: e.target.value })}
                />
                <label className="row dim small" style={{ gap: 6 }}>
                  <input
                    type="checkbox"
                    checked={draft.autoSync}
                    onChange={(e) => set({ autoSync: e.target.checked })}
                  />
                  Keep these records in sync automatically
                </label>
                {advanced && (
                  <>
                    <input
                      className="input"
                      aria-label="Public IPv4 override"
                      placeholder={
                        plan.detected?.ipv4 ? `IPv4 (detected ${plan.detected.ipv4})` : 'Public IPv4, or "off"'
                      }
                      value={draft.ipv4}
                      onChange={(e) => set({ ipv4: e.target.value })}
                    />
                    <input
                      className="input"
                      aria-label="Public IPv6 override"
                      placeholder={
                        plan.detected?.ipv6 ? `IPv6 (detected ${plan.detected.ipv6})` : 'Public IPv6, or "off"'
                      }
                      value={draft.ipv6}
                      onChange={(e) => set({ ipv6: e.target.value })}
                    />
                    <label className="row dim small" style={{ gap: 6 }}>
                      <input
                        type="checkbox"
                        checked={draft.skipHttps}
                        onChange={(e) => set({ skipHttps: e.target.checked })}
                      />
                      Don&apos;t publish an HTTPS record
                    </label>
                  </>
                )}
                <div className="row" style={{ gap: 8 }}>
                  <button className="btn" type="submit" disabled={busy === 'save'}>
                    {busy === 'save' ? 'Saving…' : 'Save settings'}
                  </button>
                  <button className="btn ghost small" type="button" onClick={() => setAdvanced((a) => !a)}>
                    {advanced ? 'Hide advanced' : 'Advanced'}
                  </button>
                </div>
              </form>

              {plan.needs_host && (
                <div className="dim" style={{ marginTop: 10 }}>
                  Choose the hostname clients will use (for example <span className="mono">dns.example.com</span>)
                  above. It has to be in a zone on your Cloudflare account and covered by your TLS certificate.
                </div>
              )}
              {plan.error && (
                <div className="error-text" style={{ marginTop: 10 }}>
                  {plan.error}
                </div>
              )}
              {!plan.needs_host && (
                <div className="dim small" style={{ marginTop: 10 }}>
                  Publishing <span className="mono">{plan.host}</span>
                  {plan.zone && <> in {plan.zone}</>} →{' '}
                  <span className="mono">{[...plan.ipv4, ...plan.ipv6].join(', ') || 'no address'}</span>
                </div>
              )}
              {plan.notes.map((n) => (
                <div className="dim small" key={n} style={{ marginTop: 4 }}>
                  ⚠ {n}
                </div>
              ))}

              {plan.items.length > 0 && (
                <div className="table-scroll" style={{ marginTop: 12 }}>
                  <table className="table">
                    <thead>
                      <tr>
                        <th>Record</th>
                        <th>Value</th>
                        <th>Status</th>
                        <th>Will</th>
                      </tr>
                    </thead>
                    <tbody>
                      {plan.items.map((it, i) => {
                        const s = STATE_BADGE[it.state] || STATE_BADGE.missing
                        return (
                          <tr key={`${it.type}-${it.name}-${it.record_id || i}-${i}`}>
                            <td title={it.purpose || undefined}>
                              <span className="chip">{it.type}</span> <span className="mono">{it.name}</span>
                            </td>
                            <td>
                              <span className="mono small">{it.want || it.have}</span>
                              {it.state === 'differs' && it.have && <div className="dim small">now: {it.have}</div>}
                            </td>
                            <td>
                              <span className={`badge ${s.badge}`} title={it.detail || undefined}>
                                {s.label}
                              </span>
                              {it.detail && it.state !== 'differs' && <div className="dim small">{it.detail}</div>}
                            </td>
                            <td>{ACTION_LABEL[it.action] || '—'}</td>
                          </tr>
                        )
                      })}
                    </tbody>
                  </table>
                </div>
              )}

              {plan.items.length > 0 && (
                <div className="row" style={{ gap: 12, marginTop: 12, flexWrap: 'wrap', alignItems: 'center' }}>
                  <button className="btn primary" type="button" onClick={apply} disabled={todo === 0 || !!busy}>
                    {busy === 'apply'
                      ? 'Applying…'
                      : todo === 0
                        ? 'Nothing to apply'
                        : `Apply ${todo} change${todo === 1 ? '' : 's'}`}
                  </button>
                  {removable > 0 && (
                    <label className="row dim small" style={{ gap: 6 }}>
                      <input type="checkbox" checked={prune} onChange={(e) => setPrune(e.target.checked)} />
                      Also remove {removable} record{removable === 1 ? '' : 's'} this server no longer needs
                    </label>
                  )}
                </div>
              )}

              {plan.sync && (
                <div className="dim small" style={{ marginTop: 10 }}>
                  Last automatic sync {fmtTime(plan.sync.at)}:{' '}
                  {plan.sync.error
                    ? `failed — ${plan.sync.error}`
                    : plan.sync.changed
                      ? `updated ${plan.sync.applied} record${plan.sync.applied === 1 ? '' : 's'}`
                      : 'nothing needed changing'}
                  {plan.sync.conflicts > 0 &&
                    ` · ${plan.sync.conflicts} conflict${plan.sync.conflicts === 1 ? '' : 's'} left for you`}
                </div>
              )}
              {plan.settings.auto_sync && (
                <div className="dim small">
                  Automatic sync creates and updates records when this server&apos;s address changes; it never deletes
                  any.
                </div>
              )}
            </>
          )}
        </>
      )}
    </div>
  )
}
