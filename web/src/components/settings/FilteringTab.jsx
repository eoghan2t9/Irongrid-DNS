// FilteringTab is the "Filtering" sub page of Settings: the global behavior
// applied to every installed blocklist (the lists themselves live on the
// dedicated Blocklists page).
export default function FilteringTab({ f }) {
  const { set, field, number, toggle, textarea } = f
  return (
    <div className="card">
      <h3>Filtering</h3>
      <p className="dim small" style={{ marginTop: -6 }}>
        Manage which blocklists are installed on the dedicated <strong>Blocklists</strong> page — this is just the
        global behavior that applies to all of them.
      </p>
      <div className="form-grid">
        {field(
          'Block response',
          'nxdomain, refused, or an IP like 0.0.0.0',
          <input
            className="input mono"
            value={f.cfg.filter.block_response}
            onChange={(e) => set('filter.block_response', e.target.value)}
          />,
        )}
        {number('Block TTL (s)', 'filter.block_ttl')}
        {field(
          'Blocklist auto-update',
          'how often every enabled blocklist refreshes itself',
          <select
            className="input"
            value={f.cfg.filter.auto_update || ''}
            onChange={(e) => set('filter.auto_update', e.target.value)}
          >
            <option value="">Never</option>
            <option value="6h">Every 6 hours</option>
            <option value="24h">Daily</option>
            <option value="168h">Weekly</option>
          </select>,
        )}
        {textarea('Whitelist (always allow)', 'filter.whitelist')}
        {textarea('Blacklist (always block)', 'filter.blacklist')}
      </div>
      <p className="dim small">
        <strong>CNAME cloaking protection</strong> checks every CNAME a query resolves through, not just the name you
        asked for — trackers hide behind first-party-looking subdomains that CNAME to a blocklisted domain, and this
        catches that. Off by default: a CNAME chain through a shared CDN could in principle collide with an overly broad
        blocklist entry.
      </p>
      <div className="form-grid">{toggle('Block CNAME-cloaked trackers', 'filter.cname_cloaking_protection')}</div>
    </div>
  )
}
