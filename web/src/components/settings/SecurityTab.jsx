import { AlertIcon } from '../ui'

// SecurityTab is the "Security" sub page of Settings: rate limiting (with
// the currently auto-blocked clients), geo blocking (with honeypot-blocked
// clients and country-data status) and abuse reporting. The blocked-client
// lists are tables with right-aligned action columns so rows stay aligned
// no matter how many actions a row offers.
export default function SecurityTab({ f }) {
  const { set, field, text, number, toggle, textarea, deepGet } = f
  return (
    <>
      <div className="card">
        <h3>Rate limiting &amp; abuse protection</h3>
        <p className="dim small" style={{ marginTop: -6 }}>
          Throttles queries per client IP — a defense against a compromised LAN device or a public listener being abused
          for DNS amplification. UDP queries over the limit are dropped silently (answering at all would still amplify
          toward a spoofed source); TCP/DoT/DoH/DoQ get REFUSED. With <strong>auto-block</strong>, a client that keeps
          tripping the limit is refused entirely for the cooldown window instead of just being throttled back.
        </p>
        <div className="form-grid">
          {toggle('Enable rate limiting', 'rate_limit.enabled')}
          {number('Sustained queries/sec per client', 'rate_limit.qps')}
          {number('Burst allowance per client', 'rate_limit.burst')}
          {toggle('Auto-block repeat offenders', 'rate_limit.auto_block')}
          {number('Violations before blocking', 'rate_limit.block_after')}
          {text('Block cooldown', 'rate_limit.block_for', 'e.g. 10m, 1h', '10m')}
          {toggle('NXDOMAIN flood guard', 'rate_limit.nxdomain_guard.enabled')}
          {number('NXDOMAINs before blocking (per prefix)', 'rate_limit.nxdomain_guard.threshold')}
          {text('Counting window', 'rate_limit.nxdomain_guard.window', 'e.g. 30s, 1m', '30s')}
          {text('Flood cooldown', 'rate_limit.nxdomain_guard.block_for', 'e.g. 10m, 1h', '10m')}
        </div>
        <p className="dim small" style={{ marginTop: 8 }}>
          The <strong>NXDOMAIN flood guard</strong> throttles random-subdomain ("water torture") attacks: it counts
          NXDOMAIN responses served per client prefix (IPv4 /24, IPv6 /64) and refuses every query from a prefix that
          produces the threshold within the counting window, for the cooldown. Unlike per-IP rate limiting, a flood
          spread over many sources or churned IPv6 privacy addresses can't dodge it. Works independently of rate
          limiting. Off by default.
        </p>
        <h4 style={{ margin: '16px 0 10px' }}>Currently blocked clients</h4>
        {f.blocked.length === 0 ? (
          <p className="dim small">No clients are currently auto-blocked.</p>
        ) : (
          <div className="table-scroll">
            <table className="table">
              <thead>
                <tr>
                  <th>Client</th>
                  <th>Blocked</th>
                  <th className="actions-cell">Actions</th>
                </tr>
              </thead>
              <tbody>
                {f.blocked.map((b) => (
                  <tr key={b.ip}>
                    <td>
                      <div className="mono">{b.ip}</div>
                      {b.first_seen && (
                        <div className="dim small">first seen {new Date(b.first_seen).toLocaleString()}</div>
                      )}
                    </td>
                    <td className="dim small">
                      until {new Date(b.blocked_until).toLocaleString()} · {b.queries ?? 0} queries · blocked{' '}
                      {b.blocks ?? 0}×
                    </td>
                    <td className="actions-cell">
                      <button className="btn tiny danger" type="button" onClick={() => f.unblock(b.ip)}>
                        Unblock
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        <div className="quick-actions" style={{ marginTop: 8 }}>
          <button className="btn small" type="button" onClick={f.loadAbuse}>
            Refresh list
          </button>
        </div>
      </div>

      <div className="card">
        <h3>Geo blocking</h3>
        <p className="dim small" style={{ marginTop: -6 }}>
          Refuses queries (<strong>REFUSED</strong> on every transport) from client IPs that belong to the selected
          countries. Country data comes from free per-country CIDR lists (ipverse/rir-ip) fetched automatically and
          cached locally — no account or API key needed. Allowlisted IPs/CIDRs always pass.
        </p>
        <div className="form-grid">
          {toggle('Enable geo blocking', 'geo_block.enabled')}
          {textarea('Blocked countries (ISO 3166-1 alpha-2)', 'geo_block.countries', 'one per line, e.g. RU, CN, KP')}
          {textarea(
            'Blocked client IPs / CIDRs',
            'geo_block.ips',
            'always refused regardless of country — e.g. known proxy-exit ranges like 38.11.0.0/17; feeds DNS and the host firewall',
          )}
          {textarea(
            'Honeypot domains',
            'geo_block.honeypots',
            'one per line — a trap matches the domain AND every subdomain under it (DDoS floods randomise the first label); a client that queries it over TCP/DoT/DoH/DoQ is blocked permanently (persisted, dropped at the firewall) until you unblock it below; plain-UDP hits are silently dropped (never answered — replying would amplify a spoofed flood) and never auto-block unless you enable the bounded UDP block or trust_udp below; trap traffic is not written to the query log',
          )}
          {toggle('Trust UDP honeypot hits (permanent auto-block)', 'geo_block.trust_udp')}
          {field(
            'Auto-block UDP honeypot sources (bounded)',
            'drop plain-UDP honeypot traffic and block its source for this window via the rate limiter — the middle ground between never blocking UDP (a flood never stops) and trust_udp (permanent blocks a spoofed source could abuse). Needs rate limiting enabled. Blocked sources show on the dashboard with a countdown and can be unblocked early.',
            <select
              className="input"
              value={deepGet('geo_block.honeypot_udp_block', '') || ''}
              onChange={(e) => set('geo_block.honeypot_udp_block', e.target.value)}
            >
              <option value="">Disabled</option>
              <option value="5m">5 minutes</option>
              <option value="10m">10 minutes</option>
              <option value="30m">30 minutes</option>
              <option value="1h">1 hour</option>
            </select>,
          )}
          {textarea('Allowlist (IPs / CIDRs)', 'geo_block.allowlist', 'clients that are never geo-blocked')}
          {text(
            'Data source URL (optional)',
            'geo_block.base_url',
            'defaults to ipverse/rir-ip; appends &lt;cc&gt;/ipv4-aggregated.txt and &lt;cc&gt;/ipv6-aggregated.txt (lowercase codes)',
          )}
          {field(
            'Auto-refresh country data',
            'how often the per-country CIDR lists re-fetch themselves',
            <select
              className="input"
              value={deepGet('geo_block.auto_update', '') || ''}
              onChange={(e) => set('geo_block.auto_update', e.target.value)}
            >
              <option value="">Never</option>
              <option value="6h">Every 6 hours</option>
              <option value="24h">Daily</option>
              <option value="168h">Weekly</option>
            </select>,
          )}
        </div>
        {deepGet('geo_block.enabled', false) &&
          (deepGet('geo_block.countries', []) || []).length === 0 &&
          (deepGet('geo_block.ips', []) || []).length === 0 &&
          (deepGet('geo_block.honeypots', []) || []).length === 0 && (
            <p
              className="dim small"
              style={{ marginTop: 8, color: 'var(--amber)', display: 'flex', gap: 6, alignItems: 'flex-start' }}
            >
              <AlertIcon size={13} style={{ flexShrink: 0, marginTop: 1 }} />
              <span>
                Geo blocking is on but nothing is configured — add countries, blocked IPs, or honeypot domains above,
                save, then refresh.
              </span>
            </p>
          )}
        {!deepGet('geo_block.enabled', false) &&
          ((deepGet('geo_block.honeypots', []) || []).length > 0 ||
            (deepGet('geo_block.ips', []) || []).length > 0) && (
            <p
              className="dim small"
              style={{ marginTop: 8, color: 'var(--amber)', display: 'flex', gap: 6, alignItems: 'flex-start' }}
            >
              <AlertIcon size={13} style={{ flexShrink: 0, marginTop: 1 }} />
              <span>
                Honeypot domains / blocked IPs are configured but <strong>Enable geo blocking</strong> is off —
                nothing is enforced until you turn it on and save.
              </span>
            </p>
          )}
        {deepGet('geo_block.trust_udp', false) && (
          <p
            className="dim small"
            style={{ marginTop: 8, color: 'var(--amber)', display: 'flex', gap: 6, alignItems: 'flex-start' }}
          >
            <AlertIcon size={13} style={{ flexShrink: 0, marginTop: 1 }} />
            <span>
              UDP sources can be spoofed — with this on, a spoofed honeypot packet can permanently block an innocent
              victim. Only enable on a trusted network where client addresses are genuine.
            </span>
          </p>
        )}
        <h4 style={{ margin: '16px 0 10px' }}>Honeypot-blocked clients</h4>
        {f.honeyBlocked.length === 0 ? (
          <p className="dim small">No clients blocked yet — honeypot-domain queries auto-block their client here.</p>
        ) : (
          <div className="table-scroll">
            <table className="table">
              <thead>
                <tr>
                  <th>Client</th>
                  <th>Blocked</th>
                  <th className="actions-cell">Actions</th>
                </tr>
              </thead>
              <tbody>
                {f.honeyBlocked.map((ip) => (
                  <tr key={ip}>
                    <td>
                      <div className="mono">{ip}</div>
                    </td>
                    <td className="dim small">permanently · firewall drop</td>
                    <td className="actions-cell">
                      <button className="btn ghost tiny" type="button" onClick={() => f.reportAbuse(ip)}>
                        Report
                      </button>
                      <button className="btn tiny" type="button" onClick={() => f.blockNet(ip, 0)}>
                        Block IP
                      </button>
                      <button
                        className="btn tiny"
                        type="button"
                        onClick={() => f.blockNet(ip, ip.includes(':') ? 64 : 24)}
                      >
                        Block /{ip.includes(':') ? 64 : 24}
                      </button>
                      <button className="btn tiny danger" type="button" onClick={() => f.unblockHoney(ip)}>
                        Unblock
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        <h4 style={{ margin: '16px 0 10px' }}>Geo data status</h4>
        {f.geoInfo && f.geoInfo.countries && f.geoInfo.countries.length > 0 ? (
          <div className="table-scroll">
            <table className="table">
              <thead>
                <tr>
                  <th>Code</th>
                  <th>Ranges</th>
                  <th>Last updated</th>
                  <th>Status</th>
                </tr>
              </thead>
              <tbody>
                {f.geoInfo.countries.map((c) => (
                  <tr key={c.code}>
                    <td className="mono">{c.code}</td>
                    <td className="dim small">
                      {c.ipv4_ranges} IPv4 · {c.ipv6_ranges} IPv6
                    </td>
                    <td className="dim small">{c.last_fetch ? new Date(c.last_fetch).toLocaleString() : '—'}</td>
                    <td>
                      {c.error ? (
                        <span className="error-text small">{c.error}</span>
                      ) : (
                        <span className="badge badge-allowed">loaded</span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <p className="dim small">
            No country data loaded — countries are optional; blocked-IP and honeypot blocking above work without them.
            Add ISO codes above, save, then refresh to load country ranges.
          </p>
        )}
        {f.geoInfo && f.geoInfo.next_refresh && deepGet('geo_block.enabled', false) && (
          <p className="dim small" style={{ marginTop: 8 }}>
            Next automatic refresh: {new Date(f.geoInfo.next_refresh).toLocaleString()}
          </p>
        )}
        {f.geoInfo && f.geoInfo.firewall && f.geoInfo.firewall.available && (
          <p className="dim small" style={{ marginTop: 8 }}>
            Host firewall:{' '}
            {f.geoInfo.firewall.active ? <strong>active</strong> : <span className="error-text">rules inactive</span>} (
            {f.geoInfo.firewall.backend || 'no backend'}) — all new inbound traffic from the blocked countries is
            dropped at the packet level, not just DNS. Established connections and allowlisted clients always pass. If
            inactive, check the service runs with root or CAP_NET_ADMIN privileges.
          </p>
        )}
        <div className="quick-actions" style={{ marginTop: 8 }}>
          <button className="btn small" type="button" onClick={f.refreshGeo}>
            Refresh country data
          </button>
        </div>
      </div>

      <div className="card">
        <h3>Abuse reporting</h3>
        <p className="dim small" style={{ marginTop: -6 }}>
          One-click reporting of honeypot-confirmed attackers to <strong>AbuseIPDB</strong> (free account at
          abuseipdb.com; DDoS category). Reports are sent from the server using this key, which is stored in{' '}
          <code>irongrid.yaml</code>. No key is needed for the <strong>Export CSV</strong> and <strong>ASN</strong>{' '}
          actions on the dashboard (those use free RIPEstat lookups and your own abuse desks).
        </p>
        <div className="form-grid">
          {field(
            'AbuseIPDB API key',
            'free tier: 1,000 checks/reports per day, one report per IP per 15 min',
            <input
              className="input mono"
              type="password"
              value={deepGet('abuse.abuseipdb_key', '')}
              onChange={(e) => set('abuse.abuseipdb_key', e.target.value)}
              autoComplete="new-password"
            />,
          )}
        </div>
      </div>
    </>
  )
}
