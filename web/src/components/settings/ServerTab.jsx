import { LineListField } from '../ui'

// ServerTab is the "Server" sub page of Settings: the DNS listeners, the
// upstream list (with conditional routes and the latency benchmark), DNSSEC
// and the raw TLS config. Everything it renders reads/writes the shared
// config through the f (form) bundle passed in by Settings.
const transportLabel = (t) => ({ udp: 'plain UDP', tls: 'DNS-over-TLS', https: 'DNS-over-HTTPS' })[t] || t

export default function ServerTab({ f }) {
  const { cfg, set, field, text, number, toggle, textarea, listEditor, deepGet } = f
  return (
    <>
      <div className="card">
        <h3>Server listeners</h3>
        <h4 className="field-group">Plain DNS</h4>
        <div className="form-grid">
          {text('UDP listener', 'server.listen_udp', 'plain DNS over UDP, "" disables', '0.0.0.0:53')}
          {text('TCP listener', 'server.listen_tcp', null, '0.0.0.0:53')}
        </div>
        <h4 className="field-group">Encrypted DNS</h4>
        <div className="form-grid">
          {text('DoT (TLS)', 'server.listen_dot', null, '0.0.0.0:853')}
          {text('DoH (HTTPS)', 'server.listen_doh', null, '0.0.0.0:443')}
          {text(
            'DoH3 (HTTP/3)',
            'server.listen_doh3',
            'DNS over HTTP/3 over UDP — same /dns-query path as DoH; typically the DoH port (443) since TCP and UDP ports are independent. Must differ from the DoQ address.',
            '0.0.0.0:443',
          )}
          {text('DoQ (QUIC)', 'server.listen_doq', null, '0.0.0.0:853')}
          {text('DoH path', 'server.doh_path', null, '/dns-query')}
        </div>
        <h4 className="field-group">Dashboard &amp; web</h4>
        <div className="form-grid">
          {text('Web dashboard', 'server.web_listen', null, '0.0.0.0:8080')}
          {toggle('Serve dashboard over HTTPS (web_tls)', 'server.web_tls')}
          {toggle('Redirect plain HTTP to HTTPS (web_redirect)', 'server.web_redirect')}
          {number('Redirect listener port', 'server.web_redirect_port')}
        </div>
        <h4 className="field-group">UDP performance</h4>
        <div className="form-grid">
          {number(
            'UDP sockets (0 = auto)',
            'server.udp_sockets',
            'SO_REUSEPORT sockets for the UDP + DoQ + DoH3 listeners; 0 = one per CPU (auto, capped), 1 = single exclusive socket, N = exactly N',
          )}
          {number(
            'UDP workers per socket (0 = auto)',
            'server.udp_workers',
            'Handler workers per plain-UDP socket; 0 = 4 x CPU (auto, capped), N = exactly N (capped at 512)',
          )}
        </div>
        <div className="row-between" style={{ marginTop: 12 }}>
          <span className="field-label">Recommended values</span>
          <button className="btn small" type="button" onClick={f.applyRecommendedUDP}>
            Set recommended
          </button>
        </div>
        <p className="dim small" style={{ marginTop: 4 }}>
          {f.numCPU
            ? `Server CPU count: ${f.numCPU}. Fills the two fields above with the auto-mode numbers (1 socket per CPU, capped at 8; 4 workers per CPU, floor 16).`
            : 'Fills the two fields above with the auto-mode numbers for this server.'}
        </p>
        <h4 className="field-group">General</h4>
        <div className="form-grid">
          {number('Upstream timeout (s)', 'server.timeout_sec')}
          {toggle('Pad encrypted responses (RFC 7830)', 'server.padding')}
          {toggle('DNS cookies (RFC 7873)', 'server.cookies')}
        </div>
        <h4 className="field-group">Connection limits (flood protection)</h4>
        <div className="form-grid">
          {number(
            'Max TCP/DoT connections per client (0 = unlimited)',
            'server.max_tcp_conns_per_ip',
            'Caps concurrent connections one IP may hold on the plain-TCP and DoT listeners — stops connection floods and slowloris-style attacks from exhausting file descriptors and goroutines. Connections past the cap are closed at accept. 0 = unlimited (default).',
          )}
          {number(
            'Max HTTP connections per client (0 = unlimited)',
            'server.max_http_conns_per_ip',
            'Caps concurrent connections one IP may hold on the DoH listener (and the shared dashboard+DoH HTTPS listener when they share a port). Same rationale as the TCP cap. 0 = unlimited (default).',
          )}
        </div>
      </div>

      <div className="card">
        <h3>Upstreams</h3>
        {listEditor('upstreams', 'upstreams', 'udp://, tcp://, tls://, https://, quic://, recursive://')}
        {/* This paragraph follows the list editor's format hint (not a heading), so it needs real
            spacing instead of the -6px tightening used under card headings — otherwise the two text
            blocks sit flush against each other. */}
        <p className="dim small" style={{ marginTop: 10 }}>
          <code>recursive://</code> resolves from the root servers itself instead of forwarding — no third-party
          resolver sees your query stream, at the cost of slower cold lookups and no upstream DNSSEC validation to rely
          on. Mix it with forwarders (the Resolution strategy below governs the order) or list it alone.
        </p>
        <div className="form-grid">
          {text(
            'Recursive per-server timeout',
            'recursive.server_timeout',
            'how long a recursive:// walk waits on one nameserver before moving on; empty = 3s built-in default',
            '3s',
          )}
          {field(
            'Resolution strategy',
            'how multiple upstreams are queried — race queries them all at once and uses the fastest answer; sequential tries them in list order, failing over to the next when one errors or answers SERVFAIL',
            <select
              className="input"
              value={cfg.upstream_mode || 'race'}
              onChange={(e) => set('upstream_mode', e.target.value)}
            >
              <option value="race">Race — all at once, fastest wins</option>
              <option value="sequential">Sequential — one at a time, in order</option>
            </select>,
          )}
        </div>
        <h4 style={{ margin: '16px 0 10px' }}>Conditional upstreams (split horizon)</h4>
        <p className="dim small" style={{ marginTop: -6 }}>
          Send queries for one domain subtree to a dedicated upstream set instead of the global ones above — e.g.{' '}
          <span className="mono">lan</span> → <span className="mono">udp://192.168.1.1:53</span> so internal names never
          leave the network. A route matches its domain and every subdomain under it; the longest match wins when routes
          overlap, and a route overrides both the global list and a client group's upstream override.
        </p>
        {(deepGet('upstream_routes', []) || []).map((rt, i) => (
          <div className="list-row" key={i} style={{ alignItems: 'flex-start' }}>
            <input
              className="input mono"
              placeholder="domain (e.g. lan)"
              value={rt.domain || ''}
              onChange={(e) => f.setRoute(i, 'domain', e.target.value)}
              style={{ maxWidth: 200 }}
            />
            <LineListField
              value={rt.upstreams || []}
              onChange={(v) => f.setRoute(i, 'upstreams', v)}
              placeholder={'upstreams, one per line (udp://, tls://, …)'}
              rows={2}
              style={{ flex: 1, minHeight: 44 }}
            />
            <button className="btn small danger" type="button" onClick={() => f.removeRoute(i)}>
              ✕
            </button>
          </div>
        ))}
        <button className="btn small" type="button" onClick={f.addRoute}>
          + Add route
        </button>
        <div className="row-between" style={{ marginTop: 16 }}>
          <h4 style={{ margin: 0, fontSize: 13 }}>Find the fastest upstreams for this server</h4>
          <button className="btn small" type="button" onClick={f.findFastest} disabled={f.fastestBusy}>
            {f.fastestBusy ? 'Benchmarking…' : 'Benchmark public resolvers'}
          </button>
        </div>
        <p className="dim small" style={{ marginTop: 4 }}>
          Measures real lookup latency from this server to the major public resolvers (plain UDP, DoT and DoH) and ranks
          them — the fastest for your location win. One click adds them to the list above; save to apply.
        </p>
        {f.pendingBenchmarkAdds > 0 && (
          <div className="info-banner" style={{ marginTop: 8 }}>
            ⚠ {f.pendingBenchmarkAdds} upstream{f.pendingBenchmarkAdds === 1 ? ' was' : 's were'} added from the
            benchmark but not saved yet — click <strong>Save &amp; apply</strong> at the top of this page to make it
            live.
          </div>
        )}
        {f.fastestErr && (
          <div className="error-banner" style={{ marginTop: 8 }}>
            {f.fastestErr}
          </div>
        )}
        {f.fastest && (
          <div style={{ marginTop: 10 }}>
            <div className="row-between">
              <span className="dim small">
                probe <span className="mono">{f.fastest.query}</span> {f.fastest.type} · best of 3
              </span>
              <button
                className="btn small"
                type="button"
                onClick={() => f.addFastestTop(3)}
                disabled={!f.fastest.results.some((r) => !r.error && !r.in_use)}
              >
                Add fastest 3
              </button>
            </div>
            <div style={{ maxHeight: 320, overflowY: 'auto', marginTop: 6 }}>
              <table className="table">
                <thead>
                  <tr>
                    <th>#</th>
                    <th>Resolver</th>
                    <th>Endpoint</th>
                    <th>Latency</th>
                    <th className="action-col"></th>
                  </tr>
                </thead>
                <tbody>
                  {f.fastest.results.map((res, i) => {
                    const lat = res.error ? null : res.latency_ms
                    const latColor =
                      lat == null ? null : lat < 15 ? 'var(--emerald)' : lat < 60 ? 'var(--cyan)' : 'var(--amber)'
                    return (
                      <tr key={res.spec}>
                        <td className="dim mono">{i + 1}</td>
                        <td>
                          <div className="strong">{res.label}</div>
                          <div className="dim small">{transportLabel(res.transport)}</div>
                        </td>
                        <td className="mono">{res.spec}</td>
                        <td>
                          {lat == null ? (
                            <span className="badge badge-error" title={res.error}>
                              unreachable
                            </span>
                          ) : (
                            <span className="mono" style={{ color: latColor, fontWeight: 650 }}>
                              {lat} ms
                            </span>
                          )}
                        </td>
                        <td className="action-col">
                          {res.in_use ? (
                            <span className="badge badge-cached">in use</span>
                          ) : lat == null ? null : (
                            <button className="btn small" type="button" onClick={() => f.addUpstream(res.spec)}>
                              Add
                            </button>
                          )}
                        </td>
                      </tr>
                    )
                  })}
                </tbody>
              </table>
            </div>
          </div>
        )}
      </div>

      <div className="card">
        <h3>DNSSEC</h3>
        <p className="dim small" style={{ marginTop: -6 }}>
          Irongrid forwards queries rather than validating the signature chain itself — like Pi-hole, AdGuard Home and
          dnsmasq, it trusts an upstream that already validates. Enabling this sets the DO bit on upstream queries and
          (optionally) rejects answers the upstream didn't mark authenticated. This is only meaningful with an{' '}
          <strong>encrypted upstream</strong> (DoT/DoH/QUIC to e.g. Cloudflare, Google or Quad9) — over plain UDP/TCP
          the authentication flag can be stripped or forged in transit.
        </p>
        <div className="form-grid">
          {toggle('Enable DNSSEC (trust upstream validation)', 'dnssec.enabled')}
          {toggle('Reject unauthenticated answers (SERVFAIL)', 'dnssec.require_ad')}
        </div>
      </div>

      <div className="card">
        <h3>TLS</h3>
        <p className="dim small" style={{ marginTop: -6 }}>
          Prefer the dedicated <strong>SSL / TLS</strong> page for generating or uploading certificates — these fields
          are the raw config behind it.
        </p>
        <div className="form-grid">
          {text('Cert file', 'tls.cert_file', null, 'data/certs/cert.pem')}
          {text('Key file', 'tls.key_file', null, 'data/certs/key.pem')}
          {text('Cert directory', 'tls.cert_dir', null, 'data/certs')}
          {toggle('Generate self-signed', 'tls.generate_self_signed')}
          {textarea('Self-signed hosts (SANs)', 'tls.self_signed_hosts', 'one per line')}
        </div>
        <h4 style={{ margin: '16px 0 10px' }}>Let&apos;s Encrypt (ACME)</h4>
        <div className="form-grid">
          {toggle('Enable ACME auto-issuance', 'tls.acme.enabled')}
          {text('Email (account contact)', 'tls.acme.email', 'required when enabled', 'you@example.com')}
          {textarea('Domains', 'tls.acme.domains', 'public hostnames, one per line')}
          {toggle('Use staging CA (test certificates)', 'tls.acme.staging')}
          {field(
            'DNS-01 provider',
            'empty = HTTP-01 (domain answers on port 80)',
            <select
              className="input"
              value={deepGet('tls.acme.dns01.provider', '')}
              onChange={(e) => set('tls.acme.dns01.provider', e.target.value)}
            >
              <option value="">HTTP-01 (no DNS API)</option>
              <option value="cloudflare">Cloudflare</option>
              <option value="digitalocean">DigitalOcean</option>
              <option value="hetzner">Hetzner</option>
              <option value="godaddy">GoDaddy</option>
              <option value="route53">AWS Route53</option>
            </select>,
          )}
          {deepGet('tls.acme.dns01.provider', '') === 'cloudflare' &&
            text('Cloudflare API token', 'tls.acme.dns01.cloudflare_token', 'Zone:DNS:Edit permission', '••••')}
          {deepGet('tls.acme.dns01.provider', '') === 'digitalocean' &&
            text(
              'DigitalOcean token',
              'tls.acme.dns01.digitalocean_token',
              'personal access token with DNS:edit',
              '••••',
            )}
          {deepGet('tls.acme.dns01.provider', '') === 'hetzner' &&
            text('Hetzner DNS token', 'tls.acme.dns01.hetzner_token', 'Hetzner DNS API token', '••••')}
          {deepGet('tls.acme.dns01.provider', '') === 'godaddy' && (
            <>
              {text('GoDaddy API key', 'tls.acme.dns01.godaddy_key', 'GoDaddy developer key', '••••')}
              {text('GoDaddy API secret', 'tls.acme.dns01.godaddy_secret', 'matching secret', '••••')}
            </>
          )}
          {deepGet('tls.acme.dns01.provider', '') === 'route53' && (
            <>
              {text(
                'AWS access key ID',
                'tls.acme.dns01.aws_access_key_id',
                'IAM key with Route53 change-resource-record-sets',
                'AKIA…',
              )}
              {text('AWS secret access key', 'tls.acme.dns01.aws_secret_access_key', 'matching secret', '••••')}
            </>
          )}
          {deepGet('tls.acme.dns01.provider', '') !== '' &&
            number('DNS-01 propagation wait (s)', 'tls.acme.dns01.propagation_wait_sec')}
          {deepGet('tls.acme.dns01.provider', '') === '' && number('HTTP-01 challenge port', 'tls.acme.http01_port')}
          {number('Renew when < N days left', 'tls.acme.renew_before_days')}
        </div>
      </div>
    </>
  )
}
