import { XIcon } from '../ui'

// NetworkTab is the "Network" sub page of Settings: the cloudflared tunnel
// boot settings and the built-in DHCP server (live leases are on the
// dedicated DHCP page).
export default function NetworkTab({ f }) {
  const { text, toggle, textarea, deepGet } = f
  return (
    <>
      <div className="card">
        <h3>Tunnel (cloudflared)</h3>
        <div className="form-grid">
          {toggle('Start on boot', 'tunnel.enabled')}
          {toggle('Quick tunnel', 'tunnel.quick_tunnel')}
          {text('Token', 'tunnel.token', 'named tunnel token')}
          {text('Config file', 'tunnel.config_file', 'cloudflared YAML path')}
          {text('Origin URL', 'tunnel.quick_tunnel_url')}
          {text('Hostname', 'tunnel.hostname')}
        </div>
      </div>

      <div className="card">
        <h3>DHCP server</h3>
        <p className="dim small" style={{ marginTop: -6 }}>
          A built-in DHCP server for the LAN this box is the DNS for: hands out IPv4 addresses from a pool (and
          optionally stateful IPv6 via DHCPv6), honours static reservations, and registers client hostnames so{' '}
          <span className="mono">hostname</span> and{' '}
          <span className="mono">hostname.{deepGet('dhcp.domain', 'lan')}</span> resolve locally — Pi-hole style.
          Requires the server to have an address inside the served subnet. Only enable on the NIC your LAN actually
          uses.
        </p>
        <div className="form-grid">
          {toggle('Enable DHCP server', 'dhcp.enabled')}
          {text('Interface', 'dhcp.interface', 'NIC to serve on (e.g. eth0, br0); empty = all interfaces', 'eth0')}
          {text('IPv4 subnet', 'dhcp.subnet', 'the network served, e.g. 192.168.1.0/24')}
          {text('Pool start', 'dhcp.range_start', 'first dynamic address, e.g. 192.168.1.100')}
          {text('Pool end', 'dhcp.range_end', 'last dynamic address, e.g. 192.168.1.200')}
          {text('Gateway', 'dhcp.gateway', "router option advertised; empty = this server's own address on the subnet")}
          {textarea('DNS servers', 'dhcp.dns', 'advertised DNS option, one per line; empty = this server')}
          {text('Lease time', 'dhcp.lease_time', 'e.g. 24h, 12h', '24h')}
          {text(
            'Domain suffix',
            'dhcp.domain',
            'hostnames resolve as hostname.domain; empty disables hostname resolution',
            'lan',
          )}
          {toggle('Enable DHCPv6', 'dhcp.ipv6')}
          {deepGet('dhcp.ipv6', false) && text('IPv6 prefix', 'dhcp.ipv6_prefix', 'e.g. fd00::/64 (ULA)')}
          {deepGet('dhcp.ipv6', false) &&
            text('IPv6 pool start', 'dhcp.ipv6_range_start', 'first stateful address (inside the prefix)')}
          {deepGet('dhcp.ipv6', false) && text('IPv6 pool end', 'dhcp.ipv6_range_end', 'last stateful address')}
        </div>
        <h4 style={{ margin: '16px 0 10px' }}>Static reservations</h4>
        <p className="dim small" style={{ marginTop: -6 }}>
          Fixed addresses that never expire. MAC keys a DHCPv4 reservation, DUID a DHCPv6 one — either is fine (v4
          clients match on MAC, v6 clients on DUID). A hostname pins the local-DNS name.
        </p>
        {(deepGet('dhcp.static_leases', []) || []).map((sl, i) => (
          <div className="list-row" key={i} style={{ alignItems: 'flex-start' }}>
            <input
              className="input mono"
              placeholder="mac (aa:bb:…)"
              value={sl.mac || ''}
              onChange={(e) => f.setStaticLease(i, 'mac', e.target.value)}
            />
            <input
              className="input mono"
              placeholder="duid"
              value={sl.duid || ''}
              onChange={(e) => f.setStaticLease(i, 'duid', e.target.value)}
            />
            <input
              className="input mono"
              placeholder="ip"
              value={sl.ip || ''}
              onChange={(e) => f.setStaticLease(i, 'ip', e.target.value)}
            />
            <input
              className="input"
              placeholder="hostname"
              value={sl.hostname || ''}
              onChange={(e) => f.setStaticLease(i, 'hostname', e.target.value)}
            />
            <button className="btn small danger" type="button" onClick={() => f.removeStaticLease(i)}>
              <XIcon size={12} />
            </button>
          </div>
        ))}
        <button className="btn small" type="button" onClick={f.addStaticLease}>
          + Add reservation
        </button>
      </div>
    </>
  )
}
