// CacheTab is the "Cache & log" sub page of Settings: the response cache,
// the proactive warmer and the query log's retention. Live utilisation is
// shown on the dashboard's Cache card.
export default function CacheTab({ f }) {
  const { text, number, toggle } = f
  return (
    <>
      <div className="card">
        <h3>Cache</h3>
        <p className="dim small" style={{ marginTop: -6 }}>
          Answers are cached in memory (L1) and persisted to an embedded on-disk store (L2) in the data directory, so
          they survive restarts — there is no separate cache server to run. Watch live utilisation on the dashboard's{' '}
          <strong>Cache</strong> card.
        </p>
        <div className="form-grid">
          {text('Positive TTL', 'cache.ttl', 'e.g. 6h, 30m, 1h30m')}
          {text('Negative TTL', 'cache.negative_ttl', 'e.g. 1m')}
          {number(
            'L1 entries (per shard)',
            'cache.l1_entries',
            'in-process cache in front of the on-disk store; 0 = auto-sized from available RAM (default), -1 disables it, N = exact per-shard cap',
          )}
          {text(
            'Serve stale',
            'cache.serve_stale',
            'keep entries answerable this long past expiry (RFC 8767) — used when the upstream is unreachable; 0 disables',
            '5m',
          )}
          {toggle('Prefetch hot entries', 'cache.prefetch')}
          {text(
            'Failure cache TTL',
            'cache.failure_ttl',
            "how long a resolution failure (unreachable upstream, no stale data) is cached as SERVFAIL so retries don't re-pay the full timeout; short = a recovered upstream shows up quickly; empty = use negative_ttl",
            '5s',
          )}
        </div>
      </div>

      <div className="card">
        <h3>Cache warmer</h3>
        <p className="dim small" style={{ marginTop: -6 }}>
          Proactively pre-caches answers for every domain your network queried within the <strong>lookback</strong>{' '}
          window (read from the query log), so a restart or cache flush doesn&apos;t leave the first query for each
          domain cold. A pass runs once at boot, then every <strong>interval</strong>, resolving only entries that are
          missing, expired or inside their serve-stale window. Off by default because it uses your upstreams even when
          nobody is asking.
        </p>
        <div className="form-grid">
          {toggle('Enable cache warmer', 'warmer.enabled')}
          {text('Interval', 'warmer.interval', 'how often a warming pass runs', '15m')}
          {text('Lookback', 'warmer.lookback', 'how far back into the query log to find active domains', '24h')}
          {number(
            'Max domains per pass',
            'warmer.max_domains',
            'cap on upstream traffic per pass; 0 = all in the window',
          )}
          {number('Parallel resolutions', 'warmer.concurrency', '0 = default (8)')}
        </div>
      </div>

      <div className="card">
        <h3>Query log</h3>
        <p className="dim small" style={{ marginTop: -6 }}>
          The query log is stored in the same embedded store as the DNS cache (under <code>kv/</code> in the data
          directory). View and filter it on the <strong>Query Log</strong> page; retention below prunes old entries
          automatically (hourly).
        </p>
        <div className="form-grid">
          {number('Retention (days)', 'log.retention_days')}
          {toggle('Verbose logging', 'log.verbose')}
        </div>
      </div>
    </>
  )
}
