// Stroke-only SVG icons (the app's icon standard — see App.jsx's navSvg)
// so no glyph can render as a colored emoji.
const UpIcon = (
  <svg
    width="12"
    height="12"
    viewBox="0 0 24 24"
    fill="none"
    stroke="currentColor"
    strokeWidth="2.2"
    strokeLinecap="round"
    strokeLinejoin="round"
    aria-hidden="true"
  >
    <path d="M12 19V5" />
    <polyline points="5 12 12 5 19 12" />
  </svg>
)
const DownloadIcon = (
  <svg
    width="12"
    height="12"
    viewBox="0 0 24 24"
    fill="none"
    stroke="currentColor"
    strokeWidth="2.2"
    strokeLinecap="round"
    strokeLinejoin="round"
    aria-hidden="true"
  >
    <path d="M12 5v14" />
    <polyline points="19 12 12 19 5 12" />
  </svg>
)

// SystemTab is the "System" sub page of Settings: web credentials, backup &
// restore, the DNS diagnostic and the cache/maintenance actions — the
// one-off operational tools that don't belong on a feature tab.
export default function SystemTab({ f }) {
  const { field, text } = f
  return (
    <>
      <div className="card">
        <h3>Web credentials</h3>
        <div className="form-grid">
          {text('Username', 'web.username')}
          {field(
            'Password',
            'leave blank to keep the current password; changing it signs out every device (including this one)',
            <input
              className="input"
              type="password"
              value={f.cfg.web.password}
              onChange={(e) => f.set('web.password', e.target.value)}
              autoComplete="new-password"
            />,
          )}
        </div>
      </div>

      <div className="card">
        <h3>Backup &amp; restore</h3>
        <p className="dim small" style={{ marginTop: -6 }}>
          Download an archive of the config file and TLS certificates — handy before upgrades or when moving servers.
          The archive contains the <strong>TLS private key</strong> and the password hash, so keep it as secure as a key
          file — or set a passphrase below to encrypt it.
        </p>
        <div className="form-grid" style={{ marginTop: 10 }}>
          <label>
            Passphrase (optional)
            <input
              className="input"
              type="password"
              autoComplete="new-password"
              placeholder="Leave blank for an unencrypted backup"
              value={f.backupPassphrase}
              onChange={(e) => f.setBackupPassphrase(e.target.value)}
            />
          </label>
        </div>
        {f.backupPassphrase && (
          <p className="dim small" style={{ marginTop: 4 }}>
            There is no way to recover an encrypted backup without this passphrase — if it's lost, the archive is
            unusable.
          </p>
        )}
        <div className="quick-actions" style={{ marginTop: 10 }}>
          <button className="btn small" type="button" onClick={f.downloadBackup} disabled={f.backupBusy}>
            {f.backupBusy ? (
              'Packing…'
            ) : (
              <>
                {DownloadIcon}
                Download backup
              </>
            )}
          </button>
          <label className="btn small" style={{ margin: 0 }}>
            {f.restoring ? (
              'Restoring…'
            ) : (
              <>
                {UpIcon}
                Restore backup
              </>
            )}
            <input
              type="file"
              accept=".zip,.enc,application/zip,application/octet-stream"
              style={{ display: 'none' }}
              onChange={f.onRestoreFile}
              disabled={f.restoring}
            />
          </label>
        </div>
        <p className="dim small" style={{ marginTop: 4 }}>
          To restore an encrypted backup, enter its passphrase above first, then choose the file.
        </p>
        {f.backupErr && (
          <div className="error-banner" style={{ marginTop: 8 }}>
            {f.backupErr}
          </div>
        )}
        {f.restoreMsg && (
          <div className="info-banner" style={{ marginTop: 8 }}>
            {f.restoreMsg}
          </div>
        )}
      </div>

      <div className="card">
        <h3>DNS diagnostic</h3>
        <form onSubmit={f.runDiag} className="form-grid">
          <input className="input" value={f.diagName} onChange={(e) => f.setDiagName(e.target.value)} />
          <select className="input" value={f.diagType} onChange={(e) => f.setDiagType(e.target.value)}>
            {['A', 'AAAA', 'TXT', 'MX', 'NS', 'CNAME'].map((t) => (
              <option key={t}>{t}</option>
            ))}
          </select>
          <button className="btn primary" type="submit">
            Resolve
          </button>
        </form>
        {f.diagResult && (
          <div className="diag-box">
            {f.diagResult.error ? (
              <div className="error-text">{f.diagResult.error}</div>
            ) : (
              <>
                <div className="dim small">
                  via <span className="mono">{f.diagResult.upstream}</span> · rcode {f.diagResult.rcode}
                  {f.diagResult.blocked_by_ip && (
                    <span className="error-text"> · blocked by IP rule ({f.diagResult.reason})</span>
                  )}
                </div>
                <ul className="diag-answers">
                  {(f.diagResult.answers || []).map((a, i) => (
                    <li key={i} className="mono">
                      {a}
                    </li>
                  ))}
                </ul>
              </>
            )}
          </div>
        )}
      </div>

      <div className="card">
        <h3>Cache &amp; maintenance</h3>
        <div className="quick-actions">
          <button className="btn" onClick={f.flush}>
            Flush DNS cache (Dragonfly)
          </button>
          <button className="btn" onClick={f.refreshLists}>
            Refresh blocklists
          </button>
        </div>
      </div>
    </>
  )
}
