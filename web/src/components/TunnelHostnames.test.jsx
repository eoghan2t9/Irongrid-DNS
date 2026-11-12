import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { ToastProvider } from '../toast'
import TunnelHostnames from './TunnelHostnames'
import { api } from '../api'

vi.mock('../api', () => ({
  api: {
    cfHostnames: vi.fn(),
    cfSaveHostname: vi.fn(),
    cfSyncDNS: vi.fn(),
    cfRemoveHostname: vi.fn(),
  },
}))

const cf = (over) => ({
  api_token_set: true,
  tunnel_id: 't1',
  tunnel: { id: 't1', name: 'irongrid', remotely_managed: true },
  suggested_origins: [
    { label: 'Irongrid dashboard + DoH (shared port)', service: 'https://localhost:443', no_tls_verify: true },
  ],
  ...over,
})

const listing = {
  catch_all: 'http_status:404',
  hostnames: [
    {
      hostname: 'ok.example.com',
      service: 'https://localhost:443',
      no_tls_verify: true,
      origin_reachable: true,
      dns: { state: 'ok' },
    },
    {
      hostname: 'missing.example.com',
      service: 'http://localhost:9',
      origin_reachable: false,
      dns: { state: 'missing', detail: 'no DNS record routes this name to the tunnel' },
    },
    {
      hostname: 'clash.example.com',
      service: 'http://localhost:1',
      origin_reachable: null,
      dns: { state: 'conflict', detail: 'a CNAME record for this name points at x.net instead' },
    },
  ],
}

const renderIt = (props) =>
  render(
    <ToastProvider>
      <TunnelHostnames cf={cf()} {...props} />
    </ToastProvider>,
  )

beforeEach(() => {
  vi.clearAllMocks()
  api.cfHostnames.mockResolvedValue(listing)
  api.cfSaveHostname.mockResolvedValue({ saved: true, dns: { state: 'ok' } })
  api.cfSyncDNS.mockResolvedValue({ dns: { state: 'ok' } })
  api.cfRemoveHostname.mockResolvedValue({ removed: true, dns_removed: 1 })
})

afterEach(() => {
  vi.restoreAllMocks()
})

describe('TunnelHostnames guidance', () => {
  it('asks for a Cloudflare account first and makes no API call', () => {
    renderIt({ cf: cf({ api_token_set: false, tunnel_id: '' }) })
    expect(screen.getByText(/Connect a Cloudflare account above/)).toBeInTheDocument()
    expect(api.cfHostnames).not.toHaveBeenCalled()
  })

  it('asks for a tunnel when none is selected', () => {
    renderIt({ cf: cf({ tunnel_id: '', tunnel: undefined }) })
    expect(screen.getByText(/Pick or create a named tunnel/)).toBeInTheDocument()
    expect(api.cfHostnames).not.toHaveBeenCalled()
  })

  it('explains that a locally-configured tunnel cannot be managed here', () => {
    renderIt({ cf: cf({ tunnel: { id: 't1', remotely_managed: false } }) })
    expect(screen.getByText(/uses a local config file/)).toBeInTheDocument()
    expect(api.cfHostnames).not.toHaveBeenCalled()
  })
})

describe('TunnelHostnames list', () => {
  it('shows each hostname with its DNS state and origin', async () => {
    renderIt()
    expect(await screen.findByText('ok.example.com')).toBeInTheDocument()
    expect(screen.getByText('DNS ok')).toBeInTheDocument()
    expect(screen.getByText('No DNS record')).toBeInTheDocument()
    expect(screen.getByText('DNS conflict')).toBeInTheDocument()
    expect(screen.getByText('TLS not verified')).toBeInTheDocument()
    expect(screen.getByText('http_status:404')).toBeInTheDocument()
    // Fix DNS only where it helps; Re-point only for a CNAME elsewhere.
    expect(screen.getAllByRole('button', { name: 'Fix DNS' })).toHaveLength(1)
    expect(screen.getAllByRole('button', { name: 'Re-point DNS' })).toHaveLength(1)
  })

  it('reports an error from the server instead of an empty list', async () => {
    api.cfHostnames.mockRejectedValue(new Error('Cloudflare refused the request'))
    renderIt()
    expect(await screen.findByText(/Cloudflare refused the request/)).toBeInTheDocument()
  })
})

describe('TunnelHostnames changes', () => {
  it('adds a hostname using an origin preset', async () => {
    renderIt()
    await screen.findByText('ok.example.com')
    await userEvent.type(screen.getByLabelText('Hostname'), 'dns.example.com')
    await userEvent.selectOptions(screen.getByLabelText('Origin preset'), '0')
    await userEvent.click(screen.getByRole('button', { name: 'Add hostname' }))

    await waitFor(() =>
      expect(api.cfSaveHostname).toHaveBeenCalledWith(
        {
          hostname: 'dns.example.com',
          service: 'https://localhost:443',
          path: '',
          // The preset knows the loopback hop uses a certificate for another name.
          no_tls_verify: true,
          create_dns: true,
        },
        false,
      ),
    )
  })

  it('will not submit without a hostname and an origin', async () => {
    renderIt()
    await screen.findByText('ok.example.com')
    expect(screen.getByRole('button', { name: 'Add hostname' })).toBeDisabled()
  })

  it('edits an existing hostname, keeping its name fixed', async () => {
    renderIt()
    await screen.findByText('ok.example.com')
    await userEvent.click(screen.getAllByRole('button', { name: 'Edit' })[0])

    expect(screen.getByLabelText('Hostname')).toBeDisabled()
    expect(screen.getByLabelText('Hostname')).toHaveValue('ok.example.com')
    await userEvent.click(screen.getByRole('button', { name: 'Save changes' }))
    await waitFor(() =>
      expect(api.cfSaveHostname).toHaveBeenCalledWith(
        {
          hostname: 'ok.example.com',
          service: 'https://localhost:443',
          path: '',
          no_tls_verify: true,
          // Its DNS is already fine, so an edit does not touch it by default.
          create_dns: false,
        },
        true,
      ),
    )
  })

  it('fixes missing DNS in one click', async () => {
    renderIt()
    await userEvent.click(await screen.findByRole('button', { name: 'Fix DNS' }))
    await waitFor(() => expect(api.cfSyncDNS).toHaveBeenCalledWith('missing.example.com', false))
  })

  it('re-points a CNAME only after confirmation', async () => {
    const confirmSpy = vi.spyOn(window, 'confirm').mockReturnValue(false)
    renderIt()
    await userEvent.click(await screen.findByRole('button', { name: 'Re-point DNS' }))
    expect(api.cfSyncDNS).not.toHaveBeenCalled()

    confirmSpy.mockReturnValue(true)
    await userEvent.click(screen.getByRole('button', { name: 'Re-point DNS' }))
    await waitFor(() => expect(api.cfSyncDNS).toHaveBeenCalledWith('clash.example.com', true))
  })

  it('removes a hostname and, by default, its DNS record', async () => {
    renderIt()
    await screen.findByText('ok.example.com')
    await userEvent.click(screen.getAllByRole('button', { name: 'Remove' })[0])

    const dialog = screen.getByRole('alertdialog')
    expect(within(dialog).getByRole('checkbox')).toBeChecked()
    await userEvent.click(within(dialog).getByRole('button', { name: 'Remove' }))
    await waitFor(() => expect(api.cfRemoveHostname).toHaveBeenCalledWith('ok.example.com', true))
  })

  it('can remove a hostname while keeping its DNS record', async () => {
    renderIt()
    await screen.findByText('ok.example.com')
    await userEvent.click(screen.getAllByRole('button', { name: 'Remove' })[0])
    const dialog = screen.getByRole('alertdialog')
    await userEvent.click(within(dialog).getByRole('checkbox'))
    await userEvent.click(within(dialog).getByRole('button', { name: 'Remove' }))
    await waitFor(() => expect(api.cfRemoveHostname).toHaveBeenCalledWith('ok.example.com', false))
  })

  it('does not remove anything when the confirmation is cancelled', async () => {
    renderIt()
    await screen.findByText('ok.example.com')
    await userEvent.click(screen.getAllByRole('button', { name: 'Remove' })[0])
    await userEvent.click(within(screen.getByRole('alertdialog')).getByRole('button', { name: 'Cancel' }))
    expect(api.cfRemoveHostname).not.toHaveBeenCalled()
    expect(screen.queryByRole('alertdialog')).not.toBeInTheDocument()
  })
})
