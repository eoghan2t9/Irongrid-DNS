import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { ToastProvider } from '../toast'
import TunnelDNSRecords from './TunnelDNSRecords'
import { api } from '../api'

vi.mock('../api', () => ({
  api: {
    cfDNSPlan: vi.fn(),
    cfDNSApply: vi.fn(),
    cfDNSSettings: vi.fn(),
  },
}))

const settings = { host: '', auto_sync: false, ipv4: '', ipv6: '', skip_https: false }

const plan = (over) => ({
  host: 'dns.example.com',
  host_default: 'dns.example.com',
  zone: 'example.com',
  protocols: [
    { name: 'DoH', port: 443, path: '/dns-query' },
    { name: 'DoT', port: 853 },
    { name: 'DoQ', port: 853 },
  ],
  ipv4: ['192.0.2.10'],
  ipv6: [],
  detected: { ipv4: '192.0.2.10', ipv6: '' },
  notes: [],
  settings,
  counts: { create: 2, update: 1 },
  in_sync: false,
  items: [
    {
      type: 'A',
      name: 'dns.example.com',
      want: '192.0.2.10',
      purpose: 'Server address',
      state: 'missing',
      action: 'create',
    },
    {
      type: 'SVCB',
      name: '_dns.dns.example.com',
      want: '1 dns.example.com alpn="h2"',
      have: '1 dns.example.com alpn="h3"',
      state: 'differs',
      action: 'update',
    },
    {
      type: 'SVCB',
      name: '_dns.dns.example.com',
      want: '2 dns.example.com alpn="dot"',
      state: 'missing',
      action: 'create',
    },
    {
      type: 'HTTPS',
      name: 'dns.example.com',
      want: '1 . alpn="h2"',
      have: '1 . alpn="h2"',
      state: 'ok',
      action: 'none',
    },
  ],
  ...over,
})

const renderIt = (props) =>
  render(
    <ToastProvider>
      <TunnelDNSRecords cf={{ api_token_set: true }} {...props} />
    </ToastProvider>,
  )

beforeEach(() => {
  vi.clearAllMocks()
  api.cfDNSPlan.mockResolvedValue(plan())
  api.cfDNSApply.mockResolvedValue({
    results: [{ ok: true }, { ok: true }, { ok: true }],
    plan: plan({ in_sync: true, counts: {} }),
  })
  api.cfDNSSettings.mockResolvedValue(plan())
  vi.spyOn(window, 'confirm').mockReturnValue(true)
})

afterEach(() => {
  vi.restoreAllMocks()
})

describe('TunnelDNSRecords', () => {
  it('asks for a Cloudflare account first and makes no API call', () => {
    renderIt({ cf: { api_token_set: false } })
    expect(screen.getByText(/Connect a Cloudflare account above/)).toBeInTheDocument()
    expect(api.cfDNSPlan).not.toHaveBeenCalled()
  })

  it('shows the protocols, the address and each record with its status', async () => {
    renderIt()
    expect(await screen.findByText('DoH :443 /dns-query')).toBeInTheDocument()
    expect(screen.getByText('DoT :853')).toBeInTheDocument()
    expect(screen.getByText(/Publishing/)).toHaveTextContent('192.0.2.10')
    expect(screen.getAllByText('Missing')).toHaveLength(2)
    expect(screen.getByText('Out of date')).toBeInTheDocument()
    expect(screen.getByText('Correct')).toBeInTheDocument()
    expect(screen.getByText(/now: 1 dns\.example\.com alpn="h3"/)).toBeInTheDocument()
    expect(screen.getByText('3 changes to apply')).toBeInTheDocument()
  })

  it('applies the changes after confirmation', async () => {
    renderIt()
    await userEvent.click(await screen.findByRole('button', { name: 'Apply 3 changes' }))
    expect(window.confirm).toHaveBeenCalled()
    await waitFor(() => expect(api.cfDNSApply).toHaveBeenCalledWith(false))
    expect(await screen.findByText('In sync')).toBeInTheDocument()
  })

  it('does not apply when the confirmation is declined', async () => {
    window.confirm.mockReturnValue(false)
    renderIt()
    await userEvent.click(await screen.findByRole('button', { name: 'Apply 3 changes' }))
    expect(api.cfDNSApply).not.toHaveBeenCalled()
  })

  it('only removes records when the user opts in', async () => {
    api.cfDNSPlan.mockResolvedValue(
      plan({
        counts: { delete: 2 },
        in_sync: true,
        items: [
          {
            type: 'A',
            name: 'dns.example.com',
            have: '203.0.113.9',
            state: 'extra',
            action: 'delete',
            detail: 'not used',
          },
        ],
      }),
    )
    renderIt()
    expect(await screen.findByRole('button', { name: 'Nothing to apply' })).toBeDisabled()
    await userEvent.click(screen.getByRole('checkbox', { name: /Also remove 2 records/ }))
    await userEvent.click(screen.getByRole('button', { name: 'Apply 2 changes' }))
    await waitFor(() => expect(api.cfDNSApply).toHaveBeenCalledWith(true))
  })

  it('reports partial failures with the first error', async () => {
    api.cfDNSApply.mockResolvedValue({
      results: [{ ok: true }, { ok: false, type: 'SVCB', name: '_dns.dns.example.com', error: 'bad value' }],
      plan: plan(),
    })
    renderIt()
    await userEvent.click(await screen.findByRole('button', { name: 'Apply 3 changes' }))
    expect(await screen.findByText(/1 applied, 1 failed: SVCB _dns\.dns\.example\.com: bad value/)).toBeInTheDocument()
  })

  it('saves the hostname and auto-sync settings', async () => {
    renderIt()
    await userEvent.type(await screen.findByLabelText('Hostname to publish'), 'dns.example.com')
    await userEvent.click(screen.getByRole('checkbox', { name: /Keep these records in sync/ }))
    await userEvent.click(screen.getByRole('button', { name: 'Save settings' }))
    await waitFor(() =>
      expect(api.cfDNSSettings).toHaveBeenCalledWith({
        host: 'dns.example.com',
        auto_sync: true,
        ipv4: '',
        ipv6: '',
        skip_https: false,
      }),
    )
  })

  it('offers address overrides and the HTTPS switch under Advanced', async () => {
    renderIt()
    expect(screen.queryByLabelText('Public IPv4 override')).not.toBeInTheDocument()
    await userEvent.click(await screen.findByRole('button', { name: 'Advanced' }))
    await userEvent.type(screen.getByLabelText('Public IPv4 override'), '198.51.100.5')
    await userEvent.type(screen.getByLabelText('Public IPv6 override'), 'off')
    await userEvent.click(screen.getByRole('checkbox', { name: /Don.t publish an HTTPS record/ }))
    await userEvent.click(screen.getByRole('button', { name: 'Save settings' }))
    await waitFor(() =>
      expect(api.cfDNSSettings).toHaveBeenCalledWith(
        expect.objectContaining({ ipv4: '198.51.100.5', ipv6: 'off', skip_https: true }),
      ),
    )
  })

  it('asks for a hostname when none can be derived', async () => {
    api.cfDNSPlan.mockResolvedValue(plan({ needs_host: true, host: '', host_default: '', items: [], counts: {} }))
    renderIt()
    expect(await screen.findByText(/Choose the hostname clients will use/)).toBeInTheDocument()
  })

  it('flags conflicts and says why', async () => {
    api.cfDNSPlan.mockResolvedValue(
      plan({
        counts: { conflict: 1 },
        in_sync: false,
        items: [
          {
            type: 'A',
            name: 'dns.example.com',
            want: '192.0.2.10',
            state: 'conflict',
            action: 'none',
            detail: 'a CNAME record already exists for dns.example.com',
          },
        ],
      }),
    )
    renderIt()
    expect(await screen.findByText('Needs attention')).toBeInTheDocument()
    expect(screen.getByText(/a CNAME record already exists/)).toBeInTheDocument()
  })

  it('shows a NAT warning and the last automatic sync', async () => {
    api.cfDNSPlan.mockResolvedValue(
      plan({
        notes: ['No public IPv4 address was detected (is this server behind NAT?).'],
        settings: { ...settings, auto_sync: true },
        sync: { at: '2026-11-12T09:00:00Z', changed: true, applied: 2, failed: 0, conflicts: 1 },
      }),
    )
    renderIt()
    expect(await screen.findByText(/behind NAT/)).toBeInTheDocument()
    expect(screen.getByText(/updated 2 records/)).toBeInTheDocument()
    expect(screen.getByText(/1 conflict left for you/)).toBeInTheDocument()
    expect(screen.getByText(/never deletes/)).toBeInTheDocument()
  })

  it('shows a failed automatic sync', async () => {
    api.cfDNSPlan.mockResolvedValue(
      plan({ sync: { at: '2026-11-12T09:00:00Z', error: 'cloudflare denies the API token' } }),
    )
    renderIt()
    expect(await screen.findByText(/failed — cloudflare denies the API token/)).toBeInTheDocument()
  })

  it('surfaces a server error instead of an empty card', async () => {
    api.cfDNSPlan.mockRejectedValue(new Error('Cloudflare refused the request'))
    renderIt()
    expect(await screen.findByText(/Cloudflare refused the request/)).toBeInTheDocument()
  })
})
