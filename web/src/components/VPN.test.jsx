import { describe, it, expect, beforeEach, vi } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import { ToastProvider } from '../toast'
import VPN from './VPN'
import { api } from '../api'

// VPN talks to the API for both the config document and live tunnel
// status; mock both so the test drives the connection-status badge logic
// in isolation.
vi.mock('../api', () => ({
  api: {
    config: vi.fn(),
    vpnStatus: vi.fn(),
    saveConfig: vi.fn(),
  },
}))

const baseConfig = (profiles) => ({
  vpn: {
    enabled: true,
    providers: { nordvpn: { token: '' }, pia: { username: '', password: '' } },
    profiles,
    routes: [],
  },
})

const renderVPN = () =>
  render(
    <ToastProvider>
      <VPN />
    </ToastProvider>,
  )

beforeEach(() => {
  vi.clearAllMocks()
})

describe('VPN connection status', () => {
  it('shows an error badge when nothing is connected', async () => {
    api.config.mockResolvedValue(baseConfig([{ id: 'uk-iplayer', provider: 'pia', region: 'uk_london' }]))
    api.vpnStatus.mockResolvedValue([])

    renderVPN()

    const badge = await screen.findByText('0/1 connected')
    expect(badge).toHaveClass('badge-error')
  })

  it('shows a warn badge when some but not all profiles are connected', async () => {
    api.config.mockResolvedValue(
      baseConfig([
        { id: 'uk-iplayer', provider: 'pia', region: 'uk_london' },
        { id: 'privacy', provider: 'nordvpn', region: 'us' },
      ]),
    )
    api.vpnStatus.mockResolvedValue([
      {
        id: 'uk-iplayer',
        provider: 'pia',
        region: 'uk_london',
        iface: 'igvpn0',
        endpoint: '1.2.3.4:51820',
        up_since: new Date().toISOString(),
      },
    ])

    renderVPN()

    const badge = await screen.findByText('1/2 connected')
    expect(badge).toHaveClass('badge-warn')
  })

  it('shows an allowed badge when every configured profile is connected', async () => {
    api.config.mockResolvedValue(baseConfig([{ id: 'uk-iplayer', provider: 'pia', region: 'uk_london' }]))
    api.vpnStatus.mockResolvedValue([
      {
        id: 'uk-iplayer',
        provider: 'pia',
        region: 'uk_london',
        iface: 'igvpn0',
        endpoint: '1.2.3.4:51820',
        up_since: new Date().toISOString(),
      },
    ])

    renderVPN()

    const badge = await screen.findByText('1/1 connected')
    expect(badge).toHaveClass('badge-allowed')
  })

  it('hides the badge entirely when VPN is not enabled', async () => {
    const cfg = baseConfig([{ id: 'uk-iplayer', provider: 'pia', region: 'uk_london' }])
    cfg.vpn.enabled = false
    api.config.mockResolvedValue(cfg)
    api.vpnStatus.mockResolvedValue([])

    renderVPN()

    await waitFor(() => expect(api.config).toHaveBeenCalled())
    expect(screen.queryByText(/connected$/)).not.toBeInTheDocument()
  })

  it('shows a "no profile configured" hint when enabled with zero profiles', async () => {
    api.config.mockResolvedValue(baseConfig([]))
    api.vpnStatus.mockResolvedValue([])

    renderVPN()

    expect(await screen.findByText(/no profile is configured yet/)).toBeInTheDocument()
  })

  it('shows a "no routes yet" hint when a profile exists but no route does', async () => {
    api.config.mockResolvedValue(baseConfig([{ id: 'uk-iplayer', provider: 'pia', region: 'uk_london' }]))
    api.vpnStatus.mockResolvedValue([])

    renderVPN()

    expect(await screen.findByText(/even once a profile connects/)).toBeInTheDocument()
    expect(screen.queryByText(/no profile is configured yet/)).not.toBeInTheDocument()
  })
})

describe('VPN Smart DNS proxy UI', () => {
  it('shows a warning when a route has Proxy relay on but the proxy itself is disabled', async () => {
    api.config.mockResolvedValue({
      vpn: {
        enabled: true,
        providers: { nordvpn: { token: '' }, pia: { username: '', password: '' } },
        profiles: [{ id: 'uk-iplayer', provider: 'pia', region: 'uk_london' }],
        routes: [{ profile: 'uk-iplayer', domains: ['imgur.com'], proxy: true }],
        proxy: { enabled: false, listen: '', listen_http: '', fallback: '', public_ip: '' },
      },
    })
    api.vpnStatus.mockResolvedValue([])

    render(
      <ToastProvider>
        <VPN />
      </ToastProvider>,
    )

    expect(await screen.findByText(/Smart DNS proxy itself is disabled/)).toBeInTheDocument()
  })

  it('does not warn once the proxy is enabled', async () => {
    api.config.mockResolvedValue({
      vpn: {
        enabled: true,
        providers: { nordvpn: { token: '' }, pia: { username: '', password: '' } },
        profiles: [{ id: 'uk-iplayer', provider: 'pia', region: 'uk_london' }],
        routes: [{ profile: 'uk-iplayer', domains: ['imgur.com'], proxy: true }],
        proxy: { enabled: true, listen: ':443', listen_http: '', fallback: '127.0.0.1:8443', public_ip: '' },
      },
    })
    api.vpnStatus.mockResolvedValue([])

    render(
      <ToastProvider>
        <VPN />
      </ToastProvider>,
    )

    await screen.findByText('imgur.com')
    expect(screen.queryByText(/Smart DNS proxy itself is disabled/)).not.toBeInTheDocument()
  })
})
