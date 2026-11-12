import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { ToastProvider } from '../toast'
import TunnelCloudflare from './TunnelCloudflare'
import { api } from '../api'

vi.mock('../api', () => ({
  api: {
    cfSetCredentials: vi.fn(),
    cfTunnels: vi.fn(),
    cfCreateTunnel: vi.fn(),
    cfSelectTunnel: vi.fn(),
    cfDeleteTunnel: vi.fn(),
  },
}))

const connectedCf = {
  api_token_set: true,
  account_id: 'acc1',
  tunnel_id: 't1',
  tunnel: {
    id: 't1',
    name: 'irongrid',
    status: 'healthy',
    remotely_managed: true,
    connections: [{ colo: 'LHR', origin_ip: '203.0.113.7' }],
  },
}

const tunnelRow = (over) => ({
  id: 't1',
  name: 'irongrid',
  status: 'healthy',
  created_at: '2026-11-01T10:00:00Z',
  remotely_managed: true,
  selected: true,
  connections: [{ colo: 'LHR' }],
  ...over,
})

const renderIt = (props) => {
  const reload = vi.fn().mockResolvedValue(undefined)
  const utils = render(
    <ToastProvider>
      <TunnelCloudflare cf={connectedCf} reload={reload} tunnelRunning={false} {...props} />
    </ToastProvider>,
  )
  return { reload, ...utils }
}

beforeEach(() => {
  vi.clearAllMocks()
  api.cfTunnels.mockResolvedValue({
    tunnels: [
      tunnelRow({}),
      tunnelRow({ id: 't2', name: 'spare', status: 'inactive', selected: false, connections: [] }),
    ],
  })
  api.cfSetCredentials.mockResolvedValue({ api_token_set: true })
  api.cfSelectTunnel.mockResolvedValue({})
  api.cfCreateTunnel.mockResolvedValue({})
  api.cfDeleteTunnel.mockResolvedValue({})
})

afterEach(() => {
  vi.restoreAllMocks()
})

describe('TunnelCloudflare when not connected', () => {
  it('explains the permissions and connects with the pasted token', async () => {
    const { reload } = renderIt({ cf: { api_token_set: false } })
    expect(screen.getByText(/Cloudflare Tunnel → Edit/)).toBeInTheDocument()
    expect(api.cfTunnels).not.toHaveBeenCalled()

    const connect = screen.getByRole('button', { name: 'Connect' })
    expect(connect).toBeDisabled()
    await userEvent.type(screen.getByLabelText('Cloudflare API token'), '  secret-token  ')
    await userEvent.click(connect)

    await waitFor(() =>
      expect(api.cfSetCredentials).toHaveBeenCalledWith({ api_token: 'secret-token', account_id: '' }),
    )
    await waitFor(() => expect(reload).toHaveBeenCalled())
  })

  it('asks for the account ID when the token can see several accounts', async () => {
    api.cfSetCredentials.mockRejectedValueOnce(
      new Error('That token can see several accounts — choose which one to manage.'),
    )
    renderIt({ cf: { api_token_set: false } })
    await userEvent.type(screen.getByLabelText('Cloudflare API token'), 'tok')
    await userEvent.click(screen.getByRole('button', { name: 'Connect' }))

    const account = await screen.findByLabelText('Cloudflare account ID')
    await userEvent.type(account, 'acc9')
    await userEvent.click(screen.getByRole('button', { name: 'Connect' }))
    await waitFor(() => expect(api.cfSetCredentials).toHaveBeenLastCalledWith({ api_token: 'tok', account_id: 'acc9' }))
  })

  it('shows a rejected token as an error and stays on the form', async () => {
    api.cfSetCredentials.mockRejectedValue(new Error('Cloudflare refused the request: Authentication error'))
    renderIt({ cf: { api_token_set: false } })
    await userEvent.type(screen.getByLabelText('Cloudflare API token'), 'bad')
    await userEvent.click(screen.getByRole('button', { name: 'Connect' }))
    expect(await screen.findByText(/Cloudflare refused the request/)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Connect' })).toBeInTheDocument()
  })
})

describe('TunnelCloudflare when connected', () => {
  it('shows the account, the selected tunnel and every tunnel on the account', async () => {
    renderIt()
    expect(await screen.findByText('spare')).toBeInTheDocument()
    expect(screen.getByText('acc1')).toBeInTheDocument()
    expect(screen.getByText(/1 connector connection · LHR/)).toBeInTheDocument()
    expect(screen.getByText('In use')).toBeInTheDocument()
  })

  it('warns when the selected tunnel is configured locally', async () => {
    renderIt({ cf: { ...connectedCf, tunnel: { ...connectedCf.tunnel, remotely_managed: false } } })
    expect(await screen.findByText(/configured by a local config file/)).toBeInTheDocument()
  })

  it('surfaces a permission problem with a way to fix it', async () => {
    renderIt({ cf: { ...connectedCf, tunnel: undefined, error: 'Authentication error', permission: true } })
    expect(await screen.findByText(/Cloudflare is refusing this token/)).toBeInTheDocument()
  })

  it('switches to another tunnel', async () => {
    const { reload } = renderIt()
    await userEvent.click(await screen.findByRole('button', { name: 'Use' }))
    await waitFor(() => expect(api.cfSelectTunnel).toHaveBeenCalledWith('t2'))
    await waitFor(() => expect(reload).toHaveBeenCalled())
  })

  it('will not switch tunnels while the tunnel is running', async () => {
    renderIt({ tunnelRunning: true })
    expect(await screen.findByRole('button', { name: 'Use' })).toBeDisabled()
    expect(screen.getByText(/stop it to switch/)).toBeInTheDocument()
  })

  it('creates a tunnel and selects it by default', async () => {
    renderIt()
    await screen.findByText('spare')
    await userEvent.type(screen.getByLabelText('New tunnel name'), 'office')
    await userEvent.click(screen.getByRole('button', { name: 'Create tunnel' }))
    await waitFor(() => expect(api.cfCreateTunnel).toHaveBeenCalledWith({ name: 'office', select: true }))
  })

  it('deletes only after confirmation', async () => {
    const confirmSpy = vi.spyOn(window, 'confirm').mockReturnValue(false)
    renderIt()
    await userEvent.click(await screen.findByRole('button', { name: 'Delete' }))
    expect(api.cfDeleteTunnel).not.toHaveBeenCalled()

    confirmSpy.mockReturnValue(true)
    await userEvent.click(screen.getByRole('button', { name: 'Delete' }))
    await waitFor(() => expect(api.cfDeleteTunnel).toHaveBeenCalledWith('t2'))
  })

  it('disconnects the account after confirmation', async () => {
    vi.spyOn(window, 'confirm').mockReturnValue(true)
    const { reload } = renderIt()
    await userEvent.click(await screen.findByRole('button', { name: 'Disconnect' }))
    await waitFor(() => expect(api.cfSetCredentials).toHaveBeenCalledWith({ api_token: '' }))
    await waitFor(() => expect(reload).toHaveBeenCalled())
  })
})
