import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { ToastProvider } from '../toast'
import Updates from './Updates'
import { api } from '../api'

vi.mock('../api', () => ({
  api: {
    updates: vi.fn(),
    updateInstall: vi.fn(),
    tunnelCheckCloudflaredUpdate: vi.fn(),
    tunnelRestart: vi.fn(),
    status: vi.fn(),
  },
}))

const tool = (over) => ({
  id: 'irongrid',
  name: 'Irongrid DNS',
  purpose: 'the DNS server',
  current_version: 'v1.40.1',
  latest_version: 'v1.41.0',
  update_available: true,
  installable: true,
  ...over,
})

const renderPage = () =>
  render(
    <ToastProvider>
      <Updates />
    </ToastProvider>,
  )

beforeEach(() => {
  vi.clearAllMocks()
  api.updates.mockResolvedValue({
    checked_at: '2026-10-22T18:00:00Z',
    tools: [
      tool({
        current_version: 'v1.39.17',
        latest_version: 'v1.39.17',
        update_available: false,
      }),
      tool({ id: 'cloudflared', name: 'cloudflared', latest_version: '2026.11.1' }),
    ],
  })
})

afterEach(() => {
  vi.restoreAllMocks()
})

describe('Updates', () => {
  it('shows one status per tool: up to date and update available', async () => {
    renderPage()
    expect(await screen.findByText('Up to date')).toBeInTheDocument()
    expect(screen.getByText('Update available')).toBeInTheDocument()
    // Only the tool with an update gets an install button.
    expect(screen.getAllByRole('button', { name: /^Update to/ })).toHaveLength(1)
  })

  it('reports a failed release check per tool', async () => {
    api.updates.mockResolvedValue({
      tools: [tool({ update_available: false, error: 'rate limited' })],
    })
    renderPage()
    expect(await screen.findByText('Check failed')).toBeInTheDocument()
    expect(screen.getByText(/Could not check: rate limited/)).toBeInTheDocument()
  })

  it('does not list Dragonfly: the cache is embedded', async () => {
    renderPage()
    await screen.findByText('Up to date')
    expect(screen.queryByText(/dragonfly/i)).not.toBeInTheDocument()
  })

  const cloudflared = (over) =>
    tool({
      id: 'cloudflared',
      name: 'cloudflared',
      current_version: '2026.10.7',
      latest_version: '2026.11.1',
      ...over,
    })

  it('updates cloudflared and restarts a running tunnel after confirmation', async () => {
    const confirmSpy = vi.spyOn(window, 'confirm').mockReturnValue(true)
    api.updates.mockResolvedValue({ tools: [cloudflared({ running_version: '2026.10.7' })] })
    api.tunnelCheckCloudflaredUpdate.mockResolvedValue({ installed: true, new_version: '2026.11.1', restarting: true })
    renderPage()
    await userEvent.click(await screen.findByRole('button', { name: 'Update to 2026.11.1' }))

    expect(confirmSpy).toHaveBeenCalledTimes(1)
    expect(confirmSpy.mock.calls[0][0]).toMatch(/tunnel is running/i)
    await waitFor(() => expect(api.tunnelCheckCloudflaredUpdate).toHaveBeenCalledWith(true))
  })

  it('updates cloudflared without a prompt or restart when the tunnel is not running', async () => {
    const confirmSpy = vi.spyOn(window, 'confirm').mockReturnValue(true)
    api.updates.mockResolvedValue({ tools: [cloudflared({})] })
    api.tunnelCheckCloudflaredUpdate.mockResolvedValue({ installed: true, new_version: '2026.11.1' })
    renderPage()
    await userEvent.click(await screen.findByRole('button', { name: 'Update to 2026.11.1' }))

    await waitFor(() => expect(api.tunnelCheckCloudflaredUpdate).toHaveBeenCalledWith(false))
    expect(confirmSpy).not.toHaveBeenCalled()
  })

  it('does not update cloudflared when the restart confirmation is declined', async () => {
    vi.spyOn(window, 'confirm').mockReturnValue(false)
    api.updates.mockResolvedValue({ tools: [cloudflared({ running_version: '2026.10.7' })] })
    renderPage()
    await userEvent.click(await screen.findByRole('button', { name: 'Update to 2026.11.1' }))

    expect(api.tunnelCheckCloudflaredUpdate).not.toHaveBeenCalled()
  })

  it('offers a tunnel restart when the new cloudflared is installed but not running', async () => {
    vi.spyOn(window, 'confirm').mockReturnValue(true)
    api.updates.mockResolvedValue({
      tools: [
        cloudflared({
          current_version: '2026.11.1',
          running_version: '2026.10.7',
          update_available: false,
          restart_pending: true,
        }),
      ],
    })
    api.tunnelRestart.mockResolvedValue({ restarting: true })
    renderPage()

    expect(await screen.findByText('Restart needed')).toBeInTheDocument()
    await userEvent.click(screen.getByRole('button', { name: 'Restart tunnel' }))
    await waitFor(() => expect(api.tunnelRestart).toHaveBeenCalledTimes(1))
  })

  it('disables the update button for a tool that cannot be updated from here', async () => {
    api.updates.mockResolvedValue({ tools: [tool({ installable: false, note: 'runs in Docker' })] })
    renderPage()

    expect(await screen.findByRole('button', { name: 'Update to v1.41.0' })).toBeDisabled()
    expect(screen.getByText('runs in Docker')).toBeInTheDocument()
  })
})
