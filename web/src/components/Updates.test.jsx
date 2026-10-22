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
    updatesDragonflyInstall: vi.fn(),
    updatesDragonflyRestart: vi.fn(),
    tunnelCheckCloudflaredUpdate: vi.fn(),
    status: vi.fn(),
  },
}))

const tool = (over) => ({
  id: 'dragonfly',
  name: 'Dragonfly',
  purpose: 'cache',
  current_version: 'v1.40.1',
  latest_version: 'v2.0.2',
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
        id: 'irongrid',
        name: 'Irongrid DNS',
        current_version: 'v1.39.17',
        latest_version: 'v1.39.17',
        update_available: false,
      }),
      tool({}),
      tool({ id: 'cloudflared', name: 'cloudflared', update_available: false, error: 'rate limited' }),
    ],
  })
})

afterEach(() => {
  vi.restoreAllMocks()
})

describe('Updates', () => {
  it('shows one status per tool: up to date, update available, check failed', async () => {
    renderPage()
    expect(await screen.findByText('Up to date')).toBeInTheDocument()
    expect(screen.getByText('Update available')).toBeInTheDocument()
    expect(screen.getByText('Check failed')).toBeInTheDocument()
    expect(screen.getByText(/Could not check: rate limited/)).toBeInTheDocument()
    // Only the tool with an update gets an install button.
    expect(screen.getAllByRole('button', { name: /^Update to/ })).toHaveLength(1)
  })

  it('updates Dragonfly after confirmation and reloads the list', async () => {
    vi.spyOn(window, 'confirm').mockReturnValue(true)
    api.updatesDragonflyInstall.mockResolvedValue({
      installed: true,
      restarting: true,
      new_version: 'v2.0.2',
      running_version: 'v2.0.2',
    })
    renderPage()
    await userEvent.click(await screen.findByRole('button', { name: 'Update to v2.0.2' }))

    await waitFor(() => expect(api.updatesDragonflyInstall).toHaveBeenCalledTimes(1))
    // Initial load plus the refresh after the install.
    await waitFor(() => expect(api.updates).toHaveBeenCalledTimes(2))
  })

  it('does nothing when the Dragonfly confirmation is declined', async () => {
    vi.spyOn(window, 'confirm').mockReturnValue(false)
    renderPage()
    await userEvent.click(await screen.findByRole('button', { name: 'Update to v2.0.2' }))

    expect(api.updatesDragonflyInstall).not.toHaveBeenCalled()
  })

  it('offers a restart when the new Dragonfly binary is installed but not running', async () => {
    vi.spyOn(window, 'confirm').mockReturnValue(true)
    api.updates.mockResolvedValue({
      tools: [
        tool({ current_version: 'v2.0.2', running_version: 'v1.40.1', update_available: false, restart_pending: true }),
      ],
    })
    api.updatesDragonflyRestart.mockResolvedValue({ restarting: true, running_version: 'v2.0.2' })
    renderPage()

    expect(await screen.findByText('Restart needed')).toBeInTheDocument()
    await userEvent.click(screen.getByRole('button', { name: 'Restart Dragonfly' }))
    await waitFor(() => expect(api.updatesDragonflyRestart).toHaveBeenCalledTimes(1))
  })

  it('disables the update button for a tool that cannot be updated from here', async () => {
    api.updates.mockResolvedValue({ tools: [tool({ installable: false, note: 'runs in Docker' })] })
    renderPage()

    expect(await screen.findByRole('button', { name: 'Update to v2.0.2' })).toBeDisabled()
    expect(screen.getByText('runs in Docker')).toBeInTheDocument()
  })
})
