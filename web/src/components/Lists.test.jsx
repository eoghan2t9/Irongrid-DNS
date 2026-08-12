import { describe, it, expect, beforeEach, vi } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { ToastProvider } from '../toast'
import Lists from './Lists'
import { api } from '../api'

// Lists talks to the API and embeds SiteScanner; mock both so the test drives
// the component's own logic (forms, pagination) in isolation.
vi.mock('../api', () => ({
  api: {
    getFilterList: vi.fn(),
    catalog: vi.fn(),
    addFilterEntry: vi.fn(),
    deleteFilterEntry: vi.fn(),
    checkFilter: vi.fn(),
  },
}))

vi.mock('./SiteScanner', () => ({ default: () => null }))

const makeList = (n) => Array.from({ length: n }, (_, i) => `host${i}.example.com`)

const renderLists = () =>
  render(
    <ToastProvider>
      <Lists />
    </ToastProvider>,
  )

beforeEach(() => {
  vi.clearAllMocks()
  api.getFilterList.mockImplementation(async (kind) =>
    kind === 'whitelist' ? { whitelist: makeList(120) } : { blacklist: [] },
  )
  api.catalog.mockResolvedValue({ whitelists: [] })
  api.addFilterEntry.mockResolvedValue({})
  api.deleteFilterEntry.mockResolvedValue({})
  api.checkFilter.mockResolvedValue({})
})

describe('Lists', () => {
  it('paginates the allow list 50 rows at a time', async () => {
    renderLists()

    expect(await screen.findByText('120 entries')).toBeInTheDocument()
    expect(screen.getByText('Page 1 / 3')).toBeInTheDocument()
    // First page: row 0 is visible, row 60 (page 2) is not.
    expect(screen.getByText('host0.example.com')).toBeInTheDocument()
    expect(screen.queryByText('host60.example.com')).not.toBeInTheDocument()

    await userEvent.click(screen.getByRole('button', { name: 'Next →' }))
    expect(screen.getByText('Page 2 / 3')).toBeInTheDocument()
    expect(screen.getByText('host50.example.com')).toBeInTheDocument()
    expect(screen.queryByText('host0.example.com')).not.toBeInTheDocument()
  })

  it('adds an entry through the form and reloads the lists', async () => {
    const user = userEvent.setup()
    renderLists()

    await user.type(screen.getByPlaceholderText('example.com, *.ads.net, or 1.2.3.4'), 'ads.example.com')
    await user.click(screen.getByRole('button', { name: 'Add' }))

    await waitFor(() => expect(api.addFilterEntry).toHaveBeenCalledWith('whitelist', 'ads.example.com'))
    // After the add, the lists are re-fetched (the form submits + load()).
    await waitFor(() => expect(api.getFilterList.mock.calls.length).toBeGreaterThanOrEqual(2))
  })

  it('shows the block list card when the allow list is empty', async () => {
    api.getFilterList.mockImplementation(async (kind) =>
      kind === 'whitelist' ? { whitelist: [] } : { blacklist: ['bad.example.com'] },
    )
    renderLists()

    expect(await screen.findByText('bad.example.com')).toBeInTheDocument()
    // The empty allow list renders the friendly empty state (title only —
    // the body copy explains what belongs there).
    expect(screen.getByText('Allow list is empty')).toBeInTheDocument()
  })
})
