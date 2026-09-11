import { describe, it, expect, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import { VPNCard } from './Dashboard'

const cfg = (profiles) => ({ vpn: { enabled: true, profiles } })

describe('VPNCard', () => {
  it('renders nothing when VPN is not enabled', () => {
    const { container } = render(<VPNCard connected={[]} config={{ vpn: { enabled: false, profiles: [] } }} onNavigate={vi.fn()} />)
    expect(container).toBeEmptyDOMElement()
  })

  it('renders nothing when config has not loaded yet', () => {
    const { container } = render(<VPNCard connected={null} config={null} onNavigate={vi.fn()} />)
    expect(container).toBeEmptyDOMElement()
  })

  it('shows a "no profile configured" hint when enabled with zero profiles', () => {
    render(<VPNCard connected={[]} config={cfg([])} onNavigate={vi.fn()} />)
    expect(screen.getByText('no profile configured')).toBeInTheDocument()
    expect(screen.getByText('Add a profile')).toBeInTheDocument()
  })

  it('shows an error badge when a profile is configured but not connected', () => {
    render(<VPNCard connected={[]} config={cfg([{ id: 'p1', provider: 'pia', region: 'uk_london' }])} onNavigate={vi.fn()} />)
    const badge = screen.getByText('0/1 connected')
    expect(badge).toHaveClass('badge-error')
  })

  it('shows an allowed badge when every profile is connected', () => {
    render(
      <VPNCard
        connected={[{ id: 'p1', provider: 'pia', region: 'uk_london', endpoint: '1.2.3.4:51820' }]}
        config={cfg([{ id: 'p1', provider: 'pia', region: 'uk_london' }])}
        onNavigate={vi.fn()}
      />,
    )
    const badge = screen.getByText('1/1 connected')
    expect(badge).toHaveClass('badge-allowed')
  })
})
