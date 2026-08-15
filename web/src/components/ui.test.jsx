import { describe, it, expect, vi } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { LineListField } from './ui'

// LineListField is the one-entry-per-line textarea behind Settings' honeypot/
// allowlist/blacklist fields and Client Groups' CIDR/upstream fields. The
// regression these tests guard: the old implementation normalised (trim +
// drop empty lines) on every keystroke, so the trailing newline was stripped
// the instant Enter was pressed and the field appeared to ignore the key.
describe('LineListField', () => {
  const renderField = (value, onChange = vi.fn()) =>
    render(<LineListField value={value} onChange={onChange} placeholder="one per line" />)

  it('keeps the newline while typing — Enter creates a real line', async () => {
    const user = userEvent.setup()
    const onChange = vi.fn()
    renderField(['exponea.com'], onChange)
    const ta = screen.getByRole('textbox')

    await user.type(ta, '{enter}fnal.gov{enter}x.fnal.gov{enter}')

    // Still mid-edit: the draft preserves every newline, and nothing has
    // been committed to the config yet.
    expect(ta.value).toBe('exponea.com\nfnal.gov\nx.fnal.gov\n')
    expect(onChange).not.toHaveBeenCalled()
  })

  it('commits a normalised list on blur and cleans the trailing newline', async () => {
    const user = userEvent.setup()
    const onChange = vi.fn()
    renderField(['exponea.com'], onChange)
    const ta = screen.getByRole('textbox')

    await user.type(ta, '{enter}fnal.gov{enter} random2.example.com {enter}')
    await user.tab() // blur

    await waitFor(() => {
      expect(onChange).toHaveBeenCalledWith(['exponea.com', 'fnal.gov', 'random2.example.com'])
    })
    expect(ta.value).toBe('exponea.com\nfnal.gov\nrandom2.example.com')
  })

  it('drops blank lines and whitespace-only lines on commit', async () => {
    const user = userEvent.setup()
    const onChange = vi.fn()
    renderField(['a.example'], onChange)
    const ta = screen.getByRole('textbox')

    await user.type(ta, '{enter}{enter}   {enter}b.example{enter}')
    await user.tab()

    await waitFor(() => {
      expect(onChange).toHaveBeenCalledWith(['a.example', 'b.example'])
    })
  })

  it('replaces the draft when the value changes from outside (not mid-typing)', async () => {
    const { rerender } = renderField(['a.example'], vi.fn())
    const ta = screen.getByRole('textbox')
    expect(ta.value).toBe('a.example')

    rerender(<LineListField value={['a.example', 'b.example']} onChange={vi.fn()} />)
    expect(ta.value).toBe('a.example\nb.example')
  })
})
