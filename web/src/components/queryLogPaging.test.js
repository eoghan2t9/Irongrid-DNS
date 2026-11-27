import { describe, it, expect } from 'vitest'
import { compareIds, mergeHead, appendOlder, MAX_ENTRIES } from './queryLogPaging'

const e = (ms, seq = 0) => ({ id: `${ms}-${seq}`, domain: `d${ms}-${seq}.example.` })
const ids = (list) => list.map((x) => x.id)

describe('compareIds', () => {
  it('orders by milliseconds then sequence, numerically', () => {
    expect(compareIds('10-0', '9-0')).toBeGreaterThan(0) // not a string compare
    expect(compareIds('5-2', '5-10')).toBeLessThan(0)
    expect(compareIds('5-3', '5-3')).toBe(0)
  })
})

describe('mergeHead', () => {
  it('starts from the head when nothing is on screen yet', () => {
    const r = mergeHead([], [e(3), e(2)], 'cur')
    expect(ids(r.list)).toEqual(['3-0', '2-0'])
    expect(r.cursor).toBe('cur')
  })

  it('prepends only the new entries and keeps the loaded older ones and the cursor', () => {
    const prev = [e(5), e(4), e(3), e(2), e(1)] // 3..1 were loaded as older pages
    const head = [e(7), e(6), e(5), e(4)] // newest page overlaps prev at 5,4
    const r = mergeHead(prev, head, 'head-next')
    expect(ids(r.list)).toEqual(['7-0', '6-0', '5-0', '4-0', '3-0', '2-0', '1-0'])
    expect(r.cursor).toBeUndefined() // keep the existing load-older cursor
  })

  it('leaves the list untouched when nothing is new', () => {
    const prev = [e(5), e(4)]
    const r = mergeHead(prev, [e(5), e(4)])
    expect(r.list).toBe(prev)
    expect(r.cursor).toBeUndefined()
  })

  it('starts over when the new page does not overlap (entries may have been missed)', () => {
    const prev = [e(5), e(4), e(3)]
    const head = [e(900), e(899), e(898)]
    const r = mergeHead(prev, head, 'head-next')
    expect(ids(r.list)).toEqual(['900-0', '899-0', '898-0'])
    expect(r.cursor).toBe('head-next')
  })

  it('empties the list when the log was cleared', () => {
    const r = mergeHead([e(5), e(4)], [], '')
    expect(r.list).toEqual([])
    expect(r.cursor).toBe('')
  })

  it('tells same-millisecond entries apart by sequence', () => {
    const prev = [e(5, 1), e(5, 0)]
    const r = mergeHead(prev, [e(5, 2), e(5, 1)])
    expect(ids(r.list)).toEqual(['5-2', '5-1', '5-0'])
  })

  it('caps the list and resumes from the last entry kept', () => {
    const prev = Array.from({ length: MAX_ENTRIES }, (_, i) => e(10000 - i))
    const head = [e(10002), e(10001), prev[0]]
    const r = mergeHead(prev, head, 'x')
    expect(r.list).toHaveLength(MAX_ENTRIES)
    expect(r.list[0].id).toBe('10002-0')
    expect(r.cursor).toBe(r.list[MAX_ENTRIES - 1].id)
  })
})

describe('appendOlder', () => {
  it('appends below and skips entries already shown', () => {
    const r = appendOlder([e(5), e(4)], [e(4), e(3), e(2)])
    expect(ids(r)).toEqual(['5-0', '4-0', '3-0', '2-0'])
  })
})
