import { describe, expect, it } from 'vitest'

import { countdown } from '@/api/incidents'
import { dateTitle, formatDateTime } from '@/lib/datetime'

describe('formatDateTime', () => {
  const now = new Date(2026, 9, 24, 12, 0, 0).getTime()

  it('drops the year in the current year', () => {
    const text = formatDateTime(new Date(2026, 9, 20, 15, 23).toISOString(), now)
    expect(text).toContain('Oct 20')
    expect(text).not.toContain('2026')
  })

  it('keeps the year otherwise', () => {
    expect(formatDateTime(new Date(2025, 9, 20, 15, 23).toISOString(), now)).toContain('2025')
  })
})

describe('dateTitle', () => {
  it('gives the relative time and the full date', () => {
    const title = dateTitle(new Date(Date.now() - 4 * 86400_000).toISOString())
    expect(title).toMatch(/^4 days ago · /)
  })
})

describe('countdown', () => {
  const now = Date.UTC(2026, 9, 24, 12, 0, 0)
  const at = (seconds: number) => new Date(now + seconds * 1000).toISOString()

  it('shows seconds inside the last day', () => {
    expect(countdown(at(3 * 3600 + 32 * 60 + 9), now).text).toBe('in 3h 32m 09s')
    expect(countdown(at(5 * 60 + 3), now).text).toBe('in 5m 03s')
    expect(countdown(at(42), now).text).toBe('in 42s')
  })

  it('shows days, hours and minutes beyond a day', () => {
    expect(countdown(at(2 * 86400 + 3 * 3600 + 7 * 60 + 30), now).text).toBe('in 2d 3h 07m')
  })

  it('marks overdue', () => {
    expect(countdown(at(-(8 * 3600 + 8 * 60 + 55)), now)).toEqual({ text: 'overdue by 8h 08m 55s', overdue: true })
  })
})
