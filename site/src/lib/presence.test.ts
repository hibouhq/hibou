import { describe, expect, it } from 'vitest'

import { isCarried, presenceTitle } from './presence'

describe('presence', () => {
  it('explains a carried finding with its last-seen commit', () => {
    expect(isCarried({ presence: 'reported' })).toBe(false)
    expect(isCarried({})).toBe(false)
    expect(presenceTitle({ presence: 'not_rechecked', presence_reason: 'file_skipped:timeout', last_seen_commit: 'a1b2c3d4e5' }))
      .toBe('Not re-checked since a1b2c3d: the scanner skipped the file (timeout). Still counted as open.')
    expect(presenceTitle({ presence: 'unconfirmed', presence_reason: 'unchanged' })).toBe('Unconfirmed: it disappeared, but the file did not change. Still counted as open.')
  })
})
