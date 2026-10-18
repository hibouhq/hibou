import { describe, expect, it } from 'vitest'

import { defaultDevicePreset, normalizeUserCode, userCodesMatch } from './deviceLogin'

describe('device login helpers', () => {
  it('normalizes user codes like the server', () => {
    expect(normalizeUserCode('bcdf-ghjk')).toBe('BCDFGHJK')
    expect(normalizeUserCode(' BCDF GHJK ')).toBe('BCDFGHJK')
    expect(normalizeUserCode('BCDF-GHJ')).toBeNull()
    expect(normalizeUserCode('ABCD-EFGH')).toBeNull() // vowels are not in the alphabet
  })

  it('matches a typed code against the link only when equal', () => {
    expect(userCodesMatch('bcdfghjk', 'BCDF-GHJK')).toBe(true)
    expect(userCodesMatch('BCDF-GHJL', 'BCDF-GHJK')).toBe(false)
    expect(userCodesMatch('', '')).toBe(false)
  })

  it('pre-selects read-only unless the CLI asked for more', () => {
    expect(defaultDevicePreset('hibou-cli', 'cli', ['cli', 'read-only'])).toBe('cli')
    expect(defaultDevicePreset('hibou-vscode', 'cli', ['cli', 'read-only'])).toBe('read-only')
    expect(defaultDevicePreset('hibou-intellij', 'read-only', ['read-only'])).toBe('read-only')
    expect(defaultDevicePreset('hibou-vscode', 'triage', ['triage', 'read-only'])).toBe('read-only')
    expect(defaultDevicePreset('hibou-intellij', 'triage', ['triage', 'read-only'])).toBe('read-only')
    expect(defaultDevicePreset('someone-else', 'cli', ['cli', 'read-only'])).toBe('read-only')
  })
})
