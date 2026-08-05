import { describe, expect, it } from 'vitest'

import { TOKEN_PRESETS } from './tokenPresets'

const preset = (key: string) => {
  const found = TOKEN_PRESETS.find((candidate) => candidate.key === key)
  if (!found) throw new Error(`preset ${key} is missing`)
  return found
}

describe('token presets', () => {
  it('read-only agent grants no write anywhere', () => {
    const levels = Object.values(preset('read-only-agent').permissions)
    expect(levels.length).toBeGreaterThan(0)
    expect(levels.every((level) => level === 'read')).toBe(true)
  })

  it('no preset ever grants admin', () => {
    for (const { key, permissions } of TOKEN_PRESETS) {
      expect(permissions.admin ?? 'none', `preset ${key} must not grant admin`).toBe('none')
    }
  })

  it('ci uploader writes uploads and nothing else', () => {
    const { permissions } = preset('ci-uploader')
    const writes = Object.entries(permissions).filter(([, level]) => level === 'write')
    expect(writes).toEqual([['uploads', 'write']])
  })

  it('triage agent cannot override gates', () => {
    const { permissions } = preset('triage-agent')
    expect(permissions.quality_gates ?? 'none').not.toBe('write')
    expect(permissions.vulnerabilities).toBe('write')
    expect(permissions.triage).toBe('write')
  })

  it('every preset grants at least one capability', () => {
    for (const { key, permissions } of TOKEN_PRESETS) {
      const granted = Object.values(permissions).filter((level) => level && level !== 'none')
      expect(granted.length, `preset ${key} grants nothing`).toBeGreaterThan(0)
    }
  })
})
