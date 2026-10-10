import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'

import { describe, expect, it } from 'vitest'

import { formatVector, parseVector, scoreVector, severityOf } from './score'

function score(raw: string): number {
  const parsed = parseVector(raw)
  if (!parsed.ok) throw new Error(`${raw}: ${parsed.error}`)
  return scoreVector(parsed.vector)
}

describe('cvss scoring', () => {
  // Scored by FIRST's own v4.0 calculator; shared with internal/cvss so the
  // frontend and the backend agree on every vector.
  it('matches FIRST on every v4.0 golden vector', () => {
    const golden = JSON.parse(readFileSync(resolve(__dirname, '../../../../internal/cvss/testdata/v4-golden.json'), 'utf8')) as Array<[string, number]>
    expect(golden.length).toBeGreaterThan(1000)
    const mismatches = golden.filter(([vector, want]) => score(vector) !== want)
    expect(mismatches).toEqual([])
  })

  it('scores v3.1, v3.0 and v2 like NVD', () => {
    expect(score('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H')).toBe(9.8)
    expect(score('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H/E:H')).toBe(10)
    expect(score('CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H')).toBe(5.9)
    expect(score('CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H')).toBe(8.6)
    expect(score('CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N')).toBe(1.6)
    expect(score('CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N')).toBe(6.4)
    expect(score('AV:N/AC:L/Au:N/C:P/I:P/A:P')).toBe(7.5)
    expect(score('(AV:N/AC:L/Au:N/C:N/I:N/A:P)')).toBe(5)
    expect(score('AV:N/AC:M/Au:N/C:N/I:P/A:N')).toBe(4.3)
  })

  it('rejects malformed vectors with a reason', () => {
    for (const raw of ['', 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H', 'CVSS:4.0/AV:X/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N', 'CVSS:5.0/AV:N', 'CVSS:3.1/AV:N/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H']) {
      const parsed = parseVector(raw)
      expect(parsed.ok, raw).toBe(false)
    }
  })

  it('formats canonically and bands scores', () => {
    const parsed = parseVector('CVSS:4.0/SA:N/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/E:X')
    expect(parsed.ok && formatVector(parsed.vector.version, parsed.vector.metrics)).toBe('CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N')
    expect([9, 7, 4, 0.1, 0].map(severityOf)).toEqual(['critical', 'high', 'medium', 'low', 'none'])
  })
})
