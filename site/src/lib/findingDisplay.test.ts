import { describe, expect, it } from 'vitest'

import { advisoryUrl, cweUrl, findingShape, isComponentBacked, severityKey } from './findingDisplay'

describe('severityKey', () => {
  it('normalizes the spellings scanners emit', () => {
    expect(severityKey('CRITICAL')).toBe('critical')
    expect(severityKey('Very High')).toBe('critical')
    expect(severityKey('Moderate')).toBe('medium')
    expect(severityKey(undefined)).toBe('info')
  })
})

describe('findingShape', () => {
  it('routes each kind to the detail view that fits it', () => {
    expect(findingShape('dependency')).toBe('component')
    expect(findingShape('container')).toBe('component')
    expect(findingShape('malware')).toBe('component')
    expect(findingShape('sast')).toBe('code')
    expect(findingShape('dast')).toBe('code')
    expect(findingShape('secret')).toBe('secret')
    expect(findingShape('manual')).toBe('generic')
    // A kind added server-side must fall back, not crash the drawer.
    expect(findingShape('supply_chain')).toBe('generic')
  })

  it('keeps VEX to component-backed kinds', () => {
    expect(isComponentBacked('dependency')).toBe(true)
    expect(isComponentBacked('container')).toBe(true)
    expect(isComponentBacked('sast')).toBe(false)
    expect(isComponentBacked(undefined)).toBe(false)
  })
})

describe('advisoryUrl', () => {
  it('links each identifier namespace to its home', () => {
    expect(advisoryUrl('CVE-2024-1234')).toBe('https://nvd.nist.gov/vuln/detail/CVE-2024-1234')
    expect(advisoryUrl('GHSA-abcd-efgh-ijkl')).toBe('https://github.com/advisories/GHSA-abcd-efgh-ijkl')
    expect(advisoryUrl('GO-2024-0001')).toBe('https://pkg.go.dev/vuln/GO-2024-0001')
    expect(advisoryUrl('PYSEC-2024-1')).toBe('https://osv.dev/vulnerability/PYSEC-2024-1')
  })

  it('returns nothing for a rule id, so no broken link is rendered', () => {
    expect(advisoryUrl('G101')).toBe('')
    expect(advisoryUrl(undefined)).toBe('')
  })
})

describe('cweUrl', () => {
  it('links a CWE and ignores anything else', () => {
    expect(cweUrl('CWE-79')).toBe('https://cwe.mitre.org/data/definitions/79.html')
    expect(cweUrl('cwe-89: SQL injection')).toBe('https://cwe.mitre.org/data/definitions/89.html')
    expect(cweUrl('injection')).toBe('')
  })
})
