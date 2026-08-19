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
    expect(advisoryUrl('RUSTSEC-2024-0001')).toBe('https://rustsec.org/advisories/RUSTSEC-2024-0001.html')
    expect(advisoryUrl('SNYK-JS-LODASH-567746')).toBe('https://security.snyk.io/vuln/SNYK-JS-LODASH-567746')
    expect(advisoryUrl('RHSA-2024:1234')).toBe('https://access.redhat.com/errata/RHSA-2024:1234')
    expect(advisoryUrl('RHBA-2024:1234')).toBe('https://access.redhat.com/errata/RHBA-2024:1234')
    expect(advisoryUrl('USN-6899-1')).toBe('https://ubuntu.com/security/notices/USN-6899-1')
    expect(advisoryUrl('DSA-5678-1')).toBe('https://security-tracker.debian.org/tracker/DSA-5678-1')
    expect(advisoryUrl('DLA-3456-1')).toBe('https://security-tracker.debian.org/tracker/DLA-3456-1')
    expect(advisoryUrl('ELSA-2024-12345')).toBe('https://linux.oracle.com/errata/ELSA-2024-12345.html')
    expect(advisoryUrl('ALAS-2024-1792')).toBe('https://alas.aws.amazon.com/ALAS-2024-1792.html')
    expect(advisoryUrl('ALAS2-2024-2273')).toBe('https://alas.aws.amazon.com/AL2/ALAS-2024-2273.html')
    expect(advisoryUrl('GLSA-202401-01')).toBe('https://security.gentoo.org/glsa/202401-01')
    expect(advisoryUrl('FEDORA-2024-abcdef1234')).toBe('https://bodhi.fedoraproject.org/updates/FEDORA-2024-abcdef1234')
  })

  it('sends OSV-hosted vendor namespaces to osv.dev, multi-segment prefixes included', () => {
    expect(advisoryUrl('ALSA-2024:1234')).toBe('https://osv.dev/vulnerability/ALSA-2024:1234')
    expect(advisoryUrl('RLSA-2024:1234')).toBe('https://osv.dev/vulnerability/RLSA-2024:1234')
    expect(advisoryUrl('SUSE-SU-2024:1234-1')).toBe('https://osv.dev/vulnerability/SUSE-SU-2024:1234-1')
    expect(advisoryUrl('openSUSE-SU-2024:1234-1')).toBe('https://osv.dev/vulnerability/openSUSE-SU-2024:1234-1')
    expect(advisoryUrl('MGASA-2024-0001')).toBe('https://osv.dev/vulnerability/MGASA-2024-0001')
    expect(advisoryUrl('MAL-2024-1234')).toBe('https://osv.dev/vulnerability/MAL-2024-1234')
    expect(advisoryUrl('CGA-6q2p-2xvv-2gqx')).toBe('https://osv.dev/vulnerability/CGA-6q2p-2xvv-2gqx')
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
