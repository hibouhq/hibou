import { afterEach, describe, expect, it, vi } from 'vitest'
import { isRemediationPending, isRemediationVerified, remediationApi, remediationPath } from './remediation'
import type { RemediationJob } from './remediation'

afterEach(() => vi.unstubAllGlobals())

describe('managed remediation state', () => {
  it('unwraps the real API data envelope', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response(JSON.stringify({ data: { id: 'draft', state: 'preparing' } }), { status: 200 })))
    const job = await remediationApi.get('/remediation', 'draft')
    expect(job.id).toBe('draft')
    expect(job.state).toBe('preparing')
  })
  it('encodes repository routing coordinates', () => {
    expect(remediationPath('github', 'org/name', 'repo?x')).toBe('/orgs/github/org%2Fname/repos/repo%3Fx/remediation')
  })
  it('polls only durable in-flight phases', () => {
    expect(isRemediationPending('generating')).toBe(true)
    expect(isRemediationPending('awaiting_selection')).toBe(false)
    expect(isRemediationPending('failed')).toBe(false)
  })
  it('never exposes success for a failed or partially verified artifact', () => {
    const job = {
      state: 'ready',
      result: { artifact: { changes: [{ path: 'package-lock.json' }], units: [{ id: '.' }], verification: [{ dependency_files_consistent: true, selected_vulns_addressed: true, no_introduced_vulns: false }] } },
    } as RemediationJob
    expect(isRemediationVerified(job)).toBe(false)
    job.result.artifact!.verification[0]!.no_introduced_vulns = true
    expect(isRemediationVerified(job)).toBe(true)
    job.state = 'failed'
    expect(isRemediationVerified(job)).toBe(false)
  })
})
