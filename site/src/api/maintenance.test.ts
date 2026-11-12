import { afterEach, describe, expect, it, vi } from 'vitest'
import { maintenanceApi } from './maintenance'

afterEach(() => vi.unstubAllGlobals())

describe('maintenance target API', () => {
  it('creates only the explicitly confirmed mapped release target', async () => {
    const fetch = vi.fn().mockResolvedValue(new Response(JSON.stringify({ data: { target_branch: 'release/1.2', source_sha: 'abc', created: true, reconciled: false } }), { status: 200 }))
    vi.stubGlobal('fetch', fetch)
    const result = await maintenanceApi.create('/remediation', { release_id: 'release', release_version: '1.2.3', tag: 'v1.2.3', sha: 'abc' }, {
      mapping: { id: 'line', tag_pattern: 'v1.2.*', target_template: 'release/{major}.{minor}' },
      target_branch: 'release/1.2', can_create: true,
    })
    expect(result.created).toBe(true)
    expect(fetch).toHaveBeenCalledWith('/api/v1/remediation/maintenance-targets', expect.objectContaining({
      method: 'POST',
      body: JSON.stringify({ release_id: 'release', mapping_id: 'line', target_branch: 'release/1.2', source_tag: 'v1.2.3', source_sha: 'abc' }),
    }))
  })
  it('fetches release-scoped suggestions without guessing a branch', async () => {
    const fetch = vi.fn().mockResolvedValue(new Response(JSON.stringify({ data: { suggestions: [], reason: 'No mappings' } }), { status: 200 }))
    vi.stubGlobal('fetch', fetch)
    const response = await maintenanceApi.suggestions('/remediation', 'release/id')
    expect(response.suggestions).toEqual([])
    expect(fetch).toHaveBeenCalledWith('/api/v1/remediation/maintenance-targets?release_id=release%2Fid', expect.anything())
  })
})
