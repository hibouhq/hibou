import { afterEach, describe, expect, it, vi } from 'vitest'

import { api, ApiError } from './client'

afterEach(() => {
  vi.unstubAllGlobals()
})

describe('repository removal preview failures', () => {
  it('explains a missing endpoint without attempting a delete', async () => {
    const fetch = vi.fn().mockResolvedValue(new Response('404 page not found', { status: 404 }))
    vi.stubGlobal('fetch', fetch)
    await expect(api.getRepositoryRemovalPreview('github', 'fixture', 'fixture-repository')).rejects.toMatchObject({
      status: 404,
      structured: false,
      message: expect.stringContaining('Update/restart the Hibou backend'),
    })
    expect(fetch).toHaveBeenCalledTimes(1)
    expect(fetch.mock.calls[0][0]).toBe('/api/v1/orgs/github/fixture/repos/fixture-repository/removal-preview')
    expect(fetch.mock.calls[0][1].method).toBeUndefined()
  })

  it('preserves a structured repository-not-found response', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response(JSON.stringify({
      error: { code: 404, message: 'repository not found' },
    }), { status: 404, headers: { 'Content-Type': 'application/json' } })))
    await expect(api.getRepositoryRemovalPreview('github', 'fixture', 'fixture-repository')).rejects.toMatchObject({
      status: 404,
      structured: true,
      message: 'repository not found',
    })
  })

  it('does not mask authentication or other transport failures', async () => {
    const response = new Response(JSON.stringify({ error: { code: 401, message: 'authentication required' } }), { status: 401 })
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(response))
    await expect(api.getRepositoryRemovalPreview('github', 'fixture', 'fixture-repository')).rejects.toEqual(new ApiError(401, 'authentication required', true))
    const failure = new TypeError('network unavailable')
    vi.stubGlobal('fetch', vi.fn().mockRejectedValue(failure))
    await expect(api.getRepositoryRemovalPreview('github', 'fixture', 'fixture-repository')).rejects.toBe(failure)
  })
})
