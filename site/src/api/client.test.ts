import { afterEach, describe, expect, it, vi } from 'vitest'
import { ApiError, apiRequest } from './client'

afterEach(() => { vi.unstubAllGlobals() })

describe('API errors', () => {
  it('retains status and Error compatibility for missing routes', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response('Not found', { status: 404 })))
    const error = await apiRequest('/missing').catch(error => error)
    expect(error).toBeInstanceOf(Error)
    expect(error).toBeInstanceOf(ApiError)
    expect(error).toMatchObject({ status: 404, structured: false, message: 'HTTP 404' })
  })

  it('preserves structured server errors', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response(JSON.stringify({ error: { message: 'Repository access revoked' } }), { status: 404 })))
    await expect(apiRequest('/missing')).rejects.toMatchObject({ status: 404, structured: true, message: 'Repository access revoked' })
  })
})
