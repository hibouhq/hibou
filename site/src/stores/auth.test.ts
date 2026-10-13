import { createPinia, setActivePinia } from 'pinia'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import { useAuthStore } from '@/stores/auth'

const user = {
  id: 'u1',
  email: 'a@example.com',
  display_name: 'A',
} as unknown as NonNullable<ReturnType<typeof useAuthStore>['user']>

describe('auth store logout', () => {
  beforeEach(() => {
    setActivePinia(createPinia())
  })
  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('keeps the user signed in when the server refuses the logout', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => new Response(
      JSON.stringify({ error: { message: 'failed to log out' } }),
      { status: 500, headers: { 'Content-Type': 'application/json' } },
    )))
    const store = useAuthStore()
    store.user = user

    await expect(store.logout()).rejects.toThrow('failed to log out')
    expect(store.isAuthenticated).toBe(true)
  })

  it('clears the user once the server confirms', async () => {
    const fetchMock = vi.fn(async () => new Response(null, { status: 204 }))
    vi.stubGlobal('fetch', fetchMock)
    const store = useAuthStore()
    store.user = user

    await store.logout()
    expect(store.isAuthenticated).toBe(false)
    expect(fetchMock).toHaveBeenCalledWith('/api/v1/auth/logout', expect.objectContaining({ method: 'POST' }))
  })
})
