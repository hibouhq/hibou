import { afterEach, describe, expect, it, vi } from 'vitest'
import { computed, createRenderer, h, nextTick, ref } from 'vue'
import { createPinia } from 'pinia'
import { ApiError, api, type ScaEnableResult } from '@/api/client'
import { useScaActions, useScaPolling } from './useScaActions'

const renderer = createRenderer<object, object>({
  createElement: () => ({}), createText: () => ({}), createComment: () => ({}),
  insert: () => {}, remove: () => {}, setText: () => {}, setElementText: () => {}, patchProp: () => {},
  parentNode: () => null, nextSibling: () => null,
})
const cleanup: Array<() => void> = []
function mount<T>(setup: () => T): T {
  let value: T
  const app = renderer.createApp({ setup() { value = setup(); return () => h('div') } })
  app.use(createPinia())
  app.mount({})
  cleanup.push(() => app.unmount())
  return value!
}

afterEach(() => {
  cleanup.splice(0).forEach(unmount => unmount())
  vi.restoreAllMocks()
  vi.useRealTimers()
})

describe('SCA action requests', () => {
  it('prevents duplicate clicks while retaining every per-item outcome', async () => {
    let resolve!: (value: { data: { results: ScaEnableResult[] } }) => void
    const request = vi.spyOn(api, 'enableSca').mockReturnValue(new Promise(done => { resolve = done }))
    const actions = mount(() => useScaActions(computed(() => 'github'), computed(() => 'example')))
    const pending = actions.enable(['1', '2'])
    expect(await actions.enable(['1'])).toBeNull()
    expect(request).toHaveBeenCalledTimes(1)
    resolve({ data: { results: [
      { provider_id: '1', status: 'accepted', job_id: 'job', repo_slug: 'one' },
      { provider_id: '2', status: 'failed', error: 'Access denied' },
    ] } })
    await pending
    expect(actions.results.value).toHaveLength(2)
    expect(actions.results.value[1].error).toBe('Access denied')
    expect(actions.pending.value).toEqual([])
  })

  it('ignores requests completed after an organization change', async () => {
    let resolve!: (value: { data: { results: ScaEnableResult[] } }) => void
    vi.spyOn(api, 'enableSca').mockReturnValue(new Promise(done => { resolve = done }))
    const slug = ref('old')
    const actions = mount(() => useScaActions(computed(() => 'github'), computed(() => slug.value)))
    const pending = actions.enable(['1'])
    slug.value = 'new'
    resolve({ data: { results: [{ provider_id: '1', status: 'existing', repo_slug: 'old-repo' }] } })
    expect(await pending).toBeNull()
    expect(actions.results.value).toEqual([])
  })

  it('retains individual failures when returning from an accepted repository', async () => {
    vi.spyOn(api, 'enableSca').mockResolvedValue({ data: { results: [
      { provider_id: '1', status: 'accepted', job_id: 'job', repo_slug: 'one' },
      { provider_id: '2', status: 'failed', error: 'Access denied' },
    ] } })
    const provider = computed(() => 'github')
    const slug = computed(() => 'navigation-fixture')
    const actions = mount(() => useScaActions(provider, slug))
    await actions.enable(['1', '2'])
    cleanup.splice(0).forEach(unmount => unmount())
    const restored = mount(() => useScaActions(provider, slug))
    expect(restored.results.value).toHaveLength(2)
    expect(restored.results.value[1].error).toBe('Access denied')
  })

  it('does not restore transient 404 errors after navigation', async () => {
    vi.spyOn(api, 'enableSca').mockRejectedValue(new ApiError(404, 'HTTP404'))
    const provider = computed(() => 'github')
    const slug = computed(() => 'transient-error')
    const actions = mount(() => useScaActions(provider, slug))
    await actions.enable(['1'])
    expect(actions.error.value).toContain('matching versions')
    cleanup.splice(0).forEach(unmount => unmount())
    const restored = mount(() => useScaActions(provider, slug))
    expect(restored.error.value).toBe('')
    expect(restored.results.value).toEqual([])
  })

  it('dismisses persisted per-item outcomes and allows a new request', async () => {
    const request = vi.spyOn(api, 'enableSca').mockResolvedValue({ data: { results: [{ provider_id: '1', status: 'failed', error: 'Access denied' }] } })
    const provider = computed(() => 'github')
    const slug = computed(() => 'dismiss-fixture')
    const actions = mount(() => useScaActions(provider, slug))
    await actions.enable(['1'])
    actions.dismiss()
    expect(actions.results.value).toEqual([])
    expect(actions.error.value).toBe('')
    cleanup.splice(0).forEach(unmount => unmount())
    const restored = mount(() => useScaActions(provider, slug))
    expect(restored.results.value).toEqual([])
    await restored.enable(['1'])
    expect(request).toHaveBeenCalledTimes(2)
    expect(restored.results.value[0].error).toBe('Access denied')
  })

  it('clears an unavailable endpoint notice when dismissed', async () => {
    vi.spyOn(api, 'enableSca').mockRejectedValue(new ApiError(404, 'HTTP 404'))
    const actions = mount(() => useScaActions(computed(() => 'github'), computed(() => 'dismiss-404')))
    await actions.enable(['1'])
    expect(actions.error.value).toContain('endpoint unavailable')
    actions.dismiss()
    expect(actions.error.value).toBe('')
    expect(actions.results.value).toEqual([])
  })
})

describe('SCA progress polling', () => {
  it('polls pending work only, and clears timers when unmounted', async () => {
    vi.useFakeTimers()
    const pending = ref(true)
    const refresh = vi.fn(async () => {})
    mount(() => useScaPolling(computed(() => 'org'), computed(() => pending.value), refresh))
    await vi.advanceTimersByTimeAsync(4000)
    expect(refresh).toHaveBeenCalledTimes(1)
    pending.value = false
    await nextTick()
    await vi.advanceTimersByTimeAsync(8000)
    expect(refresh).toHaveBeenCalledTimes(1)
    pending.value = true
    await nextTick()
    cleanup.splice(0).forEach(unmount => unmount())
    await vi.advanceTimersByTimeAsync(8000)
    expect(refresh).toHaveBeenCalledTimes(1)
  })

  it('stops after five minutes even if the worker remains pending', async () => {
    vi.useFakeTimers()
    const refresh = vi.fn(async () => {})
    mount(() => useScaPolling(computed(() => 'org'), computed(() => true), refresh))
    await vi.advanceTimersByTimeAsync(600000)
    expect(refresh).toHaveBeenCalledTimes(75)
    expect(vi.getTimerCount()).toBe(0)
  })

  it('does not rearm an in-flight timer after navigation', async () => {
    vi.useFakeTimers()
    let resolve!: () => void
    const refresh = vi.fn(() => new Promise<void>(done => { resolve = done }))
    const pending = ref(true)
    mount(() => useScaPolling(computed(() => 'org'), computed(() => pending.value), refresh))
    await vi.advanceTimersByTimeAsync(4000)
    pending.value = false
    await nextTick()
    resolve()
    await nextTick()
    expect(vi.getTimerCount()).toBe(0)
  })
})
