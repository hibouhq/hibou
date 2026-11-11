import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { effectScope, nextTick, ref, type EffectScope } from 'vue'
import { api } from '@/api/client'
import { useSnapshotSelection } from './useSnapshotSelection'

vi.mock('@/api/client', () => ({ api: { listSnapshots: vi.fn() } }))

type SnapshotResponse = Awaited<ReturnType<typeof api.listSnapshots>>
const scopes: EffectScope[] = []

function response(name: string): SnapshotResponse {
  return {
    data: [{ id: `${name}-snapshot`, ref_id: name, commit_sha: `${name}-commit`, status: 'complete', created_at: '2026-11-11T12:00:00Z' }],
    pagination: { total: 1, page: 1, per_page: 50 },
  }
}

function deferred() {
  let resolve!: (value: SnapshotResponse) => void
  const promise = new Promise<SnapshotResponse>(done => { resolve = done })
  return { promise, resolve }
}

function setup() {
  const scope = effectScope()
  scopes.push(scope)
  const open = ref(true)
  const baseName = ref('main')
  const targetName = ref('feature')
  const baseId = ref('')
  const targetId = ref('')
  const selections = scope.run(() => ({
    base: useSnapshotSelection(() => [open.value, baseName.value, 'github', 'org', 'repo'], baseId),
    target: useSnapshotSelection(() => [open.value, targetName.value, 'github', 'org', 'repo'], targetId),
  }))!
  return { ...selections, open, baseName, targetName, baseId, targetId }
}

async function flush() {
  await Promise.resolve()
  await nextTick()
  await Promise.resolve()
  await nextTick()
}

beforeEach(() => {
  vi.resetAllMocks()
  vi.mocked(api.listSnapshots).mockImplementation(async (_provider, _org, _repo, params) => response(params?.ref ?? ''))
})
afterEach(() => { scopes.splice(0).forEach(scope => scope.stop()) })

describe('independent comparison snapshot loading', () => {
  it('keeps the base selection and options untouched while a new target is loading', async () => {
    const state = setup()
    await flush()
    const baseOptions = state.base.snapshots.value
    const pending = deferred()
    vi.mocked(api.listSnapshots).mockReturnValueOnce(pending.promise)

    state.targetName.value = 'release'
    state.targetId.value = ''
    await nextTick()

    expect(api.listSnapshots).toHaveBeenCalledTimes(3)
    expect(api.listSnapshots).toHaveBeenLastCalledWith('github', 'org', 'repo', { ref: 'release', per_page: 50 })
    expect(state.base.loading.value).toBe(false)
    expect(state.base.snapshots.value).toBe(baseOptions)
    expect(state.baseId.value).toBe('main-snapshot')
    expect(state.target.loading.value).toBe(true)

    pending.resolve(response('release'))
    await flush()
    expect(state.targetId.value).toBe('release-snapshot')
    expect(state.baseId.value).toBe('main-snapshot')
  })

  it('keeps the target untouched while the base changes', async () => {
    const state = setup()
    await flush()
    const targetOptions = state.target.snapshots.value
    const pending = deferred()
    vi.mocked(api.listSnapshots).mockReturnValueOnce(pending.promise)

    state.baseName.value = 'older'
    state.baseId.value = ''
    await nextTick()
    expect(state.target.loading.value).toBe(false)
    expect(state.target.snapshots.value).toBe(targetOptions)
    expect(state.targetId.value).toBe('feature-snapshot')
    pending.resolve(response('older'))
    await flush()
  })

  it('isolates failed requests and retries to the affected side', async () => {
    const state = setup()
    await flush()
    vi.mocked(api.listSnapshots).mockRejectedValueOnce(new Error('Target unavailable'))
    state.targetName.value = 'release'
    state.targetId.value = ''
    await flush()

    expect(state.target.error.value).toBe('Target unavailable')
    expect(state.base.error.value).toBe('')
    expect(state.baseId.value).toBe('main-snapshot')
    expect(state.base.snapshots.value).toHaveLength(1)

    state.target.retry()
    await flush()
    expect(api.listSnapshots).toHaveBeenCalledTimes(4)
    expect(state.target.error.value).toBe('')
    expect(state.targetId.value).toBe('release-snapshot')
    expect(state.baseId.value).toBe('main-snapshot')
  })

  it('ignores a stale target response after switching refs again', async () => {
    const state = setup()
    await flush()
    const stale = deferred()
    vi.mocked(api.listSnapshots).mockReturnValueOnce(stale.promise)
    state.targetName.value = 'stale'
    state.targetId.value = ''
    await nextTick()

    state.targetName.value = 'newest'
    await flush()
    stale.resolve(response('stale'))
    await flush()
    expect(state.target.snapshots.value[0].id).toBe('newest-snapshot')
    expect(state.targetId.value).toBe('newest-snapshot')
    expect(state.target.loading.value).toBe(false)
  })

  it('does not apply pending results after closing the comparison panel', async () => {
    const pending = deferred()
    vi.mocked(api.listSnapshots).mockReturnValue(pending.promise)
    const state = setup()
    state.open.value = false
    await nextTick()
    pending.resolve(response('closed'))
    await flush()
    expect(state.baseId.value).toBe('')
    expect(state.targetId.value).toBe('')
    expect(state.base.loading.value).toBe(false)
    expect(state.target.loading.value).toBe(false)
  })
})
