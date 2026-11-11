import { ref, watch, type Ref } from 'vue'
import { api, type Snapshot } from '@/api/client'
import { latestComparableSnapshot } from '@/lib/compareSnapshots'

type SnapshotScope = readonly [open: boolean, refName: string, provider: string, orgSlug: string, repoSlug: string]

export function useSnapshotSelection(scope: () => SnapshotScope, selectedId: Ref<string>) {
  const snapshots = ref<Snapshot[]>([])
  const loading = ref(false)
  const error = ref('')
  const retryCount = ref(0)

  watch(
    () => [...scope(), retryCount.value] as const,
    async ([open, refName, provider, orgSlug, repoSlug], _, onCleanup) => {
      let cancelled = false
      onCleanup(() => { cancelled = true })
      loading.value = false
      if (!open || !refName || !provider || !orgSlug || !repoSlug) return

      loading.value = true
      error.value = ''
      snapshots.value = []
      try {
        const response = await api.listSnapshots(provider, orgSlug, repoSlug, { ref: refName, per_page: 50 })
        if (cancelled) return
        snapshots.value = response.data
        selectedId.value ||= latestComparableSnapshot(response.data)?.id || ''
      } catch (caught) {
        if (!cancelled) error.value = caught instanceof Error ? caught.message : 'Failed to load snapshots.'
      } finally {
        if (!cancelled) loading.value = false
      }
    },
    { immediate: true },
  )

  return { snapshots, loading, error, retry: () => { retryCount.value++ } }
}
