import { computed, onUnmounted, ref, watch, type ComputedRef } from 'vue'
import { getActivePinia } from 'pinia'
import { api, type ScaEnableResult } from '@/api/client'
import { scaErrorMessage, scaSelectionValid } from '@/lib/sca'
import { useAuthStore } from '@/stores/auth'

// Keep batch failures visible when an admin opens a successful item and comes back.
const feedback = new Map<string, ScaEnableResult[]>()

export function useScaActions(provider: ComputedRef<string>, slug: ComputedRef<string>) {
  const auth = getActivePinia() ? useAuthStore() : undefined
  const scope = computed(() => `${auth?.user?.id ?? 'anonymous'}/${provider.value}/${slug.value}`)
  const pending = ref<string[]>([])
  const results = ref<ScaEnableResult[]>(feedback.get(scope.value) ?? [])
  const error = ref('')
  let generation = 0
  watch(scope, () => {
    generation++
    pending.value = []
    results.value = feedback.get(scope.value) ?? []
    error.value = ''
  }, { flush: 'sync' })
  onUnmounted(() => { generation++ })

  function dismiss() {
    results.value = []
    error.value = ''
    feedback.delete(scope.value)
  }

  async function enable(ids: string[]): Promise<ScaEnableResult[] | null> {
    if (pending.value.length || !scaSelectionValid(ids)) return null
    const request = generation
    const requestScope = scope.value
    pending.value = [...ids]
    results.value = []
    error.value = ''
    feedback.delete(requestScope)
    try {
      const response = await api.enableSca(provider.value, slug.value, ids)
      feedback.set(requestScope, response.data.results)
      if (request !== generation) return null
      results.value = response.data.results
      return results.value
    } catch (caught) {
      const message = scaErrorMessage(caught)
      if (request === generation) error.value = message
      return null
    } finally {
      if (request === generation) pending.value = []
    }
  }
  return { pending, results, error, enable, dismiss }
}

/** At most five minutes of polling per route/operation, and only while work is pending. */
export function useScaPolling(scope: ComputedRef<string>, pending: ComputedRef<boolean>, refresh: () => Promise<void>, onError?: (error: unknown) => void) {
  let timer: ReturnType<typeof setTimeout> | undefined
  let generation = 0
  let attempts = 0
  function stop() {
    generation++
    clearTimeout(timer)
    timer = undefined
  }
  function schedule() {
    if (timer || !pending.value || attempts >= 75) return
    const request = generation
    timer = setTimeout(async () => {
      timer = undefined
      attempts++
      try { await refresh() } catch (error) {
        if (request === generation) onError?.(error)
        return
      }
      if (request === generation) schedule()
    }, 4000)
  }
  watch(scope, () => { stop(); attempts = 0; schedule() })
  watch(pending, (value) => {
    if (value) { attempts = 0; schedule() } else stop()
  }, { immediate: true })
  onUnmounted(stop)
}
