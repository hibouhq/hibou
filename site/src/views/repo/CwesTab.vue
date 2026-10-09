<template>
  <div class="space-y-4">
    <p class="text-sm text-gray-400">
      Every CWE carried by this ref's open vulnerabilities — from code scanners, dependencies, secrets and manual reports alike.
      Pick one to see its vulnerabilities.
    </p>
    <p
      v-if="error"
      class="text-sm text-amber-300"
    >
      {{ error }}
    </p>
    <CweUsageTable
      :report="report"
      :loading="loading"
      @select="openFindings"
    />
  </div>
</template>

<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'

import { api, type CWEUsageReport } from '@/api/client'
import CweUsageTable from '@/components/CweUsageTable.vue'
import { rememberCWEs } from '@/lib/cweCatalog'

// ADR-037 CWE list for one ref: what kinds of weakness this code has,
// whichever scanner or advisory reported them.
const route = useRoute()
const router = useRouter()
const provider = computed(() => route.params.provider as string)
const slug = computed(() => route.params.slug as string)
const repoSlug = computed(() => route.params.repoSlug as string)
const refName = computed(() => (typeof route.query.ref === 'string' ? route.query.ref : undefined))
const snapshot = computed(() => (typeof route.query.snapshot === 'string' ? route.query.snapshot : undefined))

const report = ref<CWEUsageReport | null>(null)
const loading = ref(false)
const error = ref('')
let requestID = 0

watch([provider, slug, repoSlug, refName, snapshot], async () => {
  if (!provider.value || !slug.value || !repoSlug.value) return
  const current = ++requestID
  loading.value = true
  error.value = ''
  try {
    const response = await api.listRefCWEs(provider.value, slug.value, repoSlug.value, { ref: refName.value, snapshot: snapshot.value })
    if (current !== requestID) return
    report.value = response.data
    rememberCWEs(response.data.cwes)
  } catch (cause) {
    if (current !== requestID) return
    report.value = null
    error.value = cause instanceof Error ? cause.message : 'Could not load CWEs'
  } finally {
    if (current === requestID) loading.value = false
  }
}, { immediate: true })

function openFindings(query: string) {
  void router.push({
    name: 'repo-vulnerabilities',
    params: route.params,
    query: { ...(refName.value ? { ref: refName.value } : {}), ...(snapshot.value ? { snapshot: snapshot.value } : {}), q: query },
  })
}
</script>
