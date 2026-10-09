<template>
  <div class="space-y-4">
    <p class="text-sm text-gray-400">
      Every CWE across the organization's repositories (current snapshots, open vulnerabilities).
      Pick one to see its vulnerabilities everywhere.
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

// ADR-037 CWE list across the org. The aggregate scans every repository's
// current findings, so it loads once per visit, never per keystroke.
const route = useRoute()
const router = useRouter()
const provider = computed(() => route.params.provider as string)
const slug = computed(() => route.params.slug as string)

const report = ref<CWEUsageReport | null>(null)
const loading = ref(false)
const error = ref('')
let requestID = 0

watch([provider, slug], async () => {
  if (!provider.value || !slug.value) return
  const current = ++requestID
  loading.value = true
  error.value = ''
  try {
    const response = await api.listOrgCWEs(provider.value, slug.value)
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
  void router.push({ name: 'org-vulnerabilities', params: route.params, query: { q: query } })
}
</script>
