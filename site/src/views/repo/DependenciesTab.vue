<template>
  <div class="space-y-5">
    <div class="flex flex-wrap items-end gap-2">
      <label class="space-y-2 text-sm text-gray-300">
        <span class="block text-[11px] uppercase tracking-[0.12em] text-gray-500">Ecosystem</span>
        <select v-model="ecosystemFilter" class="w-full rounded-lg border border-surface-border bg-surface-overlay px-3 py-1.5 text-sm text-gray-100">
          <option value="">All ecosystems</option>
          <option v-for="option in ecosystems" :key="option" :value="option">{{ option }}</option>
        </select>
      </label>

      <label class="space-y-2 text-sm text-gray-300">
        <span class="block text-[11px] uppercase tracking-[0.12em] text-gray-500">Search</span>
        <input
          v-model="search"
          type="search"
          placeholder="Search package or advisory"
          class="w-full rounded-lg border border-surface-border bg-surface-overlay px-3 py-1.5 text-sm text-gray-100 placeholder:text-gray-500"
        >
      </label>
    </div>

    <div class="overflow-hidden rounded-2xl border border-surface-border-subtle">
      <div v-if="loading" class="px-4 py-10 text-sm text-gray-500">
        Loading components...
      </div>

      <div v-else-if="filteredComponents.length === 0" class="px-4 py-10 text-sm text-gray-500">
        No components found.
      </div>

      <div v-else class="overflow-x-auto">
        <table class="min-w-full divide-y divide-surface-border-subtle text-sm">
          <thead class="bg-surface-overlay text-left text-xs uppercase tracking-[0.18em] text-gray-500">
            <tr>
              <th class="px-3 py-2 font-medium">Ecosystem</th>
              <th class="px-3 py-2 font-medium">Package</th>
              <th class="px-3 py-2 font-medium">Version</th>
              <th class="px-3 py-2 font-medium">Vulns</th>
              <th class="px-3 py-2 font-medium">Severity</th>
            </tr>
          </thead>
          <tbody class="divide-y divide-surface-border-subtle">
            <tr
              v-for="component in filteredComponents"
              :key="component.id"
              class="transition hover:bg-white/5"
              :class="component.vuln_count > 0 ? 'border-l-4 border-l-danger/70' : ''"
            >
              <td class="px-3 py-2.5">
                <span class="rounded-full border border-surface-border px-2.5 py-1 text-xs uppercase tracking-[0.14em] text-gray-300">
                  {{ component.ecosystem }}
                </span>
              </td>
              <td class="px-3 py-2.5 text-gray-200">
                <div class="font-medium">{{ component.name }}</div>
                <div class="text-xs text-gray-500">{{ component.purl }}</div>
              </td>
              <td class="px-3 py-2.5 text-gray-300">{{ component.version }}</td>
              <td class="px-3 py-2.5 text-gray-300">
                <span class="rounded-full border border-surface-border px-2.5 py-1 text-xs font-medium text-white">
                  {{ component.vuln_count }}
                </span>
              </td>
              <td class="px-3 py-2.5">
                <span v-if="component.highest_severity" :class="['rounded-full px-2.5 py-1 text-xs font-medium', severityClass(component.highest_severity)]">
                  {{ component.highest_severity }}
                </span>
                <span v-else class="text-gray-500">none</span>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { useRoute } from 'vue-router'

import { api, type ComponentWithVulns } from '@/api/client'

const route = useRoute()

const provider = computed(() => route.params.provider as string)
const slug = computed(() => route.params.slug as string)
const repoSlug = computed(() => route.params.repoSlug as string)

const components = ref<ComponentWithVulns[]>([])
const loading = ref(true)
const ecosystemFilter = ref('')
const search = ref('')

const ecosystems = computed(() => Array.from(new Set(components.value.map((component) => component.ecosystem))).sort())
const filteredComponents = computed(() => {
  const query = search.value.trim().toLowerCase()

  return components.value.filter((component) => {
    if (ecosystemFilter.value && component.ecosystem !== ecosystemFilter.value) {
      return false
    }
    if (!query) {
      return true
    }

    return [
      component.name,
      component.version,
      component.purl,
      ...(component.advisories?.map((advisory) => `${advisory.canonical_id} ${advisory.title}`) || []),
    ].some((value) => value.toLowerCase().includes(query))
  })
})

watch(
  [provider, slug, repoSlug, () => route.query.ref],
  async () => {
    if (!provider.value || !slug.value || !repoSlug.value) {
      components.value = []
      return
    }

    loading.value = true
    try {
      const res = await api.listRefComponents(provider.value, slug.value, repoSlug.value, {
        ref: typeof route.query.ref === 'string' ? route.query.ref : undefined,
      })
      components.value = res.data
    } catch {
      components.value = []
    } finally {
      loading.value = false
    }
  },
  { immediate: true },
)

function severityClass(level: string) {
  return `sev-${level.toLowerCase()}`
}
</script>
