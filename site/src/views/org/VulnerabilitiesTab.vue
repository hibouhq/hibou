<template>
  <div class="space-y-4">
    <FilterBar
      v-model="activeFilters"
      v-model:search-query="searchQuery"
      v-model:sort-value="currentSort"
      v-model:sort-direction="currentSortDirection"
      :filters="filterDefs"
      :sort-options="sortOptions"
      :sort-direction-options="sortDirectionOptions"
      :total-count="pagination.total"
      :filtered-count="hasActiveFilters ? pagination.total : undefined"
      placeholder="Filter vulnerabilities across all repositories..."
    />

    <div class="overflow-hidden rounded-2xl border border-surface-border-subtle">
      <div
        v-if="loading"
        class="px-4 py-10 text-sm text-gray-500"
      >
        Loading vulnerabilities...
      </div>
      <div
        v-else-if="vulnerabilities.length === 0"
        class="px-4 py-10 text-sm text-gray-500"
      >
        No vulnerabilities across this organization.
      </div>
      <template v-else>
        <div class="overflow-x-auto">
          <table class="min-w-full divide-y divide-surface-border-subtle text-sm">
            <thead class="bg-surface-overlay text-left text-xs uppercase tracking-[0.16em] text-gray-500">
              <tr>
                <th class="px-3 py-2 font-medium">
                  Severity
                </th>
                <th class="px-3 py-2 font-medium">
                  Repository
                </th>
                <th class="px-3 py-2 font-medium">
                  Type
                </th>
                <th class="px-3 py-2 font-medium">
                  Identifier
                </th>
                <th class="px-3 py-2 font-medium">
                  Description
                </th>
                <th class="px-3 py-2 font-medium">
                  Source
                </th>
                <th class="px-3 py-2 font-medium">
                  Detected
                </th>
              </tr>
            </thead>
            <tbody class="divide-y divide-surface-border-subtle">
              <tr
                v-for="vulnerability in vulnerabilities"
                :key="vulnerability.id"
                class="transition hover:bg-white/5"
              >
                <td class="px-3 py-2.5">
                  <span :class="severityClass(vulnerability.severity)">{{ vulnerability.severity }}</span>
                </td>
                <td class="px-3 py-2.5">
                  <RouterLink
                    :to="`/orgs/${provider}/${slug}/repos/${vulnerability.repo_slug}/vulnerabilities`"
                    class="font-medium text-accent transition hover:underline"
                  >
                    {{ vulnerability.repo_name || vulnerability.repo_slug }}
                  </RouterLink>
                </td>
                <td class="px-3 py-2.5">
                  <span class="rounded-full bg-surface-overlay px-2 py-0.5 text-xs text-gray-300">{{ vulnerability.type }}</span>
                </td>
                <td class="px-3 py-2.5 font-mono text-xs text-accent">
                  {{ vulnerability.primary_identifier?.value || vulnerability.scanner_name || 'n/a' }}
                </td>
                <td class="px-3 py-2.5">
                  <LinkedText
                    :text="vulnerability.title"
                    class="text-gray-300"
                  />
                </td>
                <td class="px-3 py-2.5 text-gray-400">
                  {{ vulnerability.scanner_name || 'n/a' }}
                </td>
                <td class="px-3 py-2.5 text-gray-400">
                  {{ formatDetected(vulnerability.detected_at) }}
                </td>
              </tr>
            </tbody>
          </table>
        </div>

        <div class="flex items-center justify-between border-t border-surface-border-subtle px-3 py-2.5 text-sm text-gray-400">
          <div>Page {{ pagination.page }} of {{ totalPages }}</div>
          <div class="flex items-center gap-3">
            <button
              class="rounded-lg border border-surface-border px-2.5 py-1 text-xs transition hover:border-accent/50 hover:text-white disabled:cursor-not-allowed disabled:opacity-40"
              type="button"
              :disabled="pagination.page <= 1"
              @click="changePage(pagination.page - 1)"
            >
              Previous
            </button>
            <button
              class="rounded-lg border border-surface-border px-2.5 py-1 text-xs transition hover:border-accent/50 hover:text-white disabled:cursor-not-allowed disabled:opacity-40"
              type="button"
              :disabled="pagination.page >= totalPages"
              @click="changePage(pagination.page + 1)"
            >
              Next
            </button>
          </div>
        </div>
      </template>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { RouterLink, useRoute } from 'vue-router'

import { api, type OrgVulnerability } from '@/api/client'
import FilterBar from '@/components/FilterBar.vue'
import LinkedText from '@/components/LinkedText.vue'

const route = useRoute()
const provider = computed(() => route.params.provider as string)
const slug = computed(() => route.params.slug as string)

const vulnerabilities = ref<OrgVulnerability[]>([])
const loading = ref(true)
const activeFilters = ref<Record<string, string>>({ status: 'detected,confirmed' })
const searchQuery = ref('')
const currentSort = ref('severity')
const currentSortDirection = ref('desc')
const pagination = ref({ page: 1, per_page: 50, total: 0 })
const seenTools = ref<Set<string>>(new Set())

const typeOptions = ['dependency', 'sast', 'secret', 'malware', 'dast', 'container', 'fuzzing', 'manual', 'generic']
const severityOptions = ['critical', 'high', 'medium', 'low', 'info']
const statusOptions = ['detected', 'confirmed', 'dismissed', 'resolved']
const toolOptions = computed(() => Array.from(seenTools.value).sort())
const filterDefs = computed(() => [
  { key: 'status', label: 'Status', options: statusOptions, multi: true, primary: true, hidden: true, defaultValue: 'detected,confirmed' },
  { key: 'type', label: 'Type', options: typeOptions, multi: true },
  { key: 'severity', label: 'Severity', options: severityOptions, multi: true },
  { key: 'tool', label: 'Sources', options: toolOptions.value, multi: true },
])
const sortOptions = [
  { key: 'severity', label: 'Severity' },
  { key: 'detected', label: 'Detected', ascLabel: 'Oldest', descLabel: 'Newest' },
  { key: 'status', label: 'Status' },
]
const sortDirectionOptions = [
  { key: 'desc', label: '↓ Desc' },
  { key: 'asc', label: '↑ Asc' },
]

const hasActiveFilters = computed(() => Object.entries(activeFilters.value).some(([key, value]) => Boolean(value) && !(key === 'status' && value === 'detected,confirmed')) || searchQuery.value.trim().length > 0)
const totalPages = computed(() => Math.max(1, Math.ceil(pagination.value.total / pagination.value.per_page)))

watch(
  [activeFilters, searchQuery, currentSort, currentSortDirection],
  () => {
    if (pagination.value.page !== 1) {
      pagination.value = { ...pagination.value, page: 1 }
    }
  },
  { deep: true },
)

watch(
  [provider, slug, activeFilters, searchQuery, currentSort, currentSortDirection, () => pagination.value.page],
  async () => {
    if (!provider.value || !slug.value) {
      vulnerabilities.value = []
      return
    }

    loading.value = true
    try {
      const res = await api.listOrgVulnerabilities(provider.value, slug.value, {
        type: activeFilters.value.type || undefined,
        severity: activeFilters.value.severity || undefined,
        status: activeFilters.value.status || undefined,
        tool: activeFilters.value.tool || undefined,
        search: searchQuery.value || undefined,
        sort: `${currentSort.value}_${currentSortDirection.value}`,
        page: pagination.value.page,
        per_page: pagination.value.per_page,
      })
      vulnerabilities.value = res.data
      const nextTools = new Set(seenTools.value)
      for (const vulnerability of res.data) {
        if (vulnerability.scanner_name) {
          nextTools.add(vulnerability.scanner_name)
        }
      }
      seenTools.value = nextTools
      pagination.value = res.pagination
    } catch {
      vulnerabilities.value = []
      pagination.value = { ...pagination.value, total: 0 }
    } finally {
      loading.value = false
    }
  },
  { immediate: true },
)

function changePage(page: number) {
  pagination.value = { ...pagination.value, page }
}

function severityClass(level: string) {
  const classes: Record<string, string> = {
    critical: 'rounded-full bg-red-500/15 px-2.5 py-1 text-xs font-medium text-red-400',
    high: 'rounded-full bg-orange-500/15 px-2.5 py-1 text-xs font-medium text-orange-400',
    medium: 'rounded-full bg-yellow-500/15 px-2.5 py-1 text-xs font-medium text-yellow-400',
    low: 'rounded-full bg-gray-500/15 px-2.5 py-1 text-xs font-medium text-gray-400',
    info: 'rounded-full bg-blue-500/15 px-2.5 py-1 text-xs font-medium text-blue-400',
  }
  return classes[level.toLowerCase()] || classes.info
}

function formatDetected(value: string) {
  return new Intl.DateTimeFormat('en', { dateStyle: 'medium' }).format(new Date(value))
}
</script>
