<template>
  <div class="space-y-5">
    <FilterBar
      v-model="activeFilters"
      v-model:sort-value="currentSort"
      v-model:sort-direction="currentSortDirection"
      :filters="filterDefs"
      :sort-options="sortOptions"
      :sort-direction-options="sortDirectionOptions"
      :total-count="pagination.total"
      :filtered-count="hasActiveFilters ? pagination.total : undefined"
      placeholder="Filter findings..."
    />

    <div class="overflow-hidden rounded-2xl border border-surface-border-subtle">
      <div
        v-if="loading"
        class="px-4 py-10 text-sm text-gray-500"
      >
        Loading findings...
      </div>

      <div
        v-else-if="findings.length === 0"
        class="px-4 py-10 text-sm text-gray-500"
      >
        No findings for this ref.
      </div>

      <template v-else>
        <div class="overflow-x-auto">
          <table class="min-w-full divide-y divide-surface-border-subtle text-sm">
            <thead class="bg-surface-overlay text-left text-xs uppercase tracking-[0.18em] text-gray-500">
              <tr>
                <th class="px-3 py-2 font-medium">
                  Severity
                </th>
                <th class="px-3 py-2 font-medium">
                  Tool
                </th>
                <th class="px-3 py-2 font-medium">
                  Rule ID
                </th>
                <th class="px-3 py-2 font-medium">
                  File
                </th>
                <th class="px-3 py-2 font-medium">
                  Status
                </th>
                <th class="px-3 py-2 font-medium">
                  Message
                </th>
              </tr>
            </thead>
            <tbody class="divide-y divide-surface-border-subtle">
              <tr
                v-for="finding in findings"
                :key="finding.id"
                class="transition hover:bg-white/5"
              >
                <td class="px-3 py-2.5">
                  <span :class="['rounded-full px-2.5 py-1 text-xs font-medium', severityClass(finding.severity)]">
                    {{ finding.severity }}
                  </span>
                </td>
                <td class="px-3 py-2.5 text-gray-300">
                  {{ finding.tool }}
                </td>
                <td class="px-3 py-2.5 font-mono text-xs text-accent">
                  {{ finding.rule_id }}
                </td>
                <td class="px-3 py-2.5 text-gray-400">
                  {{ formatLocation(finding) }}
                </td>
                <td class="px-3 py-2.5 text-gray-300">
                  {{ finding.status }}
                </td>
                <td class="px-3 py-2.5 text-gray-300">
                  {{ finding.message }}
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
import { type LocationQueryRaw, useRoute, useRouter } from 'vue-router'

import { api, type Finding } from '@/api/client'
import FilterBar from '@/components/FilterBar.vue'

const route = useRoute()
const router = useRouter()

const provider = computed(() => route.params.provider as string)
const slug = computed(() => route.params.slug as string)
const repoSlug = computed(() => route.params.repoSlug as string)

const findingsResponse = ref<Finding[]>([])
const loading = ref(true)
const activeFilters = ref<Record<string, string>>({})
const currentSort = ref('created_on')
const currentSortDirection = ref('desc')
const pagination = ref({ page: 1, per_page: 50, total: 0 })

const severityOptions = ['critical', 'high', 'medium', 'low', 'info']
const toolOptions = computed(() => Array.from(new Set(findingsResponse.value.map((finding) => finding.tool))).sort())
const statusOptions = computed(() => Array.from(new Set(findingsResponse.value.map((finding) => finding.status))).sort())
const fileOptions = computed(() => {
  const filePaths = Array.from(new Set(findingsResponse.value.map((finding) => finding.file_path))).sort()
  const fileLines = findingsResponse.value
    .filter((finding) => finding.start_line)
    .map((finding) => `${finding.file_path}:${finding.start_line}`)
  const uniqueFileLines = Array.from(new Set(fileLines)).sort()
  return [...filePaths, ...uniqueFileLines]
})
const filterDefs = computed(() => [
  { key: 'severity', label: 'Severity', options: severityOptions, multi: true },
  { key: 'tool', label: 'Tool', options: toolOptions.value, multi: true },
  { key: 'status', label: 'Status', options: statusOptions.value, multi: true },
  { key: 'file', label: 'File', options: fileOptions.value, multi: true, freeform: true },
])
const sortOptions = [
  { key: 'severity', label: 'Severity' },
  { key: 'created_on', label: 'Created on', ascLabel: 'Oldest', descLabel: 'Newest' },
  { key: 'tool', label: 'Tool' },
  { key: 'file', label: 'File' },
  { key: 'status', label: 'Status' },
]
const sortDirectionOptions = [
  { key: 'asc', label: '↑ Oldest' },
  { key: 'desc', label: '↓ Newest' },
]
const filterKeys = ['severity', 'tool', 'status', 'file'] as const
const managedQueryKeys = [...filterKeys, 'sort', 'order', 'page'] as const
const sortKeys = new Set(sortOptions.map((option) => option.key))
const sortDirectionKeys = new Set(sortDirectionOptions.map((option) => option.key))
const syncingFromRoute = ref(false)
const hasActiveFilters = computed(() => Object.values(activeFilters.value).some(Boolean))
// NOTE: Sort is client-side on the current page only. The findings API
// does not support a sort parameter yet. This is acceptable because the
// default page size (50) covers most result sets.
const findings = computed(() => {
  if (!currentSort.value) {
    return findingsResponse.value
  }

  const direction = currentSortDirection.value === 'asc' ? -1 : 1

  return [...findingsResponse.value].sort((left, right) => direction * compareFindings(left, right, currentSort.value))
})
const totalPages = computed(() => Math.max(1, Math.ceil(pagination.value.total / pagination.value.per_page)))

watch(
  () => route.query,
  () => {
    const nextState = readQueryState()

    syncingFromRoute.value = true
    try {
      if (!sameFilters(activeFilters.value, nextState.filters)) {
        activeFilters.value = nextState.filters
      }

      if (currentSort.value !== nextState.sort) {
        currentSort.value = nextState.sort
      }

      if (currentSortDirection.value !== nextState.order) {
        currentSortDirection.value = nextState.order
      }

      if (pagination.value.page !== nextState.page) {
        pagination.value = { ...pagination.value, page: nextState.page }
      }
    } finally {
      syncingFromRoute.value = false
    }
  },
  { immediate: true },
)

watch(
  [activeFilters, currentSort, currentSortDirection],
  () => {
    if (syncingFromRoute.value) {
      return
    }

    if (pagination.value.page !== 1) {
      pagination.value = { ...pagination.value, page: 1 }
      return
    }

    void syncQueryFromState()
  },
  { deep: true },
)

watch(currentSort, (sort) => {
  if (!sort && currentSortDirection.value !== 'desc') {
    currentSortDirection.value = 'desc'
  }
})

watch(
  () => pagination.value.page,
  () => {
    if (syncingFromRoute.value) {
      return
    }

    void syncQueryFromState()
  },
)

watch(
  [provider, slug, repoSlug, () => route.query.ref, activeFilters, () => pagination.value.page],
  async () => {
    if (!provider.value || !slug.value || !repoSlug.value) {
      findingsResponse.value = []
      return
    }

    loading.value = true
    try {
      const res = await api.listRefFindings(provider.value, slug.value, repoSlug.value, {
        ref: typeof route.query.ref === 'string' ? route.query.ref : undefined,
        severity: activeFilters.value.severity || undefined,
        tool: activeFilters.value.tool || undefined,
        status: activeFilters.value.status || undefined,
        page: pagination.value.page,
        per_page: pagination.value.per_page,
      })

      findingsResponse.value = res.data
      pagination.value = res.pagination
    } catch {
      findingsResponse.value = []
      pagination.value = { ...pagination.value, total: 0 }
    } finally {
      loading.value = false
    }
  },
  { immediate: true },
)

function changePage(page: number) {
  pagination.value.page = page
}

function readQueryState() {
  const filters: Record<string, string> = {}

  for (const key of filterKeys) {
    const value = route.query[key]
    if (typeof value === 'string' && value.length > 0) {
      filters[key] = value
    }
  }

  const sortValue = route.query.sort
  const sort = typeof sortValue === 'string' && sortKeys.has(sortValue) ? sortValue : 'created_on'
  const orderValue = route.query.order
  const order = sort && typeof orderValue === 'string' && sortDirectionKeys.has(orderValue) ? orderValue : 'desc'
  const pageValue = Number(typeof route.query.page === 'string' ? route.query.page : '1')
  const page = Number.isInteger(pageValue) && pageValue > 0 ? pageValue : 1

  return { filters, sort, order, page }
}

function syncQueryFromState() {
  const nextState = {
    filters: normalizeFilters(activeFilters.value),
    sort: currentSort.value,
    order: currentSort.value ? (currentSortDirection.value || 'desc') : 'desc',
    page: pagination.value.page,
  }

  if (sameQueryState(nextState, readQueryState())) {
    return
  }

  const nextQuery: LocationQueryRaw = { ...route.query }
  const nextParams = buildQueryParams(nextState)

  for (const key of managedQueryKeys) {
    delete nextQuery[key]
  }

  Object.assign(nextQuery, nextParams)

  return router.replace({ query: nextQuery })
}

function buildQueryParams(state: { filters: Record<string, string>; sort: string; order: string; page: number }) {
  const params: Record<string, string> = {}

  for (const key of filterKeys) {
    const value = state.filters[key]
    if (value) {
      params[key] = value
    }
  }

  if (state.sort && state.sort !== 'created_on') {
    params.sort = state.sort
  }

  if (state.sort && state.sort !== 'created_on' && state.order && state.order !== 'desc') {
    params.order = state.order
  }

  if (state.page > 1) {
    params.page = String(state.page)
  }

  return params
}

function normalizeFilters(filters: Record<string, string>) {
  const normalized: Record<string, string> = {}

  for (const key of filterKeys) {
    const value = filters[key]
    if (value) {
      normalized[key] = value
    }
  }

  return normalized
}

function sameFilters(left: Record<string, string>, right: Record<string, string>) {
  for (const key of filterKeys) {
    if ((left[key] || '') !== (right[key] || '')) {
      return false
    }
  }

  return true
}

function sameQueryState(
  left: { filters: Record<string, string>; sort: string; order: string; page: number },
  right: { filters: Record<string, string>; sort: string; order: string; page: number },
) {
  return sameFilters(left.filters, right.filters) && left.sort === right.sort && left.order === right.order && left.page === right.page
}

function compareFindings(left: Finding, right: Finding, sortKey: string) {
  if (sortKey === 'severity') {
    return compareSeverity(left.severity, right.severity)
  }

  if (sortKey === 'tool') {
    return left.tool.localeCompare(right.tool)
  }

  if (sortKey === 'file') {
    return formatLocation(left).localeCompare(formatLocation(right))
  }

  if (sortKey === 'status') {
    return left.status.localeCompare(right.status)
  }

  if (sortKey === 'created_on') {
    return left.created_at.localeCompare(right.created_at)
  }

  return 0
}

function compareSeverity(left: string, right: string) {
  return severityRank(left) - severityRank(right)
}

function severityRank(level: string) {
  const index = severityOptions.indexOf(level.toLowerCase())
  return index === -1 ? severityOptions.length : index
}

function severityClass(level: string) {
  return `sev-${level.toLowerCase()}`
}

function formatLocation(finding: Finding) {
  if (!finding.start_line) {
    return finding.file_path
  }

  return `${finding.file_path}:${finding.start_line}`
}
</script>
