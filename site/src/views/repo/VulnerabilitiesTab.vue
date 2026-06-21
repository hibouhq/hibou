<template>
  <div class="space-y-5">
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
      :counts="facetCounts"
      placeholder="Filter vulnerabilities..."
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
        No vulnerabilities for this ref.
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
                  Status
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
                :class="rowClass(vulnerability.type)"
              >
                <td class="px-3 py-2.5">
                  <span :class="severityClass(vulnerability.severity)">
                    {{ vulnerability.severity }}
                  </span>
                </td>
                <td class="px-3 py-2.5">
                  <span :class="typeBadgeClass(vulnerability.type)">
                    {{ vulnerability.type }}
                  </span>
                </td>
                <td class="px-3 py-2.5 font-mono text-xs text-accent">
                  {{ vulnerability.primary_identifier?.value || vulnerability.scanner_name || 'n/a' }}
                </td>
                <td class="px-3 py-2.5">
                  <LinkedText
                    :text="vulnerability.title"
                    class="text-gray-300"
                  />

                  <div
                    v-if="formatLocation(vulnerability) !== 'n/a'"
                    class="mt-0.5 font-mono text-xs text-gray-500"
                  >
                    {{ formatLocation(vulnerability) }}
                  </div>
                </td>
                <td class="px-3 py-2.5 text-gray-400">
                  {{ vulnerability.scanner_name || 'n/a' }}
                </td>
                <td class="px-3 py-2.5">
                  <span :class="statusBadgeClass(vulnerability.status)">
                    {{ vulnerability.status }}
                  </span>
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
import { type LocationQueryRaw, useRoute, useRouter } from 'vue-router'

import { api, type Vulnerability, type VulnerabilityFacets } from '@/api/client'
import FilterBar from '@/components/FilterBar.vue'
import LinkedText from '@/components/LinkedText.vue'

const route = useRoute()
const router = useRouter()

const provider = computed(() => route.params.provider as string)
const slug = computed(() => route.params.slug as string)
const repoSlug = computed(() => route.params.repoSlug as string)

const vulnerabilities = ref<Vulnerability[]>([])
const loading = ref(true)
const activeFilters = ref<Record<string, string>>({ status: 'detected,confirmed' })
const searchQuery = ref('')
const currentSort = ref('detected')
const currentSortDirection = ref('desc')
const pagination = ref({ page: 1, per_page: 50, total: 0 })
const seenTools = ref<Set<string>>(new Set())
const seenFiles = ref<Set<string>>(new Set())
const facetCounts = ref<VulnerabilityFacets>({ type: {}, severity: {}, status: {}, tool: {}, file: {} })

const typeOptions = ['dependency', 'sast', 'secret', 'malware', 'dast', 'container', 'fuzzing', 'manual', 'generic']
const severityOptions = ['critical', 'high', 'medium', 'low', 'info']
const statusOptions = ['detected', 'confirmed', 'dismissed', 'resolved']
// Build Sources/File option lists from the facet keys (full result set) merged
// with what's been seen on loaded pages, so options aren't limited to the
// current page. Order by descending count, then alphabetically.
const toolOptions = computed(() => mergeFacetOptions(facetCounts.value.tool, seenTools.value))
const fileOptions = computed(() => mergeFacetOptions(facetCounts.value.file, seenFiles.value))
const filterDefs = computed(() => [
  { key: 'status', label: 'Status', options: statusOptions, multi: true, primary: true, hidden: true, defaultValue: 'detected,confirmed' },
  { key: 'type', label: 'Type', options: typeOptions, multi: true },
  { key: 'severity', label: 'Severity', options: severityOptions, multi: true },
  { key: 'tool', label: 'Sources', options: toolOptions.value, multi: true },
  { key: 'file', label: 'File', options: fileOptions.value, multi: true, freeform: true },
])
const sortOptions = [
  { key: 'detected', label: 'Detected', ascLabel: 'Oldest', descLabel: 'Newest' },
  { key: 'severity', label: 'Severity' },
  { key: 'status', label: 'Status' },
]
const sortDirectionOptions = [
  { key: 'asc', label: '↑ Oldest' },
  { key: 'desc', label: '↓ Newest' },
]
const filterKeys = ['type', 'severity', 'status', 'tool', 'file'] as const
const managedQueryKeys = [...filterKeys, 'search', 'sort', 'order', 'page'] as const
const sortKeys = new Set(sortOptions.map((option) => option.key))
const sortDirectionKeys = new Set(sortDirectionOptions.map((option) => option.key))
const syncingFromRoute = ref(false)
const hasActiveFilters = computed(() => Object.values(activeFilters.value).some(Boolean) || searchQuery.value.trim().length > 0)
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

		if (searchQuery.value !== nextState.search) {
			searchQuery.value = nextState.search
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
  [activeFilters, searchQuery, currentSort, currentSortDirection],
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
  [provider, slug, repoSlug, () => route.query.ref, () => route.query.snapshot, activeFilters, searchQuery, currentSort, currentSortDirection, () => pagination.value.page],
  async () => {
    if (!provider.value || !slug.value || !repoSlug.value) {
      vulnerabilities.value = []
      return
    }

    loading.value = true
    try {
      const res = await api.listRefVulnerabilities(provider.value, slug.value, repoSlug.value, {
        ref: typeof route.query.ref === 'string' ? route.query.ref : undefined,
        snapshot: typeof route.query.snapshot === 'string' ? route.query.snapshot : undefined,
        type: activeFilters.value.type || undefined,
        severity: activeFilters.value.severity || undefined,
        status: activeFilters.value.status || undefined,
        tool: activeFilters.value.tool || undefined,
        file: activeFilters.value.file || undefined,
        search: searchQuery.value || undefined,
        sort: `${currentSort.value}_${currentSortDirection.value}`,
        page: pagination.value.page,
        per_page: pagination.value.per_page,
      })

      vulnerabilities.value = res.data
      const nextSeenTools = new Set(seenTools.value)
      const nextSeenFiles = new Set(seenFiles.value)

      for (const vulnerability of res.data) {
        if (isPresent(vulnerability.scanner_name)) {
          nextSeenTools.add(vulnerability.scanner_name)
        }

        const location = formatLocation(vulnerability)
        if (location !== 'n/a') {
          nextSeenFiles.add(location)
        }
      }

      seenTools.value = nextSeenTools
      seenFiles.value = nextSeenFiles
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

function mergeFacetOptions(counts: Record<string, number>, seen: Set<string>): string[] {
  const keys = new Set<string>([...Object.keys(counts), ...seen])
  return Array.from(keys).sort((a, b) => {
    const diff = (counts[b] ?? 0) - (counts[a] ?? 0)
    return diff !== 0 ? diff : a.localeCompare(b)
  })
}

// Faceted option counts. Refetched whenever the scope or filters change, but
// not on pagination/sort — facets describe the whole filtered result set.
watch(
  [provider, slug, repoSlug, () => route.query.ref, () => route.query.snapshot, activeFilters, searchQuery],
  async () => {
    if (!provider.value || !slug.value || !repoSlug.value) {
      facetCounts.value = { type: {}, severity: {}, status: {}, tool: {}, file: {} }
      return
    }

    try {
      facetCounts.value = await api.listRefVulnerabilityFacets(provider.value, slug.value, repoSlug.value, {
        ref: typeof route.query.ref === 'string' ? route.query.ref : undefined,
        snapshot: typeof route.query.snapshot === 'string' ? route.query.snapshot : undefined,
        type: activeFilters.value.type || undefined,
        severity: activeFilters.value.severity || undefined,
        status: activeFilters.value.status || undefined,
        tool: activeFilters.value.tool || undefined,
        file: activeFilters.value.file || undefined,
        search: searchQuery.value || undefined,
      })
    } catch {
      facetCounts.value = { type: {}, severity: {}, status: {}, tool: {}, file: {} }
    }
  },
  { deep: true, immediate: true },
)

function changePage(page: number) {
  pagination.value.page = page
}

function readQueryState() {
  const filters: Record<string, string> = { status: 'detected,confirmed' }

  for (const key of filterKeys) {
    const value = route.query[key]
    if (typeof value === 'string' && value.length > 0) {
      filters[key] = value
    }
  }

  const sortValue = route.query.sort
  const sort = typeof sortValue === 'string' && sortKeys.has(sortValue) ? sortValue : 'detected'
  const orderValue = route.query.order
  const order = typeof orderValue === 'string' && sortDirectionKeys.has(orderValue) ? orderValue : 'desc'
  const searchValue = route.query.search
  const search = typeof searchValue === 'string' ? searchValue : ''
  const pageValue = Number(typeof route.query.page === 'string' ? route.query.page : '1')
  const page = Number.isInteger(pageValue) && pageValue > 0 ? pageValue : 1

  return { filters, search, sort, order, page }
}

function syncQueryFromState() {
  const nextState = {
    filters: normalizeFilters(activeFilters.value),
    search: searchQuery.value.trim(),
    sort: currentSort.value,
    order: currentSortDirection.value,
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

function buildQueryParams(state: { filters: Record<string, string>; search: string; sort: string; order: string; page: number }) {
  const params: Record<string, string> = {}

  for (const key of filterKeys) {
    const value = state.filters[key]
    if (value && !(key === 'status' && value === 'detected,confirmed')) {
      params[key] = value
    }
  }

  if (state.search) {
    params.search = state.search
  }

  if (state.sort !== 'detected') {
    params.sort = state.sort
  }

  if (state.order !== 'desc') {
    params.order = state.order
  }

  if (state.page > 1) {
    params.page = String(state.page)
  }

  return params
}

function normalizeFilters(filters: Record<string, string>) {
  const normalized: Record<string, string> = { status: filters.status || 'detected,confirmed' }

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
  left: { filters: Record<string, string>; search: string; sort: string; order: string; page: number },
  right: { filters: Record<string, string>; search: string; sort: string; order: string; page: number },
) {
  return sameFilters(left.filters, right.filters) && left.search === right.search && left.sort === right.sort && left.order === right.order && left.page === right.page
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

function typeBadgeClass(type: string) {
  const classes: Record<string, string> = {
    malware: 'rounded-full bg-red-500/15 px-2.5 py-1 text-xs font-medium text-red-400',
    secret: 'rounded-full bg-amber-500/15 px-2.5 py-1 text-xs font-medium text-amber-400',
    dependency: 'rounded-full bg-blue-500/15 px-2.5 py-1 text-xs font-medium text-blue-400',
    sast: 'rounded-full bg-purple-500/15 px-2.5 py-1 text-xs font-medium text-purple-400',
    dast: 'rounded-full bg-cyan-500/15 px-2.5 py-1 text-xs font-medium text-cyan-400',
    fuzzing: 'rounded-full bg-teal-500/15 px-2.5 py-1 text-xs font-medium text-teal-400',
    container: 'rounded-full bg-slate-500/15 px-2.5 py-1 text-xs font-medium text-slate-400',
    manual: 'rounded-full bg-gray-500/15 px-2.5 py-1 text-xs font-medium text-gray-400',
    generic: 'rounded-full bg-gray-500/15 px-2.5 py-1 text-xs font-medium text-gray-400',
  }

  return classes[type] || classes.generic
}

function statusBadgeClass(status: string) {
  const classes: Record<string, string> = {
    detected: 'rounded-full bg-slate-500/15 px-2.5 py-1 text-xs font-medium text-slate-300',
    confirmed: 'rounded-full bg-blue-500/15 px-2.5 py-1 text-xs font-medium text-blue-300',
    dismissed: 'rounded-full bg-slate-500/10 px-2.5 py-1 text-xs font-medium text-gray-500 line-through',
    resolved: 'rounded-full bg-emerald-500/15 px-2.5 py-1 text-xs font-medium text-emerald-300',
  }

  return classes[status] || classes.detected
}

function rowClass(type: string) {
  if (type === 'malware') {
    return 'border-l-2 border-red-500/60'
  }

  if (type === 'secret') {
    return 'border-l-2 border-amber-500/60'
  }

  return ''
}

function formatLocation(vulnerability: Vulnerability) {
  if (['sast', 'secret', 'dast', 'fuzzing'].includes(vulnerability.type) && vulnerability.file_path) {
    return vulnerability.start_line ? `${vulnerability.file_path}:${vulnerability.start_line}` : vulnerability.file_path
  }

  if (['dependency', 'malware'].includes(vulnerability.type) && vulnerability.component_name) {
    return vulnerability.component_version
      ? `${vulnerability.component_name}@${vulnerability.component_version}`
      : vulnerability.component_name
  }

  if (vulnerability.file_path) {
    return vulnerability.start_line ? `${vulnerability.file_path}:${vulnerability.start_line}` : vulnerability.file_path
  }

  if (vulnerability.component_name) {
    return vulnerability.component_version
      ? `${vulnerability.component_name}@${vulnerability.component_version}`
      : vulnerability.component_name
  }

  return 'n/a'
}

function formatDetected(value: string) {
  return new Intl.DateTimeFormat('en', { dateStyle: 'medium' }).format(new Date(value))
}

function isPresent(value: string | undefined): value is string {
  return typeof value === 'string' && value.length > 0
}
</script>
