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

    <div class="flex items-center gap-3">
      <button
        type="button"
        class="inline-flex items-center gap-2 rounded-md border border-surface-border px-3 py-1.5 text-xs font-medium text-gray-300 transition hover:border-accent/50 hover:text-white disabled:cursor-not-allowed disabled:opacity-50"
        :disabled="secretScanRunning"
        title="Queue a full secret scan of this branch; a worker picks it up"
        @click="runSecretScan"
      >
        <KeyRound class="h-3.5 w-3.5" />
        {{ secretScanRunning ? 'Queueing...' : 'Scan secrets' }}
      </button>
      <span
        v-if="secretScanMessage"
        class="text-xs text-emerald-300"
      >{{ secretScanMessage }}</span>
      <span
        v-if="secretScanError"
        class="text-xs text-danger"
      >{{ secretScanError }}</span>
      <span
        v-if="secretScanStatusLine"
        class="text-xs"
        :class="lastSecretScanJob?.status === 'failed' ? 'text-danger' : 'text-gray-500'"
      >{{ secretScanStatusLine }}</span>
    </div>

    <TriageDialog
      v-if="dialog"
      :status="dialog.status"
      :count="dialog.fingerprints.length"
      :error="dialogError"
      :submitting="dialogSubmitting"
      @cancel="closeTriageDialog"
      @confirm="confirmTriageDialog"
    />

    <div
      v-if="selected.size > 0"
      class="flex flex-wrap items-center gap-3 rounded-xl border border-accent/40 bg-accent/10 px-4 py-2.5"
    >
      <span class="text-sm font-medium text-white">
        {{ selected.size }} selected
      </span>
      <button
        v-if="!matchingTruncated && matchingTotal === 0"
        type="button"
        class="rounded-md border border-surface-border bg-surface-overlay px-2.5 py-1 text-xs text-gray-200 transition hover:border-accent/50 hover:text-white disabled:opacity-50"
        :disabled="selectingAll"
        title="Select every finding matching the current filter, not just this page"
        @click="selectAllMatchingFilter"
      >
        {{ selectingAll ? 'Selecting…' : `Select all matching filter (${pagination.total})` }}
      </button>
      <span
        v-if="matchingTruncated"
        class="rounded border border-warning/40 bg-warning/10 px-2 py-0.5 text-[11px] text-warning"
      >first {{ selected.size }} of {{ matchingTotal }} — apply, then repeat for the rest</span>
      <button
        type="button"
        class="rounded-md border border-surface-border bg-surface-overlay px-2.5 py-1 text-xs text-gray-200 transition hover:border-accent/50 hover:text-white"
        @click="openTriageDialog('accepted', [...selected])"
      >
        Accept risk…
      </button>
      <button
        type="button"
        class="rounded-md border border-surface-border bg-surface-overlay px-2.5 py-1 text-xs text-gray-200 transition hover:border-accent/50 hover:text-white"
        @click="openTriageDialog('false_positive', [...selected])"
      >
        Mark false positive…
      </button>
      <button
        type="button"
        class="rounded-md border border-surface-border bg-surface-overlay px-2.5 py-1 text-xs text-gray-200 transition hover:border-accent/50 hover:text-white"
        title="Remove any suppression: these count against the gate again"
        @click="reopenFindings([...selected])"
      >
        Reopen
      </button>
      <button
        type="button"
        class="ml-auto text-xs text-gray-400 underline transition hover:text-white"
        @click="clearSelection"
      >
        Clear selection
      </button>
      <span
        v-if="batchMessage"
        class="text-xs text-emerald-300"
      >{{ batchMessage }}</span>
    </div>

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
                <th class="w-9 px-3 py-2">
                  <input
                    type="checkbox"
                    class="h-3.5 w-3.5 rounded border-surface-border bg-surface-overlay accent-[--color-accent]"
                    :checked="allShownSelected"
                    :indeterminate="someShownSelected"
                    :title="`Select all ${vulnerabilities.length} findings shown`"
                    :aria-label="`Select all ${vulnerabilities.length} findings shown`"
                    @change="toggleSelectAllShown"
                  >
                </th>
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
                <th class="px-3 py-2 font-medium" />
              </tr>
            </thead>
            <tbody class="divide-y divide-surface-border-subtle">
              <tr
                v-for="vulnerability in vulnerabilities"
                :key="vulnerability.id"
                class="transition hover:bg-white/5"
                :class="[rowClass(vulnerability.type), selected.has(vulnerability.fingerprint) ? 'bg-accent/10' : '']"
              >
                <td class="px-3 py-2.5">
                  <input
                    type="checkbox"
                    class="h-3.5 w-3.5 rounded border-surface-border bg-surface-overlay accent-[--color-accent]"
                    :checked="selected.has(vulnerability.fingerprint)"
                    :aria-label="`Select ${vulnerability.title}`"
                    @click.stop
                    @change="toggleSelected(vulnerability)"
                  >
                </td>
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
                  <span :title="ruleName(vulnerability) || undefined">
                    {{ vulnerability.primary_identifier_value || vulnerability.scanner_name || 'n/a' }}
                  </span>
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
                  <div class="flex items-center gap-1.5">
                    <span>{{ vulnerability.scanner_name || 'n/a' }}</span>
                    <FindingOriginBadge :finding="vulnerability" />
                  </div>
                </td>
                <td class="px-3 py-2.5">
                  <span
                    class="rounded-full border px-2.5 py-1 text-xs font-medium"
                    :class="triageFor(vulnerability).badgeClass"
                    :title="triageTitle(vulnerability)"
                  >{{ triageFor(vulnerability).label }}</span>
                </td>
                <td class="px-3 py-2.5 text-gray-400">
                  {{ formatDetected(vulnerability.detected_at) }}
                </td>
                <td class="px-3 py-2.5">
                  <button
                    v-if="acceptanceFor(vulnerability)"
                    type="button"
                    class="rounded-lg border border-surface-border px-2 py-1 text-[11px] text-gray-300 transition hover:border-accent/50 hover:text-white"
                    title="Reopen: this finding counts against the gate again"
                    @click.stop="reopenFindings([vulnerability.fingerprint])"
                  >
                    Reopen
                  </button>
                  <div
                    v-else
                    class="flex gap-1"
                  >
                    <button
                      type="button"
                      class="rounded-lg border border-surface-border px-2 py-1 text-[11px] text-gray-300 transition hover:border-accent/50 hover:text-white"
                      title="Real, but deliberately not fixing now. Requires a reason; suppressed from the gate."
                      @click.stop="openTriageDialog('accepted', [vulnerability.fingerprint])"
                    >
                      Accept risk…
                    </button>
                    <button
                      type="button"
                      class="rounded-lg border border-surface-border px-2 py-1 text-[11px] text-gray-300 transition hover:border-accent/50 hover:text-white"
                      title="Not a real issue. Requires a reason; suppressed from the gate."
                      @click.stop="openTriageDialog('false_positive', [vulnerability.fingerprint])"
                    >
                      False positive…
                    </button>
                  </div>
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
import { computed, reactive, ref, watch } from 'vue'
import { type LocationQueryRaw, useRoute, useRouter } from 'vue-router'

import { KeyRound } from 'lucide-vue-next'

import { api, type FindingAcceptance, type ScanRule, type SecretScanJob, type Vulnerability, type VulnerabilityFacets } from '@/api/client'
import FilterBar from '@/components/FilterBar.vue'
import FindingOriginBadge from '@/components/FindingOriginBadge.vue'
import LinkedText from '@/components/LinkedText.vue'
import TriageDialog from '@/components/TriageDialog.vue'
import { triageState } from '@/lib/triage'

const route = useRoute()
const router = useRouter()

const provider = computed(() => route.params.provider as string)
const slug = computed(() => route.params.slug as string)
const repoSlug = computed(() => route.params.repoSlug as string)

const vulnerabilities = ref<Vulnerability[]>([])
const acceptances = ref<Map<string, FindingAcceptance>>(new Map())

const secretScanRunning = ref(false)
const secretScanMessage = ref('')
const secretScanError = ref('')
const lastSecretScanJob = ref<SecretScanJob | null>(null)

async function refreshSecretScanStatus() {
  try {
    const response = await api.listSecretScanJobs(provider.value, slug.value, repoSlug.value)
    lastSecretScanJob.value = response.data?.[0] ?? null
  } catch {
    // Status is best-effort decoration; the findings table is the source of truth.
  }
}

const secretScanStatusLine = computed(() => {
  const job = lastSecretScanJob.value
  if (!job) return ''
  const when = new Date(job.finished_at ?? job.started_at ?? job.created_at).toLocaleString()
  switch (job.status) {
    case 'pending':
      return `Secret scan queued (${job.ref_name}) — waiting for a worker. If this never starts, no pod runs the scan loop.`
    case 'processing':
      return `Secret scan running on ${job.ref_name} (attempt ${job.attempts})…`
    case 'failed':
      return `Secret scan failed on ${job.ref_name}: ${job.last_error || 'unknown error'} (attempt ${job.attempts}, ${when})`
    default:
      return `Last secret scan: ${job.status} on ${job.ref_name} (${when})`
  }
})

watch([provider, slug, repoSlug], () => { void refreshSecretScanStatus() }, { immediate: true })

async function runSecretScan() {
  if (secretScanRunning.value) return
  secretScanRunning.value = true
  secretScanMessage.value = ''
  secretScanError.value = ''
  try {
    const refParam = route.query.ref as string | undefined
    const response = await api.triggerSecretScan(provider.value, slug.value, repoSlug.value, { ref: refParam })
    secretScanMessage.value = `Secret scan queued for ${response.data.ref}.`
    await refreshSecretScanStatus()
  } catch (error) {
    secretScanError.value = error instanceof Error ? error.message : 'Failed to queue secret scan'
  } finally {
    secretScanRunning.value = false
  }
}

watch([provider, slug, repoSlug], () => { void loadAcceptances() }, { immediate: true })
const loading = ref(true)
const activeFilters = ref<Record<string, string>>({ status: 'detected,confirmed' })
const searchQuery = ref('')
const currentSort = ref('detected')
const currentSortDirection = ref('desc')
const pagination = ref({ page: 1, per_page: 50, total: 0 })
// Rule catalog for the current snapshot, keyed by `${tool}::${rule_id}`.
// Fetched once per load and joined to findings locally (dedup on the wire).
const ruleMap = ref<Map<string, ScanRule>>(new Map())

function ruleKey(tool: string | undefined, ruleID: string | undefined): string {
  return `${tool ?? ''}::${ruleID ?? ''}`
}

function ruleName(vulnerability: Vulnerability): string {
  const rule = ruleMap.value.get(ruleKey(vulnerability.scanner_name, vulnerability.primary_identifier_value))
  return rule?.name ?? ''
}
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

      // Load the deduplicated rule catalog once and join locally; failure here
      // must not break the findings list, so degrade to an empty map.
      try {
        const rulesRes = await api.listRefRules(provider.value, slug.value, repoSlug.value, {
          ref: typeof route.query.ref === 'string' ? route.query.ref : undefined,
          snapshot: typeof route.query.snapshot === 'string' ? route.query.snapshot : undefined,
        })
        const nextRuleMap = new Map<string, ScanRule>()
        for (const rule of rulesRes.data) {
          nextRuleMap.set(ruleKey(rule.tool, rule.rule_id), rule)
        }
        ruleMap.value = nextRuleMap
      } catch {
        ruleMap.value = new Map()
      }
    } catch {
      vulnerabilities.value = []
      pagination.value = { ...pagination.value, total: 0 }
    } finally {
      loading.value = false
    }
  },
  { immediate: true },
)

function mergeFacetOptions(counts: Record<string, number> | undefined, seen: Set<string>): string[] {
  const safeCounts = counts ?? {}
  const keys = new Set<string>([...Object.keys(safeCounts), ...seen])
  return Array.from(keys).sort((a, b) => {
    const diff = (safeCounts[b] ?? 0) - (safeCounts[a] ?? 0)
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
      const facetsRes = await api.listRefVulnerabilityFacets(provider.value, slug.value, repoSlug.value, {
        ref: typeof route.query.ref === 'string' ? route.query.ref : undefined,
        snapshot: typeof route.query.snapshot === 'string' ? route.query.snapshot : undefined,
        type: activeFilters.value.type || undefined,
        severity: activeFilters.value.severity || undefined,
        status: activeFilters.value.status || undefined,
        tool: activeFilters.value.tool || undefined,
        file: activeFilters.value.file || undefined,
        search: searchQuery.value || undefined,
      })
      facetCounts.value = facetsRes.data
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

function acceptanceFor(vulnerability: Vulnerability): FindingAcceptance | undefined {
  return acceptances.value.get(vulnerability.fingerprint)
}

async function loadAcceptances() {
  try {
    const res = await api.listFindingAcceptances(provider.value, slug.value, repoSlug.value)
    acceptances.value = new Map((res.data ?? []).map((a) => [a.fingerprint, a]))
  } catch {
    acceptances.value = new Map()
  }
}

// ─── Triage: one decision, one reason, any number of findings ────────────────
// Batch-first by design: the flow is filter → select all shown → decide once.
// Reasons are typed in a real dialog (a window.prompt lost the text on any
// error and could not offer presets or an expiry).

const selected = reactive(new Set<string>())
// Targets are fingerprints, not row objects: a filter-wide selection includes
// findings that are not on the current page, and keying off rows would have
// silently triaged only the visible subset.
const dialog = ref<{ status: 'accepted' | 'false_positive'; fingerprints: string[] } | null>(null)
const dialogError = ref('')
const dialogSubmitting = ref(false)
const batchMessage = ref('')
const selectingAll = ref(false)
const selectAllError = ref('')
const matchingTotal = ref(0)
const matchingTruncated = ref(false)

const shownFingerprints = computed(() => vulnerabilities.value.map((item) => item.fingerprint).filter(Boolean))
const allShownSelected = computed(() => shownFingerprints.value.length > 0 && shownFingerprints.value.every((fp) => selected.has(fp)))
const someShownSelected = computed(() => !allShownSelected.value && shownFingerprints.value.some((fp) => selected.has(fp)))

// The filter params the current view is showing, reused for "select all
// matching" so the server selects exactly what the user sees filtered.
function currentFilterParams(): Record<string, string> {
  const params: Record<string, string> = {}
  const add = (key: string, value: unknown) => {
    if (typeof value === 'string' && value) params[key] = value
  }
  add('ref', route.query.ref)
  add('snapshot', route.query.snapshot)
  add('type', activeFilters.value.type)
  add('severity', activeFilters.value.severity)
  add('status', activeFilters.value.status)
  add('tool', activeFilters.value.tool)
  add('file', activeFilters.value.file)
  add('search', searchQuery.value)
  return params
}

// Select every finding matching the filter, not just the current page — the
// point of "filter then batch-triage". Capped server-side at the batch limit,
// and the count is reported so a truncated selection is never presented as
// "everything".
async function selectAllMatchingFilter() {
  selectAllError.value = ''
  selectingAll.value = true
  try {
    const res = await api.listRefFindingFingerprints(provider.value, slug.value, repoSlug.value, currentFilterParams())
    const data = res.data
    if (!data || data.fingerprints.length === 0) {
      selectAllError.value = 'No findings match the current filter.'
      return
    }
    data.fingerprints.forEach((fp) => selected.add(fp))
    matchingTotal.value = data.total
    matchingTruncated.value = data.truncated
  } catch (error) {
    selectAllError.value = error instanceof Error ? error.message : 'Failed to select all matching findings'
  } finally {
    selectingAll.value = false
  }
}

function toggleSelected(vulnerability: Vulnerability) {
  if (selected.has(vulnerability.fingerprint)) {
    selected.delete(vulnerability.fingerprint)
  } else {
    selected.add(vulnerability.fingerprint)
  }
}

// "All" means all currently shown (filtered + paginated) — never the whole repo,
// which would act on rows the user cannot see.
function toggleSelectAllShown() {
  if (allShownSelected.value) {
    shownFingerprints.value.forEach((fp) => selected.delete(fp))
    return
  }
  shownFingerprints.value.forEach((fp) => selected.add(fp))
}

// A row filtered out of view must never stay silently selected. Skipped while a
// filter-wide selection is active, since those fingerprints are deliberately off
// the current page.
watch(vulnerabilities, () => {
  if (matchingTotal.value > 0) return
  const visible = new Set(shownFingerprints.value)
  for (const fingerprint of [...selected]) {
    if (!visible.has(fingerprint)) selected.delete(fingerprint)
  }
})

function clearSelection() {
  selected.clear()
  matchingTotal.value = 0
  matchingTruncated.value = false
  selectAllError.value = ''
}

function openTriageDialog(status: 'accepted' | 'false_positive', fingerprints: string[]) {
  const unique = [...new Set(fingerprints.filter(Boolean))]
  if (unique.length === 0) return
  dialogError.value = ''
  batchMessage.value = ''
  dialog.value = { status, fingerprints: unique }
}

function closeTriageDialog() {
  dialog.value = null
  dialogError.value = ''
  dialogSubmitting.value = false
}

async function confirmTriageDialog(payload: { reason: string; expiresAt?: string }) {
  if (!dialog.value) return
  const { status, fingerprints } = dialog.value
  dialogSubmitting.value = true
  dialogError.value = ''
  try {
    await applyTriage(status, fingerprints, payload.reason, payload.expiresAt)
    batchMessage.value = `${fingerprints.length} ${fingerprints.length === 1 ? 'finding' : 'findings'} updated.`
    closeTriageDialog()
    clearSelection()
  } catch (error) {
    // Keep the dialog open so the typed reason is not lost.
    dialogError.value = error instanceof Error ? error.message : 'Failed to apply the decision'
    dialogSubmitting.value = false
  }
}

async function reopenFindings(fingerprints: string[]) {
  const unique = [...new Set(fingerprints.filter(Boolean))]
  if (unique.length === 0) return
  batchMessage.value = ''
  try {
    await applyTriage('open', unique, '')
    batchMessage.value = `${unique.length} ${unique.length === 1 ? 'finding' : 'findings'} reopened.`
    clearSelection()
  } catch (error) {
    batchMessage.value = ''
    secretScanError.value = error instanceof Error ? error.message : 'Failed to reopen findings'
  }
}

// One finding still goes through the batch endpoint: same validation, same audit
// shape, one code path to keep correct.
async function applyTriage(status: 'accepted' | 'false_positive' | 'open', fingerprints: string[], reason: string, expiresAt?: string) {
  if (fingerprints.length === 0) return
  await api.batchFindingAcceptance(provider.value, slug.value, repoSlug.value, {
    fingerprints,
    status,
    reason: reason || undefined,
    expires_at: expiresAt,
  })
  // Only acceptances changed; the badge derives from them, so no refetch of the
  // findings list is needed.
  await loadAcceptances()
}

function triageFor(vulnerability: Vulnerability) {
  return triageState(vulnerability, acceptanceFor(vulnerability))
}

// The tooltip carries the "why" — the recorded reason — plus the expiry when set.
function triageTitle(vulnerability: Vulnerability): string {
  const info = triageFor(vulnerability)
  const acceptance = acceptanceFor(vulnerability)
  if (!acceptance) return info.description
  const parts = [info.description, `Reason: ${acceptance.reason}`]
  if (acceptance.expires_at) {
    parts.push(`Expires: ${new Date(acceptance.expires_at).toLocaleDateString()}`)
  }
  return parts.join('\n')
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
