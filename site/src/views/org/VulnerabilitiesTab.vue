<template>
  <div class="space-y-4">
    <button
      v-if="orgMalwareOpen > 0 && advancedQuery !== OPEN_RISK_MALWARE_QUERY"
      type="button"
      class="flex w-full items-center gap-2.5 rounded-xl border border-malware/60 bg-malware/10 px-4 py-3 text-left transition hover:border-malware"
      @click="applyMalwareFilter"
    >
      <MalwareIcon />
      <span class="text-sm font-semibold text-violet-100">
        {{ orgMalwareOpen }} malware {{ orgMalwareOpen === 1 ? 'finding' : 'findings' }} across this organization — review immediately
      </span>
      <span class="ml-auto text-xs text-violet-200/80">Show only malware →</span>
    </button>

    <FilterBar
      v-model="activeFilters"
      v-model:search-query="searchQuery"
      v-model:advanced-query="advancedQuery"
      v-model:sort-value="currentSort"
      v-model:sort-direction="currentSortDirection"
      :filters="filterDefs"
      :sort-options="sortOptions"
      :sort-direction-options="sortDirectionOptions"
      :total-count="baselineTotal ?? pagination.total"
      :filtered-count="baselineTotal !== undefined && hasActiveFilters ? pagination.total : undefined"
      placeholder="Filter vulnerabilities across all repositories..."
    >
      <template #trailing>
        <SearchPresetMenu
          surface="findings"
          :filters="filterDefs"
          :builtins="BUILTIN_FINDINGS_PRESETS"
          :query="currentBarQuery"
          @apply="applyPresetQuery"
        />
      </template>
    </FilterBar>
    <p
      v-if="baselineTotal === undefined && hasActiveFilters"
      class="text-xs text-gray-400"
    >
      {{ pagination.total }} matching findings
    </p>

    <!-- Same detail drawer as the repository view; org-wide rows carry their own
         repository, so it is passed per row rather than read from the route. -->
    <FindingDetailModal
      v-if="drawer"
      :key="`${drawer.repoSlug}:${drawer.fingerprint}`"
      :provider="provider"
      :slug="slug"
      :repo-slug="drawer.repoSlug"
      :fingerprint="drawer.fingerprint"
      @close="closeDrawer"
      @cwes-updated="applyCWEsToRows"
      @accept="openTriageDialog"
      @reopen="reopenFinding"
      @revoke="markSecretRevoked"
      @navigate="navigateDrawer"
    />

    <TriageDialog
      v-if="dialog"
      :kind="dialog.kind"
      :count="1"
      :component-backed="dialog.componentBacked"
      :exploited="dialog.exploited"
      :error="dialogError"
      :submitting="dialogSubmitting"
      @cancel="closeTriageDialog"
      @confirm="confirmTriageDialog"
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
                <th
                  class="px-3 py-2 font-medium"
                  title="The CVSS score this finding uses; ◆ when raters disagree"
                >
                  CVSS
                </th>
                <th
                  class="px-3 py-2 font-medium"
                  title="Probability of exploitation in the next 30 days (FIRST EPSS)"
                >
                  EPSS
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
                class="cursor-pointer transition hover:bg-white/5"
                :class="vulnerability.type === 'malware' ? 'border-l-2 border-malware bg-malware/5' : ''"
                @click="openDrawer(vulnerability)"
              >
                <td class="px-3 py-2.5">
                  <span class="inline-flex items-center gap-1.5 whitespace-nowrap">
                    <span class="inline-flex h-5 w-5 shrink-0 items-center justify-center">
                      <MalwareIcon v-if="vulnerability.type === 'malware'" />
                      <span
                        v-else-if="vulnerability.kev"
                        class="inline-flex h-5 w-5 items-center justify-center rounded-full bg-danger-muted text-white"
                        role="img"
                        aria-label="Known exploited vulnerability"
                        title="Listed on a known-exploited catalog (CISA KEV / ENISA EUVD) — exploitation in the wild is documented"
                      >
                        <Flame
                          class="h-3 w-3"
                          aria-hidden="true"
                        />
                      </span>
                    </span>
                    <span :class="severityClass(vulnerability.severity)">{{ vulnerability.severity }}</span>
                  </span>
                </td>
                <td class="px-3 py-2.5 text-xs">
                  <CvssCell :finding="vulnerability" />
                </td>
                <td class="px-3 py-2.5 text-xs">
                  <EpssCell :epss="vulnerability.epss" />
                </td>
                <td class="px-3 py-2.5">
                  <RouterLink
                    :to="`/orgs/${provider}/${slug}/repos/${vulnerability.repo_slug}/vulnerabilities`"
                    class="font-medium text-accent transition hover:underline"
                    @click.stop
                  >
                    {{ vulnerability.repo_name || vulnerability.repo_slug }}
                  </RouterLink>
                </td>
                <td class="px-3 py-2.5">
                  <span :class="findingTypeBadgeClass(vulnerability.type)">{{ vulnerability.type }}</span>
                </td>
                <td class="px-3 py-2.5 font-mono text-xs text-accent">
                  {{ vulnerability.primary_identifier_value || vulnerability.scanner_name || 'n/a' }}
                </td>
                <td class="px-3 py-2.5">
                  <button
                    type="button"
                    class="block text-left transition hover:text-white focus:outline-none focus-visible:underline"
                    @click.stop="openDrawer(vulnerability)"
                  >
                    <LinkedText
                      :text="vulnerability.title"
                      class="text-gray-300"
                    />
                  </button>
                  <CweChips
                    v-if="vulnerability.cwes?.length"
                    class="mt-1"
                    :cwes="vulnerability.cwes"
                    :max="4"
                    clickable
                    @select="filterByCWE"
                  />
                </td>
                <td class="px-3 py-2.5 text-gray-400">
                  <div class="flex items-center gap-1.5">
                    <span>{{ vulnerability.scanner_name || 'n/a' }}</span>
                    <FindingOriginBadge :finding="vulnerability" />
                    <PresenceBadge :finding="vulnerability" />
                  </div>
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
import { Flame } from 'lucide-vue-next'
import { computed, inject, ref, watch, type Ref } from 'vue'
import { type LocationQueryRaw, RouterLink, useRoute, useRouter } from 'vue-router'

import { api, type FindingCWE, type AcceptanceReasonKind, type FindingAcceptance, type OrgDashboard, type OrgVulnerability, type VexJustification, type Vulnerability } from '@/api/client'
import FilterBar from '@/components/FilterBar.vue'
import SearchPresetMenu from '@/components/SearchPresetMenu.vue'
import FindingDetailModal from '@/components/FindingDetailModal.vue'
import FindingOriginBadge from '@/components/FindingOriginBadge.vue'
import PresenceBadge from '@/components/finding/PresenceBadge.vue'
import LinkedText from '@/components/LinkedText.vue'
import CweChips from '@/components/finding/CweChips.vue'
import MalwareIcon from '@/components/finding/MalwareIcon.vue'
import CvssCell from '@/components/finding/CvssCell.vue'
import EpssCell from '@/components/finding/EpssCell.vue'
import { cweFilterDefs } from '@/lib/cweFilters'
import { riskFilterDefs } from '@/lib/riskFilters'
import { appendBarToken, withHiddenDefaults } from '@/lib/filterBarQuery'
import TriageDialog from '@/components/TriageDialog.vue'
import { useToast } from '@/composables/useToast'
import { useDialog } from '@/composables/useDialog'
import { findingTypeBadgeClass, isComponentBacked } from '@/lib/findingDisplay'
import { createExploitedPreset } from '@/lib/exploitedPreset'
import { sameFilterValues, sameListQueryState } from '@/lib/listQueryState'
import { migrateRiskOnlyQuery, OPEN_RISK_MALWARE_QUERY } from '@/lib/openRiskPreset'
import { barQueryText, barStateFromQuery, BUILTIN_FINDINGS_PRESETS } from '@/lib/searchPresets'

const { promptDialog } = useDialog()
const route = useRoute()
const router = useRouter()
const { pushToast } = useToast()
const provider = computed(() => route.params.provider as string)
const slug = computed(() => route.params.slug as string)

const vulnerabilities = ref<OrgVulnerability[]>([])
const loading = ref(true)
const activeFilters = ref<Record<string, string>>({ status: 'detected' })
const applyExploitedPreset = createExploitedPreset()
const exploitedOnly = computed(() => activeFilters.value.exploited === 'true')
function toggleExploitedOnly(enabled: boolean) {
  activeFilters.value = applyExploitedPreset(activeFilters.value, enabled)
}
const searchQuery = ref('')
const advancedQuery = ref('')
const currentSort = ref('severity')
const currentSortDirection = ref('desc')
const pagination = ref({ page: 1, per_page: 50, total: 0 })
const baselineTotals = ref(new Map<string, number>())
const baselineScopeKey = computed(() => JSON.stringify([provider.value, slug.value]))
const baselineTotal = computed(() => baselineTotals.value.get(baselineScopeKey.value))
let baselineRequestID = 0
const seenTools = ref<Set<string>>(new Set())

const typeOptions = ['dependency', 'sast', 'secret', 'malware', 'dast', 'container', 'fuzzing', 'manual', 'generic']
const severityOptions = ['critical', 'high', 'medium', 'unknown', 'low', 'info']
const statusOptions = ['detected', 'resolved', 'suppressed']
const toolOptions = computed(() => Array.from(seenTools.value).sort())
const filterDefs = computed(() => [
  { key: 'status', label: 'Status', options: statusOptions, multi: true, primary: true, hidden: true, defaultValue: 'detected' },
  { key: 'type', label: 'Type', options: typeOptions, multi: true },
  { key: 'severity', label: 'Severity', options: severityOptions, multi: true },
  { key: 'acceptance', label: 'Triage', options: ['open', 'accepted', 'risk_accepted', 'false_positive', 'disputed'] },
  { key: 'presence', label: 'Presence', options: ['reported', 'not-rechecked', 'unconfirmed'], multi: true },
  { key: 'tool', label: 'Sources', options: toolOptions.value, multi: true },
  { key: 'exploited', label: 'Exploited', options: ['true', 'false'], control: 'boolean' as const, toggleIcon: Flame, tone: 'danger' as const, description: 'Known-exploited dependency findings (CISA KEV / ENISA EUVD)', onToggle: toggleExploitedOnly },
  // ADR-037. No org facet endpoint: completion searches the catalog.
  ...cweFilterDefs(() => undefined),
  // ADR-038 §6: server-side comparisons on the rating and the EPSS mirror.
  ...riskFilterDefs(),
])

// The query the server runs, with the hidden status:detected default.
const serverQuery = computed(() => (advancedQuery.value ? withHiddenDefaults(advancedQuery.value, filterDefs.value) : ''))

function applyCWEsToRows(fingerprint: string, cwes: FindingCWE[]) {
  vulnerabilities.value = vulnerabilities.value.map(row => (row.fingerprint === fingerprint ? { ...row, cwes } : row))
}

function filterByCWE(id: number) {
  advancedQuery.value = appendBarToken(filterDefs.value, {
    filters: activeFilters.value,
    searchText: searchQuery.value,
    advancedQuery: advancedQuery.value,
  }, `cwe:${id}`)
}
const sortOptions = [
  { key: 'severity', label: 'Severity' },
  { key: 'detected', label: 'Detected', ascLabel: 'Oldest', descLabel: 'Newest' },
  // ADR-038 §5: KEV, then EPSS, then CVSS — an order, not a blended score.
  { key: 'risk', label: 'Risk' },
  { key: 'epss', label: 'EPSS' },
  { key: 'cvss', label: 'CVSS' },
  { key: 'status', label: 'Status' },
]
const sortDirectionOptions = [
  { key: 'desc', label: '↓ Desc' },
  { key: 'asc', label: '↑ Asc' },
]
const filterKeys = ['type', 'severity', 'status', 'acceptance', 'tool', 'exploited'] as const
const managedQueryKeys = [...filterKeys, 'search', 'q', 'sort', 'order', 'page'] as const
const sortKeys = new Set(sortOptions.map((option) => option.key))
const sortDirectionKeys = new Set(sortDirectionOptions.map((option) => option.key))
const syncingFromRoute = ref(false)
let vulnerabilityRequestID = 0

watch([provider, slug], () => {
  applyExploitedPreset.reset()
})

const hasActiveFilters = computed(() => Object.values(activeFilters.value).some(Boolean) || searchQuery.value.trim().length > 0 || advancedQuery.value.trim().length > 0)
const orgDashboard = inject<Ref<OrgDashboard | null>>('orgDashboard', ref(null))
const orgMalwareOpen = computed(() => orgDashboard.value?.totals.malware_open ?? 0)

// The same set the banner counts (orgDashboard malware_open).
function applyMalwareFilter() {
  activeFilters.value = {}
  searchQuery.value = ''
  advancedQuery.value = OPEN_RISK_MALWARE_QUERY
}
const totalPages = computed(() => Math.max(1, Math.ceil(pagination.value.total / pagination.value.per_page)))

const currentBarQuery = computed(() => barQueryText({
  filters: activeFilters.value,
  search: searchQuery.value,
  advancedQuery: advancedQuery.value,
}, filterDefs.value))

function applyPresetQuery(query: string) {
  const state = barStateFromQuery(query, filterDefs.value)
  if (!state) return
  activeFilters.value = state.filters
  searchQuery.value = state.search
  advancedQuery.value = state.advancedQuery
}

watch(
  [provider, slug],
  async () => {
    if (!provider.value || !slug.value || baselineTotals.value.has(baselineScopeKey.value)) return
    const requestID = ++baselineRequestID
    const scopeKey = baselineScopeKey.value
    try {
      const response = await api.listOrgVulnerabilities(provider.value, slug.value, { page: 1, per_page: 1 })
      if (requestID !== baselineRequestID || scopeKey !== baselineScopeKey.value) return
      baselineTotals.value = new Map(baselineTotals.value).set(scopeKey, response.pagination.total)
    } catch {
      // Keep the baseline unknown rather than presenting a filtered count as total.
    }
  },
  { immediate: true },
)

watch(
  () => route.query,
  () => {
    if (route.query.risk_only === 'true') {
      void router.replace({ query: migrateRiskOnlyQuery(route.query, filterDefs.value) })
      return
    }
    const nextState = readQueryState()

    syncingFromRoute.value = true
    try {
      if (!sameFilterValues(filterKeys, activeFilters.value, nextState.filters)) activeFilters.value = nextState.filters
      if (searchQuery.value !== nextState.search) searchQuery.value = nextState.search
      if (advancedQuery.value !== nextState.q) advancedQuery.value = nextState.q
      if (currentSort.value !== nextState.sort) currentSort.value = nextState.sort
      if (currentSortDirection.value !== nextState.order) currentSortDirection.value = nextState.order
      if (pagination.value.page !== nextState.page) pagination.value = { ...pagination.value, page: nextState.page }
    } finally {
      syncingFromRoute.value = false
    }
  },
  { immediate: true },
)

watch(
  [activeFilters, searchQuery, advancedQuery, currentSort, currentSortDirection],
  () => {
    if (syncingFromRoute.value) return
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
    if (!syncingFromRoute.value) void syncQueryFromState()
  },
)

watch(
  [provider, slug, activeFilters, searchQuery, advancedQuery, currentSort, currentSortDirection, exploitedOnly, () => pagination.value.page],
  async () => {
    const requestID = ++vulnerabilityRequestID
    if (!provider.value || !slug.value) {
      vulnerabilities.value = []
      return
    }

    loading.value = true
    try {
      const res = await api.listOrgVulnerabilities(provider.value, slug.value, {
        type: advancedQuery.value ? undefined : activeFilters.value.type || undefined,
        severity: advancedQuery.value ? undefined : activeFilters.value.severity || undefined,
        status: advancedQuery.value ? undefined : activeFilters.value.status || undefined,
        acceptance: advancedQuery.value ? undefined : activeFilters.value.acceptance || undefined,
        tool: advancedQuery.value ? undefined : activeFilters.value.tool || undefined,
        search: advancedQuery.value ? undefined : searchQuery.value || undefined,
        q: serverQuery.value || undefined,
        exploited: advancedQuery.value ? undefined : activeFilters.value.exploited === 'true' ? true : activeFilters.value.exploited === 'false' ? false : undefined,
        sort: `${currentSort.value}_${currentSortDirection.value}`,
        page: pagination.value.page,
        per_page: pagination.value.per_page,
      })
      if (requestID !== vulnerabilityRequestID) return
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
      if (requestID !== vulnerabilityRequestID) return
      vulnerabilities.value = []
      pagination.value = { ...pagination.value, total: 0 }
    } finally {
      if (requestID === vulnerabilityRequestID) loading.value = false
    }
  },
  { immediate: true },
)

function readQueryState() {
  const hasQuery = typeof route.query.q === 'string' && route.query.q.length > 0
  const filters: Record<string, string> = hasQuery ? {} : { status: 'detected' }
  for (const key of filterKeys) {
    const value = route.query[key]
    if (typeof value === 'string' && value) filters[key] = value
  }

  const sortValue = route.query.sort
  const sort = typeof sortValue === 'string' && sortKeys.has(sortValue) ? sortValue : 'severity'
  const orderValue = route.query.order
  const order = typeof orderValue === 'string' && sortDirectionKeys.has(orderValue) ? orderValue : 'desc'
  const search = typeof route.query.search === 'string' ? route.query.search : ''
  const q = typeof route.query.q === 'string' ? route.query.q : ''
  const pageValue = Number(typeof route.query.page === 'string' ? route.query.page : '1')
  const page = Number.isInteger(pageValue) && pageValue > 0 ? pageValue : 1
  return { filters, search, q, sort, order, page }
}

function syncQueryFromState() {
  const nextState = {
    filters: normalizeFilters(activeFilters.value),
    search: searchQuery.value.trim(),
    q: advancedQuery.value,
    sort: currentSort.value,
    order: currentSortDirection.value,
    page: pagination.value.page,
  }
  if (sameListQueryState(filterKeys, nextState, readQueryState())) return

  const nextQuery: LocationQueryRaw = { ...route.query }
  for (const key of managedQueryKeys) delete nextQuery[key]
  Object.assign(nextQuery, buildQueryParams(nextState))
  return router.replace({ query: nextQuery })
}

function buildQueryParams(state: { filters: Record<string, string>; search: string; q: string; sort: string; order: string; page: number }) {
  const params: Record<string, string> = {}
  for (const key of filterKeys) {
    const value = state.filters[key]
    if (value && !(key === 'status' && value === 'detected')) params[key] = value
  }
  if (state.search) params.search = state.search
  if (state.q) params.q = state.q
  if (state.sort !== 'severity') params.sort = state.sort
  if (state.order !== 'desc') params.order = state.order
  if (state.page > 1) params.page = String(state.page)
  return params
}

function normalizeFilters(filters: Record<string, string>) {
  const normalized: Record<string, string> = advancedQuery.value ? {} : { status: filters.status || 'detected' }
  for (const key of filterKeys) {
    const value = filters[key]
    if (value) normalized[key] = value
  }
  return normalized
}

// ── Finding detail drawer ────────────────────────────────────────────────────
// Deep-linkable as ?finding=<fingerprint>&repo=<slug>: a row here belongs to a
// repository, so the fingerprint alone would not identify it.
const drawer = ref<{ fingerprint: string; repoSlug: string } | null>(null)

function openDrawer(vulnerability: Pick<OrgVulnerability, 'fingerprint' | 'repo_slug'>) {
  if (!vulnerability.fingerprint || !vulnerability.repo_slug) return
  drawer.value = { fingerprint: vulnerability.fingerprint, repoSlug: vulnerability.repo_slug }
  void router.replace({ query: { ...route.query, finding: vulnerability.fingerprint, repo: vulnerability.repo_slug } })
}

function closeDrawer() {
  drawer.value = null
  const next = { ...route.query }
  delete next.finding
  delete next.repo
  void router.replace({ query: next })
}

// j/k walks the loaded list, staying inside the drawer.
function navigateDrawer(delta: number) {
  const list = vulnerabilities.value
  const index = list.findIndex((row) => row.fingerprint === drawer.value?.fingerprint && row.repo_slug === drawer.value?.repoSlug)
  const next = list[index + delta]
  if (next) openDrawer(next)
}

// ── Triage, in place ─────────────────────────────────────────────────────────
// A decision applies to the repository that owns the finding, which the drawer
// already knows — bouncing to that repository's view just to click the same
// button again is not a workflow. Same dialog and same endpoints as the
// repository view; only the repo slug is per row.
const dialog = ref<{ kind: AcceptanceReasonKind; finding: Vulnerability; repoSlug: string; componentBacked: boolean; exploited?: boolean } | null>(null)
const dialogError = ref('')
const dialogSubmitting = ref(false)

function openTriageDialog(kind: AcceptanceReasonKind, finding: Vulnerability, exploited?: boolean) {
  const repoSlug = drawer.value?.repoSlug
  if (!repoSlug || !finding.fingerprint) return
  dialogError.value = ''
  drawer.value = null
  dialog.value = { kind, finding, repoSlug, componentBacked: isComponentBacked(finding.type), exploited: exploited === true }
}

function closeTriageDialog() {
  dialog.value = null
  dialogError.value = ''
  dialogSubmitting.value = false
}

async function confirmTriageDialog(payload: { reason: string; labels: string[]; vexJustification?: VexJustification; expiresAt?: string }) {
  if (!dialog.value) return
  const { kind, finding, repoSlug } = dialog.value
  dialogSubmitting.value = true
  dialogError.value = ''
  try {
    if (payload.vexJustification) {
      // A VEX justification is a statement about one component, so it goes
      // through the per-finding endpoint; the batch one rejects the vocabulary.
      await api.setFindingAcceptance(provider.value, slug.value, repoSlug, finding.id, {
        status: 'accepted',
        reason_kind: kind,
        reason: payload.reason,
        labels: payload.labels,
        vex_justification: payload.vexJustification,
        expires_at: payload.expiresAt,
      })
    } else {
      await api.batchFindingAcceptance(provider.value, slug.value, repoSlug, {
        fingerprints: [finding.fingerprint],
        status: 'accepted',
        reason_kind: kind,
        reason: payload.reason || undefined,
        labels: payload.labels,
        expires_at: payload.expiresAt,
      })
    }
    patchRowAcceptance(repoSlug, finding.fingerprint, {
      reason_kind: kind,
      reason: payload.reason,
      labels: payload.labels,
      vex_justification: payload.vexJustification,
      expires_at: payload.expiresAt,
      created_at: new Date().toISOString(),
    })
    pushToast({ title: kind === 'false_positive' ? 'Marked false positive' : 'Risk accepted', tone: 'success' })
    closeTriageDialog()
  } catch (error) {
    // Keep the dialog open so the typed reason is not lost.
    dialogError.value = error instanceof Error ? error.message : 'Failed to apply the decision'
    dialogSubmitting.value = false
  }
}

async function reopenFinding(fingerprint: string) {
  const repoSlug = drawer.value?.repoSlug
  if (!repoSlug || !fingerprint) return
  drawer.value = null
  try {
    await api.batchFindingAcceptance(provider.value, slug.value, repoSlug, { fingerprints: [fingerprint], status: 'open' })
    patchRowAcceptance(repoSlug, fingerprint, undefined)
    pushToast({ title: 'Finding reopened', description: 'It counts against the quality gate again.', tone: 'success' })
  } catch (error) {
    pushToast({ title: 'Failed to reopen the finding', description: error instanceof Error ? error.message : undefined, tone: 'error' })
  }
}

async function markSecretRevoked(finding: Vulnerability) {
  const repoSlug = drawer.value?.repoSlug
  if (!repoSlug) return
  const comment = await promptDialog({
    title: 'Attest secret revocation',
    message: 'Recorded in the audit log.',
    confirmLabel: 'Mark revoked',
    input: { label: 'How was this secret revoked/rotated?' },
  })
  if (comment === null) return
  drawer.value = null
  try {
    await api.attestSecretRevocation(provider.value, slug.value, repoSlug, finding.id, comment)
    vulnerabilities.value = vulnerabilities.value.map((row) =>
      row.id === finding.id ? { ...row, status: 'resolved' } : row,
    )
    pushToast({ title: 'Secret marked revoked', tone: 'success' })
  } catch (error) {
    pushToast({ title: 'Failed to record the revocation', description: error instanceof Error ? error.message : undefined, tone: 'error' })
  }
}

// Rows are keyed by repository as well as fingerprint: the same fingerprint can
// legitimately exist in more than one repository of the organization.
function patchRowAcceptance(repoSlug: string, fingerprint: string, acceptance: FindingAcceptance | undefined) {
  vulnerabilities.value = vulnerabilities.value.map((row) =>
    row.repo_slug === repoSlug && row.fingerprint === fingerprint ? { ...row, acceptance } : row,
  )
}

watch(
  () => [route.query.finding, route.query.repo],
  ([finding, repo]) => {
    drawer.value = typeof finding === 'string' && finding && typeof repo === 'string' && repo
      ? { fingerprint: finding, repoSlug: repo }
      : null
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
    // Unknown: no source rates it (ADR-038 §3). Neutral, dashed: not low.
    unknown: 'rounded-full border border-dashed border-gray-500/50 px-2.5 py-1 text-xs font-medium text-gray-300',
    low: 'rounded-full bg-gray-500/15 px-2.5 py-1 text-xs font-medium text-gray-400',
    info: 'rounded-full bg-blue-500/15 px-2.5 py-1 text-xs font-medium text-blue-400',
  }
  return classes[level.toLowerCase()] || classes.info
}

function formatDetected(value: string) {
  return new Intl.DateTimeFormat('en', { dateStyle: 'medium' }).format(new Date(value))
}
</script>
