<template>
  <div class="space-y-5">
    <button
      v-if="openMalwareCount > 0 && activeFilters.type !== 'malware'"
      type="button"
      class="flex w-full items-center gap-2.5 rounded-xl border border-danger/50 bg-danger/10 px-4 py-3 text-left transition hover:border-danger"
      @click="applyMalwareFilter"
    >
      <Biohazard class="h-5 w-5 shrink-0 text-danger" />
      <span class="text-sm font-semibold text-red-200">
        {{ openMalwareCount }} malware {{ openMalwareCount === 1 ? 'finding' : 'findings' }} — review immediately
      </span>
      <span class="ml-auto text-xs text-red-300/80">Show only malware →</span>
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
      :total-count="pagination.total"
      :filtered-count="hasActiveFilters ? pagination.total : undefined"
      :counts="facetCounts"
      placeholder="Filter vulnerabilities..."
    >
      <template #trailing>
        <button
          type="button"
          class="inline-flex items-center gap-1.5 rounded-md border px-3 py-1.5 text-sm transition"
          :class="exploitedOnly ? 'border-danger/60 bg-danger/10 text-danger' : 'border-surface-border text-gray-400 hover:border-danger/50 hover:text-danger'"
          title="Only findings whose advisory is on a known-exploited catalog (CISA KEV / ENISA EUVD). Server-side: pagination stays correct."
          @click="toggleExploitedOnly"
        >
          <Flame class="h-3.5 w-3.5" />
          Exploited
        </button>
      </template>
    </FilterBar>

    <div class="flex items-center gap-3">
      <button
        type="button"
        class="inline-flex items-center gap-2 rounded-md border border-surface-border px-3 py-1.5 text-xs font-medium text-gray-300 transition hover:border-accent/50 hover:text-white disabled:cursor-not-allowed disabled:opacity-50"
        :disabled="secretScanRunning"
        title="Queue a full secret scan of this branch; a worker picks it up"
        @click="runSecretScan"
      >
        <KeyRound class="h-3.5 w-3.5" />
        {{ secretScanRunning ? 'Queueing...' : lastSecretScanJob?.status === 'failed' ? 'Retry secret scan' : 'Scan secrets' }}
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
      :kind="dialog.kind"
      :count="dialog.fingerprints.length"
      :component-backed="dialog.componentBacked"
      :exploited="dialog.exploited"
      :error="dialogError"
      :submitting="dialogSubmitting"
      @cancel="closeTriageDialog"
      @confirm="confirmTriageDialog"
    />

    <FindingDetailModal
      v-if="drawerFingerprint"
      :provider="provider"
      :slug="slug"
      :repo-slug="repoSlug"
      :fingerprint="drawerFingerprint"
      @close="closeDrawer"
      @accept="(kind, finding, exploited) => { closeDrawer(); openTriageDialog(kind, [finding.fingerprint], finding, exploited) }"
      @reopen="(fingerprint) => { closeDrawer(); void reopenFindings([fingerprint]) }"
      @revoke="(finding) => { closeDrawer(); void markSecretRevoked(finding) }"
      @disputed="applyDisputeToRows"
      @navigate="navigateDrawer"
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
      <div class="relative flex">
        <button
          type="button"
          class="rounded-l-md border border-surface-border bg-surface-overlay px-2.5 py-1 text-xs text-gray-200 transition hover:border-accent/50 hover:text-white"
          title="Real, but deliberately not fixing now. Requires a reason; suppressed from the gate."
          @click="openTriageDialog('risk_accepted', [...selected])"
        >
          Accept
        </button>
        <button
          type="button"
          class="rounded-r-md border border-l-0 border-surface-border bg-surface-overlay px-1.5 py-1 text-xs text-gray-200 transition hover:border-accent/50 hover:text-white"
          aria-label="More accept options"
          @click="bulkMenuOpen = !bulkMenuOpen"
        >
          ▾
        </button>
        <!-- Alternatives only — the main button already means "accept risk". -->
        <div
          v-if="bulkMenuOpen"
          class="absolute left-0 top-full z-20 mt-1 w-44 overflow-hidden rounded-md border border-surface-border bg-surface-raised shadow-xl"
        >
          <button
            type="button"
            class="block w-full px-3 py-1.5 text-left text-xs text-gray-200 transition hover:bg-surface-overlay"
            title="Not a real issue: excluded from the gate and from risk reporting."
            @click="bulkMenuOpen = false; openTriageDialog('false_positive', [...selected])"
          >
            False positive…
          </button>
        </div>
      </div>
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
                class="cursor-pointer transition hover:bg-white/5"
                :class="[rowClass(vulnerability.type), selected.has(vulnerability.fingerprint) ? 'bg-accent/10' : '']"
                :title="'Open detail'"
                @click="openDrawer(vulnerability.fingerprint)"
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
                  <button
                    type="button"
                    class="block text-left transition hover:text-white focus:outline-none focus-visible:underline"
                    @click.stop="openDrawer(vulnerability.fingerprint)"
                  >
                    <LinkedText
                      :text="vulnerability.title"
                      class="text-gray-300"
                    />
                  </button>

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
                  <span
                    v-if="vulnerability.kev"
                    class="ml-1 inline-flex items-center gap-1 rounded-full bg-danger-muted px-2 py-0.5 text-[11px] font-semibold text-white"
                    title="Listed on a known-exploited catalog (CISA KEV / ENISA EUVD) — exploitation in the wild is documented"
                  >
                    <Flame class="h-3 w-3" />
                    exploited
                  </span>
                  <RouterLink
                    v-if="vulnerability.fixed_in_prs?.length"
                    :to="{ name: 'repo-compare', params: { provider, slug, repoSlug }, query: { head: vulnerability.fixed_in_prs[0].ref_name } }"
                    class="ml-1 inline-flex items-center gap-0.5 whitespace-nowrap rounded-full border border-emerald-500/30 bg-emerald-500/10 px-2 py-0.5 text-[11px] text-emerald-300 transition hover:bg-emerald-500/20"
                    :title="fixChipTitle(vulnerability)"
                    @click.stop
                  >
                    ⤴ fix in #{{ vulnerability.fixed_in_prs[0].number }}<template v-if="vulnerability.fixed_in_prs.length > 1">
                      +{{ vulnerability.fixed_in_prs.length - 1 }}
                    </template>
                  </RouterLink>
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
                    class="relative flex"
                  >
                    <button
                      type="button"
                      class="whitespace-nowrap rounded-l-lg border border-surface-border px-2 py-1 text-[11px] text-gray-300 transition hover:border-accent/50 hover:text-white"
                      title="Real, but deliberately not fixing now. Requires a reason; suppressed from the gate."
                      @click.stop="openTriageDialog('risk_accepted', [vulnerability.fingerprint], vulnerability)"
                    >
                      Accept
                    </button>
                    <button
                      type="button"
                      class="rounded-r-lg border border-l-0 border-surface-border px-1.5 py-1 text-[11px] text-gray-300 transition hover:border-accent/50 hover:text-white"
                      aria-label="More accept options"
                      @click.stop="rowMenuFor = rowMenuFor === vulnerability.id ? '' : vulnerability.id"
                    >
                      ▾
                    </button>
                    <!-- The menu holds only the ALTERNATIVES: the main button
                         already is "accept risk", repeating it here read as
                         two different actions. -->
                    <div
                      v-if="rowMenuFor === vulnerability.id"
                      class="absolute right-0 top-full z-20 mt-1 w-44 overflow-hidden rounded-md border border-surface-border bg-surface-raised shadow-xl"
                    >
                      <button
                        type="button"
                        class="block w-full px-3 py-1.5 text-left text-[11px] text-gray-200 transition hover:bg-surface-overlay"
                        title="Not a real issue: excluded from the gate and from risk reporting."
                        @click.stop="rowMenuFor = ''; openTriageDialog('false_positive', [vulnerability.fingerprint], vulnerability)"
                      >
                        False positive…
                      </button>
                      <button
                        v-if="vulnerability.type === 'secret'"
                        type="button"
                        class="block w-full border-t border-surface-border-subtle px-3 py-1.5 text-left text-[11px] text-emerald-300 transition hover:bg-surface-overlay"
                        title="Attest that the credential was revoked and rotated — the only way a secret resolves"
                        @click.stop="rowMenuFor = ''; markSecretRevoked(vulnerability)"
                      >
                        Mark revoked…
                      </button>
                    </div>
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

import { Biohazard, KeyRound, Flame } from 'lucide-vue-next'

import { api, type AcceptanceReasonKind, type FindingAcceptance, type FindingDispute, type ScanRule, type SecretScanJob, type VexJustification, type Vulnerability, type VulnerabilityFacets } from '@/api/client'
import { useDialog } from '@/composables/useDialog'
import FilterBar from '@/components/FilterBar.vue'
import FindingOriginBadge from '@/components/FindingOriginBadge.vue'
import LinkedText from '@/components/LinkedText.vue'
import TriageDialog from '@/components/TriageDialog.vue'
import FindingDetailModal from '@/components/FindingDetailModal.vue'
import { triageState } from '@/lib/triage'

const { promptDialog } = useDialog()
const route = useRoute()
const router = useRouter()

const provider = computed(() => route.params.provider as string)
const slug = computed(() => route.params.slug as string)
const repoSlug = computed(() => route.params.repoSlug as string)

const vulnerabilities = ref<Vulnerability[]>([])

// Exploited-only is a SERVER-side facet (the list is paginated; a client-side
// filter rendered empty pages) and lives in the URL so a filtered view can be
// bookmarked/shared, like ref and snapshot.
const exploitedOnly = ref(route.query.exploited === 'true')
function toggleExploitedOnly() {
  exploitedOnly.value = !exploitedOnly.value
  pagination.value.page = 1
  void router.replace({ query: { ...route.query, exploited: exploitedOnly.value ? 'true' : undefined } })
}

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

const loading = ref(true)
const activeFilters = ref<Record<string, string>>({ status: 'detected' })
const searchQuery = ref('')
// Non-empty while the filter bar holds an OR/parenthesised query (ADR-023
// filterquery grammar); sent verbatim as `q`, superseding discrete params.
const advancedQuery = ref('')
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
const statusOptions = ['detected', 'resolved', 'suppressed']
// Build Sources/File option lists from the facet keys (full result set) merged
// with what's been seen on loaded pages, so options aren't limited to the
// current page. Order by descending count, then alphabetically.
const toolOptions = computed(() => mergeFacetOptions(facetCounts.value.tool, seenTools.value))
const fileOptions = computed(() => mergeFacetOptions(facetCounts.value.file, seenFiles.value))
// 'disputed' is deliberately last: it lives on the dispute axis (ADR-026),
// not the acceptance one — position separates it from the acceptance states.
const acceptanceOptions = ['open', 'accepted', 'risk_accepted', 'false_positive', 'disputed']
const filterDefs = computed(() => [
  { key: 'status', label: 'Status', options: statusOptions, multi: true, primary: true, hidden: true, defaultValue: 'detected' },
  { key: 'type', label: 'Type', options: typeOptions, multi: true },
  { key: 'severity', label: 'Severity', options: severityOptions, multi: true },
  { key: 'acceptance', label: 'Triage', options: acceptanceOptions },
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
const filterKeys = ['type', 'severity', 'status', 'acceptance', 'tool', 'file'] as const
const managedQueryKeys = [...filterKeys, 'search', 'sort', 'order', 'page'] as const
const sortKeys = new Set(sortOptions.map((option) => option.key))
const sortDirectionKeys = new Set(sortDirectionOptions.map((option) => option.key))
const syncingFromRoute = ref(false)
const hasActiveFilters = computed(() => Object.values(activeFilters.value).some(Boolean) || searchQuery.value.trim().length > 0)
// Facets exclude each dimension's own filter, so with the default
// status=detected this is the open malware count for the whole snapshot.
const openMalwareCount = computed(() => facetCounts.value.type?.malware ?? 0)

function applyMalwareFilter() {
  activeFilters.value = { ...activeFilters.value, type: 'malware' }
}
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

async function loadVulnerabilities() {
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
        acceptance: activeFilters.value.acceptance || undefined,
        exploited: exploitedOnly.value || undefined,
        // An OR/parenthesised bar query runs as the server-side filterquery;
        // the server uses it exclusively when present.
        q: advancedQuery.value || undefined,
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
}

watch(
  [provider, slug, repoSlug, () => route.query.ref, () => route.query.snapshot, activeFilters, searchQuery, advancedQuery, exploitedOnly, currentSort, currentSortDirection, () => pagination.value.page],
  () => { void loadVulnerabilities() },
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
        acceptance: activeFilters.value.acceptance || undefined,
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
  const filters: Record<string, string> = { status: 'detected' }

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
    if (value && !(key === 'status' && value === 'detected')) {
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
  const normalized: Record<string, string> = { status: filters.status || 'detected' }

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

// ADR-023: the acceptance projection is joined server-side onto every row —
// no second request, no client-side join, and filters like acceptance:fp are
// real SQL predicates.
function acceptanceFor(vulnerability: Vulnerability): FindingAcceptance | undefined {
  return vulnerability.acceptance
}

// ─── Triage: one decision, one reason, any number of findings ────────────────
// Batch-first by design: the flow is filter → select all shown → decide once.
// Reasons are typed in a real dialog (a window.prompt lost the text on any
// error and could not offer presets or an expiry).

const selected = reactive(new Set<string>())
// Targets are fingerprints, not row objects: a filter-wide selection includes
// findings that are not on the current page, and keying off rows would have
// silently triaged only the visible subset.
const dialog = ref<{ kind: AcceptanceReasonKind; fingerprints: string[]; componentBacked: boolean; vulnID?: string; exploited?: boolean } | null>(null)

// ── Finding detail drawer: deep-linkable (?finding=<fingerprint>) so
// notifications, gate comments, and search can land on it open.
const drawerFingerprint = ref('')

function openDrawer(fingerprint: string) {
  if (!fingerprint) return
  drawerFingerprint.value = fingerprint
  void router.replace({ query: { ...route.query, finding: fingerprint } })
}

function closeDrawer() {
  drawerFingerprint.value = ''
  const next = { ...route.query }
  delete next.finding
  void router.replace({ query: next })
}

// j/k walks the loaded list while the drawer is open.
function navigateDrawer(delta: number) {
  const list = vulnerabilities.value
  const index = list.findIndex((vulnerability) => vulnerability.fingerprint === drawerFingerprint.value)
  const next = list[index + delta]
  if (next?.fingerprint) openDrawer(next.fingerprint)
}

watch(
  () => route.query.finding,
  (finding) => {
    drawerFingerprint.value = typeof finding === 'string' ? finding : ''
  },
  { immediate: true },
)
const bulkMenuOpen = ref(false)
const rowMenuFor = ref('')
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

function openTriageDialog(kind: AcceptanceReasonKind, fingerprints: string[], vulnerability?: Vulnerability, exploited?: boolean) {
  const unique = [...new Set(fingerprints.filter(Boolean))]
  if (unique.length === 0) return
  dialogError.value = ''
  batchMessage.value = ''
  dialog.value = {
    kind,
    fingerprints: unique,
    // VEX vocabulary only for a single component-backed finding — batch
    // decisions never carry per-component statements.
    componentBacked: unique.length === 1 && !!vulnerability && (vulnerability.type === 'dependency' || vulnerability.type === 'container'),
    vulnID: unique.length === 1 ? vulnerability?.id : undefined,
    // Only the drawer knows the advisory is KEV-listed (the flag lives on the
    // loaded detail, not on list rows); batch decisions never carry it.
    exploited: unique.length === 1 && exploited === true,
  }
}

function closeTriageDialog() {
  dialog.value = null
  dialogError.value = ''
  dialogSubmitting.value = false
}

async function confirmTriageDialog(payload: { reason: string; labels: string[]; vexJustification?: VexJustification; expiresAt?: string }) {
  if (!dialog.value) return
  const { kind, fingerprints, vulnID } = dialog.value
  dialogSubmitting.value = true
  dialogError.value = ''
  try {
    if (vulnID && payload.vexJustification) {
      // Single finding with a VEX justification goes through the per-finding
      // endpoint — the batch endpoint deliberately rejects VEX vocabulary.
      await api.setFindingAcceptance(provider.value, slug.value, repoSlug.value, vulnID, {
        status: 'accepted',
        reason_kind: kind,
        reason: payload.reason,
        labels: payload.labels,
        vex_justification: payload.vexJustification,
        expires_at: payload.expiresAt,
      })
    } else {
      await applyTriage('accepted', fingerprints, payload.reason, payload.expiresAt, kind, payload.labels)
    }
    patchRowsAfterTriage(fingerprints, {
      reason_kind: kind,
      reason: payload.reason,
      labels: payload.labels,
      vex_justification: payload.vexJustification,
      expires_at: payload.expiresAt,
      created_at: new Date().toISOString(),
    })
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
    patchRowsAfterTriage(unique, undefined)
    batchMessage.value = `${unique.length} ${unique.length === 1 ? 'finding' : 'findings'} reopened.`
    clearSelection()
  } catch (error) {
    batchMessage.value = ''
    secretScanError.value = error instanceof Error ? error.message : 'Failed to reopen findings'
  }
}

// One finding still goes through the batch endpoint: same validation, same audit
// shape, one code path to keep correct.
async function applyTriage(status: 'accepted' | 'open', fingerprints: string[], reason: string, expiresAt?: string, reasonKind?: AcceptanceReasonKind, labels?: string[]) {
  if (fingerprints.length === 0) return
  await api.batchFindingAcceptance(provider.value, slug.value, repoSlug.value, {
    fingerprints,
    status,
    reason_kind: reasonKind,
    reason: reason || undefined,
    labels,
    expires_at: expiresAt,
  })
}

// ADR-023 UX: accept/reopen patch the rows in place — no list refetch. The one
// exception is an active acceptance filter, where the decision changes which
// rows match, so the page must be requeried.
function patchRowsAfterTriage(fingerprints: string[], acceptance: FindingAcceptance | undefined) {
  if (activeFilters.value.acceptance) {
    void loadVulnerabilities()
    return
  }
  const affected = new Set(fingerprints)
  vulnerabilities.value = vulnerabilities.value.map((vulnerability) =>
    affected.has(vulnerability.fingerprint) ? { ...vulnerability, acceptance } : vulnerability,
  )
}

// The modal writes the dispute itself (ADR-026); this only keeps the row's
// badge honest without a refetch.
function applyDisputeToRows(fingerprint: string, dispute: FindingDispute | null) {
  vulnerabilities.value = vulnerabilities.value.map((vulnerability) =>
    vulnerability.fingerprint === fingerprint ? { ...vulnerability, dispute: dispute ?? undefined } : vulnerability,
  )
}

async function markSecretRevoked(vulnerability: Vulnerability) {
  const comment = await promptDialog({
    title: 'Attest secret revocation',
    message: 'Recorded in the audit log.',
    confirmLabel: 'Mark revoked',
    input: { label: 'How was this secret revoked/rotated?' },
  })
  if (comment === null) return
  batchMessage.value = ''
  try {
    await api.attestSecretRevocation(provider.value, slug.value, repoSlug.value, vulnerability.id, comment)
    batchMessage.value = 'Secret marked revoked.'
    vulnerabilities.value = vulnerabilities.value.map((row) =>
      row.id === vulnerability.id ? { ...row, status: 'resolved' } : row,
    )
  } catch (error) {
    secretScanError.value = error instanceof Error ? error.message : 'Failed to record revocation'
  }
}

// One chip, +N when several PRs resolve it; the tooltip lists them. Good
// news, not an alarm — it changes the decision ("merge #12, don't accept").
function fixChipTitle(vulnerability: Vulnerability): string {
  const fixes = vulnerability.fixed_in_prs ?? []
  // "Resolved when merged" is what the delta asserts — "already fixed" is
  // not: nothing is fixed until a merge happens (PLAN §5). Capped: a tooltip
  // listing 7 PRs is noise.
  const shown = fixes.slice(0, 3).map((fix) => `#${fix.number}${fix.title ? ' ' + fix.title : ''}`)
  const more = fixes.length > shown.length ? ` (+${fixes.length - shown.length} more)` : ''
  const base = fixes[0]?.verified_base_sha
  const verified = base ? ` — verified against ${base.slice(0, 8)}` : ''
  return 'Resolved when merged: ' + shown.join(', ') + more + verified
}

function triageFor(vulnerability: Vulnerability) {
  return triageState(vulnerability, acceptanceFor(vulnerability), new Date(), vulnerability.dispute)
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
