<template>
  <div class="space-y-4">
    <button
      v-if="orgMalwareOpen > 0 && activeFilters.type !== 'malware'"
      type="button"
      class="flex w-full items-center gap-2.5 rounded-xl border border-danger/50 bg-danger/10 px-4 py-3 text-left transition hover:border-danger"
      @click="applyMalwareFilter"
    >
      <Biohazard class="h-5 w-5 shrink-0 text-danger" />
      <span class="text-sm font-semibold text-red-200">
        {{ orgMalwareOpen }} malware {{ orgMalwareOpen === 1 ? 'finding' : 'findings' }} across this organization — review immediately
      </span>
      <span class="ml-auto text-xs text-red-300/80">Show only malware →</span>
    </button>

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
    >
      <template #trailing>
        <button
          type="button"
          class="inline-flex items-center gap-1.5 rounded-md border px-3 py-1.5 text-sm transition"
          :class="exploitedOnly ? 'border-danger/60 bg-danger/10 text-danger' : 'border-surface-border text-gray-400 hover:border-danger/50 hover:text-danger'"
          title="Only findings whose advisory is on a known-exploited catalog (CISA KEV / ENISA EUVD)"
          @click="toggleExploitedOnly"
        >
          <Flame class="h-3.5 w-3.5" />
          Exploited
        </button>
      </template>
    </FilterBar>

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
                @click="openDrawer(vulnerability)"
              >
                <td class="px-3 py-2.5">
                  <span :class="severityClass(vulnerability.severity)">{{ vulnerability.severity }}</span>
                  <span
                    v-if="vulnerability.kev"
                    class="ml-1 inline-flex items-center gap-1 rounded-full bg-danger-muted px-2 py-0.5 text-[11px] font-semibold text-white"
                    title="Listed on a known-exploited catalog (CISA KEV / ENISA EUVD) — exploitation in the wild is documented"
                  >
                    <Flame class="h-3 w-3" />
                    exploited
                  </span>
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
                  <span class="rounded-full bg-surface-overlay px-2 py-0.5 text-xs text-gray-300">{{ vulnerability.type }}</span>
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
                </td>
                <td class="px-3 py-2.5 text-gray-400">
                  <div class="flex items-center gap-1.5">
                    <span>{{ vulnerability.scanner_name || 'n/a' }}</span>
                    <FindingOriginBadge :finding="vulnerability" />
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
import { Flame, Biohazard } from 'lucide-vue-next'
import { computed, inject, ref, watch, type Ref } from 'vue'
import { RouterLink, useRoute, useRouter } from 'vue-router'

import { api, type AcceptanceReasonKind, type FindingAcceptance, type OrgDashboard, type OrgVulnerability, type VexJustification, type Vulnerability } from '@/api/client'
import FilterBar from '@/components/FilterBar.vue'
import FindingDetailModal from '@/components/FindingDetailModal.vue'
import FindingOriginBadge from '@/components/FindingOriginBadge.vue'
import LinkedText from '@/components/LinkedText.vue'
import TriageDialog from '@/components/TriageDialog.vue'
import { useToast } from '@/composables/useToast'
import { useDialog } from '@/composables/useDialog'
import { isComponentBacked } from '@/lib/findingDisplay'

const { promptDialog } = useDialog()
const route = useRoute()
const router = useRouter()
const { pushToast } = useToast()
const provider = computed(() => route.params.provider as string)
const slug = computed(() => route.params.slug as string)

// Server-side facet (SQL EXISTS against the exploited catalogs): this view is
// paginated in SQL, so the filter cannot be client-side. URL-synced so a
// filtered view can be bookmarked.
const exploitedOnly = ref(route.query.exploited === 'true')
function toggleExploitedOnly() {
  exploitedOnly.value = !exploitedOnly.value
  pagination.value.page = 1
  void router.replace({ query: { ...route.query, exploited: exploitedOnly.value ? 'true' : undefined } })
}
const vulnerabilities = ref<OrgVulnerability[]>([])
const loading = ref(true)
const activeFilters = ref<Record<string, string>>({ status: 'detected' })
const searchQuery = ref('')
const currentSort = ref('severity')
const currentSortDirection = ref('desc')
const pagination = ref({ page: 1, per_page: 50, total: 0 })
const seenTools = ref<Set<string>>(new Set())

const typeOptions = ['dependency', 'sast', 'secret', 'malware', 'dast', 'container', 'fuzzing', 'manual', 'generic']
const severityOptions = ['critical', 'high', 'medium', 'low', 'info']
const statusOptions = ['detected', 'resolved', 'suppressed']
const toolOptions = computed(() => Array.from(seenTools.value).sort())
const filterDefs = computed(() => [
  { key: 'status', label: 'Status', options: statusOptions, multi: true, primary: true, hidden: true, defaultValue: 'detected' },
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

const hasActiveFilters = computed(() => Object.entries(activeFilters.value).some(([key, value]) => Boolean(value) && !(key === 'status' && value === 'detected')) || searchQuery.value.trim().length > 0)
const orgDashboard = inject<Ref<OrgDashboard | null>>('orgDashboard', ref(null))
const orgMalwareOpen = computed(() => orgDashboard.value?.totals.malware_open ?? 0)

function applyMalwareFilter() {
  activeFilters.value = { ...activeFilters.value, type: 'malware' }
}
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
  [provider, slug, activeFilters, searchQuery, currentSort, currentSortDirection, exploitedOnly, () => pagination.value.page],
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
        exploited: exploitedOnly.value || undefined,
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
    low: 'rounded-full bg-gray-500/15 px-2.5 py-1 text-xs font-medium text-gray-400',
    info: 'rounded-full bg-blue-500/15 px-2.5 py-1 text-xs font-medium text-blue-400',
  }
  return classes[level.toLowerCase()] || classes.info
}

function formatDetected(value: string) {
  return new Intl.DateTimeFormat('en', { dateStyle: 'medium' }).format(new Date(value))
}
</script>
