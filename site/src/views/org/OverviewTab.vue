<template>
  <div class="space-y-5">
    <div
      v-if="!dashboard"
      class="rounded-xl border border-dashed border-surface-border bg-surface-overlay/40 px-5 py-12 text-center text-sm text-gray-400"
    >
      No organization data available.
    </div>

    <template v-else>
      <ScaActionResults
        :provider="provider"
        :slug="slug"
        :results="scaResults"
        :error="scaError"
        @dismiss="dismissSca"
      />
      <RouterLink
        v-if="malwareOpen > 0"
        :to="{ name: 'org-vulnerabilities', params: route.params, query: { q: OPEN_RISK_MALWARE_QUERY } }"
        class="flex items-center gap-2.5 rounded-xl border border-malware/60 bg-malware/10 px-4 py-3 transition hover:border-malware"
      >
        <MalwareIcon />
        <span class="text-sm font-semibold text-violet-100">
          {{ malwareOpen }} malicious {{ malwareOpen === 1 ? 'package' : 'packages' }} detected in {{ malwareRepoCount }} {{ malwareRepoCount === 1 ? 'repository' : 'repositories' }}
        </span>
        <span class="ml-auto text-xs text-violet-200/80">Review immediately →</span>
      </RouterLink>

      <RouterLink
        v-if="kevOpen !== null"
        :to="kevLink()"
        class="flex flex-wrap items-center gap-2.5 border-l-2 px-4 py-3 transition hover:bg-surface-overlay"
        :class="kevOpen > 0 ? 'border-danger/60 bg-danger/5' : 'border-surface-border bg-surface-overlay/30'"
        title="Known exploited vulnerabilities"
      >
        <Flame
          class="h-5 w-5 shrink-0"
          :class="kevOpen > 0 ? 'text-danger' : 'text-gray-500'"
        />
        <span class="text-sm font-semibold text-gray-200">
          {{ kevOpen }} known exploited {{ kevOpen === 1 ? 'vulnerability' : 'vulnerabilities' }} across {{ kevRepoCount }} {{ kevRepoCount === 1 ? 'repository' : 'repositories' }}
        </span>
        <span class="ml-auto text-xs text-accent">View findings</span>
      </RouterLink>
      <p
        v-else-if="kevOpen === null"
        class="text-xs text-gray-500"
      >
        <RouterLink
          v-if="knownKEVOpen > 0"
          :to="kevLink()"
          class="font-medium text-danger hover:underline"
        >
          At least {{ knownKEVOpen }} known exploited
        </RouterLink>
        <span v-else>Known exploited status unavailable</span>
        <span v-if="kevUnavailableRepos > 0"> · {{ kevUnavailableRepos }} {{ kevUnavailableRepos === 1 ? 'repository' : 'repositories' }} without KEV evidence</span>
      </p>

      <!-- Severity rollup + coverage tiles -->
      <div class="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
        <div class="rounded-xl border border-surface-border bg-surface-raised/40 p-4 sm:col-span-2">
          <div class="flex items-center justify-between">
            <h2 class="flex items-center gap-2 text-sm font-semibold text-white">
              <ShieldAlert class="h-4 w-4 text-gray-500" />
              Open vulnerabilities
            </h2>
            <RouterLink
              :to="{ name: 'org-vulnerabilities', params: route.params }"
              class="text-xs font-medium text-accent hover:text-accent-hover"
            >
              View all →
            </RouterLink>
          </div>
          <div class="mt-2 flex items-end gap-2">
            <span class="text-3xl font-semibold text-white">{{ !hasAnalysisEvidence && totalVulnerabilities === 0 ? 'Not reported' : totalVulnerabilities }}</span>
            <span class="pb-1 text-sm text-gray-400">known across {{ dashboard.totals.components_total }} components</span>
          </div>
          <div class="mt-3 flex flex-wrap gap-2">
            <span
              v-for="item in severityItems"
              :key="item.key"
              :class="severityBadgeClass(item.key)"
            >{{ item.value }} {{ item.key }}</span>
            <span
              v-if="severityItems.length === 0"
              class="text-xs text-gray-500"
            >{{ !hasAnalysisEvidence ? 'No dependency analysis reported' : 'No known open vulnerabilities in available analysis' }}</span>
          </div>
          <p class="mt-2 text-xs text-gray-400">
            {{ inventoryCount }} with inventory · {{ findingsOnlyCount }} findings only · {{ withoutInventoryCount }} without inventory.
            <span v-if="unknownInventoryCount > 0">{{ unknownInventoryCount }} status unavailable.</span>
          </p>
        </div>

        <div
          v-for="item in coverageCards"
          :key="item.label"
          class="rounded-xl border border-surface-border bg-surface-raised/40 p-4"
        >
          <div class="text-[11px] uppercase tracking-[0.16em] text-gray-500">
            {{ item.label }}
          </div>
          <div class="mt-2 text-2xl font-semibold text-white">
            {{ item.value }}
          </div>
        </div>
      </div>

      <!-- Per-repo breakdown -->
      <section class="overflow-hidden rounded-xl border border-surface-border">
        <div class="flex items-center justify-between border-b border-surface-border-subtle px-4 py-3">
          <h2 class="text-sm font-semibold text-white">
            Repositories
          </h2>
          <span class="text-xs text-gray-500">{{ dashboard.repos.length }} total</span>
        </div>

        <div
          v-if="dashboard.coverage.total_accessible === 0"
          class="px-4 py-10 text-sm text-gray-500"
        >
          No repositories discovered yet.
        </div>
        <div
          v-else
          class="min-w-0"
        >
          <table class="block w-full divide-y divide-surface-border-subtle text-sm lg:table">
            <caption class="block border-b border-surface-border-subtle px-4 py-2 text-left text-xs leading-relaxed text-gray-500 lg:table-caption">
              Counts reflect the latest available analysis, not necessarily the current commit or complete shipped inventory.
              Inventory source describes provenance; Last analysis shows freshness.
            </caption>
            <thead class="hidden bg-surface-overlay text-left text-[11px] uppercase tracking-[0.12em] text-gray-500 lg:table-header-group">
              <tr>
                <th class="w-52 px-3 py-2.5 font-medium">
                  Repository
                </th>
                <th class="hidden w-24 px-3 py-2.5 font-medium xl:table-cell">
                  Status
                </th>
                <th class="hidden px-3 py-2.5 font-medium xl:table-cell">
                  Inventory
                </th>
                <th class="w-[45%] px-3 py-2.5 font-medium">
                  Vulnerabilities
                </th>
                <th class="w-20 px-2 py-2.5 font-medium">
                  Components
                </th>
                <th class="w-24 px-2 py-2.5 font-medium">
                  Last analysis
                </th>
              </tr>
            </thead>
            <tbody class="block divide-y divide-surface-border-subtle lg:table-row-group">
              <tr
                v-for="entry in sortedRepos"
                :key="repoEntryKey(entry)"
                class="grid grid-cols-2 transition hover:bg-white/5 lg:table-row"
              >
                <td class="col-span-2 block px-3 py-3 lg:table-cell">
                  <component
                    :is="entry.enrolled && entry.repo_slug ? 'RouterLink' : 'div'"
                    :to="entry.enrolled && entry.repo_slug ? `/orgs/${provider}/${slug}/repos/${entry.repo_slug}` : undefined"
                    class="flex min-w-0 items-center gap-2.5"
                    :class="entry.enrolled && entry.repo_slug ? 'text-white transition hover:text-accent' : 'text-white'"
                  >
                    <ForgeIcon
                      :provider="entry.provider"
                      size="sm"
                      class="text-gray-400"
                    />
                    <div class="min-w-0 max-w-full lg:max-w-52">
                      <div
                        class="truncate font-medium"
                        :title="entry.repo_name"
                      >
                        {{ entry.repo_name }}
                      </div>
                      <div
                        class="truncate text-[11px] text-gray-500"
                        :title="entry.full_name || entry.provider_id"
                      >
                        {{ entry.full_name || entry.provider_id }}
                      </div>
                    </div>
                  </component>
                  <div class="mt-2 space-y-2 lg:max-w-52 xl:hidden">
                    <RepositoryIntegration :mode="entry.sca?.integration" />
                    <span
                      class="rounded-full border px-2 py-0.5 text-xs font-medium capitalize"
                      :class="statusClass(entry.status)"
                    >{{ entry.status }}</span>
                    <ScaStatus
                      compact
                      :sca="entry.sca"
                      :enrolled="entry.enrolled"
                      :can-manage="canManage"
                      :components="entry.components_total"
                      :findings="sumCounts(entry.vulnerabilities)"
                    />
                    <button
                      v-if="canManage && entryAction(entry)"
                      type="button"
                      class="rounded-lg border border-accent/40 px-2.5 py-1.5 text-xs text-accent disabled:cursor-not-allowed disabled:opacity-50"
                      :disabled="!canEnableSca(entry.status, entry.sca) || scaBusy.length > 0"
                      :title="entry.status === 'archived' ? 'Archived repositories cannot enable SCA' : 'Read default-branch manifests and lockfiles and match advisories; no workflow, upload, write permission or secret scan'"
                      @click="enableSca(entry)"
                    >
                      {{ scaBusy.includes(entry.provider_id) ? 'Requesting…' : entryAction(entry) }}
                    </button>
                  </div>
                </td>
                <td class="hidden whitespace-nowrap px-3 py-3 xl:table-cell">
                  <div class="flex flex-col items-start gap-1.5">
                    <RepositoryIntegration :mode="entry.sca?.integration" />
                    <span
                      class="rounded-full border px-2 py-0.5 text-xs font-medium capitalize"
                      :class="statusClass(entry.status)"
                    >{{ entry.status }}</span>
                  </div>
                </td>
                <td class="hidden px-3 py-3 xl:table-cell">
                  <ScaStatus
                    compact
                    :sca="entry.sca"
                    :enrolled="entry.enrolled"
                    :can-manage="canManage"
                    :components="entry.components_total"
                    :findings="sumCounts(entry.vulnerabilities)"
                  />
                  <button
                    v-if="canManage && entryAction(entry)"
                    type="button"
                    class="mt-2 rounded-lg border border-accent/40 px-2.5 py-1.5 text-xs text-accent disabled:cursor-not-allowed disabled:opacity-50"
                    :disabled="!canEnableSca(entry.status, entry.sca) || scaBusy.length > 0"
                    :title="entry.status === 'archived' ? 'Archived repositories cannot enable SCA' : 'Read default-branch manifests and lockfiles and match advisories; no workflow, upload, write permission or secret scan'"
                    @click="enableSca(entry)"
                  >
                    {{ scaBusy.includes(entry.provider_id) ? 'Requesting…' : entryAction(entry) }}
                  </button>
                </td>
                <td class="col-span-2 block px-3 py-3 lg:table-cell">
                  <p class="mb-1.5 text-[10px] uppercase tracking-[0.12em] text-gray-500 lg:hidden">
                    Vulnerabilities
                  </p>
                  <div
                    class="flex flex-wrap items-center gap-1 whitespace-nowrap sm:flex-nowrap [&>*]:shrink-0"
                    data-testid="repository-vulnerability-badges"
                  >
                    <!-- Malware first: it outranks every other chip in the row. -->
                    <component
                      :is="entry.enrolled && entry.repo_slug ? RouterLink : 'span'"
                      v-if="entry.malware_open > 0"
                      :to="entry.repo_slug ? repoVulnerabilities(entry.repo_slug, OPEN_RISK_MALWARE_QUERY) : undefined"
                      class="inline-flex items-center gap-1 rounded border border-malware/60 bg-malware/10 px-2 py-0.5 text-xs font-semibold text-malware hover:underline"
                    >
                      <MalwareIcon size="sm" />
                      {{ entry.malware_open }} malware
                    </component>
                    <RouterLink
                      v-if="entry.enrolled && entry.repo_slug && entry.kev_open != null"
                      :to="{ name: 'repo-vulnerabilities', params: { provider, slug, repoSlug: entry.repo_slug }, query: { q: OPEN_RISK_KEV_QUERY } }"
                      class="inline-flex items-center gap-1 rounded border px-2 py-0.5 text-xs hover:underline"
                      :class="entry.kev_open > 0 ? 'border-danger/60 bg-danger/10 font-semibold text-danger' : 'border-transparent text-gray-500'"
                    >
                      <Flame class="h-3 w-3" />
                      {{ entry.kev_open }} exploited
                    </RouterLink>
                    <component
                      :is="entry.enrolled && entry.repo_slug ? RouterLink : 'span'"
                      v-for="item in toSeverityItems(entry.vulnerabilities)"
                      :key="`${repoEntryKey(entry)}-${item.key}`"
                      :to="entry.repo_slug ? repoVulnerabilities(entry.repo_slug, openRiskSeverityQuery(item.key)) : undefined"
                      :class="[severityBadgeClass(item.key), 'shrink-0 whitespace-nowrap transition hover:brightness-125']"
                      :title="`Open the ${item.value} open ${item.key} findings`"
                    >
                      {{ item.value }} {{ item.key }}
                    </component>
                    <span
                      v-if="toSeverityItems(entry.vulnerabilities).length === 0"
                      class="text-gray-500"
                    >{{ scaAssessed(entry.sca) ? entry.sca?.state === 'partial' ? '0 known · partial' : '0 known' : entry.sca ? 'Not assessed' : 'Not reported' }}</span>
                  </div>
                </td>
                <td class="block px-2 py-3 text-xs text-gray-300 lg:table-cell lg:whitespace-nowrap">
                  <span class="mb-1 block text-[10px] uppercase tracking-[0.12em] text-gray-500 lg:hidden">Components</span>
                  {{ hasInventory(entry.sca, entry.components_total) ? entry.components_total : 'Not reported' }}
                </td>
                <td class="block px-2 py-3 text-right text-xs text-gray-400 lg:table-cell lg:whitespace-nowrap lg:text-left">
                  <span class="mb-1 block text-[10px] uppercase tracking-[0.12em] text-gray-500 lg:hidden">Last analysis</span>
                  <div>{{ formatDate(entry.sca?.last_assessed || entry.last_scanned) }}</div>
                  <div
                    v-if="entry.sca?.state === 'outdated' || (entry.sca?.previous_results && entry.sca.has_inventory === false) || entry.outdated"
                    class="mt-0.5 text-xs text-gray-500"
                  >
                    {{ entry.sca?.state === 'outdated' || (entry.sca?.previous_results && entry.sca.has_inventory === false) ? 'Previous commit' : 'Out of date' }}
                  </div>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </section>
    </template>
  </div>
</template>

<script setup lang="ts">
import { Flame, ShieldAlert } from 'lucide-vue-next'
import { computed, inject, onUnmounted, ref, watch, type Ref } from 'vue'
import { RouterLink, useRoute } from 'vue-router'

import { api, type Organization, type OrgDashboard, type RepoDashboardEntry, type RepoLifecycleStatus, type SeverityCounts } from '@/api/client'
import ForgeIcon from '@/components/ForgeIcon.vue'
import ScaStatus from '@/components/ScaStatus.vue'
import ScaActionResults from '@/components/ScaActionResults.vue'
import { useScaActions, useScaPolling } from '@/composables/useScaActions'
import { canEnableSca, hasInventory, hasReportedFindings, scaAction, scaAssessed, scaErrorMessage, scaPending, scaResultCoverage } from '@/lib/sca'
import RepositoryIntegration from '@/components/RepositoryIntegration.vue'
import { severityBadgeClass } from '@/lib/findingDisplay'
import { OPEN_RISK_KEV_QUERY, OPEN_RISK_MALWARE_QUERY, openRiskSeverityQuery } from '@/lib/openRiskPreset'
import MalwareIcon from '@/components/finding/MalwareIcon.vue'

const route = useRoute()
const provider = computed(() => route.params.provider as string)
const slug = computed(() => route.params.slug as string)

const dashboard = inject<Ref<OrgDashboard | null>>('orgDashboard', ref(null))
const org = inject<Ref<Organization | null>>('org', ref(null))
const canManage = computed(() => org.value?.provider === provider.value && org.value?.slug === slug.value && org.value?.role === 'admin')
const { pending: scaBusy, results: scaResults, error: scaError, enable, dismiss: dismissSca } = useScaActions(provider, slug)
const scope = computed(() => `${provider.value}/${slug.value}`)
let generation = 0
watch(scope, () => { generation++ })
onUnmounted(() => { generation++ })
useScaPolling(scope, computed(() => dashboard.value?.repos.some(entry => scaPending(entry.sca)) ?? false), refreshDashboard, error => { scaError.value = scaErrorMessage(error) })

async function refreshDashboard() {
  const request = generation
  const response = await api.getOrgDashboard(provider.value, slug.value)
  if (request === generation) dashboard.value = response.data
}

async function enableSca(entry: RepoDashboardEntry) {
  if (!canManage.value || !entryAction(entry) || !canEnableSca(entry.status, entry.sca)) return
  const request = generation
  const results = await enable([entry.provider_id])
  if (!results) return
  const result = results[0]
  if (result && result.status !== 'failed') {
    entry.enrolled = true
    entry.repo_slug = result.repo_slug || entry.repo_slug
    entry.sca = scaResultCoverage(result, entry.sca)
  }
  await refreshDashboard().catch(error => {
    if (request === generation) scaError.value = `Request recorded, but the latest status could not be loaded. ${scaErrorMessage(error)}`
  })
}

function entryAction(entry: RepoDashboardEntry) {
  return scaAction(entry.enrolled, entry.sca, entry.components_total, sumCounts(entry.vulnerabilities))
}
const inventoryCount = computed(() => dashboard.value?.repos.filter(entry => hasInventory(entry.sca, entry.components_total)).length ?? 0)
const findingsOnlyCount = computed(() => dashboard.value?.repos.filter(entry => !hasInventory(entry.sca, entry.components_total) && hasReportedFindings(entry.sca, sumCounts(entry.vulnerabilities))).length ?? 0)
const unknownInventoryCount = computed(() => (dashboard.value?.repos ?? []).filter(entry => !entry.sca && !hasInventory(entry.sca, entry.components_total) && !hasReportedFindings(entry.sca, sumCounts(entry.vulnerabilities))).length)
const withoutInventoryCount = computed(() => (dashboard.value?.repos.length ?? 0) - inventoryCount.value - findingsOnlyCount.value - unknownInventoryCount.value)
const hasAnalysisEvidence = computed(() => (dashboard.value?.repos ?? []).some(entry => scaAssessed(entry.sca) || hasReportedFindings(entry.sca, sumCounts(entry.vulnerabilities))))

const severityOrder: Array<keyof SeverityCounts> = ['critical', 'high', 'medium', 'unknown', 'low', 'info']
const severityRank: Record<string, number> = { critical: 6, high: 5, medium: 4, unknown: 3, low: 2, info: 1 }

const severityItems = computed(() => toSeverityItems(dashboard.value?.totals.vulnerabilities))
const totalVulnerabilities = computed(() => sumCounts(dashboard.value?.totals.vulnerabilities))
const malwareOpen = computed(() => dashboard.value?.totals.malware_open ?? 0)
const malwareRepoCount = computed(() => (dashboard.value?.repos ?? []).filter((entry) => entry.malware_open > 0).length)
const kevOpen = computed(() => dashboard.value?.totals.kev_open ?? null)
const knownKEVOpen = computed(() => (dashboard.value?.repos ?? []).reduce((total, entry) => total + (entry.kev_open ?? 0), 0))
const kevUnavailableRepos = computed(() => (dashboard.value?.repos ?? []).filter(entry => entry.enrolled && entry.kev_open == null).length)
const kevRepoCount = computed(() => (dashboard.value?.repos ?? []).filter((entry) => (entry.kev_open ?? 0) > 0).length)

const coverageCards = computed(() => {
  const coverage = dashboard.value?.coverage
  return [
    { label: 'Active', value: coverage?.active ?? 0 },
    { label: 'Discovered', value: coverage?.discovered ?? 0 },
    { label: 'Out of date', value: coverage?.outdated ?? 0 },
    { label: 'Inventory available', value: inventoryCount.value },
    { label: 'Findings only', value: findingsOnlyCount.value },
    { label: 'No inventory', value: withoutInventoryCount.value },
    ...(unknownInventoryCount.value > 0 ? [{ label: 'Status unavailable', value: unknownInventoryCount.value }] : []),
  ]
})

const sortedRepos = computed(() => {
  const repos = [...(dashboard.value?.repos ?? [])]
  return repos.sort((a, b) => {
    if (a.malware_open !== b.malware_open) {
      return b.malware_open - a.malware_open
    }
    if ((a.kev_open ?? 0) !== (b.kev_open ?? 0)) {
      return (b.kev_open ?? 0) - (a.kev_open ?? 0)
    }
    return riskScore(b.vulnerabilities) - riskScore(a.vulnerabilities)
  })
})

function riskScore(counts?: SeverityCounts | null) {
  if (!counts) {
    return 0
  }
  return severityOrder.reduce((total, key) => total + (counts[key] ?? 0) * (severityRank[key] ?? 1), 0)
}

function toSeverityItems(counts?: SeverityCounts | null) {
  return severityOrder
    .map((key) => ({ key, value: counts?.[key] ?? 0 }))
    .filter((item) => item.value > 0)
}

function sumCounts(counts?: SeverityCounts | null) {
  return severityOrder.reduce((total, key) => total + (counts?.[key] ?? 0), 0)
}

// A repository's vulnerability list filtered to what one dashboard count
// counts, so clicking a number shows exactly those findings.
function repoVulnerabilities(repoSlug: string, q: string) {
  return { name: 'repo-vulnerabilities', params: { provider: provider.value, slug: slug.value, repoSlug }, query: { q } }
}

function kevLink() {
  return { name: 'org-vulnerabilities', params: route.params, query: { q: OPEN_RISK_KEV_QUERY } }
}

function statusClass(status: RepoLifecycleStatus) {
  switch (status) {
    case 'active':
      return 'border-emerald-500/30 bg-emerald-500/10 text-emerald-200'
    case 'archived':
      return 'border-gray-500/30 bg-white/5 text-gray-300'
    case 'deleted':
      return 'border-rose-500/30 bg-rose-500/10 text-rose-200'
    default:
      return 'border-blue-500/30 bg-blue-500/10 text-blue-200'
  }
}

function formatDate(value?: string) {
  return value ? new Date(value).toLocaleDateString() : 'Not recorded'
}

function repoEntryKey(entry: RepoDashboardEntry) {
  return entry.repo_id || entry.provider_id || entry.full_name || entry.repo_name
}
</script>
