<template>
  <div class="space-y-5">
    <div
      v-if="!dashboard"
      class="rounded-xl border border-dashed border-surface-border bg-surface-overlay/40 px-5 py-12 text-center text-sm text-gray-400"
    >
      No organization data available.
    </div>

    <template v-else>
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
            <span class="text-3xl font-semibold text-white">{{ totalVulnerabilities }}</span>
            <span class="pb-1 text-sm text-gray-400">across {{ dashboard.totals.components_total }} components</span>
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
            >No open vulnerabilities</span>
          </div>
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
          class="overflow-x-auto"
        >
          <table class="min-w-full divide-y divide-surface-border-subtle text-sm">
            <thead class="bg-surface-overlay text-left text-xs uppercase tracking-[0.16em] text-gray-500">
              <tr>
                <th class="px-4 py-2.5 font-medium">
                  Repository
                </th>
                <th class="px-4 py-2.5 font-medium">
                  Status
                </th>
                <th class="px-4 py-2.5 font-medium">
                  Vulnerabilities
                </th>
                <th class="px-4 py-2.5 font-medium">
                  Components
                </th>
                <th class="px-4 py-2.5 font-medium">
                  Last scan
                </th>
              </tr>
            </thead>
            <tbody class="divide-y divide-surface-border-subtle">
              <tr
                v-for="entry in sortedRepos"
                :key="repoEntryKey(entry)"
                class="transition hover:bg-white/5"
              >
                <td class="px-4 py-3">
                  <component
                    :is="entry.enrolled && entry.repo_slug ? 'RouterLink' : 'div'"
                    :to="entry.enrolled && entry.repo_slug ? `/orgs/${provider}/${slug}/repos/${entry.repo_slug}` : undefined"
                    class="flex items-center gap-2.5"
                    :class="entry.enrolled && entry.repo_slug ? 'text-white transition hover:text-accent' : 'text-white'"
                  >
                    <ForgeIcon
                      :provider="entry.provider"
                      size="sm"
                      class="text-gray-400"
                    />
                    <div>
                      <div class="font-medium">
                        {{ entry.repo_name }}
                      </div>
                      <div class="text-[11px] text-gray-500">
                        {{ entry.full_name || entry.provider_id }}
                      </div>
                    </div>
                  </component>
                </td>
                <td class="px-4 py-3">
                  <span
                    class="rounded-full border px-2 py-0.5 text-xs font-medium capitalize"
                    :class="statusClass(entry.status)"
                  >{{ entry.status }}</span>
                </td>
                <td class="px-4 py-3">
                  <div class="flex flex-wrap items-center gap-1.5">
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
                      :class="[severityBadgeClass(item.key), 'transition hover:brightness-125']"
                      :title="`Open the ${item.value} open ${item.key} findings`"
                    >
                      {{ item.value }} {{ item.key }}
                    </component>
                    <span
                      v-if="toSeverityItems(entry.vulnerabilities).length === 0"
                      class="text-gray-500"
                    >None</span>
                  </div>
                </td>
                <td class="px-4 py-3 text-gray-300">
                  {{ entry.components_total }}
                </td>
                <td class="px-4 py-3 text-gray-400">
                  <div>{{ formatDate(entry.last_scanned) }}</div>
                  <div
                    v-if="entry.outdated"
                    class="mt-0.5 text-xs text-amber-300"
                  >
                    Out of date
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
import { computed, inject, ref, type Ref } from 'vue'
import { RouterLink, useRoute } from 'vue-router'

import type { OrgDashboard, RepoDashboardEntry, RepoLifecycleStatus, SeverityCounts } from '@/api/client'
import ForgeIcon from '@/components/ForgeIcon.vue'
import { severityBadgeClass } from '@/lib/findingDisplay'
import { OPEN_RISK_KEV_QUERY, OPEN_RISK_MALWARE_QUERY, openRiskSeverityQuery } from '@/lib/openRiskPreset'
import MalwareIcon from '@/components/finding/MalwareIcon.vue'

const route = useRoute()
const provider = computed(() => route.params.provider as string)
const slug = computed(() => route.params.slug as string)

const dashboard = inject<Ref<OrgDashboard | null>>('orgDashboard', ref(null))

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
  return value ? new Date(value).toLocaleDateString() : 'Never'
}

function repoEntryKey(entry: RepoDashboardEntry) {
  return entry.repo_id || entry.provider_id || entry.full_name || entry.repo_name
}
</script>
