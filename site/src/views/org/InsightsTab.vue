<template>
  <div class="space-y-5">
    <div
      v-if="!dashboard"
      class="rounded-xl border border-dashed border-surface-border bg-surface-overlay/40 px-5 py-12 text-center text-sm text-gray-400"
    >
      No organization data available yet. Insights appear after the first scans are ingested.
    </div>

    <template v-else>
      <!-- Risk distribution -->
      <section class="rounded-xl border border-surface-border bg-surface-raised/40 p-4">
        <div class="flex flex-wrap items-center justify-between gap-2">
          <h2 class="flex items-center gap-2 text-sm font-semibold text-white">
            <ShieldAlert class="h-4 w-4 text-gray-500" />
            Risk distribution
          </h2>
          <div class="flex flex-wrap items-center gap-3 text-xs text-gray-500">
            <RouterLink
              v-if="kevOpen !== null"
              :to="kevLink()"
              class="inline-flex items-center gap-1 transition hover:text-accent"
              :class="kevOpen > 0 ? 'text-danger' : 'text-gray-400'"
              title="Known exploited vulnerabilities"
            >
              <Flame class="h-3.5 w-3.5" />
              {{ kevOpen }} known exploited
            </RouterLink>
            <RouterLink
              v-else-if="knownKEVOpen > 0"
              :to="kevLink()"
              class="text-danger hover:underline"
            >
              At least {{ knownKEVOpen }} known exploited · {{ kevUnavailableRepos }} {{ kevUnavailableRepos === 1 ? 'repository' : 'repositories' }} unavailable
            </RouterLink>
            <span v-else-if="kevOpen === null">Known exploited unavailable</span>
            <span>{{ totalVulnerabilities }} open across {{ dashboard.totals.components_total }} components</span>
          </div>
        </div>

        <div
          v-if="totalVulnerabilities === 0"
          class="mt-3 text-sm text-gray-500"
        >
          No open vulnerabilities. 🎉
        </div>
        <template v-else>
          <!-- GitHub language-bar style severity split -->
          <div class="mt-3 flex h-2 overflow-hidden rounded-full bg-surface-overlay">
            <div
              v-for="item in severityItems"
              :key="item.key"
              class="h-full"
              :style="{ width: `${(item.value / totalVulnerabilities) * 100}%`, backgroundColor: item.color }"
              :title="`${item.value} ${item.key}`"
            />
          </div>
          <div class="mt-2.5 flex flex-wrap gap-x-4 gap-y-1 text-xs">
            <span
              v-for="item in severityItems"
              :key="item.key"
              class="inline-flex items-center gap-1.5 text-gray-400"
            >
              <span
                class="h-2 w-2 rounded-full"
                :style="{ backgroundColor: item.color }"
              />
              <span class="capitalize">{{ item.key }}</span>
              <span class="font-medium text-gray-200">{{ item.value }}</span>
            </span>
          </div>
        </template>
      </section>

      <div class="grid gap-4 lg:grid-cols-2">
        <!-- Coverage funnel -->
        <section class="rounded-xl border border-surface-border bg-surface-raised/40 p-4">
          <h2 class="flex items-center gap-2 text-sm font-semibold text-white">
            <Radar class="h-4 w-4 text-gray-500" />
            Scan coverage
          </h2>
          <p class="mt-1 text-xs text-gray-500">
            How much of the organization Hibou watches.
          </p>
          <dl class="mt-3 space-y-2.5">
            <div
              v-for="row in coverageRows"
              :key="row.label"
            >
              <div class="flex items-baseline justify-between text-xs">
                <dt class="text-gray-400">
                  {{ row.label }}
                </dt>
                <dd class="font-medium text-gray-200">
                  {{ row.value }}<span class="text-gray-500"> / {{ dashboard.coverage.total_accessible }}</span>
                </dd>
              </div>
              <div class="mt-1 h-1.5 overflow-hidden rounded-full bg-surface-overlay">
                <div
                  class="h-full rounded-full"
                  :class="row.barClass"
                  :style="{ width: `${percent(row.value)}%` }"
                />
              </div>
            </div>
          </dl>
          <p
            v-if="dashboard.coverage.discovered > 0"
            class="mt-3 text-xs text-gray-500"
          >
            {{ dashboard.coverage.discovered }} discovered {{ dashboard.coverage.discovered === 1 ? 'repository is' : 'repositories are' }} not enrolled yet —
            <RouterLink
              :to="{ name: 'repos', params: route.params }"
              class="text-accent hover:underline"
            >
              enroll them
            </RouterLink>
            to include them in scans.
          </p>
        </section>

        <!-- Scan freshness -->
        <section class="rounded-xl border border-surface-border bg-surface-raised/40 p-4">
          <h2 class="flex items-center gap-2 text-sm font-semibold text-white">
            <Clock class="h-4 w-4 text-gray-500" />
            Scan freshness
          </h2>
          <p class="mt-1 text-xs text-gray-500">
            Repositories whose latest results may be stale.
          </p>
          <div
            v-if="outdatedRepos.length === 0"
            class="mt-3 text-sm text-gray-500"
          >
            All enrolled repositories have recent scans.
          </div>
          <ul
            v-else
            class="mt-3 divide-y divide-surface-border-subtle"
          >
            <li
              v-for="entry in outdatedRepos"
              :key="entry.repo_slug || entry.provider_id"
              class="flex items-center justify-between gap-3 py-1.5 text-sm"
            >
              <RouterLink
                :to="`/orgs/${provider}/${slug}/repos/${entry.repo_slug}`"
                class="truncate text-gray-200 transition hover:text-accent"
              >
                {{ entry.repo_name }}
              </RouterLink>
              <span class="shrink-0 text-xs text-gray-500">
                {{ entry.last_scanned ? relativeTime(entry.last_scanned) : 'never scanned' }}
              </span>
            </li>
          </ul>
        </section>
      </div>

      <!-- Riskiest repositories -->
      <section class="overflow-x-auto rounded-xl border border-surface-border">
        <div class="flex items-center justify-between border-b border-surface-border-subtle px-4 py-3">
          <h2 class="flex items-center gap-2 text-sm font-semibold text-white">
            <Flame class="h-4 w-4 text-gray-500" />
            Riskiest repositories
          </h2>
          <RouterLink
            :to="{ name: 'org-vulnerabilities', params: route.params }"
            class="text-xs font-medium text-accent hover:text-accent-hover"
          >
            View all vulnerabilities →
          </RouterLink>
        </div>

        <div
          v-if="riskiestRepos.length === 0"
          class="px-4 py-8 text-sm text-gray-500"
        >
          No repository has open vulnerabilities.
        </div>
        <table
          v-else
          class="min-w-full divide-y divide-surface-border-subtle text-sm"
        >
          <tbody class="divide-y divide-surface-border-subtle">
            <tr
              v-for="entry in riskiestRepos"
              :key="entry.repo_slug || entry.provider_id"
              class="transition hover:bg-white/5"
            >
              <td class="px-4 py-2.5">
                <RouterLink
                  :to="`/orgs/${provider}/${slug}/repos/${entry.repo_slug}`"
                  class="font-medium text-gray-200 transition hover:text-accent"
                >
                  {{ entry.repo_name }}
                </RouterLink>
              </td>
              <td class="px-4 py-2.5">
                <div class="flex flex-wrap justify-end gap-1.5">
                  <RouterLink
                    v-if="entry.kev_open != null"
                    :to="{ name: 'repo-vulnerabilities', params: { provider, slug, repoSlug: entry.repo_slug }, query: { q: OPEN_RISK_KEV_QUERY } }"
                    class="inline-flex items-center gap-1 rounded px-2 py-0.5 text-xs hover:underline"
                    :class="entry.kev_open > 0 ? 'bg-danger/10 font-semibold text-danger' : 'text-gray-500'"
                  >
                    <Flame class="h-3 w-3" />
                    {{ entry.kev_open }} exploited
                  </RouterLink>
                  <span
                    v-for="sev in severityOrder"
                    v-show="entry.vulnerabilities[sev] > 0"
                    :key="sev"
                    class="rounded-full px-2 py-0.5 text-xs font-medium"
                    :class="`sev-${sev}`"
                  >{{ entry.vulnerabilities[sev] }} {{ sev }}</span>
                </div>
              </td>
            </tr>
          </tbody>
        </table>
      </section>
    </template>
  </div>
</template>

<script setup lang="ts">
import { Clock, Flame, Radar, ShieldAlert } from 'lucide-vue-next'
import type { Ref } from 'vue'
import { computed, inject, ref } from 'vue'
import { RouterLink, useRoute } from 'vue-router'

import type { OrgDashboard, SeverityCounts } from '@/api/client'
import { relativeTime } from '@/lib/datetime'
import { OPEN_RISK_KEV_QUERY } from '@/lib/openRiskPreset'

const route = useRoute()
const provider = computed(() => route.params.provider as string)
const slug = computed(() => route.params.slug as string)

const dashboard = inject<Ref<OrgDashboard | null>>('orgDashboard', ref(null))
const kevOpen = computed(() => dashboard.value?.totals.kev_open ?? null)
const knownKEVOpen = computed(() => (dashboard.value?.repos ?? []).reduce((total, entry) => total + (entry.kev_open ?? 0), 0))
const kevUnavailableRepos = computed(() => (dashboard.value?.repos ?? []).filter(entry => entry.enrolled && entry.kev_open == null).length)

const severityOrder: Array<keyof SeverityCounts> = ['critical', 'high', 'medium', 'low', 'info']
const severityColors: Record<keyof SeverityCounts, string> = {
  critical: '#f85149',
  high: '#e6550d',
  medium: '#d29922',
  low: '#8b949e',
  info: '#58a6ff',
}

const totalVulnerabilities = computed(() => {
  const counts = dashboard.value?.totals.vulnerabilities
  return counts ? severityOrder.reduce((total, key) => total + (counts[key] ?? 0), 0) : 0
})

const severityItems = computed(() => {
  const counts = dashboard.value?.totals.vulnerabilities
  if (!counts) {
    return []
  }
  return severityOrder
    .map((key) => ({ key, value: counts[key] ?? 0, color: severityColors[key] }))
    .filter((item) => item.value > 0)
})

const coverageRows = computed(() => {
  const coverage = dashboard.value?.coverage
  if (!coverage) {
    return []
  }
  return [
    { label: 'Enrolled', value: coverage.enrolled, barClass: 'bg-accent' },
    { label: 'Actively scanned', value: coverage.active, barClass: 'bg-ok' },
    { label: 'Archived', value: coverage.archived, barClass: 'bg-gray-600' },
  ]
})

function percent(value: number) {
  const total = dashboard.value?.coverage.total_accessible ?? 0
  return total > 0 ? Math.round((value / total) * 100) : 0
}

function kevLink() {
  return { name: 'org-vulnerabilities', params: route.params, query: { q: OPEN_RISK_KEV_QUERY } }
}

const outdatedRepos = computed(() => (dashboard.value?.repos ?? [])
  .filter((entry) => entry.enrolled && (entry.outdated || !entry.last_scanned))
  .sort((a, b) => (a.last_scanned ?? '').localeCompare(b.last_scanned ?? ''))
  .slice(0, 6))

function riskScore(counts: SeverityCounts) {
  return counts.critical * 1000 + counts.high * 100 + counts.medium * 10 + counts.low + counts.info
}

const riskiestRepos = computed(() => (dashboard.value?.repos ?? [])
  .filter((entry) => entry.enrolled && (riskScore(entry.vulnerabilities) > 0 || (entry.kev_open ?? 0) > 0 || entry.malware_open > 0))
  .sort((a, b) => b.malware_open - a.malware_open || (b.kev_open ?? 0) - (a.kev_open ?? 0) || riskScore(b.vulnerabilities) - riskScore(a.vulnerabilities))
  .slice(0, 5))
</script>
