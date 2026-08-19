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
        :to="{ name: 'org-vulnerabilities', params: route.params, query: { type: 'malware' } }"
        class="flex items-center gap-2.5 rounded-xl border border-danger/50 bg-danger/10 px-4 py-3 transition hover:border-danger"
      >
        <Biohazard class="h-5 w-5 shrink-0 text-danger" />
        <span class="text-sm font-semibold text-red-200">
          {{ malwareOpen }} malicious {{ malwareOpen === 1 ? 'package' : 'packages' }} detected in {{ malwareRepoCount }} {{ malwareRepoCount === 1 ? 'repository' : 'repositories' }}
        </span>
        <span class="ml-auto text-xs text-red-300/80">Review immediately →</span>
      </RouterLink>

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
              class="rounded-full px-2.5 py-1 text-xs font-medium"
              :class="`sev-${item.key}`"
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
                    <span
                      v-if="entry.malware_open > 0"
                      class="inline-flex items-center gap-1 rounded-full border border-danger/50 bg-danger/15 px-2 py-0.5 text-xs font-semibold text-red-200"
                    >
                      <Biohazard class="h-3 w-3" />
                      malware {{ entry.malware_open }}
                    </span>
                    <span
                      v-for="item in toSeverityItems(entry.vulnerabilities)"
                      :key="`${repoEntryKey(entry)}-${item.key}`"
                      class="rounded-full px-2 py-0.5 text-xs font-medium"
                      :class="`sev-${item.key}`"
                    >{{ item.key }} {{ item.value }}</span>
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
import { Biohazard, ShieldAlert } from 'lucide-vue-next'
import { computed, inject, ref, type Ref } from 'vue'
import { RouterLink, useRoute } from 'vue-router'

import type { OrgDashboard, RepoDashboardEntry, RepoLifecycleStatus, SeverityCounts } from '@/api/client'
import ForgeIcon from '@/components/ForgeIcon.vue'

const route = useRoute()
const provider = computed(() => route.params.provider as string)
const slug = computed(() => route.params.slug as string)

const dashboard = inject<Ref<OrgDashboard | null>>('orgDashboard', ref(null))

const severityOrder: Array<keyof SeverityCounts> = ['critical', 'high', 'medium', 'low', 'info']
const severityRank: Record<string, number> = { critical: 5, high: 4, medium: 3, low: 2, info: 1 }

const severityItems = computed(() => toSeverityItems(dashboard.value?.totals.vulnerabilities))
const totalVulnerabilities = computed(() => sumCounts(dashboard.value?.totals.vulnerabilities))
const malwareOpen = computed(() => dashboard.value?.totals.malware_open ?? 0)
const malwareRepoCount = computed(() => (dashboard.value?.repos ?? []).filter((entry) => entry.malware_open > 0).length)

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
