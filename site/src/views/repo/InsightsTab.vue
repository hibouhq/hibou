<template>
  <div class="space-y-6">
    <header class="flex flex-wrap items-end justify-between gap-4 border-b border-surface-border pb-4">
      <div>
        <h2 class="text-base font-semibold text-white">
          Repository insights
        </h2><p class="mt-1 text-sm text-gray-500">
          Observations on <span class="font-mono text-gray-300">{{ refName }}</span>
        </p>
      </div>
      <div
        class="flex"
        role="group"
        aria-label="Insight period"
      >
        <button
          v-for="window in WINDOWS"
          :key="window.days"
          type="button"
          class="border border-surface-border px-3 py-1.5 text-xs"
          :class="windowDays === window.days ? 'bg-surface-overlay text-white' : 'text-gray-400 hover:text-white'"
          :aria-pressed="windowDays === window.days"
          @click="windowDays = window.days"
        >
          {{ window.label }}
        </button>
      </div>
    </header>
    <RouterLink
      :to="{ name: 'repo-vulnerabilities', params: route.params, query: { ref: repo?.default_branch, exploited: 'true', risk_only: 'true' } }"
      class="flex flex-wrap items-center gap-3 border-l-2 px-4 py-3 transition hover:bg-surface-overlay"
      :class="kevOpen !== null && kevOpen > 0 ? 'border-danger/60 bg-danger/5' : 'border-surface-border bg-surface-overlay/30'"
    >
      <Flame
        class="h-5 w-5 shrink-0"
        :class="kevOpen !== null && kevOpen > 0 ? 'text-danger' : 'text-gray-500'"
      />
      <div class="min-w-0 flex-1">
        <span class="text-sm font-medium text-gray-200">Known exploited</span>
        <p class="mt-0.5 text-xs text-gray-400">
          Current default-branch risk, including accepted risks
        </p>
      </div>
      <span
        class="font-semibold text-white"
        :class="kevOpen !== null ? 'text-xl' : 'text-xs'"
      >{{ kevLoading ? '...' : kevOpen ?? 'Unavailable' }}</span>
      <ChevronRight class="h-4 w-4 shrink-0 text-gray-500" />
    </RouterLink>
    <div
      v-if="loading"
      class="px-1 py-8 text-sm text-gray-500"
    >
      Loading observations…
    </div>
    <section
      v-else-if="error"
      class="border-l-2 border-danger bg-danger/5 px-4 py-4"
      role="alert"
    >
      <p class="text-sm font-medium text-white">
        Insights could not be loaded.
      </p><p class="mt-1 text-sm text-gray-400">
        {{ error }}
      </p><button
        type="button"
        class="mt-3 text-sm font-medium text-accent hover:text-white"
        @click="loadTrends"
      >
        Retry
      </button>
    </section>
    <section
      v-else-if="points.length === 0"
      class="border border-dashed border-surface-border px-5 py-10 text-center"
    >
      <p class="text-sm text-gray-300">
        No usable observations in this {{ selectedWindow.label }} window.
      </p><p class="mt-1 text-xs text-gray-500">
        No completed snapshot observations are available for this period.
      </p>
    </section>
    <template v-else>
      <div class="grid border-y border-surface-border sm:grid-cols-3">
        <div
          v-for="card in summaryCards"
          :key="card.label"
          class="border-b border-surface-border px-4 py-4 last:border-b-0 sm:border-b-0 sm:border-r sm:last:border-r-0"
        >
          <div class="text-[11px] uppercase tracking-[0.16em] text-gray-500">
            {{ card.label }}
          </div><div class="mt-2 flex items-baseline gap-2">
            <span class="text-2xl font-semibold text-white">{{ card.value }}</span><span
              v-if="card.delta !== null && card.delta !== 0"
              class="text-xs font-medium"
              :class="card.tone"
            >{{ card.delta > 0 ? '+' : '' }}{{ card.delta }}</span>
          </div><p class="mt-1 text-xs text-gray-500">
            {{ card.hint }}
          </p>
        </div>
      </div>
      <section class="border-y border-surface-border py-5">
        <div class="flex flex-wrap items-start justify-between gap-3">
          <div>
            <h3 class="text-sm font-semibold text-white">
              Risk observations
            </h3><p class="mt-1 text-xs text-gray-500">
              {{ observedRange }}
            </p>
          </div><div
            class="flex border border-surface-border"
            role="group"
            aria-label="Risk metric"
          >
            <button
              v-for="choice in METRICS"
              :key="choice.key"
              type="button"
              class="px-3 py-1.5 text-xs"
              :class="metric === choice.key ? 'bg-surface-overlay text-white' : 'text-gray-400 hover:text-white'"
              :aria-pressed="metric === choice.key"
              @click="metric = choice.key"
            >
              {{ choice.label }}
            </button>
          </div>
        </div><InsightTrendChart
          class="mt-4"
          :points="points"
          :metric="metric"
          @select="selectedSnapshotId = $event"
        /><p class="mt-3 text-xs text-gray-500">
          {{ points.length }} retained observation{{ points.length === 1 ? '' : 's' }} · Latest 365 maximum · Counts reflect current triage
        </p>
      </section>
      <section class="grid gap-6 border-b border-surface-border pb-5 lg:grid-cols-[minmax(0,1fr)_18rem]">
        <div>
          <h3 class="text-sm font-semibold text-white">
            Dependency footprint
          </h3><p class="mt-1 text-sm text-gray-400">
            {{ lastPoint.components_total }} components in latest observation <span v-if="componentDelta !== null">({{ componentDelta > 0 ? '+' : '' }}{{ componentDelta }} from first observation)</span>
          </p><p class="mt-2 text-xs text-gray-500">
            Component changes are neutral: they may reflect SBOM coverage as well as dependency changes.
          </p>
        </div><div class="border-l border-surface-border pl-4">
          <h3 class="text-sm font-semibold text-white">
            Latest selected observation
          </h3><p class="mt-2 font-mono text-xs text-gray-300">
            {{ formatDateTime(selectedPoint.date) }}
          </p><p class="mt-1 font-mono text-xs text-gray-500">
            {{ selectedPoint.commit_sha || 'No commit recorded' }}
          </p><p class="mt-3 text-xs text-gray-500">
            {{ relativeTime(selectedPoint.date) }}
          </p>
          <RouterLink
            :to="{ name: 'repo-vulnerabilities', params: route.params, query: { ref: repo?.default_branch, snapshot: selectedPoint.snapshot_id } }"
            class="mt-3 inline-flex items-center gap-1 text-xs font-medium text-accent hover:underline"
          >
            Open snapshot findings
            <ChevronRight class="h-3.5 w-3.5" />
          </RouterLink>
        </div>
      </section>
      <section>
        <h3 class="text-sm font-semibold text-white">
          Snapshot observations
        </h3><div class="mt-3 overflow-x-auto border border-surface-border">
          <table class="w-full min-w-[42rem] text-left text-sm">
            <thead class="border-b border-surface-border bg-surface-overlay/50 text-xs uppercase tracking-[0.12em] text-gray-500">
              <tr>
                <th class="px-3 py-2 font-medium">
                  Observed
                </th><th class="px-3 py-2 font-medium">
                  Dependency vulnerabilities
                </th><th class="px-3 py-2 font-medium">
                  Code findings
                </th><th class="px-3 py-2 font-medium">
                  Components
                </th><th class="px-3 py-2 font-medium">
                  Commit
                </th>
              </tr>
            </thead><tbody>
              <tr
                v-for="point in points"
                :key="point.snapshot_id"
                class="border-b border-surface-border last:border-b-0"
                :class="selectedPoint.snapshot_id === point.snapshot_id ? 'bg-accent/10' : ''"
              >
                <td class="px-3 py-2">
                  <button
                    type="button"
                    class="font-mono text-xs text-accent hover:text-white"
                    :aria-current="selectedPoint.snapshot_id === point.snapshot_id ? 'true' : undefined"
                    @click="selectedSnapshotId = point.snapshot_id"
                  >
                    {{ formatDateTime(point.date) }}
                  </button>
                </td><td class="px-3 py-2 text-gray-200">
                  {{ point.vulnerabilities_total }}
                </td><td class="px-3 py-2 text-gray-200">
                  {{ point.findings_total }}
                </td><td class="px-3 py-2 text-gray-200">
                  {{ point.components_total }}
                </td><td class="px-3 py-2 font-mono text-xs text-gray-500">
                  {{ point.commit_sha || '—' }}
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
import type { Ref } from 'vue'
import { computed, inject, ref, watch } from 'vue'
import { ChevronRight, Flame } from 'lucide-vue-next'
import { RouterLink, useRoute } from 'vue-router'

import { api, type Repository } from '@/api/client'
import InsightTrendChart from '@/components/insights/InsightTrendChart.vue'
import { relativeTime } from '@/lib/datetime'
import { normalizeTrendPoints, type InsightMetric, type InsightPoint, trendBounds } from '@/lib/insights'

const route = useRoute()
const provider = computed(() => route.params.provider as string)
const slug = computed(() => route.params.slug as string)
const repoSlug = computed(() => route.params.repoSlug as string)

const repo = inject<Ref<Repository | null>>('repo', ref(null))
const kevOpen = ref<number | null>(null)
const kevLoading = ref(true)
let kevRequestVersion = 0
watch([provider, slug, repoSlug, () => repo.value?.default_branch], async () => {
  const version = ++kevRequestVersion
  kevLoading.value = true
  kevOpen.value = null
  try {
    const response = await api.getRefSummary(provider.value, slug.value, repoSlug.value, { ref: repo.value?.default_branch })
    if (version === kevRequestVersion) kevOpen.value = response.data?.kev_open ?? null
  } catch {
    if (version === kevRequestVersion) kevOpen.value = null
  } finally {
    if (version === kevRequestVersion) kevLoading.value = false
  }
}, { immediate: true })
const refName = computed(() => repo.value?.default_branch || 'default branch')
const WINDOWS = [{ label: '7d', days: 7 }, { label: '30d', days: 30 }, { label: '90d', days: 90 }] as const
const METRICS: { key: InsightMetric; label: string }[] = [{ key: 'vulnerabilities', label: 'Dependencies' }, { key: 'findings', label: 'Code findings' }]
const windowDays = ref<7 | 30 | 90>(30)
const metric = ref<InsightMetric>('vulnerabilities')
const loading = ref(true)
const error = ref('')
const points = ref<InsightPoint[]>([])
const selectedSnapshotId = ref('')
let requestVersion = 0
const selectedWindow = computed(() => WINDOWS.find((window) => window.days === windowDays.value)!)
const firstPoint = computed(() => points.value[0])
const lastPoint = computed(() => points.value[points.value.length - 1])
const selectedPoint = computed(() => points.value.find((point) => point.snapshot_id === selectedSnapshotId.value) || lastPoint.value)
const componentDelta = computed(() => firstPoint.value && lastPoint.value && points.value.length > 1 ? lastPoint.value.components_total - firstPoint.value.components_total : null)
function formatDateTime(date: string) { return new Intl.DateTimeFormat('en', { month: 'short', day: 'numeric', hour: 'numeric', minute: '2-digit', timeZoneName: 'short' }).format(new Date(date)) }
function trendSince(days: number) { return new Date(Date.now() - days * 24 * 60 * 60 * 1000).toISOString() }
async function loadTrends() {
  const version = ++requestVersion
  loading.value = true
  error.value = ''
  try {
    const response = await api.getTrends(provider.value, slug.value, repoSlug.value, { ref: repo.value?.default_branch, since: trendSince(windowDays.value), limit: 365 })
    if (version !== requestVersion) return
    points.value = normalizeTrendPoints(response.data ?? [])
    selectedSnapshotId.value = points.value[points.value.length - 1]?.snapshot_id ?? ''
  } catch (cause) {
    if (version !== requestVersion) return
    points.value = []
    error.value = cause instanceof Error && cause.message ? cause.message : 'Request failed. Check access or try again.'
  } finally { if (version === requestVersion) loading.value = false }
}
watch([provider, slug, repoSlug, refName, windowDays], loadTrends, { immediate: true })

const summaryCards = computed(() => {
  const first = firstPoint.value
  const last = lastPoint.value
  if (!first || !last) {
    return []
  }
  const difference = (current: number, initial: number) => points.value.length > 1 ? current - initial : null
  const vulnerabilityDelta = difference(last.vulnerabilities_total, first.vulnerabilities_total)
  const findingsDelta = difference(last.findings_total, first.findings_total)
  return [
    {
      label: 'Dependency vulnerabilities', value: last.vulnerabilities_total, delta: vulnerabilityDelta,
      tone: vulnerabilityDelta !== null && vulnerabilityDelta < 0 ? 'text-ok' : 'text-danger', hint: 'all severities, including informational',
    },
    {
      label: 'Code findings', value: last.findings_total, delta: findingsDelta,
      tone: findingsDelta !== null && findingsDelta < 0 ? 'text-ok' : 'text-danger', hint: 'separate from dependency vulnerabilities',
    },
    {
      label: 'Informational', value: last.vulns_info + last.findings_info, delta: difference(last.vulns_info + last.findings_info, first.vulns_info + first.findings_info),
      tone: 'text-gray-400', hint: 'included in each observation total',
    },
  ]
})
const observedRange = computed(() => {
  const bounds = trendBounds(points.value)
  return bounds ? `${formatDateTime(bounds.start.toISOString())} to ${formatDateTime(bounds.end.toISOString())}` : ''
})
</script>
