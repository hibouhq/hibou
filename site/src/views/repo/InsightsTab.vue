<template>
  <div class="space-y-5">
    <div
      v-if="loading"
      class="px-1 py-8 text-sm text-gray-500"
    >
      Loading insights…
    </div>

    <div
      v-else-if="points.length === 0"
      class="rounded-xl border border-dashed border-surface-border bg-surface-overlay/40 px-5 py-12 text-center text-sm text-gray-400"
    >
      Not enough scan history yet. Insights appear once snapshots accumulate on
      <span class="font-mono text-xs text-gray-300">{{ refName }}</span>.
    </div>

    <template v-else>
      <!-- Summary deltas over the window -->
      <div class="grid gap-3 sm:grid-cols-3">
        <div
          v-for="card in summaryCards"
          :key="card.label"
          class="rounded-xl border border-surface-border bg-surface-raised/40 p-4"
        >
          <div class="text-[11px] uppercase tracking-[0.16em] text-gray-500">
            {{ card.label }}
          </div>
          <div class="mt-2 flex items-baseline gap-2">
            <span class="text-2xl font-semibold text-white">{{ card.value }}</span>
            <span
              v-if="card.delta !== 0"
              class="text-xs font-medium"
              :class="card.deltaIsGood ? 'text-ok' : 'text-danger'"
            >
              {{ card.delta > 0 ? '+' : '' }}{{ card.delta }}
            </span>
          </div>
          <div class="mt-0.5 text-xs text-gray-500">
            {{ card.hint }}
          </div>
        </div>
      </div>

      <!-- Vulnerability trend -->
      <section class="rounded-xl border border-surface-border bg-surface-raised/40 p-4">
        <div class="flex flex-wrap items-center justify-between gap-2">
          <h2 class="flex items-center gap-2 text-sm font-semibold text-white">
            <TrendingUp class="h-4 w-4 text-gray-500" />
            Vulnerability trend
          </h2>
          <span class="text-xs text-gray-500">
            {{ points.length }} snapshots on <span class="font-mono text-gray-400">{{ refName }}</span>
          </span>
        </div>

        <svg
          :viewBox="`0 0 ${CHART_W} ${CHART_H}`"
          class="mt-3 h-44 w-full"
          preserveAspectRatio="none"
          role="img"
          aria-label="Vulnerabilities per severity over time"
        >
          <line
            v-for="tick in yTicks"
            :key="tick.y"
            :x1="0"
            :x2="CHART_W"
            :y1="tick.y"
            :y2="tick.y"
            stroke="#21262d"
            stroke-width="1"
          />
          <polyline
            v-for="series in trendSeries"
            :key="series.key"
            :points="series.path"
            fill="none"
            :stroke="series.color"
            stroke-width="1.5"
            stroke-linejoin="round"
            vector-effect="non-scaling-stroke"
          />
        </svg>

        <div class="mt-2 flex flex-wrap items-center justify-between gap-2">
          <div class="flex flex-wrap gap-x-4 gap-y-1 text-xs">
            <span
              v-for="series in trendSeries"
              :key="series.key"
              class="inline-flex items-center gap-1.5 text-gray-400"
            >
              <span
                class="h-2 w-2 rounded-full"
                :style="{ backgroundColor: series.color }"
              />
              <span class="capitalize">{{ series.key }}</span>
              <span class="font-medium text-gray-200">{{ series.latest }}</span>
            </span>
          </div>
          <div class="text-xs text-gray-500">
            {{ windowLabel }}
          </div>
        </div>
      </section>

      <!-- Components trend -->
      <section class="rounded-xl border border-surface-border bg-surface-raised/40 p-4">
        <h2 class="flex items-center gap-2 text-sm font-semibold text-white">
          <Package class="h-4 w-4 text-gray-500" />
          Dependency footprint
        </h2>
        <svg
          :viewBox="`0 0 ${CHART_W} ${SPARK_H}`"
          class="mt-3 h-20 w-full"
          preserveAspectRatio="none"
          role="img"
          aria-label="Component count over time"
        >
          <polygon
            :points="componentsArea"
            fill="#58a6ff22"
          />
          <polyline
            :points="componentsPath"
            fill="none"
            stroke="#58a6ff"
            stroke-width="1.5"
            stroke-linejoin="round"
            vector-effect="non-scaling-stroke"
          />
        </svg>
        <div class="mt-2 flex items-center justify-between text-xs text-gray-500">
          <span>{{ firstPoint?.components_total ?? 0 }} components at window start</span>
          <span class="font-medium text-gray-300">{{ lastPoint?.components_total ?? 0 }} now</span>
        </div>
      </section>
    </template>
  </div>
</template>

<script setup lang="ts">
import { Package, TrendingUp } from 'lucide-vue-next'
import type { Ref } from 'vue'
import { computed, inject, ref, watch } from 'vue'
import { useRoute } from 'vue-router'

import { api, type Repository, type TrendPoint } from '@/api/client'

const CHART_W = 600
const CHART_H = 160
const SPARK_H = 64
const PAD_Y = 8
const WINDOW = 60

const route = useRoute()
const provider = computed(() => route.params.provider as string)
const slug = computed(() => route.params.slug as string)
const repoSlug = computed(() => route.params.repoSlug as string)

const repo = inject<Ref<Repository | null>>('repo', ref(null))
const refName = computed(() => repo.value?.default_branch || 'default branch')

const loading = ref(true)
const points = ref<TrendPoint[]>([])

watch(
  [provider, slug, repoSlug],
  async () => {
    loading.value = true
    try {
      const res = await api.getTrends(provider.value, slug.value, repoSlug.value, { limit: WINDOW })
      points.value = [...(res.data ?? [])].sort((a, b) => a.date.localeCompare(b.date))
    } catch {
      points.value = []
    } finally {
      loading.value = false
    }
  },
  { immediate: true },
)

const firstPoint = computed(() => points.value[0])
const lastPoint = computed(() => points.value[points.value.length - 1])

const SEVERITIES = [
  { key: 'critical', field: 'vuln_critical', color: '#f85149' },
  { key: 'high', field: 'vuln_high', color: '#e6550d' },
  { key: 'medium', field: 'vuln_medium', color: '#d29922' },
  { key: 'low', field: 'vuln_low', color: '#8b949e' },
] as const

function xAt(index: number) {
  const count = points.value.length
  return count <= 1 ? 0 : (index / (count - 1)) * CHART_W
}

function scaleY(value: number, max: number, height: number) {
  const usable = height - PAD_Y * 2
  return height - PAD_Y - (max > 0 ? (value / max) * usable : 0)
}

const trendMax = computed(() => Math.max(
  1,
  ...points.value.flatMap((point) => SEVERITIES.map((series) => point[series.field])),
))

const trendSeries = computed(() => SEVERITIES.map((series) => ({
  key: series.key,
  color: series.color,
  latest: lastPoint.value?.[series.field] ?? 0,
  path: points.value
    .map((point, index) => `${xAt(index)},${scaleY(point[series.field], trendMax.value, CHART_H)}`)
    .join(' '),
})))

const yTicks = computed(() => [0.25, 0.5, 0.75].map((fraction) => ({
  y: PAD_Y + (CHART_H - PAD_Y * 2) * fraction,
})))

const componentsMax = computed(() => Math.max(1, ...points.value.map((point) => point.components_total)))

const componentsPath = computed(() => points.value
  .map((point, index) => `${xAt(index)},${scaleY(point.components_total, componentsMax.value, SPARK_H)}`)
  .join(' '))

const componentsArea = computed(() => {
  if (points.value.length === 0) {
    return ''
  }
  return `0,${SPARK_H} ${componentsPath.value} ${CHART_W},${SPARK_H}`
})

const windowLabel = computed(() => {
  if (!firstPoint.value || !lastPoint.value) {
    return ''
  }
  const format = new Intl.DateTimeFormat('en', { month: 'short', day: 'numeric' })
  return `${format.format(new Date(firstPoint.value.date))} – ${format.format(new Date(lastPoint.value.date))}`
})

function totalVulns(point: TrendPoint) {
  return point.vuln_critical + point.vuln_high + point.vuln_medium + point.vuln_low + point.vuln_info
}

const summaryCards = computed(() => {
  const first = firstPoint.value
  const last = lastPoint.value
  if (!first || !last) {
    return []
  }
  const criticalHigh = last.vuln_critical + last.vuln_high
  const criticalHighDelta = criticalHigh - (first.vuln_critical + first.vuln_high)
  const totalDelta = totalVulns(last) - totalVulns(first)
  const componentsDelta = last.components_total - first.components_total
  return [
    {
      label: 'Critical + High',
      value: criticalHigh,
      delta: criticalHighDelta,
      deltaIsGood: criticalHighDelta < 0,
      hint: 'change over the window',
    },
    {
      label: 'Open vulnerabilities',
      value: totalVulns(last),
      delta: totalDelta,
      deltaIsGood: totalDelta < 0,
      hint: 'all severities',
    },
    {
      label: 'Components',
      value: last.components_total,
      delta: componentsDelta,
      deltaIsGood: componentsDelta <= 0,
      hint: 'dependency count',
    },
  ]
})
</script>
