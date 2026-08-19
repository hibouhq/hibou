<template>
  <section class="rounded-xl border border-surface-border bg-surface-raised/40 p-4">
    <div class="flex flex-wrap items-center justify-between gap-2">
      <h3 class="text-sm font-semibold text-white">
        {{ kindLabel }}
      </h3>
      <span
        v-if="verdict.degraded"
        class="inline-flex items-center gap-1 rounded-full border border-danger/40 bg-danger/10 px-2 py-0.5 text-[10px] font-medium text-red-300"
      >
        <TrendingUp class="h-3 w-3" />
        degraded
      </span>
      <span
        v-else-if="verdict.comparable"
        class="rounded-full border border-ok/30 bg-ok/10 px-2 py-0.5 text-[10px] font-medium text-green-300"
      >normal</span>
      <span
        v-else
        class="rounded-full border border-surface-border px-2 py-0.5 text-[10px] text-gray-500"
      >no baseline</span>
    </div>

    <div
      v-if="verdict.current.samples === 0"
      class="py-6 text-center text-xs text-gray-500"
    >
      No finished runs in this window.
    </div>

    <template v-else>
      <!-- Throughput per bucket -->
      <div class="mt-3">
        <div class="flex items-baseline justify-between text-[10px] uppercase tracking-wide text-gray-500">
          <span>Throughput</span>
          <span class="normal-case tracking-normal">{{ totalCompleted }} ok · {{ totalFailed }} failed</span>
        </div>
        <div class="mt-1.5 flex h-14 gap-px">
          <div
            v-for="cell in cells"
            :key="cell.ms"
            class="group relative flex min-w-0 flex-1 flex-col justify-end gap-px"
            :title="cell.title"
          >
            <div
              v-if="cell.failed > 0"
              class="w-full rounded-sm"
              :style="{ height: `${cell.failedPct}%`, backgroundColor: '#f85149' }"
            />
            <div
              v-if="cell.completed > 0"
              class="w-full rounded-sm"
              :style="{ height: `${cell.completedPct}%`, backgroundColor: '#3fb950' }"
            />
            <div
              v-if="cell.completed === 0 && cell.failed === 0"
              class="h-px w-full bg-surface-border-subtle"
            />
          </div>
        </div>
      </div>

      <!-- Run duration percentiles -->
      <div class="mt-4">
        <div class="flex items-baseline justify-between text-[10px] uppercase tracking-wide text-gray-500">
          <span>Run duration</span>
          <span class="flex items-center gap-3 normal-case tracking-normal">
            <span class="inline-flex items-center gap-1"><span class="h-0.5 w-3 rounded bg-[#8b949e]" />p50 {{ formatDuration(verdict.current.p50Duration) }}</span>
            <span class="inline-flex items-center gap-1"><span class="h-0.5 w-3 rounded bg-[#58a6ff]" />p95 {{ formatDuration(verdict.current.p95Duration) }}</span>
          </span>
        </div>
        <svg
          :viewBox="`0 0 ${CHART_W} ${CHART_H}`"
          class="mt-1.5 h-12 w-full"
          preserveAspectRatio="none"
          role="img"
          :aria-label="`Run duration percentiles for ${kindLabel}`"
        >
          <line
            :x1="0"
            :x2="CHART_W"
            :y1="CHART_H - 0.5"
            :y2="CHART_H - 0.5"
            stroke="#21262d"
            stroke-width="1"
            vector-effect="non-scaling-stroke"
          />
          <polyline
            v-if="p95Path"
            :points="p95Path"
            fill="none"
            stroke="#58a6ff"
            stroke-width="1.5"
            stroke-linejoin="round"
            vector-effect="non-scaling-stroke"
          />
          <polyline
            v-if="p50Path"
            :points="p50Path"
            fill="none"
            stroke="#8b949e"
            stroke-width="1.5"
            stroke-linejoin="round"
            vector-effect="non-scaling-stroke"
          />
        </svg>
      </div>

      <!-- Current vs baseline -->
      <table class="mt-4 w-full text-xs">
        <thead>
          <tr class="text-left text-[10px] uppercase tracking-wide text-gray-500">
            <th class="pb-1 font-medium" />
            <th class="pb-1 font-medium">
              Window
            </th>
            <th class="pb-1 font-medium">
              Baseline 7d
            </th>
          </tr>
        </thead>
        <tbody class="text-gray-300">
          <tr
            v-for="row in compareRows"
            :key="row.name"
          >
            <td class="py-0.5 text-gray-500">
              {{ row.name }}
            </td>
            <td
              class="py-0.5 font-mono"
              :class="row.flagged ? 'text-red-300' : ''"
            >
              {{ formatDuration(row.current) }}
            </td>
            <td class="py-0.5 font-mono text-gray-500">
              {{ verdict.baseline ? formatDuration(row.base) : '—' }}
            </td>
          </tr>
        </tbody>
      </table>
    </template>
  </section>
</template>

<script setup lang="ts">
import { TrendingUp } from 'lucide-vue-next'
import { computed } from 'vue'

import type { InstanceJobStatsBucket } from '@/api/client'
import { formatDuration } from '@/lib/datetime'
import type { KindVerdict } from '@/lib/jobStats'

const props = defineProps<{
  kindLabel: string
  buckets: InstanceJobStatsBucket[]
  verdict: KindVerdict
  bucketSeconds: number
  sinceMs: number
  nowMs: number
}>()

const CHART_W = 100
const CHART_H = 28

// Dense bucket grid over the window so gaps render as empty slots instead of
// the sparse buckets stretching to fill the row.
const cells = computed(() => {
  const stepMs = props.bucketSeconds * 1000
  const firstMs = Math.floor(props.sinceMs / stepMs) * stepMs
  const byMs = new Map(props.buckets.map(b => [new Date(b.bucket).getTime(), b]))
  const out: { ms: number, completed: number, failed: number, completedPct: number, failedPct: number, title: string }[] = []
  let max = 1
  for (let ms = firstMs; ms <= props.nowMs; ms += stepMs) {
    const bucket = byMs.get(ms)
    max = Math.max(max, (bucket?.completed ?? 0) + (bucket?.failed ?? 0))
  }
  for (let ms = firstMs; ms <= props.nowMs; ms += stepMs) {
    const bucket = byMs.get(ms)
    const completed = bucket?.completed ?? 0
    const failed = bucket?.failed ?? 0
    out.push({
      ms,
      completed,
      failed,
      completedPct: (completed / max) * 100,
      failedPct: (failed / max) * 100,
      title: `${new Date(ms).toLocaleString('en', { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' })}: ${completed} ok, ${failed} failed`,
    })
  }
  return out
})

const totalCompleted = computed(() => props.buckets.reduce((sum, b) => sum + b.completed, 0))
const totalFailed = computed(() => props.buckets.reduce((sum, b) => sum + b.failed, 0))

function durationPath(pick: (b: InstanceJobStatsBucket) => number) {
  const rows = props.buckets
    .filter(b => b.completed + b.failed > 0)
    .map(b => ({ ms: new Date(b.bucket).getTime(), value: pick(b) }))
    .sort((a, b) => a.ms - b.ms)
  if (rows.length === 0) {
    return ''
  }
  const maxValue = Math.max(...props.buckets.map(b => b.p95_duration_seconds), 0.001)
  const spanMs = Math.max(props.nowMs - props.sinceMs, 1)
  const points = rows.map((row) => {
    const x = ((row.ms - props.sinceMs) / spanMs) * CHART_W
    const y = CHART_H - (row.value / maxValue) * (CHART_H - 2)
    return `${Math.max(x, 0).toFixed(2)},${y.toFixed(2)}`
  })
  // A single bucket still deserves a visible mark: draw a short flat segment.
  if (points.length === 1) {
    const [x, y] = points[0].split(',')
    return `${Math.max(Number(x) - 1.5, 0)},${y} ${Math.min(Number(x) + 1.5, CHART_W)},${y}`
  }
  return points.join(' ')
}

const p50Path = computed(() => durationPath(b => b.p50_duration_seconds))
const p95Path = computed(() => durationPath(b => b.p95_duration_seconds))

const compareRows = computed(() => [
  {
    name: 'Run p50',
    current: props.verdict.current.p50Duration,
    base: props.verdict.baseline?.p50_duration_seconds ?? 0,
    flagged: props.verdict.reasons.includes('run time p50'),
  },
  {
    name: 'Run p95',
    current: props.verdict.current.p95Duration,
    base: props.verdict.baseline?.p95_duration_seconds ?? 0,
    flagged: props.verdict.reasons.includes('run time p95'),
  },
  {
    name: 'Wait p50',
    current: props.verdict.current.p50Wait,
    base: props.verdict.baseline?.p50_wait_seconds ?? 0,
    flagged: props.verdict.reasons.includes('queue wait p50'),
  },
  {
    name: 'Wait p95',
    current: props.verdict.current.p95Wait,
    base: props.verdict.baseline?.p95_wait_seconds ?? 0,
    flagged: props.verdict.reasons.includes('queue wait p95'),
  },
])
</script>
