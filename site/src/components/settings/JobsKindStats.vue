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
      <!-- Both charts share the window's time domain, so one pointer handler
           drives one tooltip for the hovered bucket across both. -->
      <div
        class="cursor-crosshair"
        @pointermove="onPointerMove"
        @pointerleave="hover = null"
      >
        <!-- Throughput per bucket -->
        <div class="mt-3">
          <div class="flex items-baseline justify-between text-[10px] uppercase tracking-wide text-gray-500">
            <span>Throughput <span class="normal-case text-gray-600">— runs / {{ formatDuration(bucketSeconds) }}</span></span>
            <span class="normal-case tracking-normal">{{ totalCompleted }} ok · {{ totalFailed }} failed<span class="text-gray-600"> · peak {{ maxPerBucket }}</span></span>
          </div>
          <div class="mt-1.5 flex h-14 gap-px">
            <div
              v-for="(cell, index) in cells"
              :key="cell.ms"
              class="relative flex min-w-0 flex-1 flex-col justify-end gap-px rounded-sm"
              :class="hover?.index === index ? 'bg-surface-overlay' : ''"
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
          <div class="relative mt-1.5">
            <svg
              :viewBox="`0 0 ${CHART_W} ${CHART_H}`"
              class="h-12 w-full"
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
              <!-- y-scale: recessive gridlines at the max and its half -->
              <line
                :x1="0"
                :x2="CHART_W"
                :y1="yFor(maxDuration)"
                :y2="yFor(maxDuration)"
                stroke="#21262d"
                stroke-width="1"
                stroke-dasharray="2 3"
                vector-effect="non-scaling-stroke"
              />
              <line
                :x1="0"
                :x2="CHART_W"
                :y1="yFor(maxDuration / 2)"
                :y2="yFor(maxDuration / 2)"
                stroke="#21262d"
                stroke-width="1"
                stroke-dasharray="2 3"
                vector-effect="non-scaling-stroke"
              />
              <!-- crosshair for the hovered bucket -->
              <line
                v-if="hover"
                :x1="hoverX"
                :x2="hoverX"
                :y1="0"
                :y2="CHART_H"
                stroke="#30363d"
                stroke-width="1"
                vector-effect="non-scaling-stroke"
              />
              <!-- Lines connect only time-adjacent buckets: a gap in the data
                   is a gap on screen, never an interpolated slope. -->
              <polyline
                v-for="(segment, index) in p95Segments"
                :key="`p95-${index}`"
                :points="segment"
                fill="none"
                stroke="#58a6ff"
                stroke-width="1.5"
                stroke-linejoin="round"
                vector-effect="non-scaling-stroke"
              />
              <polyline
                v-for="(segment, index) in p50Segments"
                :key="`p50-${index}`"
                :points="segment"
                fill="none"
                stroke="#8b949e"
                stroke-width="1.5"
                stroke-linejoin="round"
                vector-effect="non-scaling-stroke"
              />
            </svg>
            <!-- y-scale labels live in HTML: svg text would be distorted by
                 the non-uniform viewBox scaling -->
            <span class="pointer-events-none absolute right-0 top-0 text-[9px] leading-none text-gray-600">{{ formatDuration(maxDuration) }}</span>
            <span class="pointer-events-none absolute bottom-0 right-0 text-[9px] leading-none text-gray-600">0</span>
          </div>
        </div>

        <!-- Time axis, shared by both charts -->
        <div class="mt-1 flex items-baseline justify-between border-t border-surface-border-subtle pt-0.5 text-[9px] text-gray-600">
          <span>{{ timeLabel(sinceMs) }}</span>
          <span>{{ timeLabel((sinceMs + nowMs) / 2) }}</span>
          <span>now</span>
        </div>
      </div>

      <!-- Bucket tooltip -->
      <div
        v-if="hover"
        class="pointer-events-none fixed z-50 rounded-md border border-surface-border bg-surface-overlay px-3 py-2 text-xs shadow-lg"
        :style="{ left: `${hover.x}px`, top: `${hover.y}px` }"
      >
        <div class="font-medium text-gray-200">
          {{ hover.cell.rangeLabel }}
        </div>
        <div class="mt-1 space-y-0.5 text-gray-400">
          <div>
            <span class="text-green-300">{{ hover.cell.completed }} ok</span>
            <template v-if="hover.cell.failed > 0">
              · <span class="text-red-300">{{ hover.cell.failed }} failed</span>
            </template>
          </div>
          <div v-if="hover.cell.hasRuns">
            p50 {{ formatDuration(hover.cell.p50) }} · p95 {{ formatDuration(hover.cell.p95) }}
          </div>
          <div
            v-else
            class="text-gray-600"
          >
            no runs in this bucket
          </div>
        </div>
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
import { computed, ref } from 'vue'

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

interface BucketCell {
  ms: number
  completed: number
  failed: number
  completedPct: number
  failedPct: number
  hasRuns: boolean
  p50: number
  p95: number
  rangeLabel: string
}

// Dense bucket grid over the window so gaps render as empty slots instead of
// the sparse buckets stretching to fill the row.
const cells = computed<BucketCell[]>(() => {
  const stepMs = props.bucketSeconds * 1000
  const firstMs = Math.floor(props.sinceMs / stepMs) * stepMs
  const byMs = new Map(props.buckets.map(b => [new Date(b.bucket).getTime(), b]))
  const out: BucketCell[] = []
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
      hasRuns: completed + failed > 0,
      p50: bucket?.p50_duration_seconds ?? 0,
      p95: bucket?.p95_duration_seconds ?? 0,
      rangeLabel: `${timeLabel(ms)} – ${timeLabel(Math.min(ms + stepMs, props.nowMs))}`,
    })
  }
  return out
})

const totalCompleted = computed(() => props.buckets.reduce((sum, b) => sum + b.completed, 0))
const totalFailed = computed(() => props.buckets.reduce((sum, b) => sum + b.failed, 0))
const maxPerBucket = computed(() => cells.value.reduce((max, cell) => Math.max(max, cell.completed + cell.failed), 0))

const maxDuration = computed(() => Math.max(...props.buckets.map(b => b.p95_duration_seconds), 0.001))

function yFor(value: number): number {
  return CHART_H - 1 - (value / maxDuration.value) * (CHART_H - 3)
}

function xFor(index: number): number {
  return ((index + 0.5) / Math.max(cells.value.length, 1)) * CHART_W
}

// Consecutive buckets with runs form one polyline segment each; an isolated
// bucket becomes a short flat dash so it stays visible. Empty buckets break
// the line — missing data is never drawn as a slope between its neighbors.
function durationSegments(pick: (cell: BucketCell) => number): string[] {
  const segments: string[] = []
  let current: string[] = []
  const flush = () => {
    if (current.length === 1) {
      const [x, y] = current[0].split(',').map(Number)
      segments.push(`${Math.max(x - 1, 0)},${y} ${Math.min(x + 1, CHART_W)},${y}`)
    } else if (current.length > 1) {
      segments.push(current.join(' '))
    }
    current = []
  }
  cells.value.forEach((cell, index) => {
    if (!cell.hasRuns) {
      flush()
      return
    }
    current.push(`${xFor(index).toFixed(2)},${yFor(pick(cell)).toFixed(2)}`)
  })
  flush()
  return segments
}

const p50Segments = computed(() => durationSegments(cell => cell.p50))
const p95Segments = computed(() => durationSegments(cell => cell.p95))

// --- hover: one tooltip for the bucket under the pointer, both charts ---

const hover = ref<{ index: number, cell: BucketCell, x: number, y: number } | null>(null)

const hoverX = computed(() => (hover.value ? xFor(hover.value.index) : 0))

function onPointerMove(event: PointerEvent) {
  const target = event.currentTarget as HTMLElement
  const rect = target.getBoundingClientRect()
  if (rect.width === 0 || cells.value.length === 0) {
    hover.value = null
    return
  }
  const fraction = (event.clientX - rect.left) / rect.width
  const index = Math.min(cells.value.length - 1, Math.max(0, Math.floor(fraction * cells.value.length)))
  hover.value = {
    index,
    cell: cells.value[index],
    x: Math.min(event.clientX + 12, window.innerWidth - 220),
    y: event.clientY + 14,
  }
}

function timeLabel(ms: number): string {
  const date = new Date(ms)
  // Windows longer than a day need the day; within a day the time suffices.
  if (props.nowMs - props.sinceMs > 24 * 3600 * 1000) {
    return date.toLocaleString('en', { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' })
  }
  return date.toLocaleTimeString('en', { hour: '2-digit', minute: '2-digit' })
}

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
