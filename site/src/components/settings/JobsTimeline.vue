<template>
  <div>
    <!-- Time axis -->
    <div class="relative ml-36 h-5 select-none">
      <span
        v-for="tick in ticks"
        :key="tick.pct"
        class="absolute top-0 -translate-x-1/2 whitespace-nowrap text-[10px] text-gray-500"
        :style="{ left: `${tick.pct}%` }"
      >{{ tick.label }}</span>
      <span class="absolute right-0 top-0 text-[10px] font-medium text-gray-400">now</span>
    </div>

    <div
      v-if="groups.length === 0"
      class="rounded-md border border-dashed border-surface-border px-4 py-10 text-center text-sm text-gray-500"
    >
      No job runs in this window.
    </div>

    <div
      v-for="group in groups"
      :key="group.kind"
      class="flex border-t border-surface-border-subtle py-1.5 first-of-type:border-t-0"
    >
      <div class="w-36 shrink-0 pr-3 pt-0.5">
        <div class="truncate text-xs font-medium text-gray-300">
          {{ kindLabel(group.kind) }}
        </div>
        <div class="text-[10px] text-gray-500">
          {{ group.total }} {{ group.total === 1 ? 'run' : 'runs' }}<template v-if="group.overflow > 0">
            · +{{ group.overflow }} hidden
          </template>
        </div>
      </div>

      <!-- Lanes -->
      <div class="relative min-w-0 flex-1">
        <!-- Grid lines -->
        <div
          v-for="tick in ticks"
          :key="tick.pct"
          class="absolute bottom-0 top-0 w-px bg-surface-border-subtle"
          :style="{ left: `${tick.pct}%` }"
        />
        <div
          v-for="(lane, laneIndex) in group.lanes"
          :key="laneIndex"
          class="relative h-4"
          :class="laneIndex > 0 ? 'mt-1' : ''"
        >
          <template
            v-for="bar in lane"
            :key="bar.run.kind + bar.run.id"
          >
            <!-- Queue-wait segment -->
            <div
              v-if="bar.waitPct > 0.05"
              class="absolute inset-y-1 rounded-sm"
              :style="{ left: `${bar.startPct}%`, width: `${bar.waitPct}%`, backgroundColor: 'rgba(139, 148, 158, 0.35)' }"
            />
            <!-- Run segment -->
            <div
              v-if="bar.runPct > 0"
              class="absolute inset-y-0.5 rounded-sm"
              :class="bar.run.status === 'running' ? 'animate-pulse' : ''"
              :style="{ left: `${bar.runStartPct}%`, width: `${Math.max(bar.runPct, 0.25)}%`, backgroundColor: statusColor(bar.run.status) }"
            />
            <!-- Full-width hit target so short runs stay hoverable -->
            <div
              class="absolute inset-y-0 cursor-default"
              :style="{ left: `${bar.startPct}%`, width: `${Math.max(bar.startPct + bar.totalPct > 100 ? 100 - bar.startPct : bar.totalPct, 0.4)}%` }"
              @mouseenter="showTooltip(bar.run, $event)"
              @mouseleave="hideTooltip"
            />
          </template>
        </div>
      </div>
    </div>

    <!-- Legend: identity is label+legend, never color alone -->
    <div class="mt-3 flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-gray-400">
      <span class="inline-flex items-center gap-1.5">
        <span
          class="h-2 w-3 rounded-sm"
          style="background-color: rgba(139, 148, 158, 0.35)"
        />
        queue wait
      </span>
      <span
        v-for="status in legendStatuses"
        :key="status"
        class="inline-flex items-center gap-1.5"
      >
        <span
          class="h-2 w-3 rounded-sm"
          :style="{ backgroundColor: statusColor(status) }"
        />
        {{ status }}
      </span>
    </div>

    <!-- Tooltip -->
    <div
      v-if="tooltip"
      class="pointer-events-none fixed z-50 max-w-xs rounded-md border border-surface-border bg-surface-overlay px-3 py-2 text-xs shadow-lg"
      :style="{ left: `${tooltip.x}px`, top: `${tooltip.y}px` }"
    >
      <div class="flex items-center gap-2">
        <span
          class="h-2 w-2 shrink-0 rounded-full"
          :style="{ backgroundColor: statusColor(tooltip.run.status) }"
        />
        <span class="truncate font-medium text-gray-200">{{ tooltip.run.label }}</span>
      </div>
      <div class="mt-1 space-y-0.5 text-gray-400">
        <div>
          {{ kindLabel(tooltip.run.kind) }} · {{ tooltip.run.status }}<template v-if="tooltip.run.detail">
            · <span class="font-mono">{{ tooltip.run.detail }}</span>
          </template>
        </div>
        <div>queued {{ relativeTime(tooltip.run.queued_at) }}</div>
        <div v-if="tooltip.waited !== null">
          waited {{ formatDuration(tooltip.waited) }}<template v-if="tooltip.ran !== null">
            · ran {{ formatDuration(tooltip.ran) }}
          </template>
        </div>
        <div
          v-if="tooltip.run.worker_id"
          class="truncate font-mono text-[10px]"
        >
          {{ tooltip.run.worker_id }}
        </div>
        <div v-if="tooltip.run.attempts > 1">
          attempt {{ tooltip.run.attempts }}
        </div>
        <div
          v-if="tooltip.run.error"
          class="line-clamp-3 text-red-300"
        >
          {{ tooltip.run.error }}
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed, ref } from 'vue'

import type { InstanceJobRun } from '@/api/client'
import { formatDuration, relativeTime } from '@/lib/datetime'
import { jobKindLabel } from '@/lib/jobStats'

const props = defineProps<{
  runs: InstanceJobRun[]
  /** Window start, ISO timestamp. */
  since: string
  /** Window end (the poll instant), ms epoch. */
  nowMs: number
}>()

const MAX_LANES_PER_KIND = 8

// Job statuses use the app's reserved status colors (ok/danger/warn/accent
// tokens); the legend and tooltip carry the words so state is never
// color-alone.
const STATUS_COLORS: Record<string, string> = {
  queued: '#8b949e',
  running: '#58a6ff',
  complete: '#3fb950',
  failed: '#f85149',
  cancelled: '#d29922',
}

function statusColor(status: string) {
  return STATUS_COLORS[status] ?? '#8b949e'
}

const kindLabel = jobKindLabel

const legendStatuses = ['queued', 'running', 'complete', 'failed', 'cancelled']

interface TimelineBar {
  run: InstanceJobRun
  startPct: number
  waitPct: number
  runStartPct: number
  runPct: number
  totalPct: number
  endMs: number
}

const windowStartMs = computed(() => new Date(props.since).getTime())
const windowSpanMs = computed(() => Math.max(props.nowMs - windowStartMs.value, 1))

function toPct(ms: number) {
  return Math.min(Math.max(((ms - windowStartMs.value) / windowSpanMs.value) * 100, 0), 100)
}

function toBar(run: InstanceJobRun): TimelineBar {
  const queued = new Date(run.queued_at).getTime()
  const started = run.started_at ? new Date(run.started_at).getTime() : null
  const finished = run.finished_at ? new Date(run.finished_at).getTime() : null
  // An unfinished bar extends to "now"; a queued one has no run segment yet.
  const waitEnd = started ?? props.nowMs
  const runEnd = started === null ? null : (finished ?? props.nowMs)

  const startPct = toPct(queued)
  const waitPct = toPct(waitEnd) - startPct
  const runStartPct = started === null ? startPct : toPct(started)
  const runPct = runEnd === null ? 0 : toPct(runEnd) - runStartPct

  return {
    run,
    startPct,
    waitPct,
    runStartPct,
    runPct,
    totalPct: toPct(runEnd ?? waitEnd) - startPct,
    endMs: runEnd ?? waitEnd,
  }
}

// Greedy lane packing per kind, Grafana-style: earliest-starting bar first,
// each dropped into the first lane whose last bar ended before it starts.
const groups = computed(() => {
  const byKind = new Map<string, TimelineBar[]>()
  for (const run of props.runs) {
    const bar = toBar(run)
    const bars = byKind.get(run.kind)
    if (bars) {
      bars.push(bar)
    } else {
      byKind.set(run.kind, [bar])
    }
  }

  const result: { kind: string, lanes: TimelineBar[][], total: number, overflow: number }[] = []
  for (const [kind, bars] of byKind) {
    bars.sort((a, b) => a.startPct - b.startPct)
    const lanes: TimelineBar[][] = []
    const laneEnds: number[] = []
    let overflow = 0
    for (const bar of bars) {
      const barStartMs = windowStartMs.value + (bar.startPct / 100) * windowSpanMs.value
      let placed = false
      for (let i = 0; i < lanes.length; i++) {
        if (laneEnds[i] <= barStartMs) {
          lanes[i].push(bar)
          laneEnds[i] = bar.endMs
          placed = true
          break
        }
      }
      if (!placed) {
        if (lanes.length >= MAX_LANES_PER_KIND) {
          overflow++
          continue
        }
        lanes.push([bar])
        laneEnds.push(bar.endMs)
      }
    }
    result.push({ kind, lanes, total: bars.length, overflow })
  }
  result.sort((a, b) => kindLabel(a.kind).localeCompare(kindLabel(b.kind)))
  return result
})

const ticks = computed(() => {
  const count = 6
  const spanMs = windowSpanMs.value
  const showDay = spanMs > 24 * 3600 * 1000
  const items: { pct: number, label: string }[] = []
  for (let i = 1; i < count; i++) {
    const at = new Date(windowStartMs.value + (spanMs * i) / count)
    const label = showDay
      ? at.toLocaleString('en', { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' })
      : at.toLocaleTimeString('en', { hour: '2-digit', minute: '2-digit' })
    items.push({ pct: (i / count) * 100, label })
  }
  return items
})

const tooltip = ref<{ run: InstanceJobRun, x: number, y: number, waited: number | null, ran: number | null } | null>(null)

function showTooltip(run: InstanceJobRun, event: MouseEvent) {
  const target = event.currentTarget as HTMLElement
  const rect = target.getBoundingClientRect()
  const queued = new Date(run.queued_at).getTime()
  const started = run.started_at ? new Date(run.started_at).getTime() : null
  const finished = run.finished_at ? new Date(run.finished_at).getTime() : null
  const waited = started === null
    ? (run.status === 'queued' ? (props.nowMs - queued) / 1000 : null)
    : (started - queued) / 1000
  const ran = started === null ? null : ((finished ?? props.nowMs) - started) / 1000
  tooltip.value = {
    run,
    x: Math.min(rect.left, window.innerWidth - 336),
    y: rect.bottom + 6,
    waited,
    ran,
  }
}

function hideTooltip() {
  tooltip.value = null
}
</script>
