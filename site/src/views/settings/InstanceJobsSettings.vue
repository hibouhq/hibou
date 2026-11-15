<template>
  <div class="space-y-5">
    <div class="flex flex-wrap items-start justify-between gap-3">
      <div>
        <h2 class="text-lg font-semibold text-white">
          Jobs &amp; workers
        </h2>
        <p class="mt-1 text-sm text-gray-400">
          Background job queues, run history and the worker fleet, instance-wide.
        </p>
      </div>
      <div class="flex items-center gap-2">
        <div class="flex rounded-md border border-surface-border">
          <button
            v-for="win in windows"
            :key="win"
            class="px-2.5 py-1 text-xs transition first:rounded-l-md last:rounded-r-md"
            :class="win === selectedWindow ? 'bg-accent-muted text-white' : 'text-gray-400 hover:bg-surface-raised hover:text-white'"
            @click="setWindow(win)"
          >
            {{ win }}
          </button>
        </div>
        <button
          class="flex items-center gap-1.5 rounded-md border border-surface-border px-2.5 py-1 text-xs text-gray-400 transition hover:bg-surface-raised hover:text-white"
          :title="paused ? 'Resume auto-refresh' : 'Pause auto-refresh'"
          @click="togglePaused"
        >
          <component
            :is="paused ? Play : Pause"
            class="h-3 w-3"
          />
          {{ paused ? 'Resume' : 'Pause' }}
        </button>
      </div>
    </div>

    <div
      v-if="loadError"
      class="rounded-md border border-danger/30 bg-danger/10 px-4 py-3 text-sm text-red-200"
    >
      {{ loadError }}
    </div>

    <div
      v-if="loading"
      class="py-6 text-sm text-gray-500"
    >
      Loading jobs…
    </div>

    <template v-else-if="overview">
      <!-- Stat tiles -->
      <div class="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
        <div class="rounded-xl border border-surface-border bg-surface-raised/40 p-4">
          <div class="text-[11px] uppercase tracking-[0.16em] text-gray-500">
            Running
          </div>
          <div class="mt-2 text-2xl font-semibold text-white">
            {{ totals.running }}
          </div>
          <div class="mt-0.5 text-xs text-gray-500">
            jobs with an active lease
          </div>
        </div>
        <div class="rounded-xl border border-surface-border bg-surface-raised/40 p-4">
          <div class="text-[11px] uppercase tracking-[0.16em] text-gray-500">
            Queued
          </div>
          <div class="mt-2 text-2xl font-semibold text-white">
            {{ totals.queued }}
          </div>
          <div class="mt-0.5 text-xs text-gray-500">
            <template v-if="oldestQueued">
              oldest waiting since {{ relativeTime(oldestQueued) }}
            </template>
            <template v-else>
              nothing waiting
            </template>
          </div>
        </div>
        <div class="rounded-xl border border-surface-border bg-surface-raised/40 p-4">
          <div class="text-[11px] uppercase tracking-[0.16em] text-gray-500">
            Failed · 24h
          </div>
          <div
            class="mt-2 text-2xl font-semibold"
            :class="totals.failed24h > 0 ? 'text-danger' : 'text-white'"
          >
            {{ totals.failed24h }}
          </div>
          <div class="mt-0.5 text-xs text-gray-500">
            {{ totals.completed24h }} completed in 24h
          </div>
        </div>
        <div class="rounded-xl border border-surface-border bg-surface-raised/40 p-4">
          <div class="text-[11px] uppercase tracking-[0.16em] text-gray-500">
            Workers online
          </div>
          <div
            class="mt-2 text-2xl font-semibold text-white"
            aria-label="Online worker count"
            title="Observed from recent heartbeats, not configured replica capacity"
          >
            {{ onlineWorkers }}
          </div>
          <div class="mt-0.5 text-xs text-gray-500">
            heartbeat every {{ formatDuration(overview.heartbeat_interval_seconds) }}
          </div>
        </div>
      </div>

      <!-- Degradation banners -->
      <div
        v-for="verdict in degradedVerdicts"
        :key="verdict.kind"
        class="flex items-start gap-2.5 rounded-md border border-warn/40 bg-warn/10 px-4 py-3 text-sm text-yellow-200"
      >
        <TrendingUp class="mt-0.5 h-4 w-4 shrink-0" />
        <div>
          <span class="font-medium">{{ jobKindLabel(verdict.kind) }} slower than usual:</span>
          {{ verdict.reasons.join(', ') }} above the trailing-7-day baseline
          (e.g. wait p50 {{ formatDuration(verdict.current.p50Wait) }} vs {{ formatDuration(verdict.baseline?.p50_wait_seconds ?? 0) }},
          run p50 {{ formatDuration(verdict.current.p50Duration) }} vs {{ formatDuration(verdict.baseline?.p50_duration_seconds ?? 0) }}).
        </div>
      </div>

      <!-- Timeline -->
      <section class="rounded-xl border border-surface-border bg-surface-raised/40 p-4">
        <div class="flex flex-wrap items-center justify-between gap-2">
          <h3 class="flex items-center gap-2 text-sm font-semibold text-white">
            <Activity class="h-4 w-4 text-gray-500" />
            Timeline
          </h3>
          <span class="text-xs text-gray-500">
            last {{ selectedWindow }}
            <template v-if="timeline?.truncated">
              · showing the newest {{ timeline.max_rows }} runs
            </template>
          </span>
        </div>
        <div class="mt-3">
          <JobsTimeline
            v-if="timeline"
            :runs="timeline.runs"
            :since="timeline.since"
            :now-ms="nowMs"
          />
        </div>
      </section>

      <!-- Per-kind stats -->
      <div class="grid gap-3 lg:grid-cols-3">
        <JobsKindStats
          v-for="kind in statKinds"
          :key="kind"
          :kind-label="jobKindLabel(kind)"
          :buckets="bucketsByKind.get(kind) ?? []"
          :verdict="verdictsByKind.get(kind)!"
          :bucket-seconds="stats?.bucket_seconds ?? 3600"
          :since-ms="statsSinceMs"
          :now-ms="nowMs"
        />
      </div>

      <!-- Workers -->
      <section
        class="workers-panel min-w-0 rounded-xl border border-surface-border bg-surface-raised/40"
        aria-label="Workers"
      >
        <div class="flex flex-wrap items-center justify-between gap-2 px-4 pt-4">
          <h3 class="flex items-center gap-2 text-sm font-semibold text-white">
            <Server class="h-4 w-4 text-gray-500" />
            Workers
          </h3>
          <span
            v-if="liveVersions.length > 1"
            class="rounded-full border border-warn/40 px-2 py-0.5 text-[10px] font-medium text-warn"
            :title="liveVersions.join(', ')"
          >{{ liveVersions.length }} versions running</span>
          <span class="text-xs text-gray-500">
            resource usage is self-reported per process, not container limits
          </span>
        </div>
        <p class="mt-2 px-4 text-xs text-gray-500">
          Observed registrations, not configured capacity. Stale records may belong to previous replicas.
        </p>
        <div class="mt-3 min-w-0">
          <table class="workers-table w-full table-fixed text-sm">
            <colgroup>
              <col class="w-[20%]">
              <col class="w-[11%]">
              <col class="w-[18%]">
              <col class="w-[20%]">
              <col class="w-[7%]">
              <col class="w-[24%]">
            </colgroup>
            <thead>
              <tr class="border-b border-surface-border text-left text-[11px] uppercase tracking-wide text-gray-500">
                <th class="px-3 py-2 font-medium">
                  Worker
                </th>
                <th class="px-3 py-2 font-medium">
                  Status
                </th>
                <th class="px-3 py-2 font-medium">
                  Activity
                </th>
                <th class="px-3 py-2 font-medium">
                  Resources
                </th>
                <th class="px-3 py-2 text-right font-medium">
                  Jobs
                </th>
                <th class="px-3 py-2 font-medium">
                  Loops
                </th>
              </tr>
            </thead>
            <tbody class="divide-y divide-surface-border-subtle">
              <tr
                v-for="worker in visibleWorkers"
                :key="worker.id"
                class="worker-row align-top"
                :class="worker.status === 'stopped' ? 'text-gray-500' : 'text-gray-300'"
              >
                <td
                  class="min-w-0 break-all px-3 py-3 font-mono text-xs"
                  :title="worker.id"
                >
                  {{ worker.hostname }}<span class="text-gray-600">:{{ worker.pid }}</span>
                  <div
                    v-if="worker.version"
                    class="text-[10px] text-gray-600"
                  >
                    {{ worker.version }}
                  </div>
                </td>
                <td class="worker-status px-3 py-3">
                  <span
                    class="inline-flex items-center gap-1.5 rounded-full border px-2 py-0.5 text-[10px] font-medium"
                    :class="workerStatusClass(worker.status)"
                  >
                    <span
                      class="h-1.5 w-1.5 rounded-full"
                      :class="worker.status === 'online' ? 'bg-ok' : worker.status === 'stale' ? 'bg-warn' : 'bg-gray-500'"
                    />
                    {{ worker.status }}
                  </span>
                </td>
                <td class="min-w-0 break-words px-3 py-3 text-xs text-gray-400">
                  <span class="worker-cell-label mb-1 text-[10px] uppercase tracking-wide text-gray-500">Activity</span>
                  <dl class="space-y-2">
                    <div>
                      <dt class="text-[10px] text-gray-500">
                        Uptime
                      </dt>
                      <dd>
                        {{ worker.status === 'stopped' ? `ran ${ranFor(worker)}` : relativeTime(worker.started_at).replace(' ago', '') }}
                      </dd>
                    </div>
                    <div>
                      <dt class="text-[10px] text-gray-500">
                        {{ worker.status === 'stopped' ? 'Stopped' : 'Heartbeat' }}
                      </dt>
                      <dd>
                        {{ relativeTime(worker.status === 'stopped' ? worker.stopped_at ?? worker.last_heartbeat_at : worker.last_heartbeat_at) }}
                      </dd>
                    </div>
                  </dl>
                </td>
                <td class="min-w-0 px-3 py-3 text-xs">
                  <span class="worker-cell-label mb-1 text-[10px] uppercase tracking-wide text-gray-500">Resources</span>
                  <dl class="grid grid-cols-[auto_minmax(0,1fr)] gap-x-2 gap-y-1">
                    <dt class="text-gray-500">
                      CPU
                    </dt>
                    <dd class="break-all text-right font-mono">
                      {{ worker.status === 'online' && worker.cpu_percent !== undefined ? `${worker.cpu_percent.toFixed(1)}%` : '—' }}
                    </dd>
                    <dt class="text-gray-500">
                      RSS
                    </dt>
                    <dd class="break-words text-right font-mono">
                      {{ worker.status === 'online' && worker.memory_rss_bytes !== undefined ? formatBytes(worker.memory_rss_bytes) : '—' }}
                    </dd>
                    <dt class="text-gray-500">
                      Heap
                    </dt>
                    <dd class="break-words text-right font-mono">
                      {{ worker.status === 'online' && worker.heap_alloc_bytes !== undefined ? formatBytes(worker.heap_alloc_bytes) : '—' }}
                    </dd>
                    <dt class="text-gray-500">
                      Goroutines
                    </dt>
                    <dd class="break-all text-right font-mono">
                      {{ worker.status === 'online' ? (worker.goroutines ?? '—') : '—' }}
                    </dd>
                  </dl>
                </td>
                <td class="worker-jobs px-3 py-3 text-right font-mono text-xs">
                  <span class="worker-cell-label mb-1 text-[10px] uppercase tracking-wide text-gray-500">Jobs</span>
                  <span :title="worker.status === 'online' ? `self-reported ${worker.active_jobs}, claimed leases ${worker.running_jobs}` : 'No current worker sample'">
                    {{ worker.status === 'online' ? Math.max(worker.active_jobs, worker.running_jobs) : '—' }}
                  </span>
                </td>
                <td class="min-w-0 px-3 py-3">
                  <span class="worker-cell-label mb-1 text-[10px] uppercase tracking-wide text-gray-500">Loops</span>
                  <button
                    v-if="worker.loops.length > 0"
                    type="button"
                    class="rounded border border-surface-border-subtle bg-surface-overlay px-2 py-1 text-[10px] text-gray-400 hover:text-gray-200"
                    :aria-expanded="expandedLoops.has(worker.id)"
                    :aria-label="`${expandedLoops.has(worker.id) ? 'Hide' : 'Show'} ${worker.loops.length} enabled loops`"
                    @click="toggleLoops(worker.id)"
                  >
                    {{ worker.loops.length }} loops
                  </button>
                  <span
                    v-else
                    class="text-[10px] text-gray-600"
                  >api only</span>
                  <div
                    v-if="expandedLoops.has(worker.id)"
                    class="mt-2 flex min-w-0 flex-wrap gap-1"
                  >
                    <span
                      v-for="loop in worker.loops"
                      :key="loop"
                      class="max-w-full break-all rounded border border-surface-border-subtle bg-surface-overlay px-1.5 py-0.5 font-mono text-[10px] text-gray-400"
                    >{{ loop }}</span>
                  </div>
                </td>
              </tr>
              <tr v-if="stoppedWorkers.length > 0">
                <td
                  colspan="6"
                  class="px-4 py-2 text-xs text-gray-500"
                >
                  <button
                    type="button"
                    class="hover:text-gray-300"
                    :aria-expanded="showStopped"
                    @click="showStopped = !showStopped"
                  >
                    {{ showStopped ? 'Hide' : 'Show' }} {{ stoppedWorkers.length }} stopped
                    {{ stoppedWorkers.length === 1 ? 'worker' : 'workers' }} (last 24h)
                  </button>
                </td>
              </tr>
              <tr v-if="overview.workers.length === 0">
                <td
                  colspan="6"
                  class="px-4 py-6 text-center text-sm text-gray-500"
                >
                  No workers have registered yet. Replicas appear here after their first heartbeat.
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </section>

      <!-- Runs: the timeline's payload as a flat, filterable list -->
      <JobsRunList
        v-if="timeline"
        :runs="timeline.runs"
        :now-ms="nowMs"
      />
    </template>
  </div>
</template>

<script setup lang="ts">
import { Activity, Pause, Play, Server, TrendingUp } from 'lucide-vue-next'
import { computed, onMounted, onUnmounted, ref } from 'vue'

import type { InstanceJobsOverview, InstanceJobsStats, InstanceJobsTimeline, InstanceJobsWindow, InstanceJobStatsBucket, InstanceWorker } from '@/api/client'
import { api } from '@/api/client'
import JobsKindStats from '@/components/settings/JobsKindStats.vue'
import JobsRunList from '@/components/settings/JobsRunList.vue'
import JobsTimeline from '@/components/settings/JobsTimeline.vue'
import { formatDuration, relativeTime } from '@/lib/datetime'
import type { KindVerdict } from '@/lib/jobStats'
import { computeKindVerdict, jobKindLabel } from '@/lib/jobStats'

const windows: InstanceJobsWindow[] = ['1h', '6h', '24h', '7d']

// Overview (counters + workers) refreshes every tick; the heavier timeline
// and stats every third tick.
const OVERVIEW_REFRESH_MS = 10_000
const HEAVY_EVERY_N_TICKS = 3

const selectedWindow = ref<InstanceJobsWindow>('24h')
const paused = ref(false)
const loading = ref(true)
const loadError = ref('')

const overview = ref<InstanceJobsOverview | null>(null)
const timeline = ref<InstanceJobsTimeline | null>(null)
const stats = ref<InstanceJobsStats | null>(null)
const nowMs = ref(Date.now())

let timer: ReturnType<typeof setInterval> | undefined
let tick = 0

async function refreshOverview() {
  const response = await api.getInstanceJobsOverview()
  overview.value = response.data ?? null
}

async function refreshHeavy() {
  const [timelineResponse, statsResponse] = await Promise.all([
    api.getInstanceJobsTimeline(selectedWindow.value),
    api.getInstanceJobsStats(selectedWindow.value),
  ])
  timeline.value = timelineResponse.data ?? null
  stats.value = statsResponse.data ?? null
  nowMs.value = Date.now()
}

async function refreshAll() {
  try {
    await Promise.all([refreshOverview(), refreshHeavy()])
    loadError.value = ''
  } catch (error) {
    loadError.value = error instanceof Error ? error.message : 'Failed to load jobs'
  } finally {
    loading.value = false
  }
}

function setWindow(win: InstanceJobsWindow) {
  if (selectedWindow.value === win) {
    return
  }
  selectedWindow.value = win
  void refreshAll()
}

function togglePaused() {
  paused.value = !paused.value
  if (!paused.value) {
    void refreshAll()
  }
}

onMounted(() => {
  void refreshAll()
  timer = setInterval(() => {
    if (paused.value || document.hidden) {
      return
    }
    tick++
    if (tick % HEAVY_EVERY_N_TICKS === 0) {
      void refreshAll()
    } else {
      refreshOverview().catch(() => { /* transient poll errors keep the last data */ })
    }
  }, OVERVIEW_REFRESH_MS)
})

onUnmounted(() => {
  if (timer !== undefined) {
    clearInterval(timer)
  }
})

const totals = computed(() => {
  const kinds = overview.value?.kinds ?? []
  return {
    queued: kinds.reduce((sum, k) => sum + k.queued, 0),
    running: kinds.reduce((sum, k) => sum + k.running, 0),
    completed24h: kinds.reduce((sum, k) => sum + k.completed_24h, 0),
    failed24h: kinds.reduce((sum, k) => sum + k.failed_24h, 0),
  }
})

const oldestQueued = computed(() => {
  const dates = (overview.value?.kinds ?? [])
    .map(k => k.oldest_queued_at)
    .filter((v): v is string => Boolean(v))
    .sort()
  return dates[0]
})

const onlineWorkers = computed(() => (overview.value?.workers ?? []).filter(w => w.status === 'online').length)

const showStopped = ref(false)
const expandedLoops = ref(new Set<string>())
const liveWorkers = computed(() => (overview.value?.workers ?? []).filter(w => w.status !== 'stopped'))
const stoppedWorkers = computed(() => (overview.value?.workers ?? []).filter(w => w.status === 'stopped'))
const visibleWorkers = computed(() => showStopped.value ? [...liveWorkers.value, ...stoppedWorkers.value] : liveWorkers.value)
const liveVersions = computed(() => [...new Set(liveWorkers.value.filter(w => w.status === 'online').map(w => w.version).filter(Boolean))])

function toggleLoops(id: string) {
  const next = new Set(expandedLoops.value)
  if (next.has(id)) {
    next.delete(id)
  } else {
    next.add(id)
  }
  expandedLoops.value = next
}

function ranFor(worker: InstanceWorker) {
  const end = new Date(worker.stopped_at ?? worker.last_heartbeat_at).getTime()
  return formatDuration(Math.max(0, end - new Date(worker.started_at).getTime()) / 1000)
}

const statsSinceMs = computed(() => (stats.value ? new Date(stats.value.since).getTime() : nowMs.value))

// Every kind the overview knows about gets a stats card, even with no runs
// in the window.
const statKinds = computed(() => (overview.value?.kinds ?? []).map(k => k.kind))

const bucketsByKind = computed(() => {
  const map = new Map<string, InstanceJobStatsBucket[]>()
  for (const bucket of stats.value?.buckets ?? []) {
    const list = map.get(bucket.kind)
    if (list) {
      list.push(bucket)
    } else {
      map.set(bucket.kind, [bucket])
    }
  }
  return map
})

const verdictsByKind = computed(() => {
  const map = new Map<string, KindVerdict>()
  for (const kind of statKinds.value) {
    const baseline = (stats.value?.baselines ?? []).find(b => b.kind === kind)
    map.set(kind, computeKindVerdict(kind, bucketsByKind.value.get(kind) ?? [], baseline))
  }
  return map
})

const degradedVerdicts = computed(() => [...verdictsByKind.value.values()].filter(v => v.degraded))

function workerStatusClass(status: string) {
  switch (status) {
    case 'online':
      return 'border-ok/30 bg-ok/10 text-green-300'
    case 'stale':
      return 'border-warn/40 bg-warn/10 text-yellow-200'
    default:
      return 'border-surface-border text-gray-500'
  }
}

function formatBytes(bytes: number) {
  if (bytes >= 1024 ** 3) {
    return `${(bytes / 1024 ** 3).toFixed(1)} GiB`
  }
  if (bytes >= 1024 ** 2) {
    return `${(bytes / 1024 ** 2).toFixed(0)} MiB`
  }
  return `${(bytes / 1024).toFixed(0)} KiB`
}
</script>

<style scoped>
.workers-panel {
  container-type: inline-size;
}

.worker-cell-label {
  display: none;
}

@container (max-width: 900px) {
  .workers-table,
  .workers-table tbody,
  .workers-table tr:not(.worker-row),
  .workers-table td {
    display: block;
  }

  .workers-table colgroup,
  .workers-table thead {
    display: none;
  }

  .workers-table .worker-row {
    display: grid;
    grid-template-columns: repeat(2, minmax(0, 1fr));
    gap: 0.75rem 1rem;
    padding: 1rem;
  }

  .worker-row td {
    padding: 0;
  }

  .worker-status {
    justify-self: end;
  }

  .worker-cell-label {
    display: block;
  }

  .worker-jobs {
    text-align: left;
  }
}
</style>
