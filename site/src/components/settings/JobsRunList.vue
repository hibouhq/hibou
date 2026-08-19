<template>
  <section class="overflow-hidden rounded-xl border border-surface-border bg-surface-raised/40">
    <div class="flex flex-wrap items-center justify-between gap-2 px-4 pt-4">
      <h3 class="flex items-center gap-2 text-sm font-semibold text-white">
        <ListOrdered class="h-4 w-4 text-gray-500" />
        Runs
      </h3>
      <div class="flex flex-wrap items-center gap-2">
        <select
          v-model="kindFilter"
          class="rounded-lg border border-surface-border bg-surface-overlay px-2 py-1 text-xs text-gray-300 focus:border-accent/50 focus:outline-none"
        >
          <option value="">
            All kinds
          </option>
          <option
            v-for="kind in kinds"
            :key="kind"
            :value="kind"
          >
            {{ jobKindLabel(kind) }}
          </option>
        </select>
        <select
          v-model="statusFilter"
          class="rounded-lg border border-surface-border bg-surface-overlay px-2 py-1 text-xs text-gray-300 focus:border-accent/50 focus:outline-none"
        >
          <option value="">
            All statuses
          </option>
          <option
            v-for="status in statuses"
            :key="status"
            :value="status"
          >
            {{ status }}
          </option>
        </select>
        <input
          v-model="search"
          type="search"
          placeholder="Filter by repo, detail, error…"
          class="w-56 rounded-lg border border-surface-border bg-surface-overlay px-2 py-1 text-xs text-gray-300 placeholder:text-gray-600 focus:border-accent/50 focus:outline-none"
        >
      </div>
    </div>

    <div class="mt-3 overflow-x-auto">
      <table class="w-full text-sm">
        <thead>
          <tr class="border-b border-surface-border text-left text-[11px] uppercase tracking-wide text-gray-500">
            <th class="px-4 py-2 font-medium">
              Job
            </th>
            <th class="px-4 py-2 font-medium">
              Kind
            </th>
            <th class="px-4 py-2 font-medium">
              Status
            </th>
            <th class="px-4 py-2 font-medium">
              Queued
            </th>
            <th class="px-4 py-2 text-right font-medium">
              Waited
            </th>
            <th class="px-4 py-2 text-right font-medium">
              Ran
            </th>
            <th class="px-4 py-2 text-right font-medium">
              Attempts
            </th>
            <th class="px-4 py-2 font-medium">
              Error
            </th>
          </tr>
        </thead>
        <tbody class="divide-y divide-surface-border-subtle">
          <tr
            v-for="run in visible"
            :key="`${run.kind}-${run.id}`"
            class="text-gray-300"
          >
            <td class="max-w-[18rem] px-4 py-2">
              <div class="truncate font-mono text-xs">
                {{ run.label }}
              </div>
              <div
                v-if="run.detail"
                class="truncate text-[10px] text-gray-600"
                :title="run.detail"
              >
                {{ run.detail }}
              </div>
            </td>
            <td class="whitespace-nowrap px-4 py-2 text-xs text-gray-400">
              {{ jobKindLabel(run.kind) }}
            </td>
            <td class="px-4 py-2">
              <span
                class="inline-flex items-center gap-1.5 rounded-full border border-surface-border-subtle px-2 py-0.5 text-[10px] font-medium text-gray-300"
              >
                <span
                  class="h-1.5 w-1.5 rounded-full"
                  :style="{ backgroundColor: statusColor(run.status) }"
                />
                {{ run.status }}
              </span>
            </td>
            <td
              class="whitespace-nowrap px-4 py-2 text-xs text-gray-400"
              :title="run.queued_at"
            >
              {{ relativeTime(run.queued_at) }}
            </td>
            <td class="whitespace-nowrap px-4 py-2 text-right font-mono text-xs">
              {{ waited(run) }}
            </td>
            <td class="whitespace-nowrap px-4 py-2 text-right font-mono text-xs">
              {{ ran(run) }}
            </td>
            <td class="px-4 py-2 text-right font-mono text-xs">
              {{ run.attempts > 0 ? run.attempts : '—' }}
            </td>
            <td class="max-w-[22rem] px-4 py-2">
              <span
                v-if="run.error"
                class="block truncate text-xs text-danger/90"
                :title="run.error"
              >{{ run.error }}</span>
              <span
                v-else
                class="text-xs text-gray-600"
              >—</span>
            </td>
          </tr>
          <tr v-if="visible.length === 0">
            <td
              colspan="8"
              class="px-4 py-6 text-center text-sm text-gray-500"
            >
              No runs match the current filters.
            </td>
          </tr>
        </tbody>
      </table>
    </div>
    <div
      v-if="filtered.length > visible.length"
      class="border-t border-surface-border-subtle px-4 py-2 text-center"
    >
      <button
        type="button"
        class="text-xs text-gray-400 transition hover:text-white"
        @click="limit += PAGE"
      >
        Show more ({{ filtered.length - visible.length }} remaining)
      </button>
    </div>
  </section>
</template>

<script setup lang="ts">
import { ListOrdered } from 'lucide-vue-next'
import { computed, ref, watch } from 'vue'

import type { InstanceJobRun } from '@/api/client'
import { formatDuration, relativeTime } from '@/lib/datetime'
import { jobKindLabel } from '@/lib/jobStats'

// The flat, filterable complement to the timeline: same runs payload, newest
// first, nothing hidden behind per-kind row caps.
const props = defineProps<{
  runs: InstanceJobRun[]
  nowMs: number
}>()

const PAGE = 25

const kindFilter = ref('')
const statusFilter = ref('')
const search = ref('')
const limit = ref(PAGE)

// New filters reset pagination — page 3 of a different result set is nonsense.
watch([kindFilter, statusFilter, search], () => {
  limit.value = PAGE
})

const kinds = computed(() => [...new Set(props.runs.map((run) => run.kind))].sort())
const statuses = computed(() => [...new Set(props.runs.map((run) => run.status))].sort())

const filtered = computed(() => {
  const needle = search.value.trim().toLowerCase()
  const matches = props.runs.filter((run) => {
    if (kindFilter.value && run.kind !== kindFilter.value) return false
    if (statusFilter.value && run.status !== statusFilter.value) return false
    if (needle) {
      const haystack = `${run.label} ${run.detail ?? ''} ${run.error ?? ''} ${run.worker_id ?? ''}`.toLowerCase()
      if (!haystack.includes(needle)) return false
    }
    return true
  })
  return matches.sort((a, b) => Date.parse(b.queued_at) - Date.parse(a.queued_at))
})

const visible = computed(() => filtered.value.slice(0, limit.value))

// Mirrors the timeline's status palette so one status is one colour everywhere.
const STATUS_COLORS: Record<string, string> = {
  queued: '#6e7681',
  running: '#58a6ff',
  complete: '#3fb950',
  failed: '#f85149',
  cancelled: '#d29922',
}

function statusColor(status: string): string {
  return STATUS_COLORS[status] ?? '#6e7681'
}

function waited(run: InstanceJobRun): string {
  const queued = Date.parse(run.queued_at)
  const started = run.started_at ? Date.parse(run.started_at) : props.nowMs
  if (!Number.isFinite(queued) || !Number.isFinite(started) || started < queued) return '—'
  return formatDuration((started - queued) / 1000)
}

function ran(run: InstanceJobRun): string {
  if (!run.started_at) return '—'
  const started = Date.parse(run.started_at)
  const finished = run.finished_at ? Date.parse(run.finished_at) : props.nowMs
  if (!Number.isFinite(started) || !Number.isFinite(finished) || finished < started) return '—'
  return formatDuration((finished - started) / 1000)
}
</script>
