<template>
  <div class="space-y-5">
    <div class="flex flex-wrap items-start justify-between gap-3">
      <div>
        <h2 class="text-lg font-semibold text-white">
          Storage
        </h2>
        <p class="mt-1 text-sm text-gray-400">
          Database and artifact storage usage, instance-wide. Sizes only; costs depend on your provider's prices.
        </p>
      </div>
      <button
        class="flex items-center gap-1.5 rounded-md border border-surface-border px-2.5 py-1 text-xs text-gray-400 transition hover:bg-surface-raised hover:text-white"
        title="Reload the latest sample"
        @click="refresh"
      >
        <RefreshCw class="h-3 w-3" />
        Reload
      </button>
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
      Loading storage…
    </div>

    <template v-else-if="storage">
      <div
        v-for="check in checks"
        :key="check.title"
        class="flex items-start gap-2.5 rounded-md border px-4 py-3 text-sm"
        :class="check.level === 'danger' ? 'border-danger/30 bg-danger/10 text-red-200' : 'border-warn/40 bg-warn/10 text-yellow-200'"
      >
        <AlertTriangle class="mt-0.5 h-4 w-4 shrink-0" />
        <div>
          <span class="font-medium">{{ check.title }}:</span>
          {{ check.detail }}
        </div>
      </div>

      <div
        v-if="!sample"
        class="rounded-xl border border-surface-border bg-surface-raised/40 p-6 text-center text-sm text-gray-400"
      >
        <template v-if="storage.enabled">
          No sample yet. The sampler runs at startup and every {{ formatInterval(storage.interval_seconds) }}; reload in a minute.
        </template>
        <template v-else>
          The storage sampler is disabled (<code class="text-gray-300">storage_usage.enabled: false</code>).
        </template>
      </div>

      <template v-else>
        <!-- Stat tiles -->
        <div class="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
          <div class="rounded-xl border border-surface-border bg-surface-raised/40 p-4">
            <div class="text-[11px] uppercase tracking-[0.16em] text-gray-500">
              Database
            </div>
            <div class="mt-2 text-2xl font-semibold text-white">
              {{ pg && !pg.error ? formatBytes(pg.database_bytes) : '—' }}
            </div>
            <div class="mt-0.5 text-xs text-gray-500">
              {{ pg ? `${pg.tables.length} tables` : 'not sampled' }}
            </div>
          </div>
          <div class="rounded-xl border border-surface-border bg-surface-raised/40 p-4">
            <div class="text-[11px] uppercase tracking-[0.16em] text-gray-500">
              Artifacts
            </div>
            <div class="mt-2 text-2xl font-semibold text-white">
              {{ formatBytes(ledger.bytes) }}
            </div>
            <div class="mt-0.5 text-xs text-gray-500">
              {{ formatCount(ledger.objects) }} objects · {{ storage.artifact_backend }}
            </div>
          </div>
          <div class="rounded-xl border border-surface-border bg-surface-raised/40 p-4">
            <div class="text-[11px] uppercase tracking-[0.16em] text-gray-500">
              Connections
            </div>
            <div class="mt-2 text-2xl font-semibold text-white">
              <template v-if="pg && !pg.error">
                {{ pg.connections_used }}<span class="text-base font-normal text-gray-500">/{{ pg.connections_max }}</span>
              </template>
              <template v-else>
                —
              </template>
            </div>
            <div class="mt-0.5 text-xs text-gray-500">
              all databases on the server
            </div>
          </div>
          <div class="rounded-xl border border-surface-border bg-surface-raised/40 p-4">
            <div class="text-[11px] uppercase tracking-[0.16em] text-gray-500">
              {{ volume ? 'Volume free' : 'Sampled' }}
            </div>
            <div class="mt-2 text-2xl font-semibold text-white">
              <template v-if="volume">
                {{ formatBytes(volume.free) }}
              </template>
              <template v-else>
                {{ sampledAt ? relativeTime(sampledAt) : '—' }}
              </template>
            </div>
            <div class="mt-0.5 text-xs text-gray-500">
              <template v-if="volume">
                of {{ formatBytes(volume.capacity) }} ({{ Math.round(volume.free / volume.capacity * 100) }}% free)
              </template>
              <template v-else>
                every {{ formatInterval(storage.interval_seconds) }}
              </template>
            </div>
          </div>
        </div>

        <!-- Database health -->
        <section
          v-if="pg && !pg.error"
          class="rounded-xl border border-surface-border bg-surface-raised/40 p-4"
        >
          <h3 class="flex items-center gap-2 text-sm font-semibold text-white">
            <Database class="h-4 w-4 text-gray-500" />
            Database health
          </h3>
          <dl class="mt-3 grid gap-3 text-sm sm:grid-cols-3">
            <div>
              <dt class="text-xs text-gray-500">
                Transaction-ID age
              </dt>
              <dd class="mt-0.5 font-mono text-gray-200">
                {{ formatCount(pg.xid_age) }}
                <span class="text-xs text-gray-500">/ 2.1B limit</span>
              </dd>
            </div>
            <div>
              <dt class="text-xs text-gray-500">
                Oldest open transaction
              </dt>
              <dd class="mt-0.5 font-mono text-gray-200">
                {{ pg.oldest_transaction_seconds !== undefined ? formatDuration(pg.oldest_transaction_seconds) : 'none' }}
              </dd>
            </div>
            <div>
              <dt class="text-xs text-gray-500">
                Cache hit ratio
              </dt>
              <dd class="mt-0.5 font-mono text-gray-200">
                {{ pg.cache_hit_ratio !== undefined ? `${(pg.cache_hit_ratio * 100).toFixed(2)}%` : '—' }}
              </dd>
            </div>
          </dl>
          <p class="mt-3 text-xs text-gray-500">
            Sampled {{ relativeTime(pg.collected_at) }} in {{ formatDuration(pg.duration_seconds) }}, every {{ formatInterval(storage.interval_seconds) }}.
          </p>
        </section>

        <!-- Tables -->
        <section
          v-if="pg && !pg.error && pg.tables.length"
          class="overflow-hidden rounded-xl border border-surface-border bg-surface-raised/40"
        >
          <div class="flex flex-wrap items-center justify-between gap-2 px-4 pt-4">
            <h3 class="flex items-center gap-2 text-sm font-semibold text-white">
              <Table2 class="h-4 w-4 text-gray-500" />
              Largest tables
            </h3>
            <span class="text-xs text-gray-500">
              partitions folded into their parent · row counts are estimates
            </span>
          </div>
          <div class="mt-3 overflow-x-auto">
            <table class="w-full text-sm">
              <thead>
                <tr class="border-b border-surface-border text-left text-[11px] uppercase tracking-wide text-gray-500">
                  <th class="px-4 py-2 font-medium">
                    Table
                  </th>
                  <th class="px-4 py-2 font-medium">
                    Share of database
                  </th>
                  <th class="px-4 py-2 text-right font-medium">
                    Data
                  </th>
                  <th class="px-4 py-2 text-right font-medium">
                    Indexes
                  </th>
                  <th class="px-4 py-2 text-right font-medium">
                    Live rows
                  </th>
                  <th class="px-4 py-2 text-right font-medium">
                    Dead rows
                  </th>
                </tr>
              </thead>
              <tbody class="divide-y divide-surface-border">
                <tr
                  v-for="table in visibleTables"
                  :key="table.name"
                  class="text-gray-300"
                >
                  <td class="px-4 py-2 font-mono text-xs">
                    {{ table.name }}
                  </td>
                  <td class="px-4 py-2">
                    <div class="flex items-center gap-2">
                      <div class="h-1.5 w-24 overflow-hidden rounded-full bg-surface-border">
                        <div
                          class="h-full rounded-full bg-accent"
                          :style="{ width: `${share(table)}%` }"
                        />
                      </div>
                      <span class="font-mono text-xs text-gray-400">{{ share(table).toFixed(1) }}%</span>
                    </div>
                  </td>
                  <td class="px-4 py-2 text-right font-mono text-xs">
                    {{ formatBytes(table.table_bytes) }}
                  </td>
                  <td class="px-4 py-2 text-right font-mono text-xs">
                    {{ formatBytes(table.index_bytes) }}
                  </td>
                  <td class="px-4 py-2 text-right font-mono text-xs">
                    {{ formatCount(table.live_rows) }}
                  </td>
                  <td
                    class="px-4 py-2 text-right font-mono text-xs"
                    :class="isBloated(table) ? 'text-warn' : ''"
                    :title="isBloated(table) ? 'Many dead rows: autovacuum may be falling behind' : undefined"
                  >
                    {{ formatCount(table.dead_rows) }}
                  </td>
                </tr>
              </tbody>
            </table>
          </div>
          <button
            v-if="pg.tables.length > TABLES_COLLAPSED"
            class="w-full border-t border-surface-border px-4 py-2 text-xs text-gray-400 transition hover:bg-surface-raised hover:text-white"
            @click="showAllTables = !showAllTables"
          >
            {{ showAllTables ? 'Show fewer' : `Show all ${pg.tables.length} tables` }}
          </button>
        </section>

        <!-- Artifacts -->
        <section class="overflow-hidden rounded-xl border border-surface-border bg-surface-raised/40">
          <div class="flex flex-wrap items-center justify-between gap-2 px-4 pt-4">
            <h3 class="flex items-center gap-2 text-sm font-semibold text-white">
              <HardDrive class="h-4 w-4 text-gray-500" />
              Artifacts
            </h3>
            <span class="text-xs text-gray-500">
              recorded by hibou, per kind
            </span>
          </div>
          <div class="mt-3 overflow-x-auto">
            <table class="w-full text-sm">
              <thead>
                <tr class="border-b border-surface-border text-left text-[11px] uppercase tracking-wide text-gray-500">
                  <th class="px-4 py-2 font-medium">
                    Kind
                  </th>
                  <th class="px-4 py-2 text-right font-medium">
                    Objects
                  </th>
                  <th class="px-4 py-2 text-right font-medium">
                    Size
                  </th>
                </tr>
              </thead>
              <tbody class="divide-y divide-surface-border">
                <tr
                  v-for="kind in sample.ledger?.kinds ?? []"
                  :key="kind.kind"
                  class="text-gray-300"
                >
                  <td class="px-4 py-2 text-xs">
                    {{ kind.kind }}
                  </td>
                  <td class="px-4 py-2 text-right font-mono text-xs">
                    {{ formatCount(kind.objects) }}
                  </td>
                  <td class="px-4 py-2 text-right font-mono text-xs">
                    {{ formatBytes(kind.bytes) }}
                  </td>
                </tr>
                <tr
                  v-if="!(sample.ledger?.kinds ?? []).length"
                  class="text-gray-500"
                >
                  <td
                    colspan="3"
                    class="px-4 py-3 text-center text-xs"
                  >
                    No artifacts stored yet.
                  </td>
                </tr>
              </tbody>
            </table>
          </div>
          <div class="border-t border-surface-border px-4 py-3 text-xs text-gray-400">
            <template v-if="!storage.inventory_enabled">
              Backend check is off. Enable <code class="text-gray-300">storage_usage.inventory.enabled</code> to compare what the {{ storage.artifact_backend }} backend actually holds against this ledger and find orphaned or missing objects.
            </template>
            <template v-else-if="!sample.backend">
              Backend check pending: it runs on the next sample.
            </template>
            <template v-else-if="!sample.backend.error">
              Backend holds {{ formatCount(sample.backend.objects) }} objects, {{ formatBytes(sample.backend.bytes) }}<template v-if="sample.backend.truncated">
                (stopped at the object cap, totals are partial)
              </template>.
              <template v-if="drift !== null">
                Difference with the ledger: <span :class="Math.abs(drift) > 0 ? 'text-gray-200' : ''">{{ drift >= 0 ? '+' : '−' }}{{ formatBytes(Math.abs(drift)) }}</span>.
              </template>
              Checked {{ relativeTime(sample.backend.collected_at) }}, every {{ formatInterval(storage.inventory_interval_seconds) }}.
            </template>
          </div>
        </section>
      </template>
    </template>
  </div>
</template>

<script setup lang="ts">
import { AlertTriangle, Database, HardDrive, RefreshCw, Table2 } from 'lucide-vue-next'
import { computed, onMounted, ref } from 'vue'

import type { InstanceStorage, StorageTableUsage } from '@/api/client'
import { api } from '@/api/client'
import { formatDuration, relativeTime } from '@/lib/datetime'
import { backendDrift, formatBytes, formatCount, formatInterval, isBloated, ledgerTotals, storageChecks, tableTotal } from '@/lib/storageUsage'

const TABLES_COLLAPSED = 15

const loading = ref(true)
const loadError = ref('')
const storage = ref<InstanceStorage | null>(null)
const showAllTables = ref(false)
const nowMs = ref(Date.now())

// The sample changes once per sampler interval, so a manual reload is enough;
// no polling.
async function refresh() {
  try {
    const response = await api.getInstanceStorage()
    storage.value = response.data ?? null
    nowMs.value = Date.now()
    loadError.value = ''
  } catch (error) {
    loadError.value = error instanceof Error ? error.message : 'Failed to load storage'
  } finally {
    loading.value = false
  }
}

onMounted(() => {
  void refresh()
})

const sample = computed(() => storage.value?.sample ?? null)
const pg = computed(() => sample.value?.postgres)
const ledger = computed(() => (storage.value ? ledgerTotals(storage.value) : { objects: 0, bytes: 0 }))
const checks = computed(() => (storage.value ? storageChecks(storage.value, nowMs.value) : []))
const drift = computed(() => (storage.value ? backendDrift(storage.value) : null))
const sampledAt = computed(() => pg.value?.collected_at ?? sample.value?.ledger?.collected_at)

const volume = computed(() => {
  const backend = sample.value?.backend
  if (!backend || backend.error || !backend.volume_capacity_bytes || backend.volume_free_bytes === undefined) {
    return null
  }
  return { capacity: backend.volume_capacity_bytes, free: backend.volume_free_bytes }
})

const visibleTables = computed(() => {
  const tables = pg.value?.tables ?? []
  return showAllTables.value ? tables : tables.slice(0, TABLES_COLLAPSED)
})

function share(table: StorageTableUsage) {
  const total = pg.value?.database_bytes ?? 0
  return total > 0 ? Math.min(100, (tableTotal(table) / total) * 100) : 0
}
</script>
