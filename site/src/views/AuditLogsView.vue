<template>
  <div class="space-y-6">
    <div>
      <h1 class="text-3xl font-semibold tracking-tight text-white">
        Audit Logs
      </h1>
      <p class="mt-2 text-sm text-gray-400">
        Review the latest organization activity and inspect action context.
      </p>
    </div>

    <section class="rounded-3xl border border-surface-border bg-surface-raised p-5">
      <div class="flex flex-col gap-3 lg:flex-row lg:items-center lg:justify-between">
        <div class="grid flex-1 gap-3 md:grid-cols-2">
          <label class="space-y-2 text-sm text-gray-300">
            <span class="block text-xs uppercase tracking-[0.2em] text-gray-500">Action</span>
            <select
              :value="actionFilter"
              class="w-full rounded-2xl border border-surface-border bg-surface-overlay px-4 py-3 text-sm text-gray-100"
              @change="handleFilterChange('action', ($event.target as HTMLSelectElement).value)"
            >
              <option value="">All actions</option>
              <option
                v-for="action in actionOptions"
                :key="action"
                :value="action"
              >
                {{ action }}
              </option>
            </select>
          </label>

          <label class="space-y-2 text-sm text-gray-300">
            <span class="block text-xs uppercase tracking-[0.2em] text-gray-500">Resource Type</span>
            <select
              :value="resourceTypeFilter"
              class="w-full rounded-2xl border border-surface-border bg-surface-overlay px-4 py-3 text-sm text-gray-100"
              @change="handleFilterChange('resource_type', ($event.target as HTMLSelectElement).value)"
            >
              <option value="">All resource types</option>
              <option
                v-for="resourceType in resourceTypeOptions"
                :key="resourceType"
                :value="resourceType"
              >
                {{ resourceType }}
              </option>
            </select>
          </label>
        </div>

        <button
          class="rounded-2xl border border-surface-border bg-surface-overlay px-4 py-3 text-sm text-gray-300 transition hover:border-accent/50 hover:text-white"
          type="button"
          @click="resetFilters"
        >
          Reset filters
        </button>
      </div>
    </section>

    <section class="overflow-hidden rounded-3xl border border-surface-border bg-surface-raised">
      <div
        v-if="loading"
        class="px-6 py-10 text-sm text-gray-500"
      >
        Loading audit logs...
      </div>

      <div
        v-else-if="entries.length === 0"
        class="px-6 py-10 text-sm text-gray-500"
      >
        No audit log entries match the current filters.
      </div>

      <template v-else>
        <div class="overflow-x-auto">
          <table class="min-w-full divide-y divide-surface-border-subtle text-sm">
            <thead class="bg-surface-overlay/80 text-left text-xs uppercase tracking-[0.18em] text-gray-500">
              <tr>
                <th class="px-6 py-4 font-medium">
                  Date/Time
                </th>
                <th class="px-6 py-4 font-medium">
                  Actor
                </th>
                <th class="px-6 py-4 font-medium">
                  Action
                </th>
                <th class="px-6 py-4 font-medium">
                  Resource Type
                </th>
                <th class="px-6 py-4 font-medium">
                  Resource
                </th>
                <th class="px-6 py-4 font-medium">
                  IP Address
                </th>
              </tr>
            </thead>
            <tbody class="divide-y divide-surface-border-subtle">
              <template
                v-for="entry in entries"
                :key="entry.id"
              >
                <tr
                  class="cursor-pointer transition hover:bg-white/5"
                  @click="toggleExpanded(entry.id)"
                >
                  <td class="whitespace-nowrap px-6 py-4 text-gray-300">
                    {{ formatDate(entry.created_at) }}
                  </td>
                  <td class="px-6 py-4">
                    <div class="flex items-center gap-3">
                      <span class="font-medium text-white">{{ entry.actor_display }}</span>
                      <span class="rounded-full border border-surface-border px-2.5 py-1 text-[11px] uppercase tracking-[0.16em] text-gray-400">
                        {{ entry.actor_type }}
                      </span>
                    </div>
                  </td>
                  <td class="px-6 py-4 font-mono text-xs text-accent">
                    {{ entry.action }}
                  </td>
                  <td class="px-6 py-4 text-gray-300">
                    {{ entry.resource_type }}
                  </td>
                  <td class="px-6 py-4 text-gray-300">
                    {{ entry.resource_id }}
                  </td>
                  <td class="px-6 py-4 text-gray-400">
                    {{ entry.ip_address }}
                  </td>
                </tr>
                <tr
                  v-if="expandedRows.includes(entry.id)"
                  class="bg-surface-overlay/70"
                >
                  <td
                    colspan="6"
                    class="px-6 py-4"
                  >
                    <pre class="overflow-x-auto rounded-2xl border border-surface-border bg-surface px-4 py-3 text-xs text-gray-300">{{ formatContext(entry.context) }}</pre>
                  </td>
                </tr>
              </template>
            </tbody>
          </table>
        </div>

        <div class="flex items-center justify-between border-t border-surface-border-subtle px-6 py-4 text-sm text-gray-400">
          <div>
            Page {{ pagination.page }} of {{ totalPages }}
          </div>
          <div class="flex items-center gap-3">
            <button
              class="rounded-xl border border-surface-border px-3 py-2 transition hover:border-accent/50 hover:text-white disabled:cursor-not-allowed disabled:opacity-40"
              type="button"
              :disabled="pagination.page <= 1"
              @click="changePage(pagination.page - 1)"
            >
              Previous
            </button>
            <button
              class="rounded-xl border border-surface-border px-3 py-2 transition hover:border-accent/50 hover:text-white disabled:cursor-not-allowed disabled:opacity-40"
              type="button"
              :disabled="pagination.page >= totalPages"
              @click="changePage(pagination.page + 1)"
            >
              Next
            </button>
          </div>
        </div>
      </template>
    </section>
  </div>
</template>

<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'

import { api, type AuditLogEntry } from '@/api/client'

const KNOWN_ACTIONS = [
  'scan.trigger',
  'vuln.suppress',
  'vuln.unsuppress',
  'release.create',
  'release.update',
  'release.delete',
  'client.create',
  'client.update',
  'client.delete',
  'gate.override',
  'gate.create',
  'gate.update',
  'gate.delete',
  'config.change',
  'onboarding.pr',
  'integration.create',
  'integration.update',
  'integration.delete',
  'repo.create',
  'repo.update',
  'repo.delete',
  'setting.update',
]

const KNOWN_RESOURCE_TYPES = [
  'scan',
  'advisory',
  'vuln_match',
  'release',
  'client',
  'repository',
  'quality_gate',
  'integration',
  'notification_rule',
]

const route = useRoute()
const router = useRouter()

const entries = ref<AuditLogEntry[]>([])
const loading = ref(true)
const expandedRows = ref<string[]>([])
const actionFilter = ref('')
const resourceTypeFilter = ref('')
const pagination = ref({ page: 1, per_page: 50, total: 0 })

const totalPages = computed(() => Math.max(1, Math.ceil(pagination.value.total / pagination.value.per_page)))
const actionOptions = computed(() => Array.from(new Set([...KNOWN_ACTIONS, ...entries.value.map((entry) => entry.action)])).sort())
const resourceTypeOptions = computed(() => Array.from(new Set([...KNOWN_RESOURCE_TYPES, ...entries.value.map((entry) => entry.resource_type)])).sort())

watch(
  () => route.query,
  () => {
    actionFilter.value = typeof route.query.action === 'string' ? route.query.action : ''
    resourceTypeFilter.value = typeof route.query.resource_type === 'string' ? route.query.resource_type : ''

    const page = Number(typeof route.query.page === 'string' ? route.query.page : '1')
    pagination.value.page = Number.isFinite(page) && page > 0 ? page : 1

    void loadAuditLogs()
  },
  { immediate: true },
)

async function loadAuditLogs() {
  loading.value = true

  try {
    const res = await api.listAuditLogs(route.params.provider as string, route.params.slug as string, {
      action: actionFilter.value || undefined,
      resource_type: resourceTypeFilter.value || undefined,
      page: pagination.value.page,
      per_page: pagination.value.per_page,
    })

    entries.value = res.data
    pagination.value = res.pagination
    expandedRows.value = []
  } catch {
    entries.value = []
    pagination.value = { ...pagination.value, total: 0 }
  } finally {
    loading.value = false
  }
}

function buildQuery(page = 1) {
  const query: Record<string, string> = {}

  if (actionFilter.value) {
    query.action = actionFilter.value
  }
  if (resourceTypeFilter.value) {
    query.resource_type = resourceTypeFilter.value
  }
  if (page > 1) {
    query.page = String(page)
  }

  return query
}

function handleFilterChange(field: 'action' | 'resource_type', value: string) {
  if (field === 'action') {
    actionFilter.value = value
  } else {
    resourceTypeFilter.value = value
  }

  void router.replace({ query: buildQuery(1) })
}

function resetFilters() {
  actionFilter.value = ''
  resourceTypeFilter.value = ''
  void router.replace({ query: {} })
}

function changePage(page: number) {
  void router.replace({ query: buildQuery(page) })
}

function toggleExpanded(id: string) {
  if (expandedRows.value.includes(id)) {
    expandedRows.value = expandedRows.value.filter((entryId) => entryId !== id)
    return
  }

  expandedRows.value = [...expandedRows.value, id]
}

function formatDate(value: string) {
  return new Date(value).toLocaleString()
}

function formatContext(context?: Record<string, unknown>) {
  return JSON.stringify(context || {}, null, 2)
}
</script>