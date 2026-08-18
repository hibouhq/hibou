<template>
  <div class="space-y-3">
    <!-- Header row: title-ish blurb + filters, GitHub audit-log style -->
    <div class="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
      <p class="text-sm text-gray-400">
        {{ repo ? 'Actions recorded for this repository.' : 'Actions recorded across this organization.' }}
        <span
          v-if="!loading && !forbidden"
          class="text-gray-500"
        >{{ pagination.total }} {{ pagination.total === 1 ? 'event' : 'events' }}</span>
      </p>

      <div class="flex flex-wrap items-center gap-2">
        <select
          v-model="actionFilter"
          class="h-7 rounded-md border border-surface-border bg-surface-overlay px-2 text-xs text-gray-300 focus:border-accent/50 focus:outline-none"
          aria-label="Filter by action"
        >
          <option value="">
            Action: all
          </option>
          <option
            v-for="action in actionOptions"
            :key="action"
            :value="action"
          >
            {{ action }}
          </option>
        </select>

        <select
          v-model="resourceTypeFilter"
          class="h-7 rounded-md border border-surface-border bg-surface-overlay px-2 text-xs text-gray-300 focus:border-accent/50 focus:outline-none"
          aria-label="Filter by resource type"
        >
          <option value="">
            Resource: all
          </option>
          <option
            v-for="resourceType in resourceTypeOptions"
            :key="resourceType"
            :value="resourceType"
          >
            {{ resourceType }}
          </option>
        </select>

        <button
          v-if="actionFilter || resourceTypeFilter"
          class="h-7 rounded-md px-2 text-xs text-gray-400 transition hover:text-white"
          type="button"
          @click="resetFilters"
        >
          Clear
        </button>
      </div>
    </div>

    <!-- Event list -->
    <div class="overflow-hidden rounded-md border border-surface-border">
      <div
        v-if="loading"
        class="px-4 py-10 text-center text-sm text-gray-500"
      >
        Loading audit log…
      </div>

      <div
        v-else-if="forbidden"
        class="px-4 py-12 text-center"
      >
        <ShieldAlert class="mx-auto h-6 w-6 text-gray-600" />
        <p class="mt-2 text-sm font-medium text-gray-300">
          Audit log is restricted
        </p>
        <p class="mt-1 text-xs text-gray-500">
          Only organization admins can view audit events.
        </p>
      </div>

      <div
        v-else-if="entries.length === 0"
        class="px-4 py-12 text-center"
      >
        <ScrollText class="mx-auto h-6 w-6 text-gray-600" />
        <p class="mt-2 text-sm font-medium text-gray-300">
          No events found
        </p>
        <p class="mt-1 text-xs text-gray-500">
          {{ actionFilter || resourceTypeFilter ? 'No events match the current filters.' : 'Actions taken here will show up in this log.' }}
        </p>
      </div>

      <ul
        v-else
        class="divide-y divide-surface-border-subtle"
      >
        <li
          v-for="entry in entries"
          :key="entry.id"
        >
          <button
            class="grid w-full grid-cols-[auto_minmax(0,1fr)_auto] items-start gap-3 px-3 py-2.5 text-left transition hover:bg-white/[0.03]"
            type="button"
            :aria-expanded="expandedId === entry.id"
            @click="toggleExpanded(entry.id)"
          >
            <span
              class="mt-0.5 flex h-6 w-6 shrink-0 items-center justify-center rounded-full border border-surface-border bg-surface-overlay"
              :title="entry.actor_type"
            >
              <KeyRound
                v-if="entry.actor_type === 'api_key'"
                class="h-3 w-3 text-gray-400"
              />
              <Bot
                v-else-if="entry.actor_type === 'system'"
                class="h-3 w-3 text-gray-400"
              />
              <span
                v-else
                class="text-[10px] font-semibold uppercase text-gray-300"
              >{{ actorInitials(entry.actor_display) }}</span>
            </span>

            <span class="min-w-0 text-[13px] leading-5">
              <span class="font-semibold text-gray-100">{{ entry.actor_display || 'unknown' }}</span>
              <code class="mx-1.5 rounded bg-surface-overlay px-1.5 py-0.5 font-mono text-xs text-accent">{{ entry.action }}</code>
              <span class="text-gray-400">{{ entry.resource_type }}</span>
              <span
                v-if="resourceLabel(entry)"
                class="text-gray-500"
              > · {{ resourceLabel(entry) }}</span>
            </span>

            <span class="flex shrink-0 flex-col items-end gap-0.5 pt-0.5 text-xs text-gray-500">
              <span :title="formatDateTime(entry.created_at)">{{ relativeTime(entry.created_at) }}</span>
              <span
                v-if="entry.ip_address"
                class="font-mono text-[11px] text-gray-600"
              >{{ entry.ip_address }}</span>
            </span>
          </button>

          <div
            v-if="expandedId === entry.id"
            class="border-t border-surface-border-subtle bg-surface px-3 py-2.5"
          >
            <dl class="grid gap-x-6 gap-y-1 text-xs sm:grid-cols-2">
              <div class="flex gap-2">
                <dt class="w-20 shrink-0 text-gray-500">
                  Resource
                </dt>
                <dd class="break-all font-mono text-gray-300">
                  {{ entry.resource_id || '—' }}
                </dd>
              </div>
              <div class="flex gap-2">
                <dt class="w-20 shrink-0 text-gray-500">
                  Time
                </dt>
                <dd class="text-gray-300">
                  {{ formatDateTime(entry.created_at) }}
                </dd>
              </div>
            </dl>
            <pre
              v-if="hasContext(entry)"
              class="mt-2 overflow-x-auto rounded-md border border-surface-border-subtle bg-surface-raised px-3 py-2 font-mono text-[11px] leading-relaxed text-gray-400"
            >{{ formatContext(entry.context) }}</pre>
          </div>
        </li>
      </ul>

      <!-- Pagination, GitHub Newer/Older style -->
      <div
        v-if="!loading && !forbidden && totalPages > 1"
        class="flex items-center justify-center gap-2 border-t border-surface-border-subtle px-3 py-2.5"
      >
        <button
          class="rounded-md px-2.5 py-1 text-xs font-medium transition"
          :class="page <= 1 ? 'cursor-not-allowed text-gray-600' : 'text-accent hover:bg-surface-overlay'"
          type="button"
          :disabled="page <= 1"
          @click="page -= 1"
        >
          ‹ Newer
        </button>
        <span class="text-xs text-gray-500">{{ page }} / {{ totalPages }}</span>
        <button
          class="rounded-md px-2.5 py-1 text-xs font-medium transition"
          :class="page >= totalPages ? 'cursor-not-allowed text-gray-600' : 'text-accent hover:bg-surface-overlay'"
          type="button"
          :disabled="page >= totalPages"
          @click="page += 1"
        >
          Older ›
        </button>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { Bot, KeyRound, ScrollText, ShieldAlert } from 'lucide-vue-next'
import { computed, ref, watch } from 'vue'

import { api, type AuditLogEntry } from '@/api/client'
import { formatDateTime, relativeTime } from '@/lib/datetime'

const props = defineProps<{
  provider: string
  slug: string
  // When set, the log is scoped to this repository.
  repo?: string
}>()

const PER_PAGE = 50

const entries = ref<AuditLogEntry[]>([])
const loading = ref(true)
const forbidden = ref(false)
const expandedId = ref('')
const actionFilter = ref('')
const resourceTypeFilter = ref('')
const page = ref(1)
const pagination = ref({ page: 1, per_page: PER_PAGE, total: 0 })

// Known values seed the dropdowns so filtering works before the first page of
// results has shown every kind; observed values are merged in.
const KNOWN_ACTIONS = [
  'scan.trigger',
  'vuln.suppress',
  'vuln.unsuppress',
  'finding.create',
  'finding.acceptance',
  'secret.revoked',
  'release.create',
  'release.update',
  'release.delete',
  'client.create',
  'client.update',
  'client.delete',
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
  'member.add',
  'member.update',
  'member.remove',
  'apikey.create',
  'apikey.update',
  'apikey.delete',
  'apikey.rotate',
]

const KNOWN_RESOURCE_TYPES = [
  'scan',
  'advisory',
  'vuln_match',
  'release',
  'client',
  'repository',
  'organization',
  'quality_gate',
  'integration',
  'notification_rule',
  'api_key',
  'member',
]

const totalPages = computed(() => Math.max(1, Math.ceil(pagination.value.total / pagination.value.per_page)))
const actionOptions = computed(() => Array.from(new Set([...KNOWN_ACTIONS, ...entries.value.map((entry) => entry.action)])).sort())
const resourceTypeOptions = computed(() => Array.from(new Set([...KNOWN_RESOURCE_TYPES, ...entries.value.map((entry) => entry.resource_type)])).sort())

watch([actionFilter, resourceTypeFilter], () => {
  page.value = 1
  void load()
})

watch(page, () => {
  void load()
})

watch(
  () => [props.provider, props.slug, props.repo],
  () => {
    page.value = 1
    void load()
  },
  { immediate: true },
)

async function load() {
  loading.value = true
  forbidden.value = false

  try {
    const res = await api.listAuditLogs(props.provider, props.slug, {
      action: actionFilter.value || undefined,
      resource_type: resourceTypeFilter.value || undefined,
      repo: props.repo || undefined,
      page: page.value,
      per_page: PER_PAGE,
    })

    entries.value = res.data
    pagination.value = res.pagination
    expandedId.value = ''
  } catch (loadError) {
    entries.value = []
    pagination.value = { page: 1, per_page: PER_PAGE, total: 0 }
    // The server answers 404 to non-admins so the log is indistinguishable
    // from a missing org; render that as the restricted state.
    if (loadError instanceof Error && /not found|forbidden|403|404/i.test(loadError.message)) {
      forbidden.value = true
    }
  } finally {
    loading.value = false
  }
}

function resetFilters() {
  actionFilter.value = ''
  resourceTypeFilter.value = ''
}

function toggleExpanded(id: string) {
  expandedId.value = expandedId.value === id ? '' : id
}

function actorInitials(display: string) {
  const trimmed = display.trim()
  if (!trimmed) {
    return '?'
  }
  return trimmed
    .split(/\s+/)
    .slice(0, 2)
    .map((part) => part[0] ?? '')
    .join('')
}

function resourceLabel(entry: AuditLogEntry) {
  // Prefer a human-readable name from the context over a bare UUID.
  const context = entry.context ?? {}
  for (const key of ['name', 'title', 'repo_name', 'token_name', 'version']) {
    const value = context[key]
    if (typeof value === 'string' && value) {
      return value
    }
  }
  return ''
}

function hasContext(entry: AuditLogEntry) {
  return entry.context && Object.keys(entry.context).length > 0
}

function formatContext(context?: Record<string, unknown>) {
  return JSON.stringify(context ?? {}, null, 2)
}
</script>
