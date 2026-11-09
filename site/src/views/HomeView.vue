<template>
  <div class="space-y-5">
    <div class="flex flex-wrap items-end justify-between gap-3 pt-1">
      <div>
        <h1 class="text-xl font-semibold text-white">
          Home
        </h1>
        <p class="mt-1 text-sm text-gray-400">
          What waits for you across your organizations.
        </p>
      </div>
      <button
        type="button"
        class="inline-flex items-center gap-1.5 rounded-md border border-surface-border bg-surface-overlay px-3 py-1.5 text-xs font-medium text-gray-300 transition hover:border-accent/40 hover:text-white disabled:opacity-50"
        :disabled="loading"
        @click="load"
      >
        <RefreshCw
          class="h-3.5 w-3.5"
          :class="loading ? 'animate-spin' : ''"
        />
        Refresh
      </button>
    </div>

    <div
      v-if="loading && !home"
      class="py-8 text-sm text-gray-500"
    >
      Loading your dashboard…
    </div>

    <div
      v-else-if="error && !home"
      class="flex flex-wrap items-center justify-between gap-3 rounded-md border border-danger/30 bg-danger/10 px-4 py-3 text-sm text-red-200"
    >
      <span>{{ error }}</span>
      <button
        type="button"
        class="rounded-md border border-danger/30 px-3 py-1 text-xs font-medium text-red-100 transition hover:bg-danger/15"
        @click="load"
      >
        Retry
      </button>
    </div>

    <template v-else-if="home">
      <div class="grid gap-5 lg:grid-cols-[17rem_minmax(0,1fr)]">
        <aside class="space-y-5 lg:sticky lg:top-4 lg:self-start">
          <!-- Organizations -->
          <section>
            <div class="flex items-center justify-between">
              <h2 class="flex items-center gap-2 text-sm font-semibold text-white">
                <Building2 class="h-4 w-4 text-gray-500" />
                Organizations
              </h2>
              <RouterLink
                :to="{ name: 'orgs' }"
                class="inline-flex items-center gap-1 rounded-md px-1.5 py-0.5 text-xs text-gray-400 transition hover:bg-surface-overlay hover:text-white"
                title="Add or manage organizations"
              >
                <Plus class="h-3.5 w-3.5" />
                Add
              </RouterLink>
            </div>
            <ul class="mt-2 space-y-0.5">
              <li
                v-for="org in home.orgs"
                :key="org.id"
              >
                <RouterLink
                  :to="{ name: 'org-overview', params: { provider: org.provider, slug: org.slug } }"
                  class="flex items-center gap-2 rounded-md px-2 py-1.5 text-sm text-gray-300 transition hover:bg-surface-overlay hover:text-white"
                  :title="`${org.provider} / ${org.slug} · ${org.role || 'member'}`"
                >
                  <ForgeIcon
                    :provider="org.provider"
                    size="sm"
                  />
                  <span class="min-w-0 flex-1 truncate">{{ org.display_name || org.name }}</span>
                  <span
                    v-if="org.open_incidents > 0"
                    class="rounded-full border border-warn/40 px-1.5 text-[11px] text-warn"
                    :title="`${org.open_incidents} open ${org.open_incidents === 1 ? 'incident' : 'incidents'}`"
                  >{{ org.open_incidents }}</span>
                </RouterLink>
              </li>
            </ul>
          </section>

          <!-- Your repositories -->
          <section>
            <h2 class="flex items-center gap-2 text-sm font-semibold text-white">
              <FolderGit2 class="h-4 w-4 text-gray-500" />
              Your repositories
            </h2>
            <ul
              v-if="home.repos.length > 0"
              class="mt-2 space-y-0.5"
            >
              <li
                v-for="repo in home.repos"
                :key="repo.id"
              >
                <RouterLink
                  :to="{ name: 'repo-overview', params: { provider: repo.org_provider, slug: repo.org_slug, repoSlug: repo.slug } }"
                  class="flex items-center gap-2 rounded-md px-2 py-1.5 text-sm transition hover:bg-surface-overlay"
                  :title="repo.last_visited_at ? `Opened ${relativeTime(repo.last_visited_at)}` : 'Recently analysed'"
                >
                  <ForgeIcon
                    :provider="repo.org_provider"
                    size="sm"
                  />
                  <span class="min-w-0 truncate text-gray-400">{{ repo.org_slug }} /</span>
                  <span class="min-w-0 flex-1 truncate font-medium text-white">{{ repo.slug }}</span>
                </RouterLink>
              </li>
            </ul>
            <p
              v-else
              class="mt-2 px-2 text-xs text-gray-500"
            >
              Repositories you open appear here.
            </p>
            <p
              v-if="home.repos.length > 0 && !home.repos.some(repo => repo.visited)"
              class="mt-2 px-2 text-xs text-gray-500"
            >
              Recently analysed; the ones you open will rise to the top.
            </p>
          </section>
        </aside>

        <div class="min-w-0 space-y-5">
          <!-- Needs you -->
          <section class="overflow-hidden rounded-xl border border-surface-border">
            <div class="flex items-center justify-between border-b border-surface-border-subtle px-4 py-3">
              <h2 class="flex items-center gap-2 text-sm font-semibold text-white">
                <BellRing class="h-4 w-4 text-gray-500" />
                Needs you
              </h2>
              <span class="text-xs text-gray-500">{{ needsYou.length + home.approvals.length }} waiting</span>
            </div>
            <div
              v-if="needsYou.length === 0 && home.approvals.length === 0"
              class="px-4 py-8 text-center text-sm text-gray-500"
            >
              Nothing waits for you.
            </div>
            <ul
              v-else
              class="divide-y divide-surface-border-subtle"
            >
              <li
                v-for="action in shownNeedsYou"
                :key="action.id"
                class="flex flex-wrap items-center gap-x-3 gap-y-1 px-4 py-2.5 text-sm"
              >
                <span :class="priorityClass(action.priority)">{{ action.priority }}</span>
                <span class="font-medium text-gray-200">{{ action.label }}</span>
                <RouterLink
                  :to="incidentLink(action.org_provider, action.org_slug, action.number)"
                  class="min-w-0 truncate text-accent hover:underline"
                >
                  #{{ action.number }} {{ action.title }}
                </RouterLink>
                <span class="ml-auto text-xs text-gray-500">{{ action.org_slug }}</span>
                <CountdownText
                  class="font-mono text-xs"
                  :at="nullTime(action.due_at)"
                />
              </li>
              <li
                v-for="approval in home.approvals"
                :key="`${approval.type}-${approval.id}`"
                class="flex flex-wrap items-center gap-x-3 gap-y-1 px-4 py-2.5 text-sm"
              >
                <span class="rounded-full border border-warn/40 bg-warn/10 px-2 py-0.5 text-[11px] font-medium text-warn">
                  {{ APPROVAL_LABELS[approval.type] }}
                </span>
                <RouterLink
                  :to="incidentLink(approval.org_provider, approval.org_slug, approval.incident_number)"
                  class="min-w-0 truncate text-accent hover:underline"
                >
                  #{{ approval.incident_number }} {{ approval.incident_title }}
                </RouterLink>
                <span class="min-w-0 truncate text-xs text-gray-400">{{ approval.detail }}</span>
                <span class="ml-auto text-xs text-gray-500">{{ approval.org_slug }}</span>
              </li>
              <li
                v-if="needsYou.length > NEEDS_YOU_PREVIEW"
                class="px-4 py-2 text-center"
              >
                <button
                  type="button"
                  class="text-xs font-medium text-gray-400 transition hover:text-white"
                  @click="showAllNeedsYou = !showAllNeedsYou"
                >
                  {{ showAllNeedsYou ? 'Show the most urgent only' : `Show all ${needsYou.length} actions` }}
                </button>
              </li>
            </ul>
          </section>

          <!-- Incidents -->
          <section class="overflow-hidden rounded-xl border border-surface-border">
            <div class="flex flex-wrap items-center justify-between gap-2 border-b border-surface-border-subtle px-4 py-3">
              <h2 class="flex items-center gap-2 text-sm font-semibold text-white">
                <Siren class="h-4 w-4 text-gray-500" />
                Incidents
              </h2>
              <div
                v-if="kinds.length > 1"
                class="flex flex-wrap gap-1.5"
              >
                <button
                  type="button"
                  class="rounded-full border px-2.5 py-0.5 text-xs transition"
                  :class="kindFilter === '' ? 'border-accent/50 bg-accent/10 text-accent' : 'border-surface-border text-gray-400 hover:text-white'"
                  @click="kindFilter = ''"
                >
                  All {{ home.incidents.length }}
                </button>
                <button
                  v-for="entry in kinds"
                  :key="entry.kind"
                  type="button"
                  class="rounded-full border px-2.5 py-0.5 text-xs transition"
                  :class="kindFilter === entry.kind ? 'border-accent/50 bg-accent/10 text-accent' : 'border-surface-border text-gray-400 hover:text-white'"
                  :title="KIND_DESCRIPTIONS[entry.kind]"
                  @click="kindFilter = entry.kind"
                >
                  {{ KIND_LABELS[entry.kind] ?? entry.kind }} {{ entry.count }}
                </button>
              </div>
            </div>
            <div
              v-if="incidents.length === 0"
              class="px-4 py-8 text-center text-sm text-gray-500"
            >
              No open incidents.
            </div>
            <div
              v-else
              class="overflow-x-auto"
            >
              <table class="min-w-full divide-y divide-surface-border-subtle text-sm">
                <thead class="bg-surface-overlay text-left text-xs uppercase tracking-[0.14em] text-gray-500">
                  <tr>
                    <th class="px-4 py-2.5 font-medium">
                      Incident
                    </th>
                    <th class="px-4 py-2.5 font-medium">
                      Kind
                    </th>
                    <th class="px-4 py-2.5 font-medium">
                      State
                    </th>
                    <th class="px-4 py-2.5 font-medium">
                      Repository
                    </th>
                    <th class="px-4 py-2.5 font-medium">
                      Due
                    </th>
                  </tr>
                </thead>
                <tbody class="divide-y divide-surface-border-subtle">
                  <tr
                    v-for="incident in incidents"
                    :key="incident.id"
                    class="transition hover:bg-surface-overlay/50"
                  >
                    <td class="px-4 py-2.5">
                      <div class="flex items-center gap-2">
                        <span :class="priorityClass(incident.priority)">{{ incident.priority }}</span>
                        <RouterLink
                          :to="incidentLink(incident.org_provider, incident.org_slug, incident.number)"
                          class="text-accent hover:underline"
                        >
                          #{{ incident.number }} {{ incident.title }}
                        </RouterLink>
                      </div>
                      <div class="mt-0.5 text-xs text-gray-500">
                        {{ incident.org_name || incident.org_slug }}
                      </div>
                    </td>
                    <td
                      class="px-4 py-2.5 text-xs text-gray-300"
                      :title="KIND_DESCRIPTIONS[incident.kind]"
                    >
                      {{ KIND_LABELS[incident.kind] ?? incident.kind }}
                    </td>
                    <td class="px-4 py-2.5 text-xs text-gray-300">
                      <IncidentStatusPill
                        :status="incident.state"
                        :label="STATE_LABELS[incident.state]"
                      />
                    </td>
                    <td class="px-4 py-2.5 font-mono text-xs text-gray-400">
                      {{ nullString(incident.repo_slug) || '—' }}
                    </td>
                    <td class="whitespace-nowrap px-4 py-2.5 font-mono text-xs">
                      <CountdownText :at="nullTime(incident.due_at)" />
                    </td>
                  </tr>
                </tbody>
              </table>
            </div>
            <div
              v-if="home.noisy_rules.length > 0"
              class="border-t border-surface-border-subtle px-4 py-3"
            >
              <h3 class="text-[11px] uppercase tracking-[0.14em] text-gray-500">
                Rules that fired most this week
              </h3>
              <ul class="mt-2 space-y-1 text-xs">
                <li
                  v-for="(rule, index) in home.noisy_rules"
                  :key="index"
                  class="flex flex-wrap items-baseline gap-x-3"
                >
                  <span class="font-mono text-gray-400">{{ nullString(rule.repo_slug) || 'all repositories' }}</span>
                  <code class="font-mono text-gray-200">{{ nullString(rule.trigger_rule) || '—' }}</code>
                  <span class="ml-auto text-warn">{{ rule.opened }} opened</span>
                </li>
              </ul>
            </div>
          </section>

          <!-- Exposure -->
          <section class="overflow-hidden rounded-xl border border-surface-border">
            <div class="flex items-center justify-between border-b border-surface-border-subtle px-4 py-3">
              <h2 class="flex items-center gap-2 text-sm font-semibold text-white">
                <Users class="h-4 w-4 text-gray-500" />
                Exposure
              </h2>
              <span class="text-xs text-gray-500">Clients on releases an open incident touches</span>
            </div>
            <div
              v-if="home.exposure.clients.length === 0 && home.exposure.unknown_releases.length === 0"
              class="px-4 py-8 text-center text-sm text-gray-500"
            >
              No client runs a release an open incident affects.
            </div>
            <ul
              v-else
              class="divide-y divide-surface-border-subtle"
            >
              <li
                v-for="row in home.exposure.clients"
                :key="`${row.client_id}-${row.number}-${row.version}`"
                class="flex flex-wrap items-center gap-x-3 gap-y-1 px-4 py-2.5 text-sm"
              >
                <RouterLink
                  :to="{ name: 'client-overview', params: { provider: row.org_provider, slug: row.org_slug, clientSlug: row.client_slug } }"
                  class="font-medium text-gray-200 hover:text-accent"
                >
                  {{ row.client_name }}
                </RouterLink>
                <span class="font-mono text-xs text-gray-300">{{ row.version }}</span>
                <span
                  class="rounded-full border px-2 py-0.5 text-[11px]"
                  :class="exposureClass(row.status)"
                >{{ row.status }}</span>
                <RouterLink
                  :to="incidentLink(row.org_provider, row.org_slug, row.number)"
                  class="ml-auto min-w-0 truncate text-xs text-accent hover:underline"
                >
                  #{{ row.number }} {{ row.title }}
                </RouterLink>
              </li>
              <li
                v-for="row in home.exposure.unknown_releases"
                :key="`${row.release_id}-${row.number}`"
                class="flex flex-wrap items-center gap-x-3 gap-y-1 px-4 py-2.5 text-sm"
              >
                <span class="font-mono text-xs text-gray-300">{{ row.version }}</span>
                <span class="text-xs text-gray-500">No inventory for this release: hibou cannot tell whether it is affected.</span>
                <RouterLink
                  :to="incidentLink(row.org_provider, row.org_slug, row.number)"
                  class="ml-auto min-w-0 truncate text-xs text-accent hover:underline"
                >
                  #{{ row.number }} {{ row.title }}
                </RouterLink>
              </li>
            </ul>
          </section>

          <!-- Since your last visit -->
          <section>
            <div class="flex items-baseline justify-between">
              <h2 class="text-sm font-semibold text-white">
                Since your last visit
              </h2>
              <span
                class="text-xs text-gray-500"
                :title="formatDateTime(home.recent.since)"
              >since {{ formatDateTime(home.recent.since) }}</span>
            </div>
            <div class="mt-3 grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
              <div
                v-for="tile in recentTiles"
                :key="tile.label"
                class="rounded-xl border border-surface-border bg-surface-raised/40 p-4"
              >
                <div class="text-[11px] uppercase tracking-[0.16em] text-gray-500">
                  {{ tile.label }}
                </div>
                <div
                  class="mt-2 text-2xl font-semibold"
                  :class="tile.value > 0 ? tile.tone : 'text-gray-600'"
                >
                  {{ tile.value }}
                </div>
              </div>
            </div>
          </section>
        </div>
      </div>
    </template>
  </div>
</template>

<script setup lang="ts">
import { BellRing, Building2, FolderGit2, Plus, RefreshCw, Siren, Users } from 'lucide-vue-next'
import { computed, onMounted, ref } from 'vue'
import { RouterLink, useRouter } from 'vue-router'

import {
  incidentsApi,
  KIND_DESCRIPTIONS,
  KIND_LABELS,
  nullString,
  nullTime,
  STATE_LABELS,
  type HomeApproval,
  type HomeResponse,
  type IncidentKind,
} from '@/api/incidents'
import ForgeIcon from '@/components/ForgeIcon.vue'
import CountdownText from '@/components/incidents/CountdownText.vue'
import IncidentStatusPill from '@/components/incidents/IncidentStatusPill.vue'
import { formatDateTime, relativeTime } from '@/lib/datetime'
import { filterByKind, kindCounts, LAST_VISIT_KEY, parseLastVisit, sortByDue } from '@/lib/home'

const APPROVAL_LABELS: Record<HomeApproval['type'], string> = {
  decision: 'Decision to approve',
  delivery: 'Notice to approve',
  waiver: 'Waiver to approve',
  merge: 'Merge to approve',
}

const router = useRouter()

const home = ref<HomeResponse | null>(null)
const loading = ref(false)
const error = ref('')
const kindFilter = ref<IncidentKind | ''>('')

// The most urgent actions; the rest one click away, so incidents stay in view.
const NEEDS_YOU_PREVIEW = 8
const showAllNeedsYou = ref(false)
const needsYou = computed(() => sortByDue(home.value?.needs_you ?? []))
const shownNeedsYou = computed(() => (showAllNeedsYou.value ? needsYou.value : needsYou.value.slice(0, NEEDS_YOU_PREVIEW)))
const kinds = computed(() => kindCounts(home.value?.incidents ?? []))
const incidents = computed(() => sortByDue(filterByKind(home.value?.incidents ?? [], kindFilter.value)))
const recentTiles = computed(() => {
  const recent = home.value?.recent
  return [
    { label: 'Failed gates', value: recent?.failed_gates ?? 0, tone: 'text-danger' },
    { label: 'Catalogue signals', value: recent?.catalogue_signals ?? 0, tone: 'text-warn' },
    { label: 'Secrets found', value: recent?.secrets_found ?? 0, tone: 'text-warn' },
    { label: 'Malware found', value: recent?.malware_found ?? 0, tone: 'text-danger' },
  ]
})

function incidentLink(provider: string, slug: string, number: number) {
  return { name: 'incident-detail', params: { provider, slug, number: String(number) } }
}

function priorityClass(priority: string) {
  const tone = priority === 'P1' ? 'border-danger/40 text-danger' : priority === 'P2' ? 'border-warn/40 text-warn' : 'border-surface-border text-gray-400'
  return `rounded border px-1.5 py-0.5 font-mono text-[10px] ${tone}`
}

function exposureClass(status: string) {
  switch (status) {
    case 'affected':
      return 'border-danger/40 bg-danger/10 text-danger'
    case 'unknown':
      return 'border-surface-border bg-surface-overlay/40 text-gray-400'
    default:
      return 'border-warn/40 bg-warn/10 text-warn'
  }
}

function readLastVisit(): string | undefined {
  try {
    return parseLastVisit(localStorage.getItem(LAST_VISIT_KEY))
  } catch {
    return undefined
  }
}

function writeLastVisit() {
  try {
    localStorage.setItem(LAST_VISIT_KEY, new Date().toISOString())
  } catch {
    // Storage unavailable: the server falls back to the last 7 days.
  }
}

// The previous visit is read once, so a refresh keeps the same window.
let since: string | undefined

async function load() {
  loading.value = true
  error.value = ''
  try {
    const res = await incidentsApi.home(since)
    if (res.data.orgs.length === 0) {
      await router.replace({ name: 'orgs' })
      return
    }
    home.value = res.data
    writeLastVisit()
  } catch (caught) {
    error.value = caught instanceof Error ? caught.message : 'Unable to load your dashboard.'
  } finally {
    loading.value = false
  }
}

onMounted(() => {
  since = readLastVisit()
  void load()
})
</script>
