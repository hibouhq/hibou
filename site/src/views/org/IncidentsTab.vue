<template>
  <section class="px-4 pb-8">
    <div class="flex flex-wrap items-start justify-between gap-3">
      <p class="max-w-2xl text-sm text-gray-400">
        Incidents of this {{ repoSlug ? 'repository' : 'organization' }}, nearest deadline first. Hibou derives the actions and keeps
        the clocks; people decide exploitation, T0, scope and content.
      </p>
      <button
        v-if="isReleaseManager"
        class="inline-flex items-center gap-1.5 rounded-md bg-accent px-3 py-1.5 text-xs font-medium text-white transition hover:bg-accent/90"
        type="button"
        @click="showOpenForm = !showOpenForm"
      >
        <Plus
          class="h-3.5 w-3.5 transition-transform"
          :class="showOpenForm ? 'rotate-45' : ''"
        />
        {{ showOpenForm ? 'Cancel' : 'New incident' }}
      </button>
    </div>

    <IncidentOpenForm
      v-if="showOpenForm"
      class="mt-4"
      :provider="provider"
      :slug="slug"
      :prefill="prefill"
      @opened="openIncident"
      @cancel="showOpenForm = false"
    />

    <!-- Filters -->
    <div class="mt-4 flex flex-wrap items-center gap-2">
      <div class="inline-flex overflow-hidden rounded-md border border-surface-border">
        <button
          v-for="option in STATE_FILTERS"
          :key="option.value"
          type="button"
          class="px-3 py-1.5 text-xs transition"
          :class="filters.state === option.value ? 'bg-surface-overlay font-medium text-white' : 'text-gray-400 hover:text-gray-200'"
          @click="filters.state = option.value"
        >
          {{ option.label }}
        </button>
      </div>
      <select
        v-model="filters.kind"
        aria-label="Kind"
        class="h-8 rounded-md border border-surface-border bg-surface-overlay px-2.5 text-xs text-gray-200 focus:border-accent/50 focus:outline-none"
      >
        <option value="">
          All kinds
        </option>
        <option
          v-for="kind in INCIDENT_KINDS"
          :key="kind"
          :value="kind"
          :title="KIND_DESCRIPTIONS[kind]"
        >
          {{ KIND_LABELS[kind] }}
        </option>
      </select>
      <select
        v-model="filters.priority"
        aria-label="Priority"
        class="h-8 rounded-md border border-surface-border bg-surface-overlay px-2.5 text-xs text-gray-200 focus:border-accent/50 focus:outline-none"
      >
        <option value="">
          All priorities
        </option>
        <option
          v-for="priority in ['P1', 'P2', 'P3']"
          :key="priority"
          :value="priority"
        >
          {{ priority }}
        </option>
      </select>
    </div>

    <!-- List -->
    <div
      v-if="loading"
      class="mt-6 text-sm text-gray-500"
    >
      Loading incidents…
    </div>

    <div
      v-else-if="error"
      class="mt-6 rounded-md border border-danger/30 bg-danger/10 px-4 py-3 text-sm text-red-200"
    >
      {{ error }}
    </div>

    <div
      v-else-if="incidents.length === 0"
      class="mt-6 rounded-md border border-dashed border-surface-border px-6 py-10 text-center"
    >
      <Siren class="mx-auto h-8 w-8 text-gray-600" />
      <p class="mt-3 text-sm font-medium text-gray-300">
        {{ filters.state === 'open' ? 'No open incidents' : 'No incidents' }}
      </p>
      <p class="mx-auto mt-1.5 max-w-md text-sm text-gray-500">
        Trigger rules open incidents on exploited, verified-secret and malware findings; anyone who
        manages incidents can open one by hand.
      </p>
    </div>

    <div
      v-else
      class="mt-4 overflow-hidden rounded-md border border-surface-border"
    >
      <div class="overflow-x-auto">
        <table class="min-w-full divide-y divide-surface-border-subtle text-sm">
          <thead class="bg-surface-overlay text-left text-xs uppercase tracking-[0.14em] text-gray-500">
            <tr>
              <th class="px-4 py-2.5 font-medium">
                #
              </th>
              <th class="px-4 py-2.5 font-medium">
                Incident
              </th>
              <th class="px-4 py-2.5 font-medium">
                State
              </th>
              <th class="px-4 py-2.5 font-medium">
                Kind
              </th>
              <th
                v-if="!repoSlug"
                class="px-4 py-2.5 font-medium"
              >
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
              class="cursor-pointer transition hover:bg-surface-overlay/50"
              @click="openIncident(incident.number)"
            >
              <td class="px-4 py-2.5 font-mono text-xs text-gray-400">
                #{{ incident.number }}
              </td>
              <td class="px-4 py-2.5">
                <div class="flex items-center gap-2">
                  <IncidentPriorityPill :priority="incident.priority" />
                  <span class="font-medium text-white">{{ incident.title }}</span>
                </div>
              </td>
              <td class="px-4 py-2.5">
                <IncidentStatusPill
                  :status="incident.state"
                  :label="STATE_LABELS[incident.state]"
                />
              </td>
              <td
                class="px-4 py-2.5 text-xs text-gray-300"
                :title="KIND_DESCRIPTIONS[incident.kind]"
              >
                {{ incident.kind_label || KIND_LABELS[incident.kind] }}
              </td>
              <td
                v-if="!repoSlug"
                class="px-4 py-2.5 text-xs text-gray-300"
              >
                <RouterLink
                  v-if="incident.repo_slug"
                  :to="{ name: 'repo-incidents', params: { provider, slug, repoSlug: incident.repo_slug } }"
                  class="hover:text-white hover:underline"
                  title="This repository's incidents"
                  @click.stop
                >
                  {{ incident.repo_name || incident.repo_slug }}
                </RouterLink>
                <span v-else>—</span>
              </td>
              <td class="px-4 py-2.5 text-xs">
                <CountdownText
                  v-if="incidentOpen(incident.state)"
                  :at="nullTime(incident.due_at)"
                />
                <span
                  v-else
                  class="text-gray-500"
                >{{ incident.closed_at.Valid ? `closed ${relativeTime(incident.closed_at.Time)}` : '—' }}</span>
              </td>
            </tr>
          </tbody>
        </table>
      </div>

      <div
        v-if="totalPages > 1"
        class="flex items-center justify-between border-t border-surface-border-subtle px-4 py-2.5 text-sm text-gray-400"
      >
        <span class="text-xs text-gray-500">Page {{ page }} of {{ totalPages }}</span>
        <div class="flex items-center gap-2">
          <button
            class="rounded-md border border-surface-border px-3 py-1.5 text-xs transition hover:text-white disabled:cursor-not-allowed disabled:opacity-40"
            type="button"
            :disabled="page <= 1"
            @click="page -= 1"
          >
            Previous
          </button>
          <button
            class="rounded-md border border-surface-border px-3 py-1.5 text-xs transition hover:text-white disabled:cursor-not-allowed disabled:opacity-40"
            type="button"
            :disabled="page >= totalPages"
            @click="page += 1"
          >
            Next
          </button>
        </div>
      </div>
    </div>
  </section>
</template>

<script setup lang="ts">
import { Plus, Siren } from 'lucide-vue-next'
import { computed, reactive, ref, watch } from 'vue'
import { RouterLink, useRoute, useRouter } from 'vue-router'

import {
  INCIDENT_KINDS,
  incidentOpen,
  incidentsApi,
  KIND_DESCRIPTIONS,
  KIND_LABELS,
  nullTime,
  STATE_LABELS,
  type IncidentSummary,
} from '@/api/incidents'
import CountdownText from '@/components/incidents/CountdownText.vue'
import IncidentOpenForm from '@/components/incidents/IncidentOpenForm.vue'
import IncidentPriorityPill from '@/components/incidents/IncidentPriorityPill.vue'
import IncidentStatusPill from '@/components/incidents/IncidentStatusPill.vue'
import { useOrgRole } from '@/composables/useOrgRole'
import { relativeTime } from '@/lib/datetime'
import { errorText } from '@/lib/incidentView'

const STATE_FILTERS = [
  { value: 'open', label: 'Open' },
  { value: 'closed', label: 'Closed' },
  { value: '', label: 'All' },
]
const PER_PAGE = 25

const route = useRoute()
const router = useRouter()
// Release managers and admins manage incidents; the server enforces it.
const { isReleaseManager } = useOrgRole()

const incidents = ref<IncidentSummary[]>([])
const total = ref(0)
const page = ref(1)
const loading = ref(true)
const error = ref('')
const queryString = (key: string) => (typeof route.query[key] === 'string' ? route.query[key] as string : undefined)
// A finding's "Open incident…" link lands here with the form prefilled.
// Under a repository (the repo's Incidents tab) the list and the form are narrowed to it.
const repoSlug = computed(() => (typeof route.params.repoSlug === 'string' ? route.params.repoSlug : ''))
const prefill = { kind: queryString('kind'), repo: repoSlug.value || queryString('repo'), vulnerability: queryString('vulnerability'), finding: queryString('finding') }
const showOpenForm = ref(route.query.open === '1')
const filters = reactive({ state: 'open', kind: '', priority: '' })

const provider = computed(() => route.params.provider as string)
const slug = computed(() => route.params.slug as string)
const totalPages = computed(() => Math.max(1, Math.ceil(total.value / PER_PAGE)))

watch(() => [filters.state, filters.kind, filters.priority], () => {
  page.value = 1
})

watch(
  () => [provider.value, slug.value, repoSlug.value, filters.state, filters.kind, filters.priority, page.value],
  () => {
    if (!provider.value || !slug.value) return
    void loadIncidents()
  },
  { immediate: true },
)

async function loadIncidents() {
  loading.value = true
  error.value = ''
  try {
    const response = await incidentsApi.list(provider.value, slug.value, {
      state: filters.state,
      kind: filters.kind,
      priority: filters.priority,
      repo: repoSlug.value || undefined,
      page: page.value,
      per_page: PER_PAGE,
    })
    incidents.value = response.data
    total.value = response.pagination.total
  } catch (loadError) {
    incidents.value = []
    total.value = 0
    error.value = errorText(loadError, 'Failed to load incidents')
  } finally {
    loading.value = false
  }
}

function openIncident(number: number) {
  void router.push({ name: 'incident-detail', params: { provider: provider.value, slug: slug.value, number: String(number) } })
}
</script>
