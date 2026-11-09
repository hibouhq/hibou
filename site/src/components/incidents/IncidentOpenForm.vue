<template>
  <form
    class="rounded-md border border-surface-border bg-surface-raised p-4"
    @submit.prevent="submit"
  >
    <h3 class="text-sm font-semibold text-white">
      Open an incident
    </h3>
    <p class="mt-1 text-xs text-gray-500">
      For a signal hibou did not see: a customer report, a CSIRT, a researcher, internal evidence.
      Opening sets no T0; the decision does.
    </p>

    <div class="mt-3 grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
      <label class="flex flex-col gap-1.5 text-xs font-medium text-gray-300">
        Kind
        <select
          v-model="form.kind"
          :class="inputClass"
        >
          <option
            v-for="kind in INCIDENT_KINDS"
            :key="kind"
            :value="kind"
            :title="KIND_DESCRIPTIONS[kind]"
          >
            {{ KIND_LABELS[kind] }}
          </option>
        </select>
      </label>
      <label class="flex flex-col gap-1.5 text-xs font-medium text-gray-300">
        Repository
        <select
          v-model="form.repo_slug"
          :class="inputClass"
        >
          <option value="">
            {{ form.kind === 'severe_incident' ? 'None (organization-wide)' : 'Choose a repository' }}
          </option>
          <option
            v-for="repo in repos"
            :key="repo.slug"
            :value="repo.slug"
          >
            {{ repo.name }}
          </option>
        </select>
      </label>
      <label class="flex flex-col gap-1.5 text-xs font-medium text-gray-300">
        Signal source
        <select
          v-model="form.signal_source"
          :class="inputClass"
        >
          <option
            v-for="source in MANUAL_SOURCES"
            :key="source"
            :value="source"
          >
            {{ humanize(source) }}
          </option>
        </select>
      </label>
      <label class="flex flex-col gap-1.5 text-xs font-medium text-gray-300">
        Priority
        <select
          v-model="form.priority"
          :class="inputClass"
        >
          <option
            v-for="priority in PRIORITIES"
            :key="priority"
            :value="priority"
          >
            {{ priority }}
          </option>
        </select>
      </label>
      <label class="flex flex-col gap-1.5 text-xs font-medium text-gray-300 sm:col-span-2">
        Title
        <input
          v-model="form.title"
          :class="inputClass"
          type="text"
          :placeholder="form.kind === 'severe_incident' ? 'Required' : 'Derived from the subject when empty'"
        >
      </label>
      <label
        v-if="form.kind === 'exploited_vulnerability'"
        class="flex flex-col gap-1.5 text-xs font-medium text-gray-300 sm:col-span-2"
      >
        Vulnerability
        <input
          v-model="form.vulnerability_id"
          :class="[inputClass, 'font-mono']"
          type="text"
          placeholder="CVE-2026-1234, GHSA-…, or a first-party identifier"
        >
      </label>
      <label
        v-else-if="form.kind !== 'severe_incident'"
        class="flex flex-col gap-1.5 text-xs font-medium text-gray-300 sm:col-span-2"
      >
        Finding id
        <input
          v-model="form.finding_id"
          :class="[inputClass, 'font-mono']"
          type="text"
          placeholder="The finding's id, from its detail page"
        >
      </label>
    </div>

    <fieldset class="mt-4">
      <legend class="text-xs font-medium text-gray-300">
        Regimes
      </legend>
      <div class="mt-1.5 flex flex-wrap gap-x-4 gap-y-1.5">
        <label
          v-for="regime in regimeOptions"
          :key="regime"
          class="inline-flex items-center gap-1.5 text-xs text-gray-300"
        >
          <input
            v-model="form.regimes"
            type="checkbox"
            class="h-3.5 w-3.5 accent-accent"
            :value="regime"
          >
          <span class="font-mono">{{ regime }}</span>
        </label>
      </div>
      <p class="mt-1 text-[11px] text-gray-500">
        None checked: the kind's default applies.
      </p>
    </fieldset>

    <div
      v-if="form.kind === 'severe_incident'"
      class="mt-4 grid gap-4 sm:grid-cols-2"
    >
      <fieldset>
        <legend class="text-xs font-medium text-gray-300">
          Affected releases
        </legend>
        <p
          v-if="!form.repo_slug"
          class="mt-1.5 text-xs text-gray-500"
        >
          Choose a repository to list its releases.
        </p>
        <p
          v-else-if="releases.length === 0"
          class="mt-1.5 text-xs text-gray-500"
        >
          No releases.
        </p>
        <div
          v-else
          class="mt-1.5 max-h-40 space-y-1 overflow-y-auto"
        >
          <label
            v-for="release in releases"
            :key="release.id"
            class="flex items-center gap-1.5 text-xs text-gray-300"
          >
            <input
              v-model="form.release_ids"
              type="checkbox"
              class="h-3.5 w-3.5 accent-accent"
              :value="release.id"
            >
            <span class="font-mono">{{ release.version }}</span>
          </label>
        </div>
      </fieldset>
      <fieldset>
        <legend class="text-xs font-medium text-gray-300">
          Affected clients
        </legend>
        <p
          v-if="clients.length === 0"
          class="mt-1.5 text-xs text-gray-500"
        >
          No clients.
        </p>
        <div
          v-else
          class="mt-1.5 max-h-40 space-y-1 overflow-y-auto"
        >
          <label
            v-for="client in clients"
            :key="client.id"
            class="flex items-center gap-1.5 text-xs text-gray-300"
          >
            <input
              v-model="form.client_ids"
              type="checkbox"
              class="h-3.5 w-3.5 accent-accent"
              :value="client.id"
            >
            {{ client.name }}
          </label>
        </div>
      </fieldset>
    </div>

    <label class="mt-4 flex flex-col gap-1.5 text-xs font-medium text-gray-300">
      Note
      <textarea
        v-model="form.note"
        rows="2"
        class="rounded-md border border-surface-border bg-surface-overlay px-2.5 py-1.5 text-sm text-gray-200 focus:border-accent/50 focus:outline-none"
        placeholder="What was reported, by whom (optional)"
      />
    </label>

    <div class="mt-4 flex items-center gap-3">
      <button
        class="rounded-md bg-accent px-3 py-1.5 text-xs font-medium text-white transition hover:bg-accent/90 disabled:cursor-not-allowed disabled:opacity-50"
        type="submit"
        :disabled="submitting"
      >
        {{ submitting ? 'Opening…' : 'Open incident' }}
      </button>
      <button
        class="rounded-md border border-surface-border px-3 py-1.5 text-xs text-gray-400 transition hover:text-white"
        type="button"
        @click="emit('cancel')"
      >
        Cancel
      </button>
      <p
        v-if="errorMessage"
        class="text-sm text-danger"
      >
        {{ errorMessage }}
      </p>
    </div>
  </form>
</template>

<script setup lang="ts">
import { computed, onMounted, reactive, ref, watch } from 'vue'

import { api, type Client, type Release, type Repository } from '@/api/client'
import { INCIDENT_KINDS, incidentsApi, KIND_DESCRIPTIONS, KIND_LABELS, type IncidentKind, type IncidentPriority } from '@/api/incidents'
import { BUILTIN_REGIMES, errorText, humanize } from '@/lib/incidentView'

// prefill comes from a finding's "Open incident…" link (?open=1&kind=…).
const props = defineProps<{ provider: string; slug: string; prefill?: { kind?: string; repo?: string; vulnerability?: string; finding?: string } }>()
const emit = defineEmits<{ opened: [number: number]; cancel: [] }>()

const MANUAL_SOURCES = ['customer', 'csirt', 'researcher', 'internal', 'other'] as const
const PRIORITIES: IncidentPriority[] = ['P1', 'P2', 'P3']
const inputClass = 'h-8 rounded-md border border-surface-border bg-surface-overlay px-2.5 text-sm font-normal text-gray-200 focus:border-accent/50 focus:outline-none'

const repos = ref<Repository[]>([])
const clients = ref<Client[]>([])
const releases = ref<Release[]>([])
const extraRegimes = ref<string[]>([])
const submitting = ref(false)
const errorMessage = ref('')

const form = reactive({
  kind: 'exploited_vulnerability' as IncidentKind,
  repo_slug: '',
  title: '',
  signal_source: 'customer',
  priority: 'P1' as IncidentPriority,
  regimes: ['cra-article-14'] as string[],
  vulnerability_id: '',
  finding_id: '',
  note: '',
  release_ids: [] as string[],
  client_ids: [] as string[],
})

if (props.prefill?.kind && (INCIDENT_KINDS as string[]).includes(props.prefill.kind)) {
  form.kind = props.prefill.kind as IncidentKind
  form.regimes = form.kind === 'exploited_vulnerability' || form.kind === 'severe_incident' ? ['cra-article-14'] : []
  form.priority = form.kind === 'policy_breach' ? 'P2' : 'P1'
  form.signal_source = 'internal'
}
form.repo_slug = props.prefill?.repo ?? form.repo_slug
form.vulnerability_id = props.prefill?.vulnerability ?? form.vulnerability_id
form.finding_id = props.prefill?.finding ?? form.finding_id

const regimeOptions = computed(() => [...new Set([...BUILTIN_REGIMES, ...extraRegimes.value])])

onMounted(async () => {
  const [repoResult, clientResult, settingsResult] = await Promise.allSettled([
    api.listRepos(props.provider, props.slug),
    api.listClients(props.provider, props.slug, { per_page: 100 }),
    incidentsApi.getSettings(props.provider, props.slug),
  ])
  if (repoResult.status === 'fulfilled') repos.value = repoResult.value.data.filter(repo => repo.enrolled ?? true)
  if (clientResult.status === 'fulfilled') clients.value = clientResult.value.data
  if (settingsResult.status === 'fulfilled') extraRegimes.value = settingsResult.value.data.regimes ?? []
})

watch(() => form.kind, (kind) => {
  form.regimes = kind === 'exploited_vulnerability' || kind === 'severe_incident' ? ['cra-article-14'] : []
})

watch(() => [form.kind, form.repo_slug], async () => {
  releases.value = []
  form.release_ids = []
  if (form.kind !== 'severe_incident' || !form.repo_slug) return
  try {
    const response = await api.listReleases(props.provider, props.slug, form.repo_slug, { per_page: 100 })
    releases.value = response.data
  } catch {
    releases.value = []
  }
})

async function submit() {
  errorMessage.value = ''
  if (form.kind === 'severe_incident' && !form.title.trim()) {
    errorMessage.value = 'A security incident needs a title'
    return
  }
  if (form.kind !== 'severe_incident' && !form.repo_slug) {
    errorMessage.value = 'This kind names a repository'
    return
  }
  submitting.value = true
  try {
    const response = await incidentsApi.open(props.provider, props.slug, {
      kind: form.kind,
      repo_slug: form.repo_slug || undefined,
      title: form.title.trim() || undefined,
      priority: form.priority,
      signal_source: form.signal_source,
      regimes: form.regimes.length > 0 ? form.regimes : undefined,
      vulnerability_id: form.kind === 'exploited_vulnerability' ? form.vulnerability_id.trim() : undefined,
      finding_id: form.kind !== 'exploited_vulnerability' && form.kind !== 'severe_incident' ? form.finding_id.trim() : undefined,
      note: form.note.trim() || undefined,
      release_ids: form.kind === 'severe_incident' && form.release_ids.length > 0 ? form.release_ids : undefined,
      client_ids: form.kind === 'severe_incident' && form.client_ids.length > 0 ? form.client_ids : undefined,
    })
    emit('opened', response.data.number)
  } catch (error) {
    errorMessage.value = errorText(error, 'Failed to open the incident')
  } finally {
    submitting.value = false
  }
}
</script>
