<template>
  <section class="space-y-6">
    <div class="flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
      <div>
        <h1 class="text-3xl font-semibold tracking-tight text-white">
          Clients
        </h1>
        <p class="mt-2 text-sm text-gray-400">
          Manage downstream clients and track the releases currently deployed across downstream environments.
        </p>
      </div>

      <button
        class="inline-flex items-center justify-center rounded-2xl border border-surface-border bg-surface-overlay px-4 py-2.5 text-sm text-gray-300 transition hover:border-accent/50 hover:text-white"
        type="button"
        @click="showCreateForm = !showCreateForm"
      >
        {{ showCreateForm ? 'Cancel' : 'New Client' }}
      </button>
    </div>

    <section
      v-if="showCreateForm"
      class="rounded-3xl border border-surface-border bg-surface-raised p-5"
    >
      <div class="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
        <label class="space-y-2 text-sm text-gray-300">
          <span class="block text-xs uppercase tracking-[0.2em] text-gray-500">Name</span>
          <input
            v-model="form.name"
            class="w-full rounded-2xl border border-surface-border bg-surface-overlay px-4 py-3 text-sm text-gray-100"
            type="text"
          >
        </label>
        <label class="space-y-2 text-sm text-gray-300">
          <span class="block text-xs uppercase tracking-[0.2em] text-gray-500">Slug</span>
          <input
            v-model="form.slug"
            class="w-full rounded-2xl border border-surface-border bg-surface-overlay px-4 py-3 text-sm text-gray-100"
            type="text"
          >
        </label>
        <label class="space-y-2 text-sm text-gray-300">
          <span class="block text-xs uppercase tracking-[0.2em] text-gray-500">Contact Name</span>
          <input
            v-model="form.contact_name"
            class="w-full rounded-2xl border border-surface-border bg-surface-overlay px-4 py-3 text-sm text-gray-100"
            type="text"
          >
        </label>
        <label class="space-y-2 text-sm text-gray-300">
          <span class="block text-xs uppercase tracking-[0.2em] text-gray-500">Type</span>
          <select
            v-model="form.client_type"
            class="w-full rounded-2xl border border-surface-border bg-surface-overlay px-4 py-3 text-sm text-gray-100"
          >
            <option value="external">External</option>
            <option value="internal">Internal</option>
          </select>
        </label>
        <div class="space-y-3 text-sm text-gray-300 md:col-span-2 xl:col-span-3">
          <div class="flex items-center justify-between gap-3">
            <span class="block text-xs uppercase tracking-[0.2em] text-gray-500">Labels</span>
            <button
              class="rounded-xl border border-surface-border px-3 py-2 text-xs uppercase tracking-[0.14em] text-gray-300 transition hover:border-accent/50 hover:text-white"
              type="button"
              @click="addLabelRow"
            >
              Add Label
            </button>
          </div>
          <div
            v-if="labelRows.length > 0"
            class="space-y-3"
          >
            <div
              v-for="row in labelRows"
              :key="row.id"
              class="grid gap-3 md:grid-cols-[minmax(0,1fr)_minmax(0,1.5fr)_auto]"
            >
              <input
                :value="row.key"
                :class="{ 'border-danger': isLabelKeyDuplicate(row) }"
                class="w-full rounded-2xl border border-surface-border bg-surface-overlay px-4 py-3 text-sm text-gray-100"
                list="label-key-suggestions"
                type="text"
                placeholder="key"
                @input="updateLabelRow(row.id, 'key', (($event.target as HTMLInputElement).value))"
              >
              <input
                :value="row.value"
                class="w-full rounded-2xl border border-surface-border bg-surface-overlay px-4 py-3 text-sm text-gray-100"
                type="text"
                placeholder="value"
                @input="updateLabelRow(row.id, 'value', (($event.target as HTMLInputElement).value))"
              >
              <button
                class="rounded-2xl border border-surface-border px-4 py-3 text-sm text-gray-300 transition hover:border-danger/50 hover:text-white"
                type="button"
                @click="removeLabelRow(row.id)"
              >
                Remove
              </button>
            </div>
          </div>
          <p
            v-else
            class="rounded-2xl border border-dashed border-surface-border px-4 py-3 text-sm text-gray-500"
          >
            No labels configured.
          </p>
          <p
            v-if="hasDuplicateLabelKeys"
            class="text-xs text-danger"
          >
            Duplicate label keys are not allowed.
          </p>
          <datalist id="label-key-suggestions">
            <option
              v-for="key in labelKeySuggestions"
              :key="key"
              :value="key"
            />
          </datalist>
        </div>
      </div>

      <div class="mt-4 grid gap-4 md:grid-cols-[minmax(0,1fr)_auto]">
        <label class="space-y-2 text-sm text-gray-300">
          <span class="block text-xs uppercase tracking-[0.2em] text-gray-500">Contact Email</span>
          <input
            v-model="form.contact_email"
            class="w-full rounded-2xl border border-surface-border bg-surface-overlay px-4 py-3 text-sm text-gray-100"
            type="email"
          >
        </label>

        <button
          class="mt-auto rounded-2xl border border-accent/30 bg-accent-muted px-5 py-3 text-sm font-medium text-accent transition hover:border-accent/50 hover:text-white disabled:cursor-not-allowed disabled:opacity-50"
          type="button"
          :disabled="submitting || hasDuplicateLabelKeys"
          @click="createClient"
        >
          {{ submitting ? 'Creating...' : 'Create Client' }}
        </button>
      </div>

      <p
        v-if="errorMessage"
        class="mt-3 text-sm text-danger"
      >
        {{ errorMessage }}
      </p>
    </section>

    <section class="overflow-hidden rounded-3xl border border-surface-border bg-surface-raised">
      <div
        v-if="loading"
        class="px-6 py-10 text-sm text-gray-500"
      >
        Loading clients...
      </div>

      <div
        v-else-if="error"
        class="px-6 py-6"
      >
        <div class="rounded-2xl border border-danger/30 bg-danger/10 px-4 py-3 text-sm text-red-200">
          {{ error }}
        </div>
      </div>

      <div
        v-else-if="clients.length === 0"
        class="px-6 py-10 text-sm text-gray-500"
      >
        No clients have been created yet.
      </div>

      <template v-else>
        <div class="overflow-x-auto">
          <table class="min-w-full divide-y divide-surface-border-subtle text-sm">
            <thead class="bg-surface-overlay text-left text-xs uppercase tracking-[0.18em] text-gray-500">
              <tr>
                <th class="px-6 py-4 font-medium">
                  Name
                </th>
                <th class="px-6 py-4 font-medium">
                  Type
                </th>
                <th class="px-6 py-4 font-medium">
                  Active Version
                </th>
                <th class="px-6 py-4 font-medium">
                  Labels
                </th>
                <th class="px-6 py-4 font-medium">
                  Contact
                </th>
                <th class="px-6 py-4 font-medium">
                  Deployments
                </th>
                <th class="px-6 py-4 font-medium">
                  Last Deployment
                </th>
              </tr>
            </thead>
            <tbody class="divide-y divide-surface-border-subtle">
              <tr
                v-for="client in clients"
                :key="client.id"
                class="cursor-pointer transition hover:bg-white/5"
                @click="openClient(client.slug)"
              >
                <td class="px-6 py-4">
                  <div class="font-medium text-white">
                    {{ client.name }}
                  </div>
                  <div class="text-xs text-gray-500">
                    {{ client.slug }}
                  </div>
                </td>
                <td class="px-6 py-4">
                  <span
                    :class="clientTypeClass(client.client_type)"
                    class="rounded-full px-2.5 py-1 text-xs font-medium uppercase tracking-[0.14em]"
                  >
                    {{ client.client_type }}
                  </span>
                </td>
                <td class="px-6 py-4 text-gray-300">
                  {{ client.active_version || 'No active version' }}
                </td>
                <td class="px-6 py-4 text-gray-300">
                  <div
                    v-if="clientLabelEntries(client).length > 0"
                    class="flex flex-wrap gap-2"
                  >
                    <span
                      v-for="[key, value] in clientLabelEntries(client)"
                      :key="`${client.id}-${key}`"
                      class="inline-flex max-w-full items-center gap-1 rounded-full border border-surface-border bg-surface-overlay px-2.5 py-1 text-xs text-gray-300"
                    >
                      <span class="font-medium text-gray-200">{{ key }}:</span>
                      <a
                        v-if="isSafeUrl(value)"
                        :href="value"
                        class="truncate text-accent transition hover:text-white hover:underline"
                        target="_blank"
                        rel="noreferrer"
                        @click.stop
                      >
                        {{ value }}
                      </a>
                      <span
                        v-else
                        class="truncate"
                      >
                        {{ value }}
                      </span>
                    </span>
                  </div>
                  <span
                    v-else
                    class="text-gray-500"
                  >
                    No labels
                  </span>
                </td>
                <td class="px-6 py-4 text-gray-300">
                  <div>
                    {{ client.contact_name || 'No contact' }}
                  </div>
                  <div class="text-xs text-gray-500">
                    {{ client.contact_email || 'No email' }}
                  </div>
                </td>
                <td class="px-6 py-4 text-gray-300">
                  {{ client.deployments_count ?? 0 }}
                </td>
                <td class="px-6 py-4 text-gray-400">
                  {{ formatDate(client.last_deployment_at) }}
                </td>
              </tr>
            </tbody>
          </table>
        </div>

        <div class="flex items-center justify-between border-t border-surface-border-subtle px-6 py-4 text-sm text-gray-400">
          <div>Page {{ pagination.page }} of {{ totalPages }}</div>
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
  </section>
</template>

<script setup lang="ts">
import { computed, reactive, ref, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'

import { api, type Client } from '@/api/client'

type LabelRow = {
  id: number
  key: string
  value: string
}

const route = useRoute()
const router = useRouter()

const clients = ref<Client[]>([])
const loading = ref(true)
const submitting = ref(false)
const showCreateForm = ref(false)
const error = ref('')
const errorMessage = ref('')
const pagination = ref({ page: 1, per_page: 20, total: 0 })
const labelRows = ref<LabelRow[]>([])
const labelKeySuggestions = ref<string[]>([])
let nextLabelRowID = 1
const form = reactive({
  name: '',
  slug: '',
  labels: {} as Record<string, string>,
  client_type: 'external',
  contact_name: '',
  contact_email: '',
})

const provider = computed(() => route.params.provider as string)
const slug = computed(() => route.params.slug as string)
const totalPages = computed(() => Math.max(1, Math.ceil(pagination.value.total / pagination.value.per_page)))
const hasDuplicateLabelKeys = computed(() => {
  const keys = labelRows.value.map((row) => row.key.trim()).filter((key) => key !== '')
  return new Set(keys).size !== keys.length
})

watch(
  () => [provider.value, slug.value, route.query.page],
  () => {
    const page = Number(typeof route.query.page === 'string' ? route.query.page : '1')
    pagination.value.page = Number.isFinite(page) && page > 0 ? page : 1
    void loadClients()
    void loadLabelKeys()
  },
  { immediate: true },
)

async function loadClients() {
  loading.value = true
  error.value = ''
  try {
    const response = await api.listClients(provider.value, slug.value, {
      page: pagination.value.page,
      per_page: pagination.value.per_page,
    })
    clients.value = response.data
    pagination.value = response.pagination
  } catch (loadError) {
    clients.value = []
    pagination.value = { ...pagination.value, total: 0 }
    error.value = loadError instanceof Error ? loadError.message : 'Failed to load clients'
  } finally {
    loading.value = false
  }
}

async function loadLabelKeys() {
  try {
    const response = await api.listClientLabelKeys(provider.value, slug.value)
    labelKeySuggestions.value = response.data
  } catch {
    labelKeySuggestions.value = []
  }
}

async function createClient() {
  errorMessage.value = ''

  const name = form.name.trim()
  const slugValue = form.slug.trim()
  if (!name || !slugValue) {
    errorMessage.value = 'Name and slug are required'
    return
  }
  if (hasDuplicateLabelKeys.value) {
    errorMessage.value = 'Duplicate label keys are not allowed'
    return
  }

  syncLabelsFromRows()

  submitting.value = true
  try {
    await api.createClient(provider.value, slug.value, {
      name,
      slug: slugValue,
      labels: Object.keys(form.labels).length > 0 ? { ...form.labels } : undefined,
      client_type: form.client_type,
      contact_name: form.contact_name.trim() || undefined,
      contact_email: form.contact_email.trim() || undefined,
    })
    showCreateForm.value = false
    Object.assign(form, {
      name: '',
      slug: '',
      labels: {},
      client_type: 'external',
      contact_name: '',
      contact_email: '',
    })
    labelRows.value = []
    await Promise.all([loadClients(), loadLabelKeys()])
  } catch (error) {
    errorMessage.value = error instanceof Error ? error.message : 'Failed to create client'
  } finally {
    submitting.value = false
  }
}

function openClient(clientSlug: string) {
  void router.push({ name: 'client-detail', params: { ...route.params, clientSlug } })
}

function changePage(page: number) {
  void router.replace({ query: page > 1 ? { page: String(page) } : {} })
}

function formatDate(value?: string) {
  if (!value) {
    return 'No deployments yet'
  }

  return new Date(value).toLocaleString()
}

function isSafeUrl(url: string) {
  return /^https?:\/\//i.test(url.trim())
}

function clientLabelEntries(client: Client) {
  return Object.entries(client.labels || {})
}

function addLabelRow() {
  labelRows.value.push({ id: nextLabelRowID++, key: '', value: '' })
}

function updateLabelRow(id: number, field: 'key' | 'value', value: string) {
  const row = labelRows.value.find((entry) => entry.id === id)
  if (!row) {
    return
  }

  row[field] = value
  syncLabelsFromRows()
}

function removeLabelRow(id: number) {
  labelRows.value = labelRows.value.filter((entry) => entry.id !== id)
  syncLabelsFromRows()
}

function syncLabelsFromRows() {
  const labels: Record<string, string> = {}
  for (const row of labelRows.value) {
    const key = row.key.trim()
    const value = row.value.trim()
    if (!key || !value) {
      continue
    }
    labels[key] = value
  }
  form.labels = labels
}

function isLabelKeyDuplicate(row: LabelRow) {
  const key = row.key.trim()
  if (!key) {
    return false
  }

  return labelRows.value.filter((entry) => entry.key.trim() === key).length > 1
}

function clientTypeClass(clientType: string) {
  return clientType === 'internal' ? 'bg-amber-500/10 text-amber-300' : 'bg-sky-500/10 text-sky-300'
}
</script>
