<template>
  <section class="px-4 pb-8">
    <div class="flex flex-wrap items-start justify-between gap-3">
      <p class="max-w-2xl text-sm text-gray-400">
        Downstream clients of this organization — usable from any repository's Releases tab to
        track who runs which build.
      </p>
      <button
        v-if="isOrgAdmin"
        class="inline-flex items-center gap-1.5 rounded-md bg-accent px-3 py-1.5 text-xs font-medium text-white transition hover:bg-accent/90"
        type="button"
        @click="showCreateForm = !showCreateForm"
      >
        <Plus
          class="h-3.5 w-3.5 transition-transform"
          :class="showCreateForm ? 'rotate-45' : ''"
        />
        {{ showCreateForm ? 'Cancel' : 'New client' }}
      </button>
    </div>

    <!-- Create form -->
    <section
      v-if="showCreateForm"
      class="mt-4 rounded-md border border-surface-border bg-surface-raised p-4"
    >
      <div class="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
        <div class="flex flex-col gap-1.5">
          <label
            class="text-xs font-medium text-gray-300"
            for="client-name"
          >Name</label>
          <input
            id="client-name"
            v-model="form.name"
            class="h-8 rounded-md border border-surface-border bg-surface-overlay px-2.5 text-sm text-gray-200 focus:border-accent/50 focus:outline-none"
            type="text"
          >
        </div>
        <div class="flex flex-col gap-1.5">
          <label
            class="text-xs font-medium text-gray-300"
            for="client-slug"
          >Slug</label>
          <input
            id="client-slug"
            v-model="form.slug"
            class="h-8 rounded-md border border-surface-border bg-surface-overlay px-2.5 font-mono text-sm text-gray-200 focus:border-accent/50 focus:outline-none"
            type="text"
          >
        </div>
        <div class="flex flex-col gap-1.5">
          <label
            class="text-xs font-medium text-gray-300"
            for="client-type"
          >Type</label>
          <select
            id="client-type"
            v-model="form.client_type"
            class="h-8 rounded-md border border-surface-border bg-surface-overlay px-2.5 text-sm text-gray-200 focus:border-accent/50 focus:outline-none"
          >
            <option value="external">
              External
            </option>
            <option value="internal">
              Internal
            </option>
          </select>
        </div>
        <div class="flex flex-col gap-1.5">
          <label
            class="text-xs font-medium text-gray-300"
            for="client-contact-name"
          >Contact name</label>
          <input
            id="client-contact-name"
            v-model="form.contact_name"
            class="h-8 rounded-md border border-surface-border bg-surface-overlay px-2.5 text-sm text-gray-200 focus:border-accent/50 focus:outline-none"
            type="text"
          >
        </div>
        <div class="flex flex-col gap-1.5">
          <label
            class="text-xs font-medium text-gray-300"
            for="client-contact-email"
          >Contact email</label>
          <input
            id="client-contact-email"
            v-model="form.contact_email"
            class="h-8 rounded-md border border-surface-border bg-surface-overlay px-2.5 text-sm text-gray-200 focus:border-accent/50 focus:outline-none"
            type="email"
          >
        </div>
      </div>

      <!-- Labels -->
      <div class="mt-4">
        <div class="flex items-center justify-between">
          <span class="text-xs font-medium text-gray-300">Labels</span>
          <button
            class="text-xs text-accent transition hover:underline"
            type="button"
            @click="addLabelRow"
          >
            Add label
          </button>
        </div>
        <div
          v-if="labelRows.length > 0"
          class="mt-2 space-y-2"
        >
          <div
            v-for="row in labelRows"
            :key="row.id"
            class="flex items-center gap-2"
          >
            <input
              :value="row.key"
              :class="isLabelKeyDuplicate(row) ? 'border-danger' : 'border-surface-border'"
              class="h-8 w-40 rounded-md border bg-surface-overlay px-2.5 text-sm text-gray-200 focus:border-accent/50 focus:outline-none"
              list="label-key-suggestions"
              type="text"
              placeholder="key"
              @input="updateLabelRow(row.id, 'key', ($event.target as HTMLInputElement).value)"
            >
            <input
              :value="row.value"
              class="h-8 flex-1 rounded-md border border-surface-border bg-surface-overlay px-2.5 text-sm text-gray-200 focus:border-accent/50 focus:outline-none"
              type="text"
              placeholder="value"
              @input="updateLabelRow(row.id, 'value', ($event.target as HTMLInputElement).value)"
            >
            <button
              class="rounded-md p-1.5 text-gray-500 transition hover:text-danger"
              type="button"
              @click="removeLabelRow(row.id)"
            >
              <X class="h-3.5 w-3.5" />
            </button>
          </div>
        </div>
        <p
          v-if="hasDuplicateLabelKeys"
          class="mt-1.5 text-xs text-danger"
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

      <div class="mt-4 flex items-center gap-3">
        <button
          class="rounded-md bg-ok-muted px-3 py-1.5 text-sm font-medium text-white transition hover:bg-ok-muted/80 disabled:cursor-not-allowed disabled:opacity-50"
          type="button"
          :disabled="submitting || hasDuplicateLabelKeys"
          @click="createClient"
        >
          {{ submitting ? 'Creating…' : 'Create client' }}
        </button>
        <p
          v-if="errorMessage"
          class="text-sm text-danger"
        >
          {{ errorMessage }}
        </p>
      </div>
    </section>

    <!-- List -->
    <div
      v-if="loading"
      class="mt-6 text-sm text-gray-500"
    >
      Loading clients…
    </div>

    <div
      v-else-if="error"
      class="mt-6 rounded-md border border-danger/30 bg-danger/10 px-4 py-3 text-sm text-red-200"
    >
      {{ error }}
    </div>

    <div
      v-else-if="clients.length === 0"
      class="mt-6 rounded-md border border-dashed border-surface-border px-6 py-10 text-center"
    >
      <Users class="mx-auto h-8 w-8 text-gray-600" />
      <p class="mt-3 text-sm font-medium text-gray-300">
        No clients yet
      </p>
      <p class="mx-auto mt-1.5 max-w-md text-sm text-gray-500">
        Create clients here, then assign them to releases from any repository's Releases tab.
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
                Name
              </th>
              <th class="px-4 py-2.5 font-medium">
                Type
              </th>
              <th class="px-4 py-2.5 font-medium">
                Active version
              </th>
              <th class="px-4 py-2.5 font-medium">
                Labels
              </th>
              <th class="px-4 py-2.5 font-medium">
                Contact
              </th>
              <th class="px-4 py-2.5 text-right font-medium">
                Deployments
              </th>
              <th class="px-4 py-2.5 font-medium">
                Last deployment
              </th>
            </tr>
          </thead>
          <tbody class="divide-y divide-surface-border-subtle">
            <tr
              v-for="client in clients"
              :key="client.id"
              class="cursor-pointer transition hover:bg-surface-overlay/50"
              @click="openClient(client.slug)"
            >
              <td class="px-4 py-2.5">
                <div class="font-medium text-white">
                  {{ client.name }}
                </div>
                <div class="text-xs text-gray-500">
                  {{ client.slug }}
                </div>
              </td>
              <td class="px-4 py-2.5">
                <span
                  class="rounded-full border px-2 py-0.5 text-[11px] font-medium capitalize"
                  :class="client.client_type === 'internal' ? 'border-amber-500/40 text-amber-300' : 'border-sky-500/40 text-sky-300'"
                >
                  {{ client.client_type }}
                </span>
              </td>
              <td class="px-4 py-2.5 font-mono text-xs text-gray-300">
                {{ client.active_version || '—' }}
              </td>
              <td class="px-4 py-2.5">
                <div
                  v-if="clientLabelEntries(client).length > 0"
                  class="flex max-w-xs flex-wrap gap-1.5"
                >
                  <span
                    v-for="[key, value] in clientLabelEntries(client)"
                    :key="`${client.id}-${key}`"
                    class="inline-flex max-w-full items-center gap-1 rounded-full bg-surface-overlay px-2 py-0.5 text-[11px] text-gray-300"
                  >
                    <span class="font-medium text-gray-200">{{ key }}:</span>
                    <a
                      v-if="isSafeUrl(value)"
                      :href="value"
                      class="truncate text-accent transition hover:underline"
                      target="_blank"
                      rel="noreferrer"
                      @click.stop
                    >{{ value }}</a>
                    <span
                      v-else
                      class="truncate"
                    >{{ value }}</span>
                  </span>
                </div>
                <span
                  v-else
                  class="text-xs text-gray-600"
                >—</span>
              </td>
              <td class="px-4 py-2.5 text-gray-300">
                <div class="text-xs">
                  {{ client.contact_name || '—' }}
                </div>
                <div class="text-xs text-gray-500">
                  {{ client.contact_email || '' }}
                </div>
              </td>
              <td class="px-4 py-2.5 text-right text-gray-300">
                {{ client.deployments_count ?? 0 }}
              </td>
              <td class="px-4 py-2.5 text-xs text-gray-400">
                {{ client.last_deployment_at ? relativeTime(client.last_deployment_at) : 'never' }}
              </td>
            </tr>
          </tbody>
        </table>
      </div>

      <div
        v-if="totalPages > 1"
        class="flex items-center justify-between border-t border-surface-border-subtle px-4 py-2.5 text-sm text-gray-400"
      >
        <span class="text-xs text-gray-500">Page {{ pagination.page }} of {{ totalPages }}</span>
        <div class="flex items-center gap-2">
          <button
            class="rounded-md border border-surface-border px-3 py-1.5 text-xs transition hover:text-white disabled:cursor-not-allowed disabled:opacity-40"
            type="button"
            :disabled="pagination.page <= 1"
            @click="changePage(pagination.page - 1)"
          >
            Previous
          </button>
          <button
            class="rounded-md border border-surface-border px-3 py-1.5 text-xs transition hover:text-white disabled:cursor-not-allowed disabled:opacity-40"
            type="button"
            :disabled="pagination.page >= totalPages"
            @click="changePage(pagination.page + 1)"
          >
            Next
          </button>
        </div>
      </div>
    </div>
  </section>
</template>

<script setup lang="ts">
import { Plus, Users, X } from 'lucide-vue-next'
import { computed, reactive, ref, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'

import { api, type Client } from '@/api/client'
import { useOrgRole } from '@/composables/useOrgRole'
import { relativeTime } from '@/lib/datetime'

type LabelRow = {
  id: number
  key: string
  value: string
}

const route = useRoute()
const router = useRouter()
const { isOrgAdmin } = useOrgRole()

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
  } catch (createError) {
    errorMessage.value = createError instanceof Error ? createError.message : 'Failed to create client'
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
</script>
