<template>
  <div class="space-y-4">
    <div class="flex items-center justify-between border-b border-surface-border pb-2">
      <h2 class="text-base font-semibold text-white">
        Integrations
      </h2>
      <button
        v-if="isOrgAdmin"
        type="button"
        class="rounded-md border border-surface-border bg-surface-overlay px-3 py-1.5 text-xs font-medium text-gray-200 transition hover:border-accent/50 hover:text-white"
        @click="openCreate"
      >
        New integration
      </button>
      <span
        v-else
        class="text-xs text-gray-500"
      >Read-only — org admins can manage integrations</span>
    </div>

    <p class="text-sm text-gray-500">
      Delivery targets for notification rules: webhooks, Slack, Teams, Discord, or email.
    </p>

    <div
      v-if="loading"
      class="text-sm text-gray-500"
    >
      Loading integrations…
    </div>
    <div
      v-else-if="loadFailed"
      class="text-sm text-gray-500"
    >
      Integrations could not be loaded.
    </div>

    <ul
      v-else
      class="divide-y divide-surface-border-subtle rounded-lg border border-surface-border"
    >
      <li
        v-for="integration in integrations"
        :key="integration.id"
        class="flex items-center gap-3 px-4 py-3"
      >
        <div class="min-w-0 flex-1">
          <div class="flex items-center gap-2 text-sm font-medium text-gray-100">
            <span class="truncate">{{ integration.name }}</span>
            <span class="rounded-full border border-surface-border px-1.5 text-[10px] uppercase tracking-wide text-gray-500">
              {{ integration.integration_type }}
            </span>
            <span
              v-if="!integration.enabled"
              class="rounded-full bg-surface-overlay px-1.5 text-[10px] text-gray-500"
            >disabled</span>
          </div>
          <div class="mt-0.5 text-xs text-gray-500">
            <span
              v-if="integration.failure_count > 0"
              class="text-danger"
            >
              {{ integration.failure_count }} consecutive failure{{ integration.failure_count > 1 ? 's' : '' }}
              <template v-if="integration.last_failure_at?.Valid">
                · last {{ relativeTime(integration.last_failure_at.Time) }}
              </template>
            </span>
            <span v-else-if="integration.last_success_at?.Valid">
              Last delivery {{ relativeTime(integration.last_success_at.Time) }}
            </span>
            <span v-else>No deliveries yet</span>
          </div>
        </div>

        <template v-if="isOrgAdmin">
          <button
            type="button"
            class="rounded-md border border-surface-border px-2 py-1 text-xs text-gray-400 transition hover:border-accent/50 hover:text-gray-200 disabled:opacity-50"
            :disabled="busyID === integration.id"
            title="Re-send recent undelivered events"
            @click="replay(integration)"
          >
            Replay
          </button>
          <button
            type="button"
            class="rounded-md border border-surface-border px-2 py-1 text-xs text-gray-400 transition hover:border-accent/50 hover:text-gray-200"
            @click="openEdit(integration)"
          >
            Edit
          </button>
          <button
            type="button"
            class="rounded-md border border-surface-border px-2 py-1 text-xs text-gray-400 transition hover:border-danger/50 hover:text-danger disabled:opacity-50"
            :disabled="busyID === integration.id"
            @click="remove(integration)"
          >
            Delete
          </button>
        </template>
      </li>
      <li
        v-if="integrations.length === 0"
        class="px-4 py-6 text-center text-sm text-gray-500"
      >
        No integrations configured.
      </li>
    </ul>

    <!-- Create / edit form -->
    <form
      v-if="formOpen"
      class="space-y-3 rounded-lg border border-surface-border bg-surface-raised p-4"
      @submit.prevent="submit"
    >
      <h3 class="text-sm font-semibold text-white">
        {{ editing ? 'Edit integration' : 'New integration' }}
      </h3>
      <div class="grid gap-3 sm:grid-cols-2">
        <label class="block text-xs text-gray-400">
          Name
          <input
            v-model="form.name"
            required
            class="mt-1 w-full rounded-md border border-surface-border bg-surface-overlay px-2.5 py-1.5 text-sm text-gray-100 focus:border-accent/50 focus:outline-none"
          >
        </label>
        <label class="block text-xs text-gray-400">
          Type
          <select
            v-model="form.integration_type"
            :disabled="!!editing"
            class="mt-1 w-full rounded-md border border-surface-border bg-surface-overlay px-2.5 py-1.5 text-sm text-gray-100 focus:border-accent/50 focus:outline-none disabled:opacity-60"
          >
            <option
              v-for="integrationType in INTEGRATION_TYPES"
              :key="integrationType"
              :value="integrationType"
            >
              {{ integrationType }}
            </option>
          </select>
        </label>
      </div>
      <label class="block text-xs text-gray-400">
        Config (JSON — e.g. {{ configHint }})
        <textarea
          v-model="form.configText"
          rows="3"
          class="mt-1 w-full rounded-md border border-surface-border bg-surface-overlay px-2.5 py-1.5 font-mono text-xs text-gray-100 focus:border-accent/50 focus:outline-none"
        />
      </label>
      <label class="flex items-center gap-2 text-xs text-gray-300">
        <input
          v-model="form.enabled"
          type="checkbox"
          class="rounded border-surface-border"
        >
        Enabled
      </label>
      <p
        v-if="formError"
        class="text-xs text-danger"
      >
        {{ formError }}
      </p>
      <div class="flex gap-2">
        <button
          type="submit"
          class="rounded-md bg-accent px-3 py-1.5 text-xs font-medium text-white transition hover:bg-accent/80 disabled:opacity-50"
          :disabled="submitting"
        >
          {{ editing ? 'Save' : 'Create' }}
        </button>
        <button
          type="button"
          class="rounded-md border border-surface-border px-3 py-1.5 text-xs text-gray-400 transition hover:text-gray-200"
          @click="formOpen = false"
        >
          Cancel
        </button>
      </div>
    </form>
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, reactive, ref } from 'vue'
import { useRoute } from 'vue-router'

import { api, INTEGRATION_TYPES, type OrgIntegration } from '@/api/client'
import { useOrgRole } from '@/composables/useOrgRole'
import { useToast } from '@/composables/useToast'
import { relativeTime } from '@/lib/datetime'

const route = useRoute()
const { isOrgAdmin } = useOrgRole()
const { pushToast } = useToast()

const provider = route.params.provider as string
const slug = route.params.slug as string

const integrations = ref<OrgIntegration[]>([])
const loading = ref(true)
const loadFailed = ref(false)
const busyID = ref('')

const formOpen = ref(false)
const editing = ref<OrgIntegration | null>(null)
const submitting = ref(false)
const formError = ref('')
const form = reactive({
  name: '',
  integration_type: 'webhook',
  configText: '{\n  "url": ""\n}',
  enabled: true,
})

const configHint = computed(() => {
  switch (form.integration_type) {
    case 'email':
      return '{"to": "security@acme.com"}'
    case 'webhook':
      return '{"url": "https://…", "secret": "…"}'
    default:
      return '{"webhook_url": "https://…"}'
  }
})

async function load() {
  loading.value = true
  loadFailed.value = false
  try {
    const res = await api.listIntegrations(provider, slug)
    integrations.value = res.data
  } catch {
    loadFailed.value = true
  } finally {
    loading.value = false
  }
}

function openCreate() {
  editing.value = null
  form.name = ''
  form.integration_type = 'webhook'
  form.configText = '{\n  "url": ""\n}'
  form.enabled = true
  formError.value = ''
  formOpen.value = true
}

function openEdit(integration: OrgIntegration) {
  editing.value = integration
  form.name = integration.name
  form.integration_type = integration.integration_type
  form.configText = JSON.stringify(integration.config ?? {}, null, 2)
  form.enabled = integration.enabled
  formError.value = ''
  formOpen.value = true
}

async function submit() {
  formError.value = ''
  let config: Record<string, unknown>
  try {
    config = JSON.parse(form.configText || '{}')
  } catch {
    formError.value = 'Config must be valid JSON.'
    return
  }
  submitting.value = true
  try {
    if (editing.value) {
      await api.updateIntegration(provider, slug, editing.value.id, {
        name: form.name,
        config,
        enabled: form.enabled,
      })
    } else {
      await api.createIntegration(provider, slug, {
        name: form.name,
        integration_type: form.integration_type,
        config,
        enabled: form.enabled,
      })
    }
    formOpen.value = false
    pushToast({ title: editing.value ? 'Integration updated' : 'Integration created', tone: 'success' })
    await load()
  } catch (err) {
    formError.value = err instanceof Error ? err.message : 'Request failed.'
  } finally {
    submitting.value = false
  }
}

async function replay(integration: OrgIntegration) {
  busyID.value = integration.id
  try {
    const res = await api.replayIntegration(provider, slug, integration.id)
    pushToast({
      title: 'Replay finished',
      description: `${res.data.replayed} replayed, ${res.data.skipped} skipped`,
      tone: 'success',
    })
    await load()
  } catch (err) {
    pushToast({ title: 'Replay failed', description: err instanceof Error ? err.message : undefined, tone: 'error' })
  } finally {
    busyID.value = ''
  }
}

async function remove(integration: OrgIntegration) {
  if (!window.confirm(`Delete integration "${integration.name}"? Notification rules pointing at it stop delivering.`)) {
    return
  }
  busyID.value = integration.id
  try {
    await api.deleteIntegration(provider, slug, integration.id)
    integrations.value = integrations.value.filter((entry) => entry.id !== integration.id)
    pushToast({ title: 'Integration deleted', tone: 'success' })
  } catch (err) {
    pushToast({ title: 'Delete failed', description: err instanceof Error ? err.message : undefined, tone: 'error' })
  } finally {
    busyID.value = ''
  }
}

onMounted(load)
</script>
