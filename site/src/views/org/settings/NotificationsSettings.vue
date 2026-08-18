<template>
  <div class="space-y-4">
    <div class="flex items-center justify-between border-b border-surface-border pb-2">
      <h2 class="text-base font-semibold text-white">
        Notification rules
      </h2>
      <button
        v-if="isOrgAdmin"
        type="button"
        class="rounded-md border border-surface-border bg-surface-overlay px-3 py-1.5 text-xs font-medium text-gray-200 transition hover:border-accent/50 hover:text-white"
        @click="openCreate"
      >
        New rule
      </button>
      <span
        v-else
        class="text-xs text-gray-500"
      >Read-only — org admins can manage rules</span>
    </div>

    <p class="text-sm text-gray-500">
      Route events (gate failures, new vulnerabilities, leaked secrets…) to an integration.
      In-app notifications are always on; rules add external delivery.
    </p>

    <div
      v-if="loading"
      class="text-sm text-gray-500"
    >
      Loading rules…
    </div>
    <div
      v-else-if="loadFailed"
      class="text-sm text-gray-500"
    >
      Rules could not be loaded.
    </div>

    <ul
      v-else
      class="divide-y divide-surface-border-subtle rounded-lg border border-surface-border"
    >
      <li
        v-for="rule in rules"
        :key="rule.id"
        class="flex items-center gap-3 px-4 py-3"
      >
        <div class="min-w-0 flex-1">
          <div class="flex items-center gap-2 text-sm font-medium text-gray-100">
            <span class="truncate">{{ rule.name }}</span>
            <span
              v-if="!rule.enabled"
              class="rounded-full bg-surface-overlay px-1.5 text-[10px] text-gray-500"
            >disabled</span>
          </div>
          <div class="mt-0.5 text-xs text-gray-500">
            on <span class="font-mono text-gray-400">{{ rule.event_type }}</span>
            → {{ rule.destination_type }}
          </div>
        </div>

        <template v-if="isOrgAdmin">
          <button
            type="button"
            class="rounded-md border border-surface-border px-2 py-1 text-xs text-gray-400 transition hover:border-accent/50 hover:text-gray-200 disabled:opacity-50"
            :disabled="busyID === rule.id"
            @click="toggle(rule)"
          >
            {{ rule.enabled ? 'Disable' : 'Enable' }}
          </button>
          <button
            type="button"
            class="rounded-md border border-surface-border px-2 py-1 text-xs text-gray-400 transition hover:border-accent/50 hover:text-gray-200"
            @click="openEdit(rule)"
          >
            Edit
          </button>
          <button
            type="button"
            class="rounded-md border border-surface-border px-2 py-1 text-xs text-gray-400 transition hover:border-danger/50 hover:text-danger disabled:opacity-50"
            :disabled="busyID === rule.id"
            @click="remove(rule)"
          >
            Delete
          </button>
        </template>
      </li>
      <li
        v-if="rules.length === 0"
        class="px-4 py-6 text-center text-sm text-gray-500"
      >
        No rules yet — events stay in-app only.
      </li>
    </ul>

    <form
      v-if="formOpen"
      class="space-y-3 rounded-lg border border-surface-border bg-surface-raised p-4"
      @submit.prevent="submit"
    >
      <h3 class="text-sm font-semibold text-white">
        {{ editing ? 'Edit rule' : 'New rule' }}
      </h3>
      <div class="grid gap-3 sm:grid-cols-3">
        <label class="block text-xs text-gray-400">
          Name
          <input
            v-model="form.name"
            required
            class="mt-1 w-full rounded-md border border-surface-border bg-surface-overlay px-2.5 py-1.5 text-sm text-gray-100 focus:border-accent/50 focus:outline-none"
          >
        </label>
        <label class="block text-xs text-gray-400">
          Event
          <select
            v-model="form.event_type"
            class="mt-1 w-full rounded-md border border-surface-border bg-surface-overlay px-2.5 py-1.5 text-sm text-gray-100 focus:border-accent/50 focus:outline-none"
          >
            <option
              v-for="eventType in NOTIFICATION_EVENT_TYPES"
              :key="eventType"
              :value="eventType"
            >
              {{ eventType }}
            </option>
          </select>
        </label>
        <label class="block text-xs text-gray-400">
          Destination
          <select
            v-model="form.destination_type"
            class="mt-1 w-full rounded-md border border-surface-border bg-surface-overlay px-2.5 py-1.5 text-sm text-gray-100 focus:border-accent/50 focus:outline-none"
          >
            <option
              v-for="destinationType in INTEGRATION_TYPES"
              :key="destinationType"
              :value="destinationType"
            >
              {{ destinationType }}
            </option>
          </select>
        </label>
      </div>
      <label class="block text-xs text-gray-400">
        Destination config (JSON — usually {"integration_id": "…"} or a direct target)
        <textarea
          v-model="form.destinationConfigText"
          rows="2"
          class="mt-1 w-full rounded-md border border-surface-border bg-surface-overlay px-2.5 py-1.5 font-mono text-xs text-gray-100 focus:border-accent/50 focus:outline-none"
        />
      </label>
      <label class="block text-xs text-gray-400">
        Conditions (JSON — optional filters, e.g. {"severity": "critical"})
        <textarea
          v-model="form.conditionsText"
          rows="2"
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
import { onMounted, reactive, ref } from 'vue'
import { useRoute } from 'vue-router'

import { api, INTEGRATION_TYPES, NOTIFICATION_EVENT_TYPES, type NotificationRule } from '@/api/client'
import { useOrgRole } from '@/composables/useOrgRole'
import { useToast } from '@/composables/useToast'

const route = useRoute()
const { isOrgAdmin } = useOrgRole()
const { pushToast } = useToast()

const provider = route.params.provider as string
const slug = route.params.slug as string

const rules = ref<NotificationRule[]>([])
const loading = ref(true)
const loadFailed = ref(false)
const busyID = ref('')

const formOpen = ref(false)
const editing = ref<NotificationRule | null>(null)
const submitting = ref(false)
const formError = ref('')
const form = reactive({
  name: '',
  event_type: 'gate.failed' as string,
  destination_type: 'webhook' as string,
  destinationConfigText: '{}',
  conditionsText: '{}',
  enabled: true,
})

async function load() {
  loading.value = true
  loadFailed.value = false
  try {
    const res = await api.listNotificationRules(provider, slug)
    rules.value = res.data
  } catch {
    loadFailed.value = true
  } finally {
    loading.value = false
  }
}

function openCreate() {
  editing.value = null
  form.name = ''
  form.event_type = 'gate.failed'
  form.destination_type = 'webhook'
  form.destinationConfigText = '{}'
  form.conditionsText = '{}'
  formError.value = ''
  form.enabled = true
  formOpen.value = true
}

function openEdit(rule: NotificationRule) {
  editing.value = rule
  form.name = rule.name
  form.event_type = rule.event_type
  form.destination_type = rule.destination_type
  form.destinationConfigText = JSON.stringify(rule.destination_config ?? {}, null, 2)
  form.conditionsText = JSON.stringify(rule.conditions ?? {}, null, 2)
  form.enabled = rule.enabled
  formError.value = ''
  formOpen.value = true
}

function parseJSONField(text: string, label: string): Record<string, unknown> | null {
  try {
    return JSON.parse(text || '{}')
  } catch {
    formError.value = `${label} must be valid JSON.`
    return null
  }
}

function ruleBody(destinationConfig: Record<string, unknown>, conditions: Record<string, unknown>) {
  return {
    name: form.name,
    event_type: form.event_type,
    conditions,
    destination_type: form.destination_type,
    destination_config: destinationConfig,
    enabled: form.enabled,
  }
}

async function submit() {
  formError.value = ''
  const destinationConfig = parseJSONField(form.destinationConfigText, 'Destination config')
  if (!destinationConfig) {
    return
  }
  const conditions = parseJSONField(form.conditionsText, 'Conditions')
  if (!conditions) {
    return
  }
  submitting.value = true
  try {
    if (editing.value) {
      await api.updateNotificationRule(provider, slug, editing.value.id, ruleBody(destinationConfig, conditions))
    } else {
      await api.createNotificationRule(provider, slug, ruleBody(destinationConfig, conditions))
    }
    formOpen.value = false
    pushToast({ title: editing.value ? 'Rule updated' : 'Rule created', tone: 'success' })
    await load()
  } catch (err) {
    formError.value = err instanceof Error ? err.message : 'Request failed.'
  } finally {
    submitting.value = false
  }
}

async function toggle(rule: NotificationRule) {
  busyID.value = rule.id
  try {
    await api.updateNotificationRule(provider, slug, rule.id, {
      name: rule.name,
      event_type: rule.event_type,
      conditions: rule.conditions ?? {},
      destination_type: rule.destination_type,
      destination_config: rule.destination_config ?? {},
      enabled: !rule.enabled,
    })
    rule.enabled = !rule.enabled
  } catch (err) {
    pushToast({ title: 'Update failed', description: err instanceof Error ? err.message : undefined, tone: 'error' })
  } finally {
    busyID.value = ''
  }
}

async function remove(rule: NotificationRule) {
  if (!window.confirm(`Delete rule "${rule.name}"?`)) {
    return
  }
  busyID.value = rule.id
  try {
    await api.deleteNotificationRule(provider, slug, rule.id)
    rules.value = rules.value.filter((entry) => entry.id !== rule.id)
    pushToast({ title: 'Rule deleted', tone: 'success' })
  } catch (err) {
    pushToast({ title: 'Delete failed', description: err instanceof Error ? err.message : undefined, tone: 'error' })
  } finally {
    busyID.value = ''
  }
}

onMounted(load)
</script>
