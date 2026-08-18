<template>
  <div class="space-y-4">
    <div class="flex items-center justify-between border-b border-surface-border pb-2">
      <h2 class="text-base font-semibold text-white">
        Quality gates
      </h2>
      <button
        v-if="isOrgAdmin"
        type="button"
        class="rounded-md border border-surface-border bg-surface-overlay px-3 py-1.5 text-xs font-medium text-gray-200 transition hover:border-accent/50 hover:text-white"
        @click="openCreate"
      >
        New gate
      </button>
      <span
        v-else
        class="text-xs text-gray-500"
      >Read-only — org admins can manage gates</span>
    </div>

    <!-- GitOps precedence: the file is the source of truth, this page is the net under it. -->
    <div class="rounded-lg border border-surface-border bg-surface-raised px-4 py-3 text-sm text-gray-400">
      <p>
        Gates are configured <span class="font-medium text-gray-200">in each repository's</span>
        <code class="rounded bg-surface-overlay px-1 font-mono text-xs">.hibou.yml</code> — reviewed
        and versioned like any code change (see each repo's
        <span class="text-gray-300">Settings → Configuration</span>, which can open the onboarding PR).
        The gates below are the <span class="font-medium text-gray-200">org-wide fallback</span> for
        repositories that don't have the file yet; a repo file always wins over them.
      </p>
      <details class="mt-2">
        <summary class="cursor-pointer text-xs text-gray-500 transition hover:text-gray-300">
          Example .hibou.yml
        </summary>
        <pre class="mt-2 overflow-x-auto rounded-md bg-surface-overlay p-3 font-mono text-xs leading-relaxed text-gray-300">version: 1
quality_gates:
  - branches: ["main"]
    enforcement: blocking
    vulnerabilities:
      max_critical: 0
      max_high: 0
      max_new_total: 0
    secrets:
      max_new: 0
    coverage:
      min_coverage: 80</pre>
      </details>
    </div>

    <div
      v-if="loading"
      class="text-sm text-gray-500"
    >
      Loading gates…
    </div>
    <div
      v-else-if="loadFailed"
      class="text-sm text-gray-500"
    >
      Gates could not be loaded.
    </div>

    <ul
      v-else
      class="divide-y divide-surface-border-subtle rounded-lg border border-surface-border"
    >
      <li
        v-for="gate in gates"
        :key="gate.id"
        class="flex items-center gap-3 px-4 py-3"
      >
        <div class="min-w-0 flex-1">
          <div class="flex items-center gap-2 text-sm font-medium text-gray-100">
            <span class="truncate">{{ gate.name }}</span>
            <span class="rounded-full border border-surface-border px-1.5 text-[10px] text-gray-500">
              {{ gate.repo_id?.Valid ? 'repo-scoped' : 'org-wide' }}
            </span>
            <span
              v-if="!gate.enabled"
              class="rounded-full bg-surface-overlay px-1.5 text-[10px] text-gray-500"
            >disabled</span>
          </div>
          <div class="mt-0.5 text-xs text-gray-500">
            max critical {{ gate.max_critical }} · max high {{ gate.max_high }}
            <template v-if="gate.max_medium?.Valid">
              · max medium {{ gate.max_medium.Int32 }}
            </template>
            <template v-if="gate.max_new_findings?.Valid">
              · max new findings {{ gate.max_new_findings.Int32 }}
            </template>
            <template v-if="gate.description">
              — {{ gate.description }}
            </template>
          </div>
        </div>

        <template v-if="isOrgAdmin">
          <button
            type="button"
            class="rounded-md border border-surface-border px-2 py-1 text-xs text-gray-400 transition hover:border-accent/50 hover:text-gray-200"
            @click="openEdit(gate)"
          >
            Edit
          </button>
          <button
            type="button"
            class="rounded-md border border-surface-border px-2 py-1 text-xs text-gray-400 transition hover:border-danger/50 hover:text-danger disabled:opacity-50"
            :disabled="busyID === gate.id"
            @click="remove(gate)"
          >
            Delete
          </button>
        </template>
      </li>
      <li
        v-if="gates.length === 0"
        class="px-4 py-6 text-center text-sm text-gray-500"
      >
        No gates — repositories rely on their .hibou.yml, or pass by default.
      </li>
    </ul>

    <form
      v-if="formOpen"
      class="space-y-3 rounded-lg border border-surface-border bg-surface-raised p-4"
      @submit.prevent="submit"
    >
      <h3 class="text-sm font-semibold text-white">
        {{ editing ? 'Edit gate' : 'New org-wide gate' }}
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
          Description
          <input
            v-model="form.description"
            class="mt-1 w-full rounded-md border border-surface-border bg-surface-overlay px-2.5 py-1.5 text-sm text-gray-100 focus:border-accent/50 focus:outline-none"
          >
        </label>
      </div>
      <div class="grid gap-3 sm:grid-cols-4">
        <label class="block text-xs text-gray-400">
          Max critical
          <input
            v-model.number="form.max_critical"
            type="number"
            min="0"
            required
            class="mt-1 w-full rounded-md border border-surface-border bg-surface-overlay px-2.5 py-1.5 text-sm text-gray-100 focus:border-accent/50 focus:outline-none"
          >
        </label>
        <label class="block text-xs text-gray-400">
          Max high
          <input
            v-model.number="form.max_high"
            type="number"
            min="0"
            required
            class="mt-1 w-full rounded-md border border-surface-border bg-surface-overlay px-2.5 py-1.5 text-sm text-gray-100 focus:border-accent/50 focus:outline-none"
          >
        </label>
        <label class="block text-xs text-gray-400">
          Max medium (blank = ∞)
          <input
            v-model="form.max_medium"
            type="number"
            min="0"
            class="mt-1 w-full rounded-md border border-surface-border bg-surface-overlay px-2.5 py-1.5 text-sm text-gray-100 focus:border-accent/50 focus:outline-none"
          >
        </label>
        <label class="block text-xs text-gray-400">
          Max new findings (blank = ∞)
          <input
            v-model="form.max_new_findings"
            type="number"
            min="0"
            class="mt-1 w-full rounded-md border border-surface-border bg-surface-overlay px-2.5 py-1.5 text-sm text-gray-100 focus:border-accent/50 focus:outline-none"
          >
        </label>
      </div>
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

import { api, type QualityGate, type QualityGateInput } from '@/api/client'
import { useOrgRole } from '@/composables/useOrgRole'
import { useToast } from '@/composables/useToast'

const route = useRoute()
const { isOrgAdmin } = useOrgRole()
const { pushToast } = useToast()

const provider = route.params.provider as string
const slug = route.params.slug as string

const gates = ref<QualityGate[]>([])
const loading = ref(true)
const loadFailed = ref(false)
const busyID = ref('')

const formOpen = ref(false)
const editing = ref<QualityGate | null>(null)
const submitting = ref(false)
const formError = ref('')
const form = reactive({
  name: '',
  description: '',
  max_critical: 0,
  max_high: 0,
  max_medium: '' as string | number,
  max_new_findings: '' as string | number,
  enabled: true,
})

async function load() {
  loading.value = true
  loadFailed.value = false
  try {
    const res = await api.listQualityGates(provider, slug)
    gates.value = res.data
  } catch {
    loadFailed.value = true
  } finally {
    loading.value = false
  }
}

function openCreate() {
  editing.value = null
  form.name = ''
  form.description = ''
  form.max_critical = 0
  form.max_high = 0
  form.max_medium = ''
  form.max_new_findings = ''
  form.enabled = true
  formError.value = ''
  formOpen.value = true
}

function openEdit(gate: QualityGate) {
  editing.value = gate
  form.name = gate.name
  form.description = gate.description
  form.max_critical = gate.max_critical
  form.max_high = gate.max_high
  form.max_medium = gate.max_medium?.Valid ? gate.max_medium.Int32 : ''
  form.max_new_findings = gate.max_new_findings?.Valid ? gate.max_new_findings.Int32 : ''
  form.enabled = gate.enabled
  formError.value = ''
  formOpen.value = true
}

function optionalNumber(value: string | number): number | undefined {
  if (value === '' || value === null) {
    return undefined
  }
  return Number(value)
}

function gateBody(): QualityGateInput {
  return {
    name: form.name,
    description: form.description,
    max_critical: form.max_critical,
    max_high: form.max_high,
    max_medium: optionalNumber(form.max_medium),
    max_new_findings: optionalNumber(form.max_new_findings),
    enabled: form.enabled,
  }
}

async function submit() {
  formError.value = ''
  submitting.value = true
  try {
    if (editing.value) {
      await api.updateQualityGate(provider, slug, editing.value.id, gateBody())
    } else {
      await api.createQualityGate(provider, slug, gateBody())
    }
    formOpen.value = false
    pushToast({ title: editing.value ? 'Gate updated' : 'Gate created', tone: 'success' })
    await load()
  } catch (err) {
    formError.value = err instanceof Error ? err.message : 'Request failed.'
  } finally {
    submitting.value = false
  }
}

async function remove(gate: QualityGate) {
  if (!window.confirm(`Delete gate "${gate.name}"?`)) {
    return
  }
  busyID.value = gate.id
  try {
    await api.deleteQualityGate(provider, slug, gate.id)
    gates.value = gates.value.filter((entry) => entry.id !== gate.id)
    pushToast({ title: 'Gate deleted', tone: 'success' })
  } catch (err) {
    pushToast({ title: 'Delete failed', description: err instanceof Error ? err.message : undefined, tone: 'error' })
  } finally {
    busyID.value = ''
  }
}

onMounted(load)
</script>
