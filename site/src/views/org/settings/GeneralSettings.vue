<template>
  <div class="space-y-6">
    <!-- Org identity -->
    <section>
      <h2 class="border-b border-surface-border pb-2 text-base font-semibold text-white">
        Organization
      </h2>
      <dl class="mt-3 grid gap-x-8 gap-y-2 text-sm sm:grid-cols-2">
        <div class="flex justify-between gap-4 sm:block">
          <dt class="text-gray-500">
            Name
          </dt>
          <dd class="text-gray-200 sm:mt-0.5">
            {{ org?.display_name || org?.name || '—' }}
          </dd>
        </div>
        <div class="flex justify-between gap-4 sm:block">
          <dt class="text-gray-500">
            Slug
          </dt>
          <dd class="font-mono text-gray-200 sm:mt-0.5">
            {{ org?.slug || '—' }}
          </dd>
        </div>
        <div class="flex justify-between gap-4 sm:block">
          <dt class="text-gray-500">
            Forge
          </dt>
          <dd class="text-gray-200 sm:mt-0.5">
            <a
              v-if="org?.forge_url"
              :href="org.forge_url"
              target="_blank"
              rel="noopener noreferrer"
              class="text-accent hover:underline"
            >{{ org.provider }}</a>
            <template v-else>
              {{ org?.provider || '—' }}
            </template>
          </dd>
        </div>
        <div class="flex justify-between gap-4 sm:block">
          <dt class="text-gray-500">
            Your role
          </dt>
          <dd class="sm:mt-0.5">
            <span class="rounded-full border border-surface-border px-2 py-0.5 text-xs font-medium capitalize text-gray-300">
              {{ role || 'member' }}
            </span>
          </dd>
        </div>
      </dl>
    </section>

    <!-- Analysis settings -->
    <section>
      <div class="flex items-center justify-between border-b border-surface-border pb-2">
        <h2 class="text-base font-semibold text-white">
          Analysis
        </h2>
        <span
          v-if="!isOrgAdmin"
          class="text-xs text-gray-500"
        >Read-only — org admins can change these</span>
      </div>

      <div
        v-if="loading"
        class="mt-3 text-sm text-gray-500"
      >
        Loading settings…
      </div>

      <div
        v-else-if="loadFailed"
        class="mt-3 text-sm text-gray-500"
      >
        Settings could not be loaded.
      </div>

      <div
        v-else
        class="mt-1 divide-y divide-surface-border-subtle"
      >
        <label class="flex items-start justify-between gap-6 py-3">
          <span>
            <span class="block text-sm font-medium text-gray-200">VEX auto-propagation</span>
            <span class="mt-0.5 block text-xs text-gray-500">
              Automatically carry VEX statements (not-affected / fixed verdicts) forward to new
              snapshots of the same component, so triage doesn't repeat on every scan.
            </span>
          </span>
          <input
            v-model="form.vex_auto_propagate"
            type="checkbox"
            class="mt-1 h-4 w-4 shrink-0 accent-accent"
            :disabled="!isOrgAdmin"
          >
        </label>

        <label class="flex items-start justify-between gap-6 py-3">
          <span>
            <span class="block text-sm font-medium text-gray-200">Reachability analysis</span>
            <span class="mt-0.5 block text-xs text-gray-500">
              Use call-graph reachability results (when uploaded) to justify VEX statements:
              vulnerable code that is never called can be marked not-affected with evidence.
            </span>
          </span>
          <input
            v-model="form.vex_reachability_analysis"
            type="checkbox"
            class="mt-1 h-4 w-4 shrink-0 accent-accent"
            :disabled="!isOrgAdmin"
          >
        </label>

        <div class="flex items-start justify-between gap-6 py-3">
          <div>
            <div class="text-sm font-medium text-gray-200">
              Default TLP label
            </div>
            <p class="mt-0.5 text-xs text-gray-500">
              Traffic Light Protocol marking applied to exported documents (VEX, compliance
              reports) when no explicit label is chosen.
            </p>
          </div>
          <select
            v-model="form.default_tlp_label"
            class="h-8 shrink-0 rounded-md border border-surface-border bg-surface-overlay px-2 text-sm text-gray-200 focus:border-accent/50 focus:outline-none disabled:opacity-60"
            :disabled="!isOrgAdmin"
          >
            <option value="">
              Not set
            </option>
            <option
              v-for="label in TLP_LABELS"
              :key="label"
              :value="label"
            >
              {{ label }}
            </option>
          </select>
        </div>
      </div>

      <div
        v-if="isOrgAdmin && !loading && !loadFailed"
        class="mt-4 flex items-center gap-3"
      >
        <button
          class="rounded-md bg-ok-muted px-3 py-1.5 text-sm font-medium text-white transition hover:bg-ok-muted/80 disabled:cursor-not-allowed disabled:opacity-50"
          type="button"
          :disabled="saving || !isDirty"
          @click="save"
        >
          {{ saving ? 'Saving…' : 'Save changes' }}
        </button>
        <span
          v-if="saveError"
          class="text-xs text-danger"
        >{{ saveError }}</span>
        <span
          v-else-if="saved"
          class="text-xs text-ok"
        >Saved.</span>
      </div>
    </section>

    <!-- Danger zone -->
    <section v-if="isOrgAdmin">
      <h2 class="border-b border-danger/30 pb-2 text-base font-semibold text-danger">
        Danger zone
      </h2>
      <div class="mt-3 flex flex-col gap-3 rounded-lg border border-danger/30 p-4 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <div class="text-sm font-medium text-gray-100">
            Delete this organization
          </div>
          <div class="text-xs text-gray-500">
            Removes the organization from Hibou with all its repositories, snapshots, findings, and tokens.
            Nothing is touched on the forge.
          </div>
        </div>
        <button
          type="button"
          class="shrink-0 rounded-md border border-danger/50 px-3 py-1.5 text-xs font-medium text-danger transition hover:bg-danger/10 disabled:opacity-50"
          :disabled="deleting"
          @click="deleteOrg"
        >
          Delete organization
        </button>
      </div>
      <p
        v-if="deleteError"
        class="mt-2 text-xs text-danger"
      >
        {{ deleteError }}
      </p>
    </section>
  </div>
</template>

<script setup lang="ts">
import type { Ref } from 'vue'
import { computed, inject, reactive, ref, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'

import { api, type Organization, type OrgSettings } from '@/api/client'
import { useOrgRole } from '@/composables/useOrgRole'

const TLP_LABELS = ['TLP:CLEAR', 'TLP:GREEN', 'TLP:AMBER', 'TLP:AMBER+STRICT', 'TLP:RED']

const route = useRoute()
const router = useRouter()
const provider = computed(() => route.params.provider as string)
const slug = computed(() => route.params.slug as string)

const org = inject<Ref<Organization | null>>('org', ref(null))
const { role, isOrgAdmin } = useOrgRole()

const loading = ref(true)
const loadFailed = ref(false)
const saving = ref(false)
const saved = ref(false)
const saveError = ref('')
const persisted = ref<OrgSettings | null>(null)
const form = reactive<OrgSettings>({
  vex_auto_propagate: false,
  vex_reachability_analysis: false,
  default_tlp_label: '',
})

const isDirty = computed(() => {
  const current = persisted.value
  if (!current) {
    return false
  }
  return current.vex_auto_propagate !== form.vex_auto_propagate
    || current.vex_reachability_analysis !== form.vex_reachability_analysis
    || current.default_tlp_label !== form.default_tlp_label
})

watch(
  [provider, slug],
  async () => {
    loading.value = true
    loadFailed.value = false
    try {
      const res = await api.getOrgSettings(provider.value, slug.value)
      persisted.value = res.data
      Object.assign(form, res.data)
    } catch {
      loadFailed.value = true
    } finally {
      loading.value = false
    }
  },
  { immediate: true },
)

async function save() {
  saving.value = true
  saved.value = false
  saveError.value = ''
  try {
    const res = await api.updateOrgSettings(provider.value, slug.value, { ...form })
    persisted.value = res.data
    Object.assign(form, res.data)
    saved.value = true
  } catch (error) {
    saveError.value = error instanceof Error ? error.message : 'Failed to save settings'
  } finally {
    saving.value = false
  }
}

const deleting = ref(false)
const deleteError = ref('')

async function deleteOrg() {
  const expected = slug.value
  const typed = window.prompt(
    `This permanently deletes the organization and all its Hibou data.\n\nType "${expected}" to confirm:`,
  )
  if (typed !== expected) {
    return
  }
  deleting.value = true
  deleteError.value = ''
  try {
    await api.deleteOrg(provider.value, slug.value)
    await router.push('/orgs')
  } catch (error) {
    deleteError.value = error instanceof Error ? error.message : 'Failed to delete organization'
  } finally {
    deleting.value = false
  }
}
</script>
