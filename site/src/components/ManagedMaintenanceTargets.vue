<template>
  <section
    class="mt-6 rounded border border-surface-border bg-surface-overlay/40 p-5"
    aria-labelledby="maintenance-heading"
  >
    <div class="flex flex-wrap items-start justify-between gap-3">
      <div>
        <h2
          id="maintenance-heading"
          class="text-sm font-semibold text-gray-200"
        >
          Maintenance targets / declared release lines
        </h2>
        <p class="mt-1 text-xs leading-5 text-gray-500">
          Suggestions are explicit organization mappings, not dependency inventory branches. Nothing is created automatically.
        </p>
      </div>
      <button
        type="button"
        class="action"
        :disabled="busy"
        @click="load"
      >
        Refresh evidence
      </button>
    </div>
    <p
      v-if="error"
      class="mt-3 text-xs text-danger"
      role="alert"
    >
      {{ error }}
    </p>
    <p
      v-if="!suggestions && !error"
      class="mt-3 text-xs text-gray-500"
      role="status"
    >
      Loading pinned release evidence…
    </p>
    <template v-if="suggestions">
      <p class="mt-4 break-all font-mono text-[11px] leading-5 text-gray-400">
        {{ suggestions.source.release_version }} · tag {{ suggestions.source.tag }}<br>
        <span class="text-gray-500">{{ suggestions.source.sha }}</span>
      </p>
      <p
        v-if="suggestions.reason"
        class="mt-3 text-xs text-gray-500"
      >
        {{ suggestions.reason }}
      </p>
      <article
        v-for="candidate in suggestions.suggestions"
        :key="candidate.mapping.id"
        class="mt-4 border-t border-surface-border pt-4"
      >
        <div class="flex flex-wrap items-start justify-between gap-3">
          <div class="min-w-0">
            <h3 class="break-all font-mono text-xs text-gray-200">
              {{ candidate.target_branch || candidate.mapping.target_template }}
            </h3>
            <p class="mt-1 break-all font-mono text-[10px] text-gray-500">
              Declared: {{ candidate.mapping.tag_pattern }} → {{ candidate.mapping.target_template }}
            </p>
            <p
              class="mt-2 text-xs leading-5"
              :class="candidate.evidence?.tag_confirmed ? 'text-gray-400' : 'text-warn'"
            >
              {{ candidate.reason }}
            </p>
            <p
              v-if="candidate.evidence?.exists"
              class="mt-1 break-all font-mono text-[10px] text-gray-500"
            >
              Head {{ candidate.evidence.head_sha }} · release ancestor: {{ candidate.evidence.source_ancestor ? 'confirmed' : 'not confirmed' }}
            </p>
          </div>
          <button
            v-if="candidate.evidence?.exists && candidate.evidence.tag_confirmed"
            type="button"
            class="action"
            :disabled="busy"
            @click="choose(candidate)"
          >
            Choose existing target
          </button>
        </div>
        <template v-if="candidate.can_create">
          <label class="mt-3 flex items-start gap-2 text-xs leading-5 text-gray-400">
            <input
              v-model="confirmed[candidate.mapping.id]"
              type="checkbox"
              class="mt-1 accent-accent"
            >
            <span>Create <code>{{ candidate.target_branch }}</code> from exactly <code>{{ suggestions.source.sha }}</code>. Existing branches will never be repointed.</span>
          </label>
          <button
            type="button"
            class="action mt-3"
            :disabled="busy || !confirmed[candidate.mapping.id]"
            @click="create(candidate)"
          >
            Create confirmed maintenance target
          </button>
        </template>
      </article>
      <p
        v-if="suggestions.creation_reason"
        class="mt-4 text-xs leading-5 text-gray-500"
      >
        {{ suggestions.creation_reason }}
      </p>
    </template>
    <details
      v-if="configuration?.can_configure"
      class="mt-5 border-t border-surface-border pt-4"
    >
      <summary class="cursor-pointer text-xs text-accent">
        Organization admin / configure explicit mappings
      </summary>
      <p class="mt-3 text-xs leading-5 text-gray-500">
        Standard tag globs, with target placeholders {major}, {minor}, {patch}, {tag}. Templates only suggest names; a separate confirmed action creates a branch. Settings apply to this organization’s repositories.
      </p>
      <template v-if="!configuration.branch_pr_consent">
        <label class="mt-3 flex items-start gap-2 text-xs leading-5 text-gray-400">
          <input
            v-model="grantBranchConsent"
            type="checkbox"
            class="mt-1 accent-accent"
          >
          <span>I authorize managed Hibou branch and pull-request creation for this organization, subject to caller permissions and operator limits.</span>
        </label>
        <button
          type="button"
          class="action mt-3"
          :disabled="busy || !grantBranchConsent"
          @click="saveBranchConsent"
        >
          Enable organization branch/PR consent
        </button>
      </template>
      <div
        v-for="(mapping, index) in settings.mappings"
        :key="index"
        class="mt-3 grid gap-2 md:grid-cols-[1fr_1fr_1.5fr_auto]"
      >
        <label class="text-[10px] text-gray-500">Mapping ID<input
          v-model="mapping.id"
          class="field mt-1 w-full"
          type="text"
        ></label>
        <label class="text-[10px] text-gray-500">Source tag pattern<input
          v-model="mapping.tag_pattern"
          class="field mt-1 w-full"
          type="text"
          placeholder="v1.2.*"
        ></label>
        <label class="text-[10px] text-gray-500">Explicit target template<input
          v-model="mapping.target_template"
          class="field mt-1 w-full"
          type="text"
          placeholder="release/{major}.{minor}"
        ></label>
        <button
          type="button"
          class="action self-end"
          :aria-label="`Remove mapping ${mapping.id || index + 1}`"
          @click="settings.mappings.splice(index, 1)"
        >
          Remove
        </button>
      </div>
      <div class="mt-3 flex flex-wrap gap-2">
        <button
          type="button"
          class="action"
          @click="addMapping"
        >
          Add release-line mapping
        </button>
        <button
          v-if="selectedBranch && suggestions"
          type="button"
          class="action"
          @click="remember"
        >
          Remember this tag → typed target
        </button>
      </div>
      <label class="mt-4 flex items-start gap-2 text-xs leading-5 text-gray-400">
        <input
          v-model="settings.allow_creation"
          type="checkbox"
          class="mt-1 accent-accent"
        >
        <span>Permit explicit admin maintenance-target creation, additionally constrained by organization branch/PR consent and the operator allowlist.</span>
      </label>
      <button
        type="button"
        class="action mt-4"
        :disabled="busy"
        @click="save"
      >
        Save organization mappings
      </button>
      <p
        v-if="configuration.creation_reason"
        class="mt-3 text-xs leading-5 text-gray-500"
      >
        {{ configuration.creation_reason }}
      </p>
    </details>
  </section>
</template>

<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { maintenanceApi } from '@/api/maintenance'
import { remediationApi } from '@/api/remediation'
import type { MaintenanceSettings, MaintenanceSettingsResponse, MaintenanceSuggestion, MaintenanceSuggestions } from '@/api/maintenance'

const props = defineProps<{ base: string; releaseId: string; selectedBranch: string }>()
const emit = defineEmits<{ choose: [selection: { branch: string; headSHA: string }] }>()
const busy = ref(false)
const error = ref('')
const configuration = ref<MaintenanceSettingsResponse>()
const suggestions = ref<MaintenanceSuggestions>()
const settings = ref<MaintenanceSettings>({ allow_creation: false, mappings: [] })
const confirmed = ref<Record<string, boolean>>({})
const grantBranchConsent = ref(false)
async function perform(action: () => Promise<void>) {
  busy.value = true; error.value = ''
  try { await action() } catch (e) { error.value = e instanceof Error ? e.message : 'Maintenance target request failed.' } finally { busy.value = false }
}
async function load() {
  await perform(async () => {
    const [config, targets] = await Promise.all([maintenanceApi.settings(props.base), maintenanceApi.suggestions(props.base, props.releaseId)])
    configuration.value = config
    settings.value = structuredClone(config.settings)
    suggestions.value = targets
    confirmed.value = {}
  })
}
function choose(candidate: MaintenanceSuggestion) {
  if (candidate.target_branch && candidate.evidence?.exists && candidate.evidence.head_sha) {
    emit('choose', { branch: candidate.target_branch, headSHA: candidate.evidence.head_sha })
  }
}
function addMapping() {
  settings.value.mappings.push({ id: `line-${Date.now()}`, tag_pattern: '', target_template: '' })
}
function remember() {
  if (!suggestions.value || !props.selectedBranch) return
  settings.value.mappings.push({ id: `tag-${Date.now()}`, tag_pattern: suggestions.value.source.tag, target_template: props.selectedBranch })
}
async function save() {
  await perform(async () => {
    configuration.value = await maintenanceApi.save(props.base, settings.value)
    suggestions.value = await maintenanceApi.suggestions(props.base, props.releaseId)
    confirmed.value = {}
  })
}
async function create(candidate: MaintenanceSuggestion) {
  if (!suggestions.value || !confirmed.value[candidate.mapping.id]) return
  await perform(async () => {
    const result = await maintenanceApi.create(props.base, suggestions.value!.source, candidate)
    emit('choose', { branch: result.target_branch, headSHA: result.source_sha })
    suggestions.value = await maintenanceApi.suggestions(props.base, props.releaseId)
    confirmed.value = {}
  })
}
async function saveBranchConsent() {
  if (!grantBranchConsent.value) return
  await perform(async () => {
    await remediationApi.consent(props.base, true)
    configuration.value = await maintenanceApi.settings(props.base)
    suggestions.value = await maintenanceApi.suggestions(props.base, props.releaseId)
    grantBranchConsent.value = false
  })
}
onMounted(load)
</script>

<style scoped>
.action { @apply rounded border border-surface-border px-3 py-2 text-xs text-gray-300 hover:border-accent/50 hover:text-accent disabled:cursor-not-allowed disabled:opacity-40; }
.field { @apply rounded border border-surface-border bg-surface-overlay px-2 py-2 text-xs text-gray-200 outline-none focus:border-accent; }
</style>
