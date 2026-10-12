<template>
  <div class="space-y-6">
    <section>
      <div class="flex items-center justify-between border-b border-surface-border pb-2">
        <h2 class="text-base font-semibold text-white">
          Scanners
        </h2>
        <button
          type="button"
          class="rounded-md border border-surface-border bg-surface-overlay px-3 py-1.5 text-xs font-medium text-gray-200 transition hover:border-accent/50 hover:text-white disabled:opacity-50"
          :disabled="refreshing"
          @click="refresh"
        >
          {{ refreshing ? 'Detecting…' : 'Detect again' }}
        </button>
      </div>
      <p class="mt-2 text-sm text-gray-500">
        Which bundled scanners apply to this repository, detected from the default branch's file list. Nothing in the repository is run.
        Enabling scanners comes later; this view shows what would be scanned and why.
      </p>
    </section>

    <p
      v-if="loading"
      class="text-sm text-gray-500"
    >
      Loading…
    </p>
    <p
      v-else-if="loadError"
      class="text-sm text-danger"
    >
      {{ loadError }}
    </p>
    <p
      v-else-if="!applicability"
      class="text-sm text-gray-500"
    >
      Not detected yet. Detection runs on the next push to the default branch, or now with “Detect again”.
    </p>

    <template v-else>
      <p
        v-if="applicability.status !== 'complete'"
        class="rounded-lg border border-amber-500/30 bg-amber-500/[0.06] px-3 py-2 text-sm text-amber-200"
      >
        {{ applicability.status === 'truncated'
          ? 'The forge returned only part of the file list: what applies is unknown beyond what is shown.'
          : 'The forge could not list the repository: applicability is unknown, not "nothing applies".' }}
      </p>

      <section>
        <h3 class="text-xs font-semibold uppercase tracking-wide text-gray-500">
          Detected
        </h3>
        <p class="mt-1 text-xs text-gray-500">
          {{ applicability.result.file_count }} files on <span class="font-mono">{{ applicability.ref_name }}</span>
          at <span class="font-mono">{{ applicability.commit_sha.slice(0, 7) }}</span> · {{ relativeTime(applicability.created_at) }}
        </p>
        <div class="mt-2 flex flex-wrap gap-1.5">
          <span
            v-for="language in languages"
            :key="language.name"
            class="rounded-full border border-surface-border bg-surface-overlay px-2 py-0.5 text-xs text-gray-300"
          >{{ language.name }} <span class="text-gray-500">{{ language.count }}</span></span>
          <span
            v-if="applicability.result.text_only"
            class="text-xs text-gray-500"
          >No source code: source scanners do not apply; secret scanning still does.</span>
        </div>
        <ul
          v-if="applicability.result.modules.length > 0"
          class="mt-3 space-y-1 text-xs text-gray-400"
        >
          <li
            v-for="module in applicability.result.modules"
            :key="module.root"
          >
            <span class="font-mono text-gray-200">{{ module.root }}</span>
            · {{ module.build_system }}<span v-if="module.languages.length"> · {{ module.languages.join(', ') }}</span>
          </li>
        </ul>
      </section>

      <section>
        <h3 class="text-xs font-semibold uppercase tracking-wide text-gray-500">
          Applicable scanners
        </h3>
        <p
          v-if="applicability.result.applicable.length === 0"
          class="mt-1 text-sm text-gray-500"
        >
          None of the bundled scanners applies.
        </p>
        <ul class="mt-2 divide-y divide-surface-border-subtle rounded-lg border border-surface-border">
          <li
            v-for="scope in applicability.result.applicable"
            :key="scope.scanner_id"
            class="px-4 py-3"
          >
            <div class="flex flex-wrap items-center gap-2 text-sm text-gray-100">
              <span>{{ scannerName(scope.scanner_id) }}</span>
              <span
                v-if="scope.preview"
                class="rounded-full bg-amber-500/15 px-1.5 text-[10px] text-amber-300"
              >pre-release</span>
              <span class="text-xs text-gray-500">{{ scannerVersion(scope.scanner_id) }}</span>
            </div>
            <p class="mt-0.5 text-xs text-gray-500">
              {{ scope.reason }} · {{ scope.modules.length ? scope.modules.join(', ') : 'repository root' }}
            </p>
            <div class="mt-1.5 flex flex-wrap gap-1">
              <span
                v-for="capability in scope.capabilities"
                :key="`${capability.language}-${capability.capability}`"
                class="rounded border px-1.5 py-0.5 text-[11px]"
                :class="capability.evidence.startsWith('measured:') ? 'border-emerald-500/30 text-emerald-300' : 'border-surface-border text-gray-400'"
                :title="capability.evidence.startsWith('measured:') ? `Measured: ${capability.evidence.slice('measured:'.length)}` : 'Declared by the engine, not measured by hibou'"
              >{{ capability.language }} · {{ capability.capability }}</span>
            </div>
          </li>
        </ul>
      </section>

      <section>
        <h3 class="text-xs font-semibold uppercase tracking-wide text-gray-500">
          What runs
        </h3>
        <p class="mt-1 text-xs text-gray-500">
          Organization requirements come first and cannot be switched off here; an exception approved by an org admin can waive one.
        </p>
        <ul class="mt-2 divide-y divide-surface-border-subtle rounded-lg border border-surface-border">
          <li
            v-for="decision in visibleDecisions"
            :key="decision.scanner_id"
            class="px-4 py-3 text-xs"
          >
            <div class="flex flex-wrap items-center gap-2">
              <span class="text-sm text-gray-100">{{ scannerName(decision.scanner_id) }}</span>
              <span
                class="rounded-full px-1.5 text-[10px]"
                :class="stateClass(decision.state)"
              >{{ stateLabel(decision.state) }}</span>
              <select
                v-if="canEdit"
                :value="decision.repo_mode"
                :disabled="savingScanner === decision.scanner_id"
                class="ml-auto rounded-md border border-surface-border bg-surface-overlay px-2 py-1 text-xs text-gray-200"
                :aria-label="`Repository setting for ${scannerName(decision.scanner_id)}`"
                @change="saveMode(decision.scanner_id, ($event.target as HTMLSelectElement).value as ScannerDecision['repo_mode'])"
              >
                <option value="inherit">
                  Inherit
                </option>
                <option value="enabled">
                  Enabled
                </option>
                <option value="disabled">
                  Disabled
                </option>
              </select>
            </div>
            <p class="mt-0.5 text-gray-500">
              {{ decision.reason }}
            </p>
            <div
              v-if="decision.state === 'required'"
              class="mt-1.5"
            >
              <button
                v-if="exceptionFor !== decision.scanner_id"
                type="button"
                class="text-accent hover:underline"
                @click="openException(decision)"
              >
                Request an exception…
              </button>
              <div
                v-else
                class="flex flex-wrap items-center gap-2"
              >
                <input
                  v-model="exceptionReason"
                  type="text"
                  class="w-72 rounded-md border border-surface-border bg-surface-overlay px-2 py-1 text-xs text-gray-200"
                  placeholder="Why this repository should not need it"
                >
                <label class="inline-flex items-center gap-1 text-gray-400">
                  for
                  <input
                    v-model.number="exceptionDays"
                    type="number"
                    min="1"
                    max="365"
                    class="w-16 rounded-md border border-surface-border bg-surface-overlay px-2 py-1 text-xs text-gray-200"
                  >
                  days
                </label>
                <button
                  type="button"
                  class="rounded-md border border-surface-border px-2 py-1 text-gray-200 disabled:opacity-50"
                  :disabled="!exceptionReason.trim()"
                  @click="submitException(decision)"
                >
                  Request
                </button>
                <button
                  type="button"
                  class="text-gray-500"
                  @click="exceptionFor = ''"
                >
                  Cancel
                </button>
              </div>
            </div>
          </li>
        </ul>
        <ul
          v-if="exceptions.length"
          class="mt-2 space-y-0.5 text-xs text-gray-400"
        >
          <li
            v-for="exception in exceptions"
            :key="exception.id"
          >
            Exception {{ exception.status }} — “{{ exception.reason }}” · expires {{ relativeTime(exception.expires_at) }}
          </li>
        </ul>
      </section>

      <section>
        <div class="flex items-center justify-between">
          <h3 class="text-xs font-semibold uppercase tracking-wide text-gray-500">
            Scan plan preview
          </h3>
          <button
            type="button"
            class="text-xs text-accent hover:underline disabled:opacity-50"
            :disabled="planLoading"
            @click="previewPlan"
          >
            {{ plan ? 'Refresh preview' : 'Preview plan' }}
          </button>
        </div>
        <p class="mt-1 text-xs text-gray-500">
          What CI would run on a Linux x86-64 runner, without running anything. No CI YAML knowledge needed to see what waits on what.
        </p>
        <p
          v-if="planError"
          class="mt-2 text-xs text-danger"
        >
          {{ planError }}
        </p>
        <template v-if="plan">
          <p class="mt-2 text-xs text-gray-400">
            Mode <span class="font-medium text-gray-200">{{ plan.mode }}</span> — {{ plan.mode_reason }}.
          </p>
          <ul class="mt-2 divide-y divide-surface-border-subtle rounded-lg border border-surface-border">
            <li
              v-for="job in plan.jobs"
              :key="job.id"
              class="px-4 py-3 text-xs"
            >
              <div class="flex items-center gap-2">
                <span
                  class="h-2 w-2 shrink-0 rounded-full"
                  :class="job.status === 'ready' ? 'bg-emerald-400' : 'bg-warning'"
                />
                <span class="text-sm text-gray-100">{{ scannerName(job.scanner_id) }}</span>
                <span class="text-gray-500">{{ job.scope }} · {{ job.targets.join(', ') }}</span>
              </div>
              <p
                v-if="job.blocked_reason"
                class="mt-1 text-amber-300"
              >
                Blocked: {{ job.blocked_reason }}
              </p>
              <p
                v-if="job.prerequisites.length"
                class="mt-1 text-gray-500"
              >
                Waits for: {{ job.prerequisites.join(', ') }}
              </p>
              <p
                v-if="job.artifact"
                class="mt-1 truncate text-gray-500"
                :title="job.artifact.url"
              >
                Artifact from {{ job.artifact.source }}, sha256 {{ job.artifact.sha256.slice(0, 12) }}…
              </p>
            </li>
          </ul>
        </template>
      </section>

      <section>
        <h3 class="text-xs font-semibold uppercase tracking-wide text-gray-500">
          Scope
        </h3>
        <ul
          v-if="applicability.result.exclusions.length"
          class="mt-2 space-y-0.5 text-xs text-gray-400"
        >
          <li
            v-for="exclusion in applicability.result.exclusions"
            :key="exclusion.path"
          >
            <span class="font-mono text-gray-300">{{ exclusion.path }}</span> — excluded: {{ exclusion.reason }}
          </li>
        </ul>
        <ul
          v-if="blockedExclusions.length"
          class="mt-1 space-y-0.5 text-xs text-amber-300"
        >
          <li
            v-for="exclusion in blockedExclusions"
            :key="exclusion.path"
          >
            <span class="font-mono">{{ exclusion.path }}</span> — not excluded: {{ exclusion.blocked }}
          </li>
        </ul>
        <ul
          v-if="overrides.length"
          class="mt-2 space-y-0.5 text-xs text-gray-400"
        >
          <li
            v-for="override in overrides"
            :key="override.id"
            class="flex items-center gap-2"
          >
            <span>{{ override.kind === 'exclude' ? 'Exclude' : 'Module root' }} <span class="font-mono text-gray-300">{{ override.path }}</span> — {{ override.reason }}</span>
            <button
              v-if="canEdit"
              type="button"
              class="text-gray-500 hover:text-danger"
              @click="removeOverride(override.id)"
            >
              Remove
            </button>
          </li>
        </ul>
        <div
          v-if="canEdit"
          class="mt-2 flex flex-wrap items-center gap-2 text-xs"
        >
          <select
            v-model="overrideDraft.kind"
            class="rounded-md border border-surface-border bg-surface-overlay px-2 py-1 text-gray-200"
          >
            <option value="exclude">
              Exclude path
            </option>
            <option value="module_root">
              Declare module root
            </option>
          </select>
          <input
            v-model="overrideDraft.path"
            type="text"
            placeholder="path/in/repo"
            class="w-44 rounded-md border border-surface-border bg-surface-overlay px-2 py-1 font-mono text-gray-200"
          >
          <input
            v-model="overrideDraft.reason"
            type="text"
            placeholder="Why"
            class="w-64 rounded-md border border-surface-border bg-surface-overlay px-2 py-1 text-gray-200"
          >
          <button
            type="button"
            class="rounded-md border border-surface-border px-2 py-1 text-gray-200 disabled:opacity-50"
            :disabled="!overrideDraft.path.trim() || !overrideDraft.reason.trim()"
            @click="addOverride"
          >
            Add
          </button>
          <span class="text-gray-500">Detection re-runs; an exclusion hiding code the org requires scanned needs an approved exception for that path.</span>
        </div>
      </section>
    </template>
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, reactive, ref } from 'vue'
import { useRoute } from 'vue-router'

import { api, type CoverageException, type RepoApplicability, type RepoScopeOverride, type ScanPlan, type ScannerCatalog, type ScannerDecision } from '@/api/client'
import { useOrgRole } from '@/composables/useOrgRole'
import { relativeTime } from '@/lib/datetime'

const route = useRoute()
const provider = route.params.provider as string
const slug = route.params.slug as string
const repoSlug = route.params.repoSlug as string

const applicability = ref<RepoApplicability | null>(null)
const catalog = ref<ScannerCatalog | null>(null)
const loading = ref(true)
const loadError = ref('')
const refreshing = ref(false)
const { isOrgAdmin } = useOrgRole()
const canEdit = computed(() => isOrgAdmin.value)
const decisions = ref<ScannerDecision[]>([])
const exceptions = ref<CoverageException[]>([])
const savingScanner = ref('')
const exceptionFor = ref('')
const exceptionReason = ref('')
const exceptionDays = ref(90)

const overrides = ref<RepoScopeOverride[]>([])
const overrideDraft = reactive<{ kind: RepoScopeOverride['kind']; path: string; reason: string }>({ kind: 'exclude', path: '', reason: '' })
const blockedExclusions = computed(() => (applicability.value?.result.owner_exclusions ?? []).filter(exclusion => !exclusion.applied))

async function loadOverrides() {
  try {
    overrides.value = (await api.listScopeOverrides(provider, slug, repoSlug)).data ?? []
  } catch {
    overrides.value = []
  }
}

async function addOverride() {
  try {
    await api.createScopeOverride(provider, slug, repoSlug, { kind: overrideDraft.kind, path: overrideDraft.path.trim(), reason: overrideDraft.reason.trim() })
    overrideDraft.path = ''
    overrideDraft.reason = ''
    await loadOverrides()
  } catch (err) {
    loadError.value = err instanceof Error ? err.message : 'Could not save the override'
  }
}

async function removeOverride(id: string) {
  try {
    await api.deleteScopeOverride(provider, slug, repoSlug, id)
    await loadOverrides()
  } catch (err) {
    loadError.value = err instanceof Error ? err.message : 'Could not remove the override'
  }
}

const visibleDecisions = computed(() => decisions.value.filter(decision => decision.state !== 'not_applicable'))

async function loadDecisions() {
  try {
    const response = await api.getRepoScannerSettings(provider, slug, repoSlug)
    decisions.value = response.data?.decisions ?? []
    exceptions.value = response.data?.exceptions ?? []
  } catch {
    decisions.value = []
  }
}

async function saveMode(scannerID: string, mode: ScannerDecision['repo_mode']) {
  savingScanner.value = scannerID
  try {
    const response = await api.setRepoScannerSetting(provider, slug, repoSlug, scannerID, mode)
    decisions.value = response.data?.decisions ?? decisions.value
    plan.value = null
  } catch (err) {
    loadError.value = err instanceof Error ? err.message : 'Could not save the setting'
  } finally {
    savingScanner.value = ''
  }
}

function openException(decision: ScannerDecision) {
  exceptionFor.value = decision.scanner_id
  exceptionReason.value = ''
}

async function submitException(decision: ScannerDecision) {
  const requirement = decision.requirements?.[0]
  if (!requirement) return
  try {
    await api.requestCoverageException(provider, slug, repoSlug, { requirement_id: requirement, reason: exceptionReason.value.trim(), expires_in_days: exceptionDays.value })
    exceptionFor.value = ''
    await Promise.all([loadDecisions(), loadOverrides()])
  } catch (err) {
    loadError.value = err instanceof Error ? err.message : 'Could not request the exception'
  }
}

function stateLabel(state: ScannerDecision['state']) {
  return { required: 'required by org', enabled: 'enabled', recommended: 'on by default', disabled: 'disabled', off: 'pre-release, off', not_applicable: 'not applicable' }[state]
}

function stateClass(state: ScannerDecision['state']) {
  switch (state) {
    case 'required':
      return 'bg-accent/15 text-accent'
    case 'enabled':
    case 'recommended':
      return 'bg-emerald-500/15 text-emerald-300'
    default:
      return 'bg-surface-overlay text-gray-400'
  }
}

const plan = ref<ScanPlan | null>(null)
const planLoading = ref(false)
const planError = ref('')

async function previewPlan() {
  planLoading.value = true
  planError.value = ''
  try {
    const response = await api.previewScanPlan(provider, slug, repoSlug, { os: 'linux', arch: 'amd64' })
    plan.value = response.data?.plan ?? null
  } catch (err) {
    planError.value = err instanceof Error ? err.message : 'Could not build the plan'
  } finally {
    planLoading.value = false
  }
}

const languages = computed(() =>
  Object.entries(applicability.value?.result.languages ?? {})
    .map(([name, count]) => ({ name, count }))
    .sort((a, b) => b.count - a.count),
)

function scannerName(id: string) {
  return catalog.value?.scanners.find(scanner => scanner.id === id)?.name ?? id
}

function scannerVersion(id: string) {
  return catalog.value?.scanners.find(scanner => scanner.id === id)?.engine_version ?? ''
}

onMounted(async () => {
  try {
    const [detected, scanners] = await Promise.all([
      api.getRepoApplicability(provider, slug, repoSlug),
      api.getScannerCatalog().catch(() => null),
    ])
    applicability.value = detected.data?.applicability ?? null
    catalog.value = scanners?.data ?? null
    await loadDecisions()
  } catch (err) {
    loadError.value = err instanceof Error ? err.message : 'Could not load scanner applicability'
  } finally {
    loading.value = false
  }
})

async function refresh() {
  refreshing.value = true
  loadError.value = ''
  try {
    const response = await api.refreshRepoApplicability(provider, slug, repoSlug)
    applicability.value = response.data?.applicability ?? null
  } catch (err) {
    loadError.value = err instanceof Error ? err.message : 'Detection failed'
  } finally {
    refreshing.value = false
  }
}
</script>
