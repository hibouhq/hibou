<template>
  <section
    class="remediation mx-auto max-w-6xl px-4 pb-12"
    aria-labelledby="remediation-heading"
  >
    <header class="border-b border-surface-border pb-6">
      <p class="mb-2 font-mono text-[10px] uppercase tracking-[0.24em] text-accent">
        Dependency remediation / managed workspace
      </p>
      <div class="flex flex-wrap items-start justify-between gap-4">
        <div>
          <h1
            id="remediation-heading"
            class="text-2xl font-semibold tracking-tight text-white"
          >
            A patch, not a promise.
          </h1>
          <p class="mt-2 max-w-2xl text-sm leading-6 text-gray-400">
            Resolve selected advisories in an isolated toolchain. Review a verified dependency-only patch before downloading or opening a pull request.
          </p>
        </div>
        <RouterLink
          :to="{ name: 'repo-releases', params: route.params }"
          class="text-xs text-gray-400 hover:text-accent"
        >
          ← Releases
        </RouterLink>
      </div>
    </header>

    <p
      v-if="error"
      role="alert"
      class="mt-5 rounded border border-danger/40 bg-danger/5 px-4 py-3 text-sm text-danger"
    >
      {{ error }}
    </p>
    <div
      v-if="!capabilities"
      class="mt-8 text-sm text-gray-400"
      role="status"
    >
      Checking managed capability…
    </div>
    <aside
      v-else-if="!capabilities.available && !job"
      class="mt-6 border-l-2 border-warn bg-surface-overlay px-5 py-5"
    >
      <h2 class="text-sm font-semibold text-warn">
        Managed execution unavailable
      </h2>
      <p class="mt-2 text-sm text-gray-400">
        {{ capabilities.reason }}
      </p>
      <p class="mt-2 text-xs text-gray-500">
        No manifest-only or unverified patch will be produced.
      </p>
    </aside>

    <ManagedMaintenanceTargets
      v-if="releaseID && !job"
      :base="base"
      :release-id="releaseID"
      :selected-branch="targetBranch"
      @choose="chooseMaintenance"
    />

    <form
      v-if="capabilities?.available && !job"
      class="mt-8 grid gap-6 md:grid-cols-[1fr_19rem]"
      @submit.prevent="prepare"
    >
      <div class="space-y-5">
        <div>
          <h2 class="text-base font-semibold text-gray-100">
            01 / Pin the source
          </h2>
          <p class="mt-2 text-sm text-gray-400">
            {{ releaseID ? 'The exact shipped release snapshot is selected by default. Its tag moving does not change the pinned build.' : 'The current head of the selected existing branch will be pinned for this draft.' }}
          </p>
        </div>
        <label
          v-if="releaseID"
          class="flex items-start gap-3 text-sm text-gray-300"
        >
          <input
            v-model="maintenanceTarget"
            type="checkbox"
            class="mt-1 accent-accent"
          >
          <span>Use an existing maintenance branch instead of shipped source
            <span class="mt-1 block text-xs text-gray-500">This is a separate source choice, not a release-to-branch guess.</span>
          </span>
        </label>
        <label class="block text-xs text-gray-400">
          {{ maintenanceTarget ? 'Existing maintenance branch (required)' : 'Existing PR target branch (blank uses repository default)' }}
          <input
            v-model="targetBranch"
            :required="maintenanceTarget"
            type="text"
            autocomplete="off"
            class="field mt-2 w-full"
            placeholder="main"
          >
        </label>
        <p
          v-if="releaseID && !maintenanceTarget"
          class="text-xs leading-5 text-warn"
        >
          A patch against shipped source can only be published as a PR when the target head equals that source. Otherwise download it or start a separate maintenance draft.
        </p>
        <button
          type="submit"
          class="primary"
          :disabled="busy || !capabilities.can_generate"
        >
          {{ busy ? 'Pinning source…' : 'Prepare isolated workspace →' }}
        </button>
        <p
          v-if="!capabilities.can_generate"
          class="text-xs text-warn"
        >
          {{ capabilities.generation_reason }}
        </p>
      </div>
      <aside class="rounded border border-surface-border bg-surface-overlay p-5">
        <p class="font-mono text-[10px] uppercase tracking-widest text-gray-500">
          Approved profile
        </p>
        <p class="mt-2 text-sm font-medium text-gray-200">
          {{ capabilities.profile }}
        </p>
        <ul class="mt-4 space-y-3 text-xs leading-5 text-gray-500">
          <li
            v-for="limit in capabilities.limits"
            :key="limit"
          >
            {{ limit }}
          </li>
        </ul>
      </aside>
    </form>

    <template v-if="job">
      <dl class="mt-6 grid gap-px overflow-hidden rounded border border-surface-border bg-surface-border md:grid-cols-3">
        <div class="bg-surface-overlay p-4">
          <dt class="label">
            Source / immutable commit
          </dt><dd class="mt-2 break-all font-mono text-xs text-gray-200">
            {{ job.source_ref }}<br><span class="text-gray-500">{{ job.base_sha }}</span>
          </dd>
        </div>
        <div class="bg-surface-overlay p-4">
          <dt class="label">
            Existing PR target
          </dt><dd class="mt-2 break-all font-mono text-xs text-gray-200">
            {{ job.target_branch }}
          </dd>
        </div>
        <div class="bg-surface-overlay p-4">
          <dt class="label">
            Draft {{ job.revision }} / expires
          </dt><dd class="mt-2 text-xs text-gray-300">
            {{ new Date(job.expires_at).toLocaleString() }}
          </dd>
        </div>
      </dl>
      <div
        class="mt-6 flex flex-wrap items-center justify-between gap-3"
        aria-live="polite"
      >
        <p class="text-sm text-accent">
          <span
            v-if="pending"
            class="mr-2 inline-block h-2 w-2 animate-pulse rounded-full bg-accent"
          />{{ phaseLabel }}
        </p>
        <button
          v-if="capabilities?.can_generate && (pending || job.state === 'awaiting_selection')"
          class="secondary"
          :disabled="busy"
          @click="cancel"
        >
          Cancel draft
        </button>
      </div>
      <p
        v-if="job.error"
        role="alert"
        class="mt-4 text-sm text-danger"
      >
        {{ job.error }}
      </p>
      <p
        v-if="job.result.unavailable"
        class="mt-4 text-sm text-warn"
        role="status"
      >
        {{ job.result.unavailable }}
      </p>

      <div
        v-if="job.state === 'awaiting_selection'"
        class="mt-7"
      >
        <h2 class="text-base font-semibold text-white">
          02 / Choose resolution boundaries
        </h2>
        <p class="mt-2 text-sm text-gray-400">
          {{ selectedCount }} of {{ modules.length }} modules selected. Unselected or unavailable modules remain unresolved; the patch is not a claim that the entire release is fixed.
        </p>
        <div class="mt-5 space-y-3">
          <article
            v-for="module in modules"
            :key="module.manifest"
            class="rounded border border-surface-border p-4"
            :class="module.unit ? 'bg-surface-overlay' : 'opacity-70'"
          >
            <div class="flex flex-wrap items-center justify-between gap-4">
              <label class="flex items-center gap-3">
                <input
                  v-if="module.unit"
                  v-model="selected[module.unit.id]"
                  type="checkbox"
                  class="accent-accent"
                >
                <span class="font-mono text-sm text-gray-200">{{ module.manifest }}</span>
              </label>
              <label
                v-if="module.unit"
                class="text-xs text-gray-400"
              >Upgrade ceiling
                <select
                  v-model="levels[module.unit.id]"
                  class="field ml-2"
                ><option value="patch">Patch</option><option value="minor">Minor</option><option value="major">Major</option></select>
              </label>
            </div>
            <p
              v-if="module.unavailable"
              class="mt-3 text-xs leading-5 text-warn"
            >
              {{ module.unavailable }}
            </p>
            <template v-if="module.unit">
              <p class="mt-3 text-xs text-gray-500">
                {{ module.unit.vulns.join(' · ') }}
              </p>
              <div
                v-for="pkg in module.unit.direct_packages ?? []"
                :key="pkg.name"
                class="mt-3 flex flex-wrap items-center gap-3 border-t border-surface-border pt-3"
              >
                <span class="min-w-40 font-mono text-xs text-gray-400">{{ pkg.name }} <span class="text-gray-600">{{ pkg.version }}</span></span>
                <label
                  class="sr-only"
                  :for="choiceID(module.unit.id, pkg.name)"
                >Target choice for {{ pkg.name }}</label>
                <select
                  :id="choiceID(module.unit.id, pkg.name)"
                  v-model="choices[choiceID(module.unit.id, pkg.name)]"
                  class="field"
                  :disabled="!selected[module.unit.id]"
                >
                  <option value="automatic">
                    Automatic solver
                  </option><option value="exact">
                    Exact version…
                  </option>
                  <option
                    v-if="pkg.recommended_version"
                    value="gossip"
                  >
                    Gossip recommendation · {{ pkg.recommended_version }}
                  </option>
                </select>
                <input
                  v-if="choices[choiceID(module.unit.id, pkg.name)] === 'exact'"
                  v-model="versions[choiceID(module.unit.id, pkg.name)]"
                  class="field w-36"
                  type="text"
                  :aria-label="`Exact version for ${pkg.name}`"
                  placeholder="1.2.3"
                >
              </div>
            </template>
          </article>
        </div>
        <button
          class="primary mt-6"
          :disabled="busy || selectedCount === 0 || !capabilities?.can_generate"
          @click="generate"
        >
          {{ busy ? 'Queuing…' : 'Generate & verify selected modules →' }}
        </button>
      </div>

      <div
        v-if="verified"
        class="mt-7 grid gap-6 md:grid-cols-[1fr_19rem]"
      >
        <div>
          <h2 class="text-base font-semibold text-white">
            03 / Verified dependency changes
          </h2>
          <p class="mt-2 text-sm text-gray-400">
            Lockfile consistency · selected advisories addressed · no introduced advisories. Builds and tests were not run.
          </p>
          <aside
            v-if="unresolvedModules.length"
            class="mt-5 border-l-2 border-warn bg-surface-overlay px-4 py-3"
          >
            <h3 class="text-xs font-semibold text-warn">
              Outside this patch · {{ unresolvedModules.length }} unresolved modules
            </h3>
            <ul class="mt-2 space-y-2 text-xs leading-5 text-gray-400">
              <li
                v-for="module in unresolvedModules"
                :key="module.manifest"
              >
                <code>{{ module.manifest }}</code> — {{ module.unavailable || 'Not selected for this draft. Advisories in this module remain unresolved.' }}
              </li>
            </ul>
          </aside>
          <div
            v-for="unit in job.result.artifact?.units ?? []"
            :key="unit.id"
            class="mt-5 border-t border-surface-border pt-4"
          >
            <h3 class="font-mono text-xs text-gray-300">
              {{ unit.id }}
            </h3>
            <p
              v-for="update in unit.updates"
              :key="`${update.name}:${update.from}:${update.to}`"
              class="mt-2 font-mono text-xs text-gray-400"
            >
              {{ update.name }} <span class="text-gray-600">{{ update.from }}</span> <span class="text-accent">→ {{ update.to }}</span>
            </p>
          </div>
          <button
            class="secondary mt-5"
            :disabled="busy"
            @click="loadDiff"
          >
            Review complete patch
          </button>
          <pre
            v-if="diff"
            class="mt-4 max-h-[34rem] overflow-auto rounded border border-surface-border bg-black/30 p-4 text-[11px] leading-5 text-gray-300"
            tabindex="0"
            aria-label="Verified dependency patch"
          >{{ diff }}</pre>
        </div>
        <aside class="h-fit rounded border border-accent/30 bg-surface-overlay p-5">
          <p class="label">
            Verified artifact
          </p>
          <p class="mt-2 break-all font-mono text-[10px] leading-5 text-gray-500">
            {{ job.result.artifact?.sha256 }}
          </p>
          <a
            :href="patchURL"
            class="primary mt-4 block text-center"
            download
          >Download patch</a>
          <button
            v-if="capabilities?.publication_available"
            class="secondary mt-3 w-full"
            :disabled="busy"
            @click="publish"
          >
            {{ busy ? 'Reconciling…' : 'Create branch + pull request' }}
          </button>
          <p
            v-else
            class="mt-3 text-xs leading-5 text-gray-500"
          >
            {{ capabilities?.publication_reason }}
          </p>
          <label
            v-if="capabilities?.can_consent && !capabilities.publication_available"
            class="mt-4 flex gap-2 text-xs leading-5 text-gray-400"
          >
            <input
              v-model="consent"
              type="checkbox"
              class="mt-1 accent-accent"
            >
            <span>As an organization admin, I authorize Hibou remediation branch and PR creation.</span>
          </label>
          <button
            v-if="consent && capabilities?.can_consent && !capabilities.publication_available"
            class="secondary mt-3"
            :disabled="busy"
            @click="saveConsent"
          >
            Save organization consent
          </button>
          <a
            v-if="pullRequest && safePRURL"
            :href="safePRURL"
            class="mt-4 block text-sm text-accent"
            target="_blank"
            rel="noopener noreferrer"
          >Open pull request #{{ pullRequest.number }} ↗</a>
          <p class="mt-4 text-[11px] leading-5 text-gray-500">
            No automatic merge, tag, release or publishing. Existing user commits are never overwritten.
          </p>
        </aside>
      </div>
      <button
        v-if="['failed', 'cancelled', 'expired'].includes(job.state)"
        class="secondary mt-6"
        @click="restart"
      >
        Start a new draft
      </button>
    </template>
  </section>
</template>

<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref, watch } from 'vue'
import { RouterLink, useRoute, useRouter } from 'vue-router'
import { ApiError } from '@/api/client'
import ManagedMaintenanceTargets from '@/components/ManagedMaintenanceTargets.vue'
import { isRemediationPending, isRemediationVerified, remediationApi, remediationPath } from '@/api/remediation'
import type { RemediationCapabilities, RemediationJob, RemediationSelection, VersionTarget } from '@/api/remediation'

const route = useRoute()
const router = useRouter()
const base = computed(() => remediationPath(String(route.params.provider), String(route.params.slug), String(route.params.repoSlug)))
const releaseID = computed(() => typeof route.query.release === 'string' ? route.query.release : undefined)
const capabilities = ref<RemediationCapabilities>()
const job = ref<RemediationJob>()
const busy = ref(false)
const error = ref('')
const targetBranch = ref('')
const maintenanceTarget = ref(false)
const selectedMaintenance = ref<{ branch: string; headSHA: string }>()
const consent = ref(false)
const selected = ref<Record<string, boolean>>({})
const levels = ref<Record<string, string>>({})
const choices = ref<Record<string, string>>({})
const versions = ref<Record<string, string>>({})
const diff = ref('')
const pullRequest = ref<{ number: number; html_url: string }>()
const safePRURL = computed(() => {
  try { const url = new URL(pullRequest.value?.html_url ?? ''); return url.protocol === 'https:' ? url.href : '' } catch { return '' }
})
const modules = computed(() => job.value?.result.modules ?? [])
const unresolvedModules = computed(() => {
  const resolved = new Set(job.value?.result.artifact?.units.map(unit => unit.id) ?? [])
  return modules.value.filter(module => !module.unit || !resolved.has(module.unit.id))
})
const selectedCount = computed(() => modules.value.filter(m => m.unit && selected.value[m.unit.id]).length)
const pending = computed(() => !!job.value && isRemediationPending(job.value.state))
const verified = computed(() => !!job.value && isRemediationVerified(job.value))
const patchURL = computed(() => `/api/v1${base.value}/${job.value?.id}/patch`)
const phaseLabel = computed(() => ({
  queued_prepare: 'Queued / waiting for isolated worker',
  preparing: 'Preparing / discovering committed modules and checking approved profile',
  awaiting_selection: 'Prepared / choose the modules to resolve',
  queued_generate: 'Queued / immutable draft selection accepted',
  generating: 'Generating / solving, relocking and verifying the complete selected graph',
  ready: 'Ready / all selected verification checks passed',
  failed: 'Failed / no verified artifact produced',
  cancelled: 'Cancelled / isolated execution stopped',
  expired: 'Expired / prepare a new draft',
})[job.value?.state ?? 'queued_prepare'])
const choiceID = (unit: string, pkg: string) => JSON.stringify([unit, pkg])
function chooseMaintenance(selection: { branch: string; headSHA: string }) {
  selectedMaintenance.value = selection
  targetBranch.value = selection.branch
  maintenanceTarget.value = true
}
watch(targetBranch, branch => {
  if (selectedMaintenance.value?.branch !== branch) selectedMaintenance.value = undefined
})
let timer: ReturnType<typeof setTimeout> | undefined
let alive = true
async function perform(action: () => Promise<void>) {
  busy.value = true; error.value = ''
  try { await action() } catch (e) { error.value = e instanceof Error ? e.message : 'Remediation request failed.' } finally { busy.value = false }
}
function initializeSelections() {
  for (const module of modules.value) {
    if (!module.unit) continue
    const unit = module.unit
    selected.value[unit.id] ??= false
    levels.value[unit.id] ??= 'patch'
    for (const pkg of unit.direct_packages ?? []) choices.value[choiceID(unit.id, pkg.name)] ??= 'automatic'
  }
}
function schedulePoll() {
  if (timer) clearTimeout(timer)
  if (!alive || !job.value || !isRemediationPending(job.value.state)) return
  timer = setTimeout(async () => {
    try { job.value = await remediationApi.get(base.value, job.value!.id); initializeSelections(); schedulePoll() }
    catch (e) {
      if (e instanceof ApiError && e.status === 410 && job.value) job.value.state = 'expired'
      error.value = e instanceof Error ? e.message : 'Unable to refresh draft. Reload to retry.'
    }
  }, 2500)
}
async function prepare() {
  await perform(async () => {
    job.value = await remediationApi.prepare(base.value, {
      release_id: releaseID.value, target_branch: targetBranch.value || undefined, maintenance_target: maintenanceTarget.value,
      expected_head_sha: maintenanceTarget.value ? selectedMaintenance.value?.headSHA : undefined,
    })
    await router.replace({ query: { ...route.query, draft: job.value.id } })
    schedulePoll()
  })
}
async function generate() {
  if (!job.value) return
  await perform(async () => {
    const units: RemediationSelection[] = []
    for (const module of modules.value) {
      const unit = module.unit
      if (!unit || !selected.value[unit.id]) continue
      const targets: VersionTarget[] = []
      for (const pkg of unit.direct_packages ?? []) {
        const key = choiceID(unit.id, pkg.name)
        const mode = choices.value[key]
        if (mode === 'exact' || mode === 'gossip') {
          const version = mode === 'gossip' ? pkg.recommended_version : versions.value[key]?.trim()
          if (!version) throw new Error(`Choose an exact target for ${pkg.name}.`)
          targets.push({ name: pkg.name, mode, version })
        }
      }
      units.push({ id: unit.id, upgrade_level: levels.value[unit.id] ?? 'patch', version_targets: targets })
    }
    job.value = await remediationApi.generate(base.value, job.value!, units)
    schedulePoll()
  })
}
async function cancel() {
  if (!job.value) return
  await perform(async () => { await remediationApi.cancel(base.value, job.value!.id); job.value = await remediationApi.get(base.value, job.value!.id) })
}
async function loadDiff() {
  await perform(async () => {
    const response = await fetch(patchURL.value, { credentials: 'same-origin', headers: { Accept: 'text/x-diff' } })
    if (!response.ok) throw new Error('Verified patch is unavailable or expired.')
    diff.value = await response.text()
  })
}
async function publish() {
  if (!job.value) return
  await perform(async () => { pullRequest.value = await remediationApi.publish(base.value, job.value!) })
}
async function saveConsent() {
  await perform(async () => { await remediationApi.consent(base.value, true); capabilities.value = await remediationApi.capabilities(base.value) })
}
async function restart() {
  job.value = undefined; diff.value = ''; error.value = ''
  selected.value = {}; choices.value = {}; versions.value = {}; levels.value = {}
  pullRequest.value = undefined
  await router.replace({ query: { ...route.query, draft: undefined } })
}
onMounted(() => perform(async () => {
  capabilities.value = await remediationApi.capabilities(base.value)
  if (typeof route.query.draft === 'string') {
    job.value = await remediationApi.get(base.value, route.query.draft)
    initializeSelections(); schedulePoll()
  }
}))
onUnmounted(() => { alive = false; if (timer) clearTimeout(timer) })
</script>

<style scoped>
.label { @apply font-mono text-[10px] uppercase tracking-widest text-gray-500; }
.field { @apply rounded border border-surface-border bg-surface-overlay px-3 py-2 text-xs text-gray-200 outline-none focus:border-accent; }
.primary { @apply rounded border border-accent/40 bg-accent/10 px-4 py-2.5 text-xs font-semibold text-accent transition hover:bg-accent/20 disabled:cursor-not-allowed disabled:opacity-40; }
.secondary { @apply rounded border border-surface-border px-3 py-2 text-xs text-gray-300 transition hover:border-accent/50 hover:text-accent disabled:opacity-40; }
@media (prefers-reduced-motion: reduce) { .animate-pulse { animation: none; } }
</style>
