<template>
  <div class="space-y-6">
    <section>
      <div class="flex items-center justify-between border-b border-surface-border pb-2">
        <h2 class="text-base font-semibold text-white">
          License policy
        </h2>
        <span
          v-if="!isOrgAdmin"
          class="text-xs text-gray-500"
        >Read-only — org admins can change this</span>
      </div>

      <p class="mt-3 text-sm text-gray-500">
        One policy for the whole organization: which licenses fail a gate, and which packages are
        excused. Every enrolled repository is held to it unless it declares its own.
      </p>

      <!-- The override escape hatch decides how much this page is worth, so it is
           stated before the form rather than as a footnote under it. -->
      <div class="mt-3 rounded-lg border border-warn/30 bg-surface-raised px-4 py-3 text-sm text-gray-400">
        <p>
          <span class="font-medium text-gray-200">A repository can override this policy</span> by
          declaring a <code class="rounded bg-surface-overlay px-1 font-mono text-xs">licenses:</code>
          block in its <code class="rounded bg-surface-overlay px-1 font-mono text-xs">.hibou.yaml</code>.
          An override <span class="font-medium text-gray-200">replaces</span> this policy for that
          repository — the two are not merged, so nothing here is a floor.
        </p>
        <p class="mt-1.5">
          Which repositories inherit and which override — and in which direction — is listed on the
          <RouterLink
            :to="{ name: 'org-licenses', params: route.params }"
            class="text-accent hover:underline"
          >
            Licenses tab
          </RouterLink>.
        </p>
      </div>
    </section>

    <!-- Reading the policy is one query, so it loads on arrival. Finding out which
         repositories override it is the expensive part and stays explicit. -->
    <section v-if="!loaded">
      <div class="rounded-lg border border-surface-border bg-surface-raised p-4">
        <div class="text-sm font-medium text-gray-200">
          {{ loading ? 'Loading the current policy…' : 'The current policy could not be loaded' }}
        </div>
        <p
          v-if="loadError"
          class="mt-1 text-xs text-danger"
        >
          {{ loadError }}
        </p>
        <button
          v-if="!loading"
          type="button"
          class="mt-3 rounded-md bg-accent px-3 py-1.5 text-sm font-medium text-white transition hover:bg-accent/80 disabled:cursor-not-allowed disabled:opacity-50"
          @click="load"
        >
          Retry
        </button>
        <p
          v-if="loadError"
          class="mt-2 text-xs text-danger"
        >
          {{ loadError }}
        </p>
      </div>
    </section>

    <template v-else>
      <section class="space-y-2">
        <div
          class="rounded-lg border px-4 py-3 text-sm"
          :class="configured ? 'border-ok/30 text-gray-300' : 'border-surface-border text-gray-400'"
        >
          <template v-if="configured">
            A policy is active. Repositories that inherit it fail their license gate when it is
            breached.
          </template>
          <template v-else>
            No policy is configured — the license gate is skipped everywhere except in repositories
            that declare their own.
          </template>
        </div>

        <p
          v-if="summary && summary.total > 0"
          class="text-xs text-gray-500"
        >
          {{ summary.inheriting }} of {{ summary.total }} repositories inherit ·
          {{ summary.overriding }} override
          <span v-if="summary.departures > 0">
            (<span class="text-warn">{{ summary.departures }} looser or mixed</span>)</span>
          <span v-if="summary.unreadable > 0">
            · <span class="text-warn">{{ summary.unreadable }} unreadable — config could not be
              fetched, so their stance is unknown</span>
          </span>
        </p>
        <!-- Dropped on save because every relation was measured against the policy
             that has just been replaced; re-checking is another forge fan-out. -->
        <button
          v-else-if="!summary"
          type="button"
          class="text-xs text-accent transition hover:underline disabled:opacity-50"
          :disabled="checkingOverrides"
          @click="checkOverrides"
        >
          {{ checkingOverrides ? 'Checking repositories…' : 'Check which repositories override this policy' }}
        </button>
        <p
          v-if="overrideError"
          class="text-xs text-danger"
        >
          {{ overrideError }}
        </p>
        <p
          v-if="loaded && loadError"
          class="text-xs text-danger"
        >
          {{ loadError }}
        </p>
      </section>

      <section>
        <h3 class="border-b border-surface-border pb-2 text-sm font-semibold text-white">
          Denied categories
        </h3>
        <p class="mt-2 text-xs text-gray-500">
          A category denies every license classified into it, including ones added to the catalog
          later. Pick the legal stance; the license ids follow from it.
        </p>
        <div class="mt-1 divide-y divide-surface-border-subtle">
          <label
            v-for="category in CATEGORIES"
            :key="category.id"
            class="flex items-start justify-between gap-6 py-3"
          >
            <span>
              <span class="block text-sm font-medium text-gray-200">{{ category.label }}</span>
              <span class="mt-0.5 block text-xs text-gray-500">{{ category.meaning }}</span>
            </span>
            <input
              v-model="form.denyCategories"
              type="checkbox"
              :value="category.id"
              class="mt-1 h-4 w-4 shrink-0 accent-accent"
              :disabled="!isOrgAdmin"
            >
          </label>
        </div>
      </section>

      <section>
        <h3 class="border-b border-surface-border pb-2 text-sm font-semibold text-white">
          Named licenses and exempt packages
        </h3>
        <div class="mt-3 space-y-3">
          <label class="block text-xs text-gray-400">
            Denied licenses — license ids, one per line or comma-separated
            <textarea
              v-model="form.denyText"
              rows="2"
              placeholder="AGPL-3.0-only, SSPL-1.0"
              class="mt-1 w-full rounded-md border border-surface-border bg-surface-overlay px-2.5 py-1.5 font-mono text-xs text-gray-100 focus:border-accent/50 focus:outline-none disabled:opacity-60"
              :disabled="!isOrgAdmin"
            />
            <span class="mt-1 block text-xs text-gray-500">
              Denied on top of the categories above, for a single license you will not accept.
            </span>
          </label>

          <label class="block text-xs text-gray-400">
            Allowed licenses — license ids, one per line or comma-separated
            <textarea
              v-model="form.allowText"
              rows="2"
              placeholder="MPL-2.0"
              class="mt-1 w-full rounded-md border border-surface-border bg-surface-overlay px-2.5 py-1.5 font-mono text-xs text-gray-100 focus:border-accent/50 focus:outline-none disabled:opacity-60"
              :disabled="!isOrgAdmin"
            />
            <!-- allow vs exempt_purls is the mistake users actually make, so the two
                 fields say what they match rather than assuming it is obvious. -->
            <span class="mt-1 block text-xs text-gray-500">
              Matches <span class="font-medium text-gray-300">licenses</span>: an id here is
              accepted even when its category is denied. Use it to carve one license out of a
              category, not to excuse a package.
            </span>
          </label>

          <label class="block text-xs text-gray-400">
            Exempt packages — package URLs (purls), one per line or comma-separated
            <textarea
              v-model="form.exemptText"
              rows="2"
              placeholder="pkg:npm/some-package@1.2.3"
              class="mt-1 w-full rounded-md border border-surface-border bg-surface-overlay px-2.5 py-1.5 font-mono text-xs text-gray-100 focus:border-accent/50 focus:outline-none disabled:opacity-60"
              :disabled="!isOrgAdmin"
            />
            <span class="mt-1 block text-xs text-gray-500">
              Matches <span class="font-medium text-gray-300">packages</span>, not licenses: the
              named dependency is excused whatever it is licensed under. Everything else keeps the
              policy.
            </span>
          </label>
        </div>
      </section>

      <section>
        <h3 class="border-b border-surface-border pb-2 text-sm font-semibold text-white">
          Evaluation
        </h3>
        <div class="mt-1 divide-y divide-surface-border-subtle">
          <label class="flex items-start justify-between gap-6 py-3">
            <span>
              <span class="block text-sm font-medium text-gray-200">Deny components with no
                usable license</span>
              <span class="mt-0.5 block text-xs text-gray-500">
                A dependency whose license metadata is missing or unreadable has not been cleared
                by anyone — it is an unreviewed legal risk, not a safe default.
              </span>
            </span>
            <input
              v-model="form.denyUnknown"
              type="checkbox"
              class="mt-1 h-4 w-4 shrink-0 accent-accent"
              :disabled="!isOrgAdmin"
            >
          </label>

          <div class="flex items-start justify-between gap-6 py-3">
            <div>
              <div class="text-sm font-medium text-gray-200">
                What to evaluate
              </div>
              <p class="mt-0.5 text-xs text-gray-500">
                <span class="font-medium text-gray-300">New only</span> judges what a change
                introduces, so an existing dependency does not block unrelated work.
                <span class="font-medium text-gray-300">Whole tree</span> judges every dependency
                on every run, and will fail on debt that is already there.
              </p>
            </div>
            <select
              v-model="form.evaluate"
              class="h-8 shrink-0 rounded-md border border-surface-border bg-surface-overlay px-2 text-sm text-gray-200 focus:border-accent/50 focus:outline-none disabled:opacity-60"
              :disabled="!isOrgAdmin"
            >
              <option value="new">
                New only
              </option>
              <option value="all">
                Whole tree
              </option>
            </select>
          </div>
        </div>

        <div
          v-if="isOrgAdmin"
          class="mt-4 flex items-center gap-3"
        >
          <button
            type="button"
            class="rounded-md bg-ok-muted px-3 py-1.5 text-sm font-medium text-white transition hover:bg-ok-muted/80 disabled:cursor-not-allowed disabled:opacity-50"
            :disabled="saving || !isDirty"
            @click="save"
          >
            {{ saving ? 'Saving…' : 'Save policy' }}
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

        <!-- Adopting a legal stance blind is the friction this removes: the
             preview reports what the draft WOULD flag, using the same evaluator
             the gate uses, without saving anything. -->
        <div
          v-if="isOrgAdmin"
          class="mt-4 rounded-lg border border-surface-border bg-surface-overlay/30 p-3"
        >
          <div class="flex flex-wrap items-center justify-between gap-3">
            <div class="text-xs text-gray-400">
              Preview the impact before saving
            </div>
            <button
              type="button"
              class="rounded-md border border-surface-border px-2.5 py-1 text-xs text-gray-200 transition hover:border-accent/50 hover:text-white disabled:opacity-50"
              :disabled="simulating"
              @click="simulate"
            >
              {{ simulating ? 'Evaluating…' : 'Preview impact' }}
            </button>
          </div>
          <p
            v-if="simulateError"
            class="mt-2 text-xs text-danger"
          >
            {{ simulateError }}
          </p>
          <template v-else-if="simulation">
            <p class="mt-2 text-xs leading-relaxed text-gray-400">
              Would flag
              <span :class="simulation.components_flagged > 0 ? 'font-medium text-warn' : 'font-medium text-ok'">
                {{ simulation.components_flagged }}</span>
              of {{ simulation.components_total }} components across
              {{ simulation.repos.length }} of {{ simulation.repos_total }} repositories.
              <span v-if="simulation.exempted > 0">
                {{ simulation.exempted }} more would be flagged but for
                <code class="font-mono">exempt_purls</code>.
              </span>
            </p>
            <p class="mt-1 text-[11px] leading-relaxed text-gray-600">
              Counted against each repository's current default-branch snapshot. With
              <code class="font-mono">evaluate: new</code> a pull request only fails on what it
              introduces, so this is the standing exposure, not what any one change would break.
            </p>
            <ul
              v-if="simulation.licenses.length"
              class="mt-2 space-y-0.5"
            >
              <li
                v-for="stat in simulation.licenses.slice(0, 6)"
                :key="stat.license"
                class="font-mono text-[11px] text-gray-400"
              >
                {{ stat.license }} <span class="text-gray-600">×{{ stat.components }}</span>
              </li>
            </ul>
            <ul
              v-if="simulation.repos.length"
              class="mt-2 flex flex-wrap gap-1.5"
            >
              <li
                v-for="repo in simulation.repos.slice(0, 8)"
                :key="repo.slug"
                class="rounded-full border border-surface-border px-2 py-0.5 text-[11px] text-gray-300"
              >
                {{ repo.slug }} <span class="text-gray-600">{{ repo.count }}</span>
              </li>
            </ul>
          </template>
        </div>
      </section>

      <section v-if="isOrgAdmin && configured">
        <h2 class="border-b border-danger/30 pb-2 text-base font-semibold text-danger">
          Danger zone
        </h2>
        <div class="mt-3 flex flex-col gap-3 rounded-lg border border-danger/30 p-4 sm:flex-row sm:items-center sm:justify-between">
          <div>
            <div class="text-sm font-medium text-gray-100">
              Retire this policy
            </div>
            <div class="text-xs text-gray-500">
              Stops license enforcement in every repository that inherits it. This is not the same
              as a policy that denies nothing: that one still runs and still flags unknown
              licenses. Retiring runs no check at all.
            </div>
          </div>
          <button
            type="button"
            class="shrink-0 rounded-md border border-danger/50 px-3 py-1.5 text-xs font-medium text-danger transition hover:bg-danger/10 disabled:opacity-50"
            :disabled="retiring"
            @click="retire"
          >
            {{ retiring ? 'Retiring…' : 'Retire policy' }}
          </button>
        </div>
        <p
          v-if="retireError"
          class="mt-2 text-xs text-danger"
        >
          {{ retireError }}
        </p>
      </section>
    </template>
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, reactive, ref, watch } from 'vue'
import { RouterLink, useRoute } from 'vue-router'

import {
  api,
  type LicenseCategory,
  type OrgLicensePolicyInput,
  type OrgLicensePolicyOverview,
  type OrgLicenseSimulation,
} from '@/api/client'
import {
  LICENSE_CATEGORY_LABELS,
  LICENSE_CATEGORY_MEANINGS,
  LICENSE_CATEGORY_ORDER,
} from '@/lib/licenses'
import { useDialog } from '@/composables/useDialog'
import { useOrgRole } from '@/composables/useOrgRole'
import { useToast } from '@/composables/useToast'

const { confirmDialog } = useDialog()
const route = useRoute()
const { isOrgAdmin } = useOrgRole()
const { pushToast } = useToast()

const provider = route.params.provider as string
const slug = route.params.slug as string

// Most restrictive first, matching the Licenses tab: an admin setting a stance
// reads down until the obligations become acceptable. The meanings name licenses
// only as examples — choosing a stance must not require knowing SPDX.
// Built from the shared taxonomy rather than restated here; see lib/licenses.
const CATEGORIES = LICENSE_CATEGORY_ORDER.map((id) => ({
  id,
  label: LICENSE_CATEGORY_LABELS[id],
  meaning: LICENSE_CATEGORY_MEANINGS[id],
}))

const loaded = ref(false)
const loading = ref(false)
const loadError = ref('')
const configured = ref(false)
const summary = ref<OrgLicensePolicyOverview | null>(null)
const persistedKey = ref('')

const saving = ref(false)
const saved = ref(false)
const saveError = ref('')
const retiring = ref(false)
const retireError = ref('')

const form = reactive({
  denyCategories: [] as LicenseCategory[],
  denyText: '',
  allowText: '',
  exemptText: '',
  // Fail closed: an unreviewed component is a risk, so the default stance denies
  // it and an admin has to choose to accept it.
  denyUnknown: true,
  evaluate: 'new' as 'new' | 'all',
})

function parseList(text: string): string[] {
  return text
    .split(/[,\n]/)
    .map((entry) => entry.trim())
    .filter(Boolean)
}

const draft = computed<OrgLicensePolicyInput>(() => ({
  deny_categories: [...form.denyCategories],
  deny: parseList(form.denyText),
  allow: parseList(form.allowText),
  exempt_purls: parseList(form.exemptText),
  deny_unknown: form.denyUnknown,
  evaluate: form.evaluate,
  enabled: true,
}))

// Checkbox order is an artefact of clicking, so categories are compared as a set;
// the id lists keep the order the admin typed.
function policyKey(policy: Omit<OrgLicensePolicyInput, 'enabled'>): string {
  return JSON.stringify([
    [...policy.deny_categories].sort(),
    policy.deny,
    policy.allow,
    policy.exempt_purls,
    policy.deny_unknown,
    policy.evaluate,
  ])
}

const isDirty = computed(() => {
  if (!loaded.value) return false
  // With no policy stored, the untouched form matches the synthetic default and
  // would look unchanged — but saving it is the meaningful act of adopting a
  // policy, so Save must be available.
  if (!configured.value) return true
  return policyKey(draft.value) !== persistedKey.value
})

function applyPolicy(overview: OrgLicensePolicyOverview) {
  configured.value = overview.configured
  const policy = overview.policy
  form.denyCategories = (policy?.deny_categories ?? []) as LicenseCategory[]
  form.denyText = (policy?.deny ?? []).join('\n')
  form.allowText = (policy?.allow ?? []).join('\n')
  form.exemptText = (policy?.exempt_purls ?? []).join('\n')
  form.denyUnknown = policy?.deny_unknown ?? true
  form.evaluate = policy?.evaluate ?? 'new'
  persistedKey.value = policyKey(draft.value)
}

const simulating = ref(false)
const simulateError = ref('')
const simulation = ref<OrgLicenseSimulation | null>(null)

// Uses the DRAFT, not the stored policy: previewing what is already saved would
// answer a question nobody asked.
async function simulate() {
  simulating.value = true
  simulateError.value = ''
  try {
    const res = await api.simulateOrgLicensePolicy(provider, slug, draft.value)
    simulation.value = res.data
  } catch (error) {
    simulation.value = null
    simulateError.value = error instanceof Error ? error.message : 'Failed to preview the policy'
  } finally {
    simulating.value = false
  }
}

const checkingOverrides = ref(false)
const overrideError = ref('')

// The one call that fans out to the forge, one request per repository. Kept
// separate from load() so simply opening this page costs a single query.
async function checkOverrides() {
  checkingOverrides.value = true
  overrideError.value = ''
  try {
    const res = await api.getOrgLicensePolicy(provider, slug, true)
    if (!res.data.repos_scanned) {
      // The server declined to scan; reporting the zeroed counts would be an
      // all-clear nobody earned.
      overrideError.value = 'Repositories were not checked, so their stance is unknown.'
      return
    }
    summary.value = res.data
  } catch (error) {
    overrideError.value = error instanceof Error ? error.message : 'Failed to check repository overrides'
  } finally {
    checkingOverrides.value = false
  }
}

async function load() {
  loading.value = true
  loadError.value = ''
  try {
    // Policy only — the repository fan-out is a separate, explicit action.
    const res = await api.getOrgLicensePolicy(provider, slug)
    applyPolicy(res.data)
    loaded.value = true
  } catch (error) {
    loadError.value = error instanceof Error ? error.message : 'Failed to load the license policy'
  } finally {
    loading.value = false
  }
}

async function save() {
  saving.value = true
  saved.value = false
  saveError.value = ''
  try {
    const res = await api.updateOrgLicensePolicy(provider, slug, draft.value)
    applyPolicy(res.data)
    summary.value = null
    saved.value = true
    // A policy that denies nothing is stored but skipped by the gate, so
    // "Saved" alone would read as "now enforced".
    if (!res.data.configured) {
      pushToast({
        title: 'Saved, but nothing is enforced',
        description: 'This policy denies nothing, so no license gate will run. Deny at least one category, one id, or unknown licenses.',
        tone: 'info',
      })
    } else {
      pushToast({ title: 'License policy saved', tone: 'success' })
    }
  } catch (error) {
    // Includes the server's rejection of an unknown category — shown as sent
    // rather than reduced to "save failed".
    saveError.value = error instanceof Error ? error.message : 'Failed to save the license policy'
  } finally {
    saving.value = false
  }
}

// Any policy change invalidates every measured relation, since they were taken
// against the policy that has just been replaced.
watch(() => persistedKey.value, () => {
  summary.value = null
  overrideError.value = ''
})

// The preview describes the draft as it was; any edit invalidates it, and a
// stale number here would be read as the new one.
watch(() => policyKey(draft.value), () => {
  simulation.value = null
  simulateError.value = ''
})

onMounted(load)

async function retire() {
  const confirmed = await confirmDialog({
    title: 'Retire the license policy',
    message: 'License checks stop in every repository that inherits this policy. A repository with its own licenses: block keeps enforcing that one. The policy is kept and can be set again later.',
    confirmLabel: 'Retire policy',
    tone: 'danger',
  })
  if (!confirmed) {
    return
  }
  retiring.value = true
  retireError.value = ''
  saveError.value = ''
  saved.value = false
  try {
    await api.updateOrgLicensePolicy(provider, slug, { ...draft.value, enabled: false })
    // Deliberately NOT applyPolicy: the response carries no policy, and feeding
    // that back would blank the form — losing the very content the confirmation
    // promised could be set again. Only the enforced/not-enforced state changes.
    configured.value = false
    summary.value = null
    pushToast({ title: 'License policy retired', tone: 'success' })
  } catch (error) {
    retireError.value = error instanceof Error ? error.message : 'Failed to retire the license policy'
  } finally {
    retiring.value = false
  }
}
</script>
