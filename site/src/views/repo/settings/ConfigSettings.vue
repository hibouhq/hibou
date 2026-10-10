<template>
  <div class="space-y-6">
    <!-- Effective configuration: the merge of every source, with provenance.
         Rendered above the file because "what applies" is the question people
         actually arrive with, and the file alone cannot answer it. -->
    <section>
      <div class="flex flex-wrap items-center justify-between gap-2 border-b border-surface-border pb-2">
        <h2 class="text-base font-semibold text-white">
          Effective configuration
        </h2>
        <div class="flex items-center gap-2">
          <label
            for="effective-branch"
            class="text-xs text-gray-500"
          >Branch</label>
          <input
            id="effective-branch"
            v-model="branchInput"
            type="text"
            class="w-40 rounded border border-surface-border bg-surface-overlay/40 px-2 py-1 font-mono text-xs text-gray-200 focus:border-gray-600 focus:outline-none"
            :placeholder="repo?.default_branch || 'main'"
            @keyup.enter="loadEffective"
            @blur="loadEffective"
          >
        </div>
      </div>
      <p class="mt-2 text-sm text-gray-400">
        Everything that decides a gate outcome on
        <span class="font-mono text-xs text-gray-300">{{ effective?.branch || branchInput }}</span>,
        merged from the matching <code class="rounded bg-surface-overlay px-1 py-0.5 font-mono text-xs">.hibou.yml</code>
        gate, stored quality gates, and defaults Hibou applies on your behalf. Every value is
        labelled with where it came from.
      </p>

      <div
        v-if="effectiveLoading"
        class="mt-4 text-sm text-gray-500"
      >
        Resolving configuration…
      </div>
      <div
        v-else-if="effectiveError"
        class="mt-4 rounded-md border border-surface-border bg-surface-overlay/40 px-4 py-3 text-sm text-gray-400"
      >
        {{ effectiveError }}
      </div>
      <template v-else-if="effective">
        <div class="mt-4 flex flex-wrap items-center gap-2">
          <span
            class="rounded-full border px-2.5 py-0.5 text-xs"
            :class="effective.enforcement === 'blocking'
              ? 'border-danger/40 bg-danger/10 text-danger'
              : 'border-surface-border bg-surface-overlay/40 text-warn'"
          >
            {{ effective.enforcement === 'blocking' ? 'Blocking' : 'Advisory' }}
          </span>
          <span class="text-xs text-gray-500">
            enforcement · {{ sourceLabel(effective.enforcement_source) }}
          </span>
          <span
            v-if="effective.file_gate_matched && effective.file_gate_branches?.length"
            class="text-xs text-gray-500"
          >
            · matched <code class="font-mono text-gray-400">{{ effective.file_gate_branches.join(', ') }}</code>
          </span>
        </div>

        <!-- Warnings sit above the tables: they are the reason someone opened
             this page, not a footnote to it. -->
        <ul
          v-if="effective.warnings.length"
          class="mt-4 space-y-1.5"
        >
          <li
            v-for="warning in effective.warnings"
            :key="warning"
            class="flex gap-2 rounded-md border border-surface-border bg-surface-overlay/30 px-3 py-2 text-xs leading-relaxed text-gray-400"
          >
            <span class="text-warn">!</span>
            <span>{{ warning }}</span>
          </li>
        </ul>

        <div class="mt-4 space-y-3">
          <div
            v-for="section in effective.sections"
            :key="section.name"
            class="overflow-hidden rounded-lg border border-surface-border"
          >
            <div class="flex items-center justify-between gap-2 border-b border-surface-border bg-surface-overlay/30 px-3 py-2">
              <span class="text-sm font-medium text-gray-200">{{ section.name }}</span>
              <span
                class="text-[11px] uppercase tracking-wide"
                :class="statusClass(section.status)"
              >{{ statusLabel(section.status) }}</span>
            </div>
            <div
              v-if="section.rules.length === 0"
              class="px-3 py-2 text-xs text-gray-500"
            >
              {{ section.note || 'Nothing set — this axis cannot fail a pull request.' }}
            </div>
            <template v-else>
              <div
                v-for="(rule, index) in section.rules"
                :key="section.name + rule.label + index"
                class="flex flex-wrap items-baseline gap-x-3 gap-y-1 border-b border-surface-border/50 px-3 py-2 text-xs last:border-0"
              >
                <span class="w-44 shrink-0 text-gray-400">{{ rule.label }}</span>
                <span class="font-mono text-gray-200">{{ rule.value }}</span>
                <span
                  class="rounded border px-1.5 py-0.5 text-[10px]"
                  :class="sourceClass(rule.source)"
                >{{ sourceLabel(rule.source) }}</span>
                <span
                  v-if="rule.detail"
                  class="text-gray-600"
                >{{ rule.detail }}</span>
              </div>
              <p
                v-if="section.note"
                class="border-t border-surface-border/50 px-3 py-2 text-[11px] leading-relaxed text-gray-500"
              >
                {{ section.note }}
              </p>
            </template>
          </div>
        </div>
      </template>
    </section>

    <section>
      <div class="flex flex-wrap items-center justify-between gap-2 border-b border-surface-border pb-2">
        <h2 class="text-base font-semibold text-white">
          Declared in the repository
        </h2>
        <code class="rounded bg-surface-overlay px-1.5 py-0.5 font-mono text-xs text-gray-400">.hibou.yml</code>
      </div>
      <p class="mt-2 text-sm text-gray-400">
        The file as written, read from
        <span class="font-mono text-xs text-gray-300">{{ repo?.default_branch || 'the default branch' }}</span>.
        This is only part of what applies — stored gates and defaults are in the section above.
        Changes are made by editing the file, so they are reviewed like any other code change.
      </p>

      <div
        v-if="loading"
        class="mt-4 text-sm text-gray-500"
      >
        Loading configuration…
      </div>

      <div
        v-else-if="loadFailed"
        class="mt-4 rounded-md border border-surface-border bg-surface-overlay/40 px-4 py-3 text-sm text-gray-400"
      >
        The configuration could not be loaded from the forge right now. Try again later.
      </div>

      <!-- No config: explain and offer onboarding -->
      <div
        v-else-if="!hasGates"
        class="mt-4 rounded-md border border-dashed border-surface-border px-5 py-8 text-center"
      >
        <FileCog class="mx-auto h-6 w-6 text-gray-600" />
        <p class="mt-2 text-sm font-medium text-gray-300">
          No quality gates configured
        </p>
        <p class="mx-auto mt-1 max-w-md text-xs text-gray-500">
          Without gates, scans are recorded but nothing blocks a pull request. Add a
          <code class="rounded bg-surface-overlay px-1 py-0.5 font-mono">.hibou.yml</code>
          to define thresholds for vulnerabilities, coverage, licenses and secrets.
        </p>
        <div
          v-if="isOrgAdmin"
          class="mt-4"
        >
          <template v-if="openPR">
            <p class="inline-flex flex-wrap items-center justify-center gap-1.5 text-sm text-gray-300">
              <GitPullRequest class="h-4 w-4 shrink-0 text-ok" />
              Onboarding pull request
              <a
                :href="openPR.html_url"
                target="_blank"
                rel="noopener noreferrer"
                class="font-medium text-accent hover:underline"
              >#{{ openPR.number }}</a>
              is open.
            </p>
            <p class="mt-1 text-xs text-gray-500">
              Merge it to apply the starter configuration. If it was closed without merging, you can
              <button
                type="button"
                class="text-accent hover:underline disabled:cursor-not-allowed disabled:opacity-50"
                :disabled="onboarding"
                @click="onboard"
              >
                {{ onboarding ? 'open a new one…' : 'open a new one' }}
              </button>.
            </p>
          </template>
          <button
            v-else
            class="rounded-md bg-ok-muted px-3 py-1.5 text-sm font-medium text-white transition hover:bg-ok-muted/80 disabled:cursor-not-allowed disabled:opacity-50"
            type="button"
            :disabled="onboarding"
            @click="onboard"
          >
            {{ onboarding ? 'Opening PR…' : 'Open onboarding pull request' }}
          </button>
          <p
            v-if="onboardError"
            class="mt-2 text-xs text-danger"
          >
            {{ onboardError }}
          </p>
        </div>
      </div>

      <!-- Config present: render gates -->
      <div
        v-else
        class="mt-4 space-y-4"
      >
        <div
          v-for="(gate, index) in config?.quality_gates ?? []"
          :key="index"
          class="overflow-hidden rounded-md border border-surface-border"
        >
          <div class="flex flex-wrap items-center gap-2 border-b border-surface-border-subtle bg-surface-overlay/50 px-3 py-2">
            <GitBranch class="h-3.5 w-3.5 text-gray-500" />
            <code
              v-for="branch in gate.branches"
              :key="branch"
              class="rounded bg-surface-overlay px-1.5 py-0.5 font-mono text-xs text-gray-300"
            >{{ branch }}</code>
          </div>
          <dl class="divide-y divide-surface-border-subtle text-sm">
            <div
              v-for="rule in gateRules(gate)"
              :key="rule.label"
              class="flex items-start justify-between gap-4 px-3 py-2"
            >
              <dt class="text-gray-400">
                {{ rule.label }}
              </dt>
              <dd class="text-right font-mono text-xs text-gray-200">
                {{ rule.value }}
              </dd>
            </div>
          </dl>
        </div>

        <div
          v-if="config?.coverage?.exclude?.length"
          class="overflow-hidden rounded-md border border-surface-border"
        >
          <div class="border-b border-surface-border-subtle bg-surface-overlay/50 px-3 py-2 text-xs font-medium text-gray-300">
            Coverage exclusions
          </div>
          <div class="flex flex-wrap gap-1.5 px-3 py-2.5">
            <code
              v-for="pattern in config.coverage.exclude"
              :key="pattern"
              class="rounded bg-surface-overlay px-1.5 py-0.5 font-mono text-xs text-gray-400"
            >{{ pattern }}</code>
          </div>
        </div>

        <p
          v-if="config?.upload?.window"
          class="text-xs text-gray-500"
        >
          Upload window: reports for one snapshot are merged for
          <span class="font-mono text-gray-300">{{ config.upload.window }}</span> after the first upload.
        </p>
      </div>
    </section>
  </div>
</template>

<script setup lang="ts">
import { FileCog, GitBranch, GitPullRequest } from 'lucide-vue-next'
import type { Ref } from 'vue'
import { computed, inject, ref, watch } from 'vue'
import { useRoute } from 'vue-router'

import {
  api,
  type EffectiveConfig,
  type EffectiveSectionStatus,
  type EffectiveSource,
  type RepoConfig,
  type RepoConfigGate,
  type Repository,
} from '@/api/client'
import { useOrgRole } from '@/composables/useOrgRole'

const route = useRoute()
const provider = computed(() => route.params.provider as string)
const slug = computed(() => route.params.slug as string)
const repoSlug = computed(() => route.params.repoSlug as string)

const repo = inject<Ref<Repository | null>>('repo', ref(null))
const { isOrgAdmin } = useOrgRole()

const config = ref<RepoConfig | null>(null)
const loading = ref(true)
const loadFailed = ref(false)
const onboarding = ref(false)
const onboardError = ref('')
const onboardedPR = ref<{ number: number; html_url: string } | null>(null)
const existingPR = ref<{ number: number; html_url: string } | null>(null)

const effective = ref<EffectiveConfig | null>(null)
const effectiveLoading = ref(true)
const effectiveError = ref('')
const branchInput = ref('')

const SOURCE_LABELS: Record<EffectiveSource, string> = {
  'file': '.hibou.yml',
  'repo-gate': 'repository gate',
  'org-gate': 'inherited from org',
  'org-policy': 'org license policy',
  'default': 'Hibou default',
  'always': 'always on',
}

function sourceLabel(source: EffectiveSource): string {
  return SOURCE_LABELS[source] ?? source
}

function sourceClass(source: EffectiveSource): string {
  switch (source) {
    // Inherited and defaulted values are the ones people do not know are in
    // play, so they get the visual weight rather than the ones they wrote.
    case 'org-gate':
    case 'org-policy':
      return 'border-warn/40 bg-warn/10 text-warn'
    case 'default':
      return 'border-surface-border bg-surface-overlay/40 text-gray-400'
    case 'always':
      return 'border-surface-border bg-surface-overlay/40 text-gray-400'
    default:
      return 'border-surface-border bg-surface-overlay/40 text-gray-300'
  }
}

const STATUS_LABELS: Record<EffectiveSectionStatus, string> = {
  'enforced': 'enforced',
  'not-configured': 'not configured',
  'disabled': 'disabled',
}

function statusLabel(status: EffectiveSectionStatus): string {
  return STATUS_LABELS[status] ?? status
}

function statusClass(status: EffectiveSectionStatus): string {
  switch (status) {
    case 'enforced':
      return 'text-ok'
    case 'disabled':
      return 'text-warn'
    default:
      return 'text-gray-600'
  }
}

async function loadEffective() {
  if (!provider.value || !slug.value || !repoSlug.value) return
  const branch = branchInput.value.trim()
  // Skip a redundant fetch when a blur fires without the branch having changed.
  if (effective.value && effective.value.branch === branch && !effectiveError.value) return
  effectiveLoading.value = true
  effectiveError.value = ''
  try {
    const res = await api.getEffectiveRepoConfig(provider.value, slug.value, repoSlug.value, branch || undefined)
    effective.value = res.data
    branchInput.value = res.data.branch
  } catch {
    effective.value = null
    effectiveError.value = 'The effective configuration could not be resolved right now. Try again later.'
  } finally {
    effectiveLoading.value = false
  }
}

const hasGates = computed(() => (config.value?.quality_gates?.length ?? 0) > 0)
// PR opened in this session wins over the one replayed from the audit log.
const openPR = computed(() => onboardedPR.value ?? existingPR.value)

watch(
  [provider, slug, repoSlug],
  async () => {
    loading.value = true
    loadFailed.value = false
    // Reset so a stale branch from the previous repo cannot be reused.
    effective.value = null
    branchInput.value = ''
    void loadEffective()
    try {
      const res = await api.getRepoConfig(provider.value, slug.value, repoSlug.value)
      config.value = res.data
      if ((res.data?.quality_gates?.length ?? 0) === 0) {
        await loadOnboardingStatus()
      }
    } catch {
      config.value = null
      loadFailed.value = true
    } finally {
      loading.value = false
    }
  },
  { immediate: true },
)

async function loadOnboardingStatus() {
  try {
    const res = await api.getOnboardingStatus(provider.value, slug.value, repoSlug.value)
    existingPR.value = res.data?.pull_request ?? null
  } catch {
    existingPR.value = null
  }
}

interface GateRule { label: string; value: string }

function limit(value: number | null | undefined) {
  return value === null || value === undefined ? null : String(value)
}

// Flatten a gate into readable "rule → threshold" rows, skipping unset knobs.
function gateRules(gate: RepoConfigGate): GateRule[] {
  const rules: GateRule[] = []

  const vulnerabilities = gate.vulnerabilities
  if (vulnerabilities && vulnerabilities.enabled !== false) {
    const parts = [
      limit(vulnerabilities.max_critical) !== null ? `critical ≤ ${vulnerabilities.max_critical}` : '',
      limit(vulnerabilities.max_high) !== null ? `high ≤ ${vulnerabilities.max_high}` : '',
      limit(vulnerabilities.max_medium) !== null ? `medium ≤ ${vulnerabilities.max_medium}` : '',
      limit(vulnerabilities.max_unknown) !== null ? `unrated ≤ ${vulnerabilities.max_unknown}` : '',
      limit(vulnerabilities.max_new_total) !== null ? `new ≤ ${vulnerabilities.max_new_total}` : '',
    ].filter(Boolean)
    if (parts.length > 0) {
      rules.push({ label: 'Vulnerabilities', value: parts.join(' · ') })
    }
  }

  const code = gate.code
  if (code && code.enabled !== false) {
    const parts = [
      limit(code.max_critical) !== null ? `critical ≤ ${code.max_critical}` : '',
      limit(code.max_high) !== null ? `high ≤ ${code.max_high}` : '',
      limit(code.max_medium) !== null ? `medium ≤ ${code.max_medium}` : '',
    ].filter(Boolean)
    if (parts.length > 0) {
      rules.push({ label: 'Code findings', value: parts.join(' · ') })
    }
  }

  // ADR-037: titles for each denied CWE are on the effective-config view.
  const cwePolicy = gate.cwe
  if (cwePolicy) {
    const parts = [
      cwePolicy.deny?.length ? `deny ${cwePolicy.deny.join(', ')}` : '',
      cwePolicy.deny_tree?.length ? `with descendants ${cwePolicy.deny_tree.join(', ')}` : '',
      cwePolicy.deny_sets?.length ? `lists ${cwePolicy.deny_sets.join(', ')}` : '',
      cwePolicy.deny_categories?.length ? `categories ${cwePolicy.deny_categories.join(', ')}` : '',
      cwePolicy.types?.length ? `types ${cwePolicy.types.join(', ')}` : '',
      cwePolicy.min_severity ? `≥ ${cwePolicy.min_severity}` : '',
    ].filter(Boolean)
    if (parts.length > 0) {
      rules.push({ label: 'CWE deny list', value: parts.join(' · ') })
    }
  }

  const coverage = gate.coverage
  if (coverage) {
    const parts = [
      limit(coverage.min_coverage) !== null ? `min ${coverage.min_coverage}%` : '',
      limit(coverage.grace) !== null ? `grace ${coverage.grace}%` : '',
      limit(coverage.diff_minimum) !== null ? `diff ≥ ${coverage.diff_minimum}%` : '',
    ].filter(Boolean)
    if (parts.length > 0) {
      rules.push({ label: 'Coverage', value: parts.join(' · ') })
    }
  }

  const secrets = gate.secrets
  if (secrets && limit(secrets.max_new) !== null) {
    rules.push({ label: 'Secrets', value: `new ≤ ${secrets.max_new}` })
  }

  const licenses = gate.licenses
  if (licenses) {
    const parts = [
      licenses.deny_categories?.length ? `deny categories: ${licenses.deny_categories.join(', ')}` : '',
      licenses.deny?.length ? `deny: ${licenses.deny.join(', ')}` : '',
      licenses.allow?.length ? `allow: ${licenses.allow.join(', ')}` : '',
      licenses.deny_unknown ? 'deny unknown' : '',
    ].filter(Boolean)
    if (parts.length > 0) {
      rules.push({ label: 'Licenses', value: parts.join(' · ') })
    }
  }

  if (rules.length === 0) {
    rules.push({ label: 'No thresholds set', value: 'gate records results only' })
  }

  return rules
}

async function onboard() {
  onboarding.value = true
  onboardError.value = ''
  try {
    const res = await api.onboardRepo(provider.value, slug.value, repoSlug.value)
    onboardedPR.value = res.data
  } catch (error) {
    onboardError.value = error instanceof Error ? error.message : 'Failed to open the onboarding PR'
  } finally {
    onboarding.value = false
  }
}
</script>
