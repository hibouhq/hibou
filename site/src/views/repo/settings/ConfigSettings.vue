<template>
  <div class="space-y-6">
    <section>
      <div class="flex flex-wrap items-center justify-between gap-2 border-b border-surface-border pb-2">
        <h2 class="text-base font-semibold text-white">
          Effective configuration
        </h2>
        <code class="rounded bg-surface-overlay px-1.5 py-0.5 font-mono text-xs text-gray-400">.hibou.yml</code>
      </div>
      <p class="mt-2 text-sm text-gray-400">
        What Hibou applies to this repository right now — quality gates, coverage rules and
        upload policy, resolved from
        <code class="rounded bg-surface-overlay px-1 py-0.5 font-mono text-xs">.hibou.yml</code>
        on <span class="font-mono text-xs text-gray-300">{{ repo?.default_branch || 'the default branch' }}</span>.
        Changes are made by editing that file, so they are reviewed like any other code change.
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
          <button
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
          <p
            v-else-if="onboardedPR"
            class="mt-2 text-xs text-ok"
          >
            Opened
            <a
              :href="onboardedPR.html_url"
              target="_blank"
              rel="noopener noreferrer"
              class="text-accent hover:underline"
            >PR #{{ onboardedPR.number }}</a> with a starter configuration.
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
import { FileCog, GitBranch } from 'lucide-vue-next'
import type { Ref } from 'vue'
import { computed, inject, ref, watch } from 'vue'
import { useRoute } from 'vue-router'

import { api, type RepoConfig, type RepoConfigGate, type Repository } from '@/api/client'
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

const hasGates = computed(() => (config.value?.quality_gates?.length ?? 0) > 0)

watch(
  [provider, slug, repoSlug],
  async () => {
    loading.value = true
    loadFailed.value = false
    try {
      const res = await api.getRepoConfig(provider.value, slug.value, repoSlug.value)
      config.value = res.data
    } catch {
      config.value = null
      loadFailed.value = true
    } finally {
      loading.value = false
    }
  },
  { immediate: true },
)

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
      limit(vulnerabilities.max_new_total) !== null ? `new ≤ ${vulnerabilities.max_new_total}` : '',
    ].filter(Boolean)
    if (parts.length > 0) {
      rules.push({ label: 'Vulnerabilities', value: parts.join(' · ') })
    }
  }

  const weaknesses = gate.weaknesses
  if (weaknesses) {
    const parts = [
      limit(weaknesses.max_critical) !== null ? `critical ≤ ${weaknesses.max_critical}` : '',
      limit(weaknesses.max_high) !== null ? `high ≤ ${weaknesses.max_high}` : '',
      limit(weaknesses.max_medium) !== null ? `medium ≤ ${weaknesses.max_medium}` : '',
    ].filter(Boolean)
    if (parts.length > 0) {
      rules.push({
        label: `Weaknesses${weaknesses.enforcement ? ` (${weaknesses.enforcement})` : ''}`,
        value: parts.join(' · '),
      })
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
