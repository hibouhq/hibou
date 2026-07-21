<template>
  <div class="px-4 pt-5 pb-8">
    <!-- Header / breadcrumb -->
    <div class="flex flex-wrap items-start justify-between gap-3">
      <div class="min-w-0">
        <p class="mb-1 flex items-center gap-2 text-xs uppercase tracking-[0.24em] text-gray-500">
          <GitPullRequest class="h-3.5 w-3.5" />
          Pull Request · Quality Gate
        </p>
        <h1 class="flex flex-wrap items-center gap-x-2 gap-y-1 text-xl font-semibold tracking-tight sm:text-2xl">
          <RouterLink
            :to="`/orgs/${provider}/${slug}`"
            class="text-accent transition hover:underline"
          >
            {{ slug }}
          </RouterLink>
          <span class="text-gray-600">/</span>
          <RouterLink
            :to="{ name: 'repo-overview', params: { provider, slug, repoSlug } }"
            class="text-accent transition hover:underline"
          >
            {{ repoSlug }}
          </RouterLink>
          <span class="text-gray-600">/</span>
          <span class="text-white">#{{ pr }}</span>
        </h1>
      </div>
      <button
        type="button"
        class="inline-flex items-center gap-1.5 rounded-md border border-surface-border bg-surface-overlay px-3 py-1.5 text-xs font-medium text-gray-300 transition hover:border-accent/50 hover:text-white disabled:cursor-not-allowed disabled:opacity-50"
        :disabled="loading || refreshing"
        @click="refresh"
      >
        <RefreshCw
          class="h-3.5 w-3.5"
          :class="{ 'animate-spin': refreshing }"
        />
        Refresh
      </button>
    </div>

    <!-- Loading -->
    <div
      v-if="loading"
      class="mt-5 rounded-2xl border border-dashed border-surface-border-subtle px-4 py-8 text-sm text-gray-500"
    >
      Loading quality gate…
    </div>

    <!-- Error -->
    <div
      v-else-if="error"
      class="mt-5 rounded-2xl border border-danger/30 bg-danger/10 px-4 py-5 text-sm text-danger"
    >
      {{ error }}
    </div>

    <template v-else-if="gate">
      <!-- Verdict -->
      <div
        class="mt-5 flex items-center gap-4 rounded-2xl border p-5"
        :class="verdict.shellClass"
      >
        <span
          class="flex h-12 w-12 shrink-0 items-center justify-center rounded-xl border"
          :class="verdict.iconWrapClass"
        >
          <component
            :is="verdict.icon"
            class="h-6 w-6"
          />
        </span>
        <div class="min-w-0">
          <div class="flex flex-wrap items-center gap-2">
            <p
              class="text-xs uppercase tracking-[0.22em]"
              :class="verdict.eyebrowClass"
            >
              {{ verdict.eyebrow }}
            </p>
            <span
              class="rounded-full border px-2.5 py-0.5 text-[11px] font-medium"
              :class="enforcementBadgeClass"
            >
              {{ enforcementLabel }}
            </span>
          </div>
          <p class="mt-1 text-xl font-semibold text-white">
            {{ verdict.headline }}
          </p>
          <p class="mt-1 text-sm text-gray-400">
            {{ verdict.detail }}
          </p>
        </div>
      </div>

      <!-- Reasons -->
      <div
        v-if="gate.reasons.length > 0"
        class="mt-4 rounded-2xl border border-surface-border-subtle bg-surface-overlay/60 p-4"
      >
        <p class="text-sm font-semibold text-white">
          {{ gate.passed ? 'Gate details' : 'Why the gate failed' }}
        </p>
        <ul class="mt-3 space-y-2">
          <li
            v-for="(reason, index) in gate.reasons"
            :key="index"
            class="flex items-start gap-2.5 text-sm text-gray-300"
          >
            <span
              class="mt-1.5 h-1.5 w-1.5 shrink-0 rounded-full"
              :class="verdict.dotClass"
            />
            <span>{{ reason }}</span>
          </li>
        </ul>
      </div>

      <div
        v-else-if="gate.state !== 'pending'"
        class="mt-4 rounded-2xl border border-dashed border-surface-border-subtle px-4 py-6 text-sm text-gray-500"
      >
        No specific findings reported for this gate.
      </div>

      <!-- Metadata -->
      <div class="mt-4 flex flex-wrap items-center gap-x-5 gap-y-2 text-xs text-gray-500">
        <span class="inline-flex items-center gap-1.5">
          <GitPullRequest class="h-3.5 w-3.5" />
          PR #{{ gate.pr_number }}
        </span>
        <span
          v-if="shortSha"
          class="inline-flex items-center gap-1.5"
        >
          <GitCommitHorizontal class="h-3.5 w-3.5" />
          <span class="font-mono text-gray-300">{{ shortSha }}</span>
        </span>
        <span class="inline-flex items-center gap-1.5">
          Context
          <span class="font-mono text-gray-300">{{ gate.context }}</span>
        </span>
        <span
          class="inline-flex items-center gap-1.5 rounded-full border border-surface-border px-2 py-0.5"
          :title="sourceHint"
        >
          {{ sourceLabel }}
        </span>
        <span
          v-if="gate.updated_at"
          class="inline-flex items-center gap-1.5"
        >
          <Clock class="h-3.5 w-3.5" />
          Updated {{ formatDateTime(gate.updated_at) }}
        </span>
        <a
          v-if="gate.target_url"
          :href="gate.target_url"
          target="_blank"
          rel="noopener"
          class="inline-flex items-center gap-1.5 text-gray-400 transition hover:text-white"
        >
          <ExternalLink class="h-3.5 w-3.5" />
          Open check on forge
        </a>
      </div>

      <!-- Triage call-to-action -->
      <div class="mt-6 rounded-2xl border border-surface-border-subtle bg-surface-overlay/40 p-5">
        <div class="flex items-start gap-3">
          <ShieldAlert class="mt-0.5 h-5 w-5 shrink-0 text-accent" />
          <div class="min-w-0">
            <p class="text-sm font-semibold text-white">
              Triage findings
            </p>
            <p class="mt-1 max-w-2xl text-sm text-gray-400">
              Findings are dismissed with VEX. Marking a finding as a false positive or adding a VEX
              statement in the repository's vulnerabilities view updates this gate automatically —
              no CI re-run required.
            </p>
            <RouterLink
              :to="vulnerabilitiesLink"
              class="mt-3 inline-flex items-center gap-1.5 rounded-md bg-accent px-3 py-1.5 text-xs font-medium text-white transition hover:bg-accent/90"
            >
              Review findings for this PR
              <ArrowRight class="h-3.5 w-3.5" />
            </RouterLink>
          </div>
        </div>
      </div>
    </template>
  </div>
</template>

<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { ArrowRight, Clock, ExternalLink, GitCommitHorizontal, GitPullRequest, RefreshCw, ShieldAlert, ShieldCheck } from 'lucide-vue-next'
import { RouterLink, useRoute } from 'vue-router'

import { api, type PRGate } from '@/api/client'

const route = useRoute()

const provider = computed(() => route.params.provider as string)
const slug = computed(() => route.params.slug as string)
const repoSlug = computed(() => route.params.repoSlug as string)
const pr = computed(() => route.params.pr as string)

const gate = ref<PRGate | null>(null)
const loading = ref(true)
const refreshing = ref(false)
const error = ref('')

let requestToken = 0

async function load(opts: { silent?: boolean } = {}) {
  if (!provider.value || !slug.value || !repoSlug.value || !pr.value) {
    return
  }
  if (opts.silent) {
    refreshing.value = true
  } else {
    loading.value = true
  }
  error.value = ''
  const token = ++requestToken

  try {
    const res = await api.getPRGate(provider.value, slug.value, repoSlug.value, pr.value)
    if (token !== requestToken) {
      return
    }
    gate.value = res.data
  } catch (err) {
    if (token !== requestToken) {
      return
    }
    gate.value = null
    error.value = err instanceof Error ? err.message : 'Failed to load the quality gate.'
  } finally {
    if (token === requestToken) {
      loading.value = false
      refreshing.value = false
    }
  }
}

function refresh() {
  void load({ silent: true })
}

watch(
  () => [provider.value, slug.value, repoSlug.value, pr.value] as const,
  () => {
    void load()
  },
  { immediate: true },
)

const shortSha = computed(() => gate.value?.head_sha?.slice(0, 7) ?? '')

// PR ref names follow the forge convention used server-side (see webhooks.go).
const prRefName = computed(() =>
  provider.value === 'gitlab' ? `refs/merge-requests/${pr.value}` : `refs/pull/${pr.value}`,
)

const vulnerabilitiesLink = computed(() => ({
  name: 'repo-vulnerabilities',
  params: { provider: provider.value, slug: slug.value, repoSlug: repoSlug.value },
  query: { ref: prRefName.value },
}))

const enforcementLabel = computed(() => (gate.value?.enforcement === 'blocking' ? 'Blocking' : 'Advisory'))

const enforcementBadgeClass = computed(() =>
  gate.value?.enforcement === 'blocking'
    ? 'border-danger/40 bg-danger/10 text-danger'
    : 'border-surface-border bg-surface-overlay text-gray-400',
)

const sourceLabel = computed(() => {
  switch (gate.value?.source) {
    case 'persisted':
      return 'Published to forge'
    case 'computed':
      return 'Computed live'
    default:
      return 'Pending'
  }
})

const sourceHint = computed(() => {
  switch (gate.value?.source) {
    case 'persisted':
      return 'Last outcome published to the forge PR check.'
    case 'computed':
      return 'Evaluated on demand; not yet published to the forge.'
    default:
      return 'No scan has completed for this pull request yet.'
  }
})

const verdict = computed(() => {
  const g = gate.value
  if (!g || g.state === 'pending') {
    return {
      icon: Clock,
      eyebrow: 'Pending',
      headline: 'Quality gate pending',
      detail: 'No scan has completed for this pull request yet. The gate evaluates once the head and target snapshots are available.',
      shellClass: 'border-surface-border-subtle bg-surface-overlay/40',
      iconWrapClass: 'border-surface-border-subtle bg-surface-overlay text-gray-400',
      eyebrowClass: 'text-gray-500',
      dotClass: 'bg-gray-500',
    }
  }
  if (g.passed) {
    return {
      icon: ShieldCheck,
      eyebrow: 'Passed',
      headline: 'Quality gate passed',
      detail: 'This pull request meets the security quality gate.',
      shellClass: 'border-emerald-500/30 bg-emerald-500/[0.06]',
      iconWrapClass: 'border-emerald-500/40 bg-emerald-500/10 text-emerald-300',
      eyebrowClass: 'text-emerald-300',
      dotClass: 'bg-emerald-400',
    }
  }
  if (g.enforcement === 'blocking') {
    return {
      icon: ShieldAlert,
      eyebrow: 'Failed',
      headline: 'Quality gate failed',
      detail: 'Blocking — this gate must pass before the pull request can merge.',
      shellClass: 'border-danger/30 bg-danger/[0.06]',
      iconWrapClass: 'border-danger/40 bg-danger/10 text-danger',
      eyebrowClass: 'text-danger',
      dotClass: 'bg-danger',
    }
  }
  return {
    icon: ShieldAlert,
    eyebrow: 'Failed',
    headline: 'Quality gate failed',
    detail: 'Advisory — does not block merge, but review the findings below.',
    shellClass: 'border-amber-500/30 bg-amber-500/[0.06]',
    iconWrapClass: 'border-amber-500/40 bg-amber-500/10 text-amber-300',
    eyebrowClass: 'text-amber-300',
    dotClass: 'bg-amber-400',
  }
})

function formatDateTime(value: string) {
  return new Intl.DateTimeFormat('en', { dateStyle: 'medium', timeStyle: 'short' }).format(new Date(value))
}
</script>
