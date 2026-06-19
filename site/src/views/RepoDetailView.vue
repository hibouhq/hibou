<template>
  <div>
    <div
      v-if="loading"
      class="px-5 py-8 text-sm text-gray-500"
    >
      Loading repository details...
    </div>

    <template v-else-if="repo">
      <!-- Repo header (GitHub-style) -->
      <div class="px-4 pt-5">
        <div class="flex flex-wrap items-start justify-between gap-3">
          <div class="min-w-0">
            <h1 class="flex flex-wrap items-center gap-x-2 gap-y-1 text-xl">
              <BookMarked class="h-5 w-5 shrink-0 text-gray-500" />
              <RouterLink
                :to="`/orgs/${provider}/${orgSlug}`"
                class="text-accent transition hover:underline"
              >
                {{ orgSlug }}
              </RouterLink>
              <span class="text-gray-600">/</span>
              <span class="font-semibold text-white">{{ repo.name }}</span>
              <span
                class="ml-1 rounded-full border px-2 py-0.5 text-[11px] font-medium"
                :class="repo.private
                  ? 'border-surface-border text-gray-400'
                  : 'border-ok/40 text-ok'"
              >
                {{ repo.private ? 'Private' : 'Public' }}
              </span>
            </h1>
            <p
              v-if="repoDescription"
              class="mt-1.5 max-w-2xl text-sm text-gray-400"
            >
              {{ repoDescription }}
            </p>
          </div>
          <div class="flex items-center gap-2">
            <RouterLink
              v-if="selectedPRNumber"
              class="inline-flex items-center gap-1.5 rounded-md border border-surface-border bg-surface-overlay px-3 py-1.5 text-xs font-medium text-gray-300 transition hover:border-accent/50 hover:text-white"
              :to="{ name: 'pr-review', params: { ...route.params, number: selectedPRNumber }, query: { ref: selectedRefName } }"
            >
              <GitPullRequest class="h-3.5 w-3.5" />
              PR Review
            </RouterLink>
            <a
              v-if="repo.html_url"
              :href="repo.html_url"
              target="_blank"
              rel="noopener"
              class="inline-flex items-center gap-1.5 rounded-md border border-surface-border bg-surface-overlay px-3 py-1.5 text-xs font-medium text-gray-300 transition hover:border-accent/50 hover:text-white"
            >
              <ExternalLink class="h-3.5 w-3.5" />
              <span class="hidden sm:inline">Open on forge</span>
            </a>
          </div>
        </div>
      </div>

      <!-- Tabs (GitHub-style) -->
      <div class="mt-4 border-b border-surface-border px-2">
        <nav class="flex gap-0.5 overflow-x-auto">
          <RouterLink
            v-for="tab in tabs"
            :key="tab.name"
            :to="tab.to"
            class="group flex items-center gap-2 border-b-2 px-3 pb-2.5 pt-1.5 text-sm transition"
            :class="isActiveTab(tab.name)
              ? 'border-accent font-semibold text-white'
              : 'border-transparent text-gray-400 hover:border-surface-border hover:text-gray-200'"
          >
            <component
              :is="tab.icon"
              class="h-4 w-4 shrink-0"
              :class="isActiveTab(tab.name) ? 'text-gray-300' : 'text-gray-500'"
            />
            {{ tab.label }}
            <span
              v-if="tabCount(tab.name) !== null"
              class="inline-flex min-w-[1.25rem] items-center justify-center rounded-full px-1.5 text-[10px] leading-[18px]"
              :class="isActiveTab(tab.name) ? 'bg-accent/15 text-accent' : 'bg-surface-overlay text-gray-500'"
            >
              {{ tabCount(tab.name) }}
            </span>
          </RouterLink>
        </nav>
      </div>

      <div class="px-4 pt-3">
        <BranchPRSelector
          :refs="refs"
          :selected-ref-name="selectedRefName"
          :default-branch="repo.default_branch"
          :loading="loading"
          @select="selectRef"
        />
      </div>

      <div
        v-if="snapshots.length > 0 || snapshotsLoading"
        class="flex items-center gap-2 overflow-x-auto border-b border-surface-border-subtle px-4 py-2"
      >
        <span class="shrink-0 text-[11px] uppercase tracking-[0.14em] text-gray-500">Snapshot</span>
        <button
          class="snapshot-chip shrink-0"
          :class="[
            latestSnapshot ? snapshotChipToneClass(latestSnapshot) : 'snapshot-chip--default',
            !selectedSnapshotId ? 'snapshot-chip--selected' : 'snapshot-chip--idle',
          ]"
          :title="latestSnapshotTitle"
          type="button"
          @click="selectSnapshot()"
        >
          <span class="snapshot-chip__primary">Latest</span>
          <span class="snapshot-chip__secondary">
            {{ latestSnapshot ? relativeTime(latestSnapshot.created_at) : 'Most recent build' }}
          </span>
        </button>
        <button
          v-for="snapshot in snapshots.slice(0, 6)"
          :key="snapshot.id"
          class="snapshot-chip shrink-0"
          :class="[
            snapshotChipToneClass(snapshot),
            snapshot.id === selectedSnapshotId ? 'snapshot-chip--selected' : 'snapshot-chip--idle',
          ]"
          :title="snapshotTitle(snapshot)"
          type="button"
          @click="selectSnapshot(snapshot.id)"
        >
          <span class="snapshot-chip__primary">{{ snapshotLabel(snapshot) }}</span>
          <span class="snapshot-chip__secondary">{{ relativeTime(snapshot.created_at) }}</span>
        </button>
        <span
          v-if="snapshotsLoading"
          class="text-[11px] text-gray-500"
        >
          Loading...
        </span>
      </div>

      <div class="pt-4">
        <RouterView />
      </div>
    </template>

    <div
      v-else
      class="px-5 py-8 text-sm text-gray-500"
    >
      Repository not found.
    </div>
  </div>
</template>

<script setup lang="ts">
import {
  Activity,
  BookMarked,
  ExternalLink,
  FlaskConical,
  GitPullRequest,
  LayoutDashboard,
  Package,
  ShieldAlert,
} from 'lucide-vue-next'
import { computed, onMounted, onUnmounted, provide, ref, watch } from 'vue'
import { RouterLink, RouterView, useRoute, useRouter } from 'vue-router'

import { api, type EnhancedRef, type RefSummary, type Repository, type Snapshot } from '@/api/client'
import BranchPRSelector from '@/components/BranchPRSelector.vue'
import { useOrgStore } from '@/stores/org'

const route = useRoute()
const router = useRouter()
const orgStore = useOrgStore()

const repo = ref<Repository | null>(null)
const refs = ref<EnhancedRef[]>([])
const snapshots = ref<Snapshot[]>([])
const summary = ref<RefSummary | null>(null)
const loading = ref(true)
const snapshotsLoading = ref(false)
let snapshotPollTimer: number | null = null
let snapshotRequestToken = 0
let pendingSnapshotRequests = 0

const forgeUrl = computed(() => orgStore.currentOrg?.forge_url || '')
const repoProviderID = computed(() => repo.value?.provider_id || '')
provide('forgeUrl', forgeUrl)
provide('repoProviderID', repoProviderID)
provide('repo', repo)

const provider = computed(() => route.params.provider as string)
const orgSlug = computed(() => route.params.slug as string)
const repoSlug = computed(() => route.params.repoSlug as string)
const selectedSnapshotId = computed(() => typeof route.query.snapshot === 'string' ? route.query.snapshot : '')
const selectedRefName = computed(() => {
  if (typeof route.query.ref === 'string' && route.query.ref.length > 0) {
    return route.query.ref
  }

  return repo.value?.default_branch || refs.value[0]?.name || 'No refs available'
})
const selectedRef = computed(() => refs.value.find((item) => item.name === selectedRefName.value) ?? null)
const latestSnapshot = computed(() => snapshots.value.find(isFinishedSnapshot) ?? snapshots.value[0] ?? null)
provide('latestSnapshot', latestSnapshot)
const selectedPRNumber = computed(() => {
  if (selectedRef.value?.ref_type !== 'pull_request') {
    return ''
  }

  return extractPullRequestNumber(selectedRef.value.name)
})

const tabs = computed(() => {
  const query = selectedRefName.value !== 'No refs available'
    ? {
        ref: selectedRefName.value,
        ...(selectedSnapshotId.value ? { snapshot: selectedSnapshotId.value } : {}),
      }
    : undefined

  return [
    { label: 'Overview', name: 'repo-overview', icon: LayoutDashboard, to: { name: 'repo-overview', params: route.params, query } },
    { label: 'Vulnerabilities', name: 'repo-vulnerabilities', icon: ShieldAlert, to: { name: 'repo-vulnerabilities', params: route.params, query } },
    { label: 'Coverage', name: 'repo-coverage', icon: Activity, to: { name: 'repo-coverage', params: route.params, query } },
    { label: 'Tests', name: 'repo-tests', icon: FlaskConical, to: { name: 'repo-tests', params: route.params, query } },
    { label: 'Dependencies', name: 'repo-dependencies', icon: Package, to: { name: 'repo-dependencies', params: route.params, query } },
  ]
})

const repoDescription = computed(() => repo.value?.description || '')

const prevParams = ref({ provider: '', slug: '', repoSlug: '' })
const latestSnapshotTitle = computed(() => snapshotTitle(latestSnapshot.value, 'Latest snapshot'))

onMounted(() => {
  prevParams.value = { provider: provider.value, slug: orgSlug.value, repoSlug: repoSlug.value }
  if (orgStore.orgs.length === 0) {
    void orgStore.fetchOrgs()
  }
  void loadRepoShell()
})

onUnmounted(() => {
  stopSnapshotPolling()
})

watch(
  () => [route.params.provider, route.params.slug, route.params.repoSlug],
  ([p, s, r]) => {
    const pStr = p as string
    const sStr = s as string
    const rStr = r as string
    if (pStr === prevParams.value.provider && sStr === prevParams.value.slug && rStr === prevParams.value.repoSlug) {
      return
    }
    stopSnapshotPolling()
    prevParams.value = { provider: pStr, slug: sStr, repoSlug: rStr }
    void loadRepoShell()
  },
)

watch(
  () => selectedRefName.value,
  () => {
    stopSnapshotPolling()
    void loadSnapshots()
    void loadSummary()
  },
)

function isActiveTab(name: string) {
  return route.name === name
}

async function loadRepoShell() {
  loading.value = true
  stopSnapshotPolling()

  try {
    const [repoRes, refsRes] = await Promise.all([
      api.getRepo(provider.value, orgSlug.value, repoSlug.value),
      api.listRefsEnhanced(provider.value, orgSlug.value, repoSlug.value),
    ])

    repo.value = repoRes.data
    refs.value = refsRes.data

    if (!route.query.ref && repoRes.data.default_branch) {
      await router.replace({ query: { ...route.query, ref: repoRes.data.default_branch } })
    }

    await Promise.all([loadSnapshots(), loadSummary()])
  } catch {
    repo.value = null
    refs.value = []
    snapshots.value = []
    summary.value = null
  } finally {
    loading.value = false
  }
}

function selectRef(name: string) {
  const nextQuery: Record<string, string> = {}
  for (const [key, value] of Object.entries(route.query)) {
    if (typeof value === 'string') {
      nextQuery[key] = value
    }
  }
  nextQuery.ref = name
  delete nextQuery.snapshot
  void router.replace({ query: nextQuery })
}

async function loadSnapshots() {
  if (!provider.value || !orgSlug.value || !repoSlug.value || selectedRefName.value === 'No refs available') {
    snapshotRequestToken++
    stopSnapshotPolling()
    snapshots.value = []
    return
  }

  const requestProvider = provider.value
  const requestOrgSlug = orgSlug.value
  const requestRepoSlug = repoSlug.value
  const requestRefName = selectedRefName.value
  const requestScope = snapshotScopeKey(requestProvider, requestOrgSlug, requestRepoSlug, requestRefName)
  const requestToken = ++snapshotRequestToken

  pendingSnapshotRequests++
  snapshotsLoading.value = true
  try {
    const response = await api.listSnapshots(requestProvider, requestOrgSlug, requestRepoSlug, {
      ref: requestRefName,
      per_page: 12,
    })

    if (requestToken !== snapshotRequestToken || requestRefName !== selectedRefName.value || requestScope !== currentSnapshotScopeKey()) {
      return
    }

    snapshots.value = response.data
  } catch {
    if (requestToken !== snapshotRequestToken || requestRefName !== selectedRefName.value || requestScope !== currentSnapshotScopeKey()) {
      return
    }

    snapshots.value = []
  } finally {
    if (requestToken === snapshotRequestToken && requestRefName === selectedRefName.value && requestScope === currentSnapshotScopeKey()) {
      syncSnapshotPolling(requestScope)
    }

    pendingSnapshotRequests--
    snapshotsLoading.value = pendingSnapshotRequests > 0
  }
}

async function loadSummary() {
  if (!provider.value || !orgSlug.value || !repoSlug.value || selectedRefName.value === 'No refs available') {
    summary.value = null
    return
  }

  try {
    const response = await api.getRefSummary(provider.value, orgSlug.value, repoSlug.value, { ref: selectedRefName.value })
    summary.value = response.data
  } catch {
    summary.value = null
  }
}

function totalSeverity(counts?: { critical: number; high: number; medium: number; low: number; info: number }) {
  if (!counts) {
    return 0
  }

  return counts.critical + counts.high + counts.medium + counts.low + counts.info
}

function tabCount(name: string): number | null {
  const counts: Record<string, number | null> = {
    'repo-vulnerabilities': summary.value ? totalSeverity(summary.value.vulnerabilities) : null,
    'repo-coverage': null,
    'repo-dependencies': summary.value ? summary.value.components_total : null,
  }

  return counts[name] ?? null
}

function selectSnapshot(id?: string) {
  const nextQuery: Record<string, string> = {}
  for (const [key, value] of Object.entries(route.query)) {
    if (typeof value === 'string') {
      nextQuery[key] = value
    }
  }
  nextQuery.ref = selectedRefName.value
  if (id) {
    nextQuery.snapshot = id
  } else {
    delete nextQuery.snapshot
  }
  void router.replace({ query: nextQuery })
}

function snapshotLabel(snapshot: Snapshot) {
  return snapshot.tag || snapshot.commit_sha.slice(0, 7)
}

function isFinishedSnapshot(snapshot: Snapshot) {
  return snapshot.status === 'complete' || snapshot.status === 'active'
}

function snapshotTitle(snapshot: Snapshot | null, prefix = 'Snapshot') {
  if (!snapshot) {
    return prefix
  }

  const details = [`Commit ${snapshot.commit_sha}`]
  if (snapshot.status === 'failed') {
    details.push('Status: timed out / failed')
  }
  if (snapshot.tag) {
    details.push(`Tag ${snapshot.tag}`)
  }
  if (snapshot.run_number) {
    details.push(`Run #${snapshot.run_number}`)
  } else if (snapshot.run_id) {
    details.push(`Run ${snapshot.run_id}`)
  }
  if (snapshot.pr_number) {
    const branch = snapshot.pr_target_branch ? ` -> ${snapshot.pr_target_branch}` : ''
    details.push(`PR #${snapshot.pr_number}${branch}`)
  }

  return `${prefix}\n${details.join('\n')}`
}

function snapshotChipToneClass(snapshot: Snapshot) {
  if (snapshot.status === 'failed') {
    return 'snapshot-chip--failed'
  }
  if (snapshot.status === 'pending') {
    return 'snapshot-chip--pending'
  }
  if (snapshot.tag) {
    return 'snapshot-chip--release'
  }
  return 'snapshot-chip--default'
}

function hasPendingSnapshots() {
  return snapshots.value.some((snapshot) => snapshot.status === 'pending')
}

function syncSnapshotPolling(scopeKey: string) {
  if (scopeKey !== currentSnapshotScopeKey()) {
    stopSnapshotPolling()
    return
  }

  if (hasPendingSnapshots()) {
    if (snapshotPollTimer === null) {
      snapshotPollTimer = window.setInterval(() => {
        if (scopeKey !== currentSnapshotScopeKey()) {
          stopSnapshotPolling()
          return
        }
        void loadSnapshots()
      }, 4000)
    }
    return
  }

  stopSnapshotPolling()
}

function stopSnapshotPolling() {
  if (snapshotPollTimer !== null) {
    window.clearInterval(snapshotPollTimer)
    snapshotPollTimer = null
  }
}

function currentSnapshotScopeKey() {
  return snapshotScopeKey(provider.value, orgSlug.value, repoSlug.value, selectedRefName.value)
}

function snapshotScopeKey(providerName: string, orgName: string, repoName: string, refName: string) {
  return `${providerName}:${orgName}:${repoName}:${refName}`
}

function extractPullRequestNumber(refName: string) {
  const normalized = refName.trim()
  const patterns = [
    /^refs\/(?:pull|merge-requests)\/(\d+)(?:\/|$)/i,
    /^(?:pr|mr)[-_ ]?(\d+)$/i,
    /^(\d+)$/,
  ]

  for (const pattern of patterns) {
    const match = normalized.match(pattern)
    if (match?.[1]) {
      return match[1]
    }
  }

  return ''
}

function relativeTime(input: string) {
  const target = new Date(input)
  const diffSeconds = Math.round((target.getTime() - Date.now()) / 1000)
  const formatter = new Intl.RelativeTimeFormat('en', { numeric: 'auto' })

  if (Math.abs(diffSeconds) >= 86400) {
    return formatter.format(Math.round(diffSeconds / 86400), 'day')
  }
  if (Math.abs(diffSeconds) >= 3600) {
    return formatter.format(Math.round(diffSeconds / 3600), 'hour')
  }
  if (Math.abs(diffSeconds) >= 60) {
    return formatter.format(Math.round(diffSeconds / 60), 'minute')
  }
  return formatter.format(diffSeconds, 'second')
}
</script>

<style scoped>
.snapshot-chip {
  position: relative;
  isolation: isolate;
  display: inline-flex;
  min-width: 5.75rem;
  flex-direction: column;
  align-items: flex-start;
  gap: 0.1rem;
  overflow: hidden;
  border-radius: 9999px;
  border: 1px solid rgba(148, 163, 184, 0.18);
  background: rgba(17, 24, 39, 0.76);
  padding: 0.45rem 0.8rem 0.42rem;
  color: rgb(209, 213, 219);
  transition:
    border-color 280ms ease,
    background-color 280ms ease,
    color 280ms ease,
    box-shadow 280ms ease,
    transform 200ms ease;
}

.snapshot-chip::before {
  content: '';
  position: absolute;
  inset: -1px;
  border-radius: inherit;
  padding: 1px;
  background: transparent;
  opacity: 0;
  transition: opacity 320ms ease;
  -webkit-mask:
    linear-gradient(#fff 0 0) content-box,
    linear-gradient(#fff 0 0);
  -webkit-mask-composite: xor;
  mask-composite: exclude;
}

.snapshot-chip--idle:hover {
  color: rgb(255, 255, 255);
  transform: translateY(-1px);
}

.snapshot-chip--selected {
  box-shadow: 0 0 0 1px rgba(255, 255, 255, 0.04), 0 10px 24px -18px rgba(15, 23, 42, 0.85);
}

.snapshot-chip--default {
  border-color: rgb(63 93 138 / 0.42);
  background: linear-gradient(180deg, rgb(28 44 66 / 0.72), rgb(18 28 43 / 0.9));
  color: rgb(147 197 253);
}

.snapshot-chip--default.snapshot-chip--selected {
  border-color: rgb(96 165 250 / 0.64);
  background: linear-gradient(180deg, rgb(29 78 216 / 0.22), rgb(18 28 43 / 0.94));
  color: rgb(191 219 254);
}

.snapshot-chip--release {
  border-color: rgb(74 222 128 / 0.34);
  background: linear-gradient(180deg, rgb(22 101 52 / 0.22), rgb(17 24 39 / 0.9));
  color: rgb(134 239 172);
}

.snapshot-chip--release.snapshot-chip--selected {
  border-color: rgb(74 222 128 / 0.58);
  background: linear-gradient(180deg, rgb(22 163 74 / 0.2), rgb(20 83 45 / 0.88));
  color: rgb(220 252 231);
}

.snapshot-chip--pending {
  border-color: rgb(251 191 36 / 0.48);
  background: linear-gradient(180deg, rgb(120 53 15 / 0.26), rgb(17 24 39 / 0.92));
  color: rgb(253 224 71);
  box-shadow: 0 0 0 1px rgb(251 191 36 / 0.1);
}

.snapshot-chip--pending::before {
  opacity: 0.96;
  background: conic-gradient(
    from 0deg,
    rgb(251 191 36 / 0.08),
    rgb(253 224 71 / 0.92),
    rgb(245 158 11 / 0.28),
    rgb(253 224 71 / 0.92),
    rgb(251 191 36 / 0.08)
  );
  animation: snapshot-border-spin 2.8s linear infinite;
}

.snapshot-chip--pending.snapshot-chip--selected {
  border-color: rgb(251 191 36 / 0.72);
  background: linear-gradient(180deg, rgb(180 83 9 / 0.28), rgb(120 53 15 / 0.92));
  color: rgb(254 249 195);
}

.snapshot-chip--failed {
  border-color: rgb(248 113 113 / 0.6);
  background: linear-gradient(180deg, rgb(185 28 28 / 0.3), rgb(69 10 10 / 0.94));
  color: rgb(254 202 202);
  box-shadow: 0 0 0 1px rgb(239 68 68 / 0.12);
}

.snapshot-chip--failed.snapshot-chip--selected {
  border-color: rgb(248 113 113 / 0.8);
  background: linear-gradient(180deg, rgb(220 38 38 / 0.34), rgb(127 29 29 / 0.96));
  color: rgb(254 226 226);
}

.snapshot-chip__primary {
  position: relative;
  z-index: 1;
  font-size: 0.72rem;
  font-weight: 600;
  line-height: 1;
}

.snapshot-chip__secondary {
  position: relative;
  z-index: 1;
  font-size: 0.61rem;
  line-height: 1;
  opacity: 0.78;
}

@keyframes snapshot-border-spin {
  to {
    transform: rotate(1turn);
  }
}

@media (prefers-reduced-motion: reduce) {
  .snapshot-chip,
  .snapshot-chip::before {
    animation: none !important;
    transition-duration: 0ms;
  }

  .snapshot-chip--idle:hover {
    transform: none;
  }
}
</style>
