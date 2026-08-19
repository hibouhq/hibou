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
          <div class="flex flex-wrap items-center gap-2">
            <div
              v-if="compareRefOptions.length > 0"
              ref="compareMenuRef"
              class="relative"
            >
              <button
                class="inline-flex items-center gap-1.5 rounded-md border border-surface-border bg-surface-overlay px-3 py-1.5 text-xs font-medium text-gray-300 transition hover:border-accent/50 hover:text-white"
                type="button"
                @click.stop="toggleCompareMenu"
              >
                <GitCompareArrows class="h-3.5 w-3.5" />
                Compare with
              </button>

              <div
                v-if="compareMenuOpen"
                class="absolute right-0 top-[calc(100%+0.5rem)] z-30 w-[22rem] max-w-[calc(100vw-2rem)] rounded-xl border border-surface-border bg-surface-overlay p-3 shadow-2xl"
              >
                <div class="space-y-3">
                  <div>
                    <p class="mb-1 text-[11px] font-medium uppercase tracking-wide text-gray-500">
                      Base
                    </p>
                    <BranchPRSelector
                      :refs="refs"
                      :selected-ref-name="compareBaseRefName"
                      :default-branch="repo.default_branch"
                      :repo-html-url="repo.html_url"
                      :provider="repo.provider"
                      compact
                      block
                      @select="selectCompareBase"
                    />
                    <p
                      v-if="selectedSnapshotId && sameComparableRef(compareBaseRefName, selectedRefName)"
                      class="mt-1 text-[11px] text-gray-500"
                    >
                      Uses the snapshot currently selected on this page.
                    </p>
                  </div>

                  <div>
                    <p class="mb-1 text-[11px] font-medium uppercase tracking-wide text-gray-500">
                      Target
                    </p>
                    <BranchPRSelector
                      :refs="compareTargetOptions"
                      :selected-ref-name="compareTargetRefName"
                      :default-branch="repo.default_branch"
                      :repo-html-url="repo.html_url"
                      :provider="repo.provider"
                      compact
                      block
                      @select="selectCompareTarget"
                    />
                  </div>

                  <div class="flex items-center justify-end gap-2 pt-1">
                    <button
                      class="rounded-md border border-surface-border px-3 py-1.5 text-xs font-medium text-gray-400 transition hover:text-white"
                      type="button"
                      @click="compareMenuOpen = false"
                    >
                      Cancel
                    </button>
                    <button
                      class="rounded-md bg-accent px-3 py-1.5 text-xs font-medium text-white transition hover:bg-accent/90 disabled:cursor-not-allowed disabled:opacity-50"
                      type="button"
                      :disabled="!canRunCompare"
                      @click="runCompare"
                    >
                      Open compare
                    </button>
                  </div>
                </div>
              </div>
            </div>
            <RouterLink
              v-if="selectedPRNumber"
              class="inline-flex items-center gap-1.5 rounded-md border border-surface-border bg-surface-overlay px-3 py-1.5 text-xs font-medium text-gray-300 transition hover:border-accent/50 hover:text-white"
              :to="{ name: 'repo-compare', params: route.params, query: { base: selectedRef?.merge_target_ref_name || repo?.default_branch || 'main', head: selectedRefName } }"
            >
              <GitPullRequest class="h-3.5 w-3.5" />
              PR Review
            </RouterLink>
          </div>
        </div>
      </div>

      <!-- Tabs (GitHub-style); the Releases tab is a different species —
           shipped artifacts, not ref-scoped analysis — fenced by dividers and
           rendered as a pill (ADR-024 §1). -->
      <div class="mt-4 border-b border-surface-border px-2">
        <nav class="flex items-center gap-0.5 overflow-x-auto">
          <template
            v-for="(tab, tabIndex) in tabs"
            :key="tab.name"
          >
            <template v-if="tab.fenced">
              <span
                v-if="!tabs[tabIndex - 1]?.fenced"
                aria-hidden="true"
                class="mx-1.5 mb-1.5 h-5 w-px shrink-0 bg-surface-border"
              />
              <RouterLink
                :to="tab.to"
                class="group mb-2 flex items-center gap-2 rounded-full border px-3 py-1 text-sm transition"
                :class="isActiveTab(tab.name)
                  ? 'border-accent/60 bg-accent/15 font-semibold text-accent'
                  : 'border-surface-border bg-surface-overlay text-gray-400 hover:border-accent/40 hover:text-gray-200'"
              >
                <component
                  :is="tab.icon"
                  class="h-4 w-4 shrink-0"
                  :class="isActiveTab(tab.name) ? 'text-accent' : 'text-gray-500'"
                />
                {{ tab.label }}
                <span
                  v-if="tab.badge"
                  class="rounded-full border border-accent/40 px-1.5 py-0.5 text-[10px] font-medium leading-none"
                  :class="isActiveTab(tab.name) ? 'text-accent' : 'text-gray-500'"
                >{{ tab.badge }}</span>
              </RouterLink>
              <span
                v-if="!tabs[tabIndex + 1]?.fenced"
                aria-hidden="true"
                class="mx-1.5 mb-1.5 h-5 w-px shrink-0 bg-surface-border"
              />
            </template>
            <RouterLink
              v-else
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
          </template>
        </nav>
      </div>

      <div
        v-if="!isFencedTabActive"
        class="px-4 pt-3"
      >
        <BranchPRSelector
          :refs="refs"
          :selected-ref-name="selectedRefName"
          :default-branch="repo.default_branch"
          :loading="loading"
          :repo-html-url="repo.html_url"
          :provider="repo.provider"
          @select="selectRef"
        />
      </div>

      <div
        v-if="!isFencedTabActive && (snapshots.length > 0 || snapshotsLoading)"
        class="flex items-center gap-2 overflow-x-auto border-b border-surface-border-subtle px-4 py-2"
      >
        <span class="shrink-0 text-[11px] uppercase tracking-[0.14em] text-gray-500">Snapshot</span>
        <button
          v-for="snapshot in snapshotChips"
          :key="snapshot.id"
          class="snapshot-chip shrink-0"
          :class="[
            snapshotChipToneClass(snapshot),
            isLatestSnapshot(snapshot) ? 'snapshot-chip--latest' : '',
            isSelectedSnapshot(snapshot) ? 'snapshot-chip--selected' : 'snapshot-chip--idle',
          ]"
          :title="snapshotTitle(snapshot, isLatestSnapshot(snapshot) ? 'Latest successful snapshot' : 'Snapshot')"
          type="button"
          @click="selectSnapshot(isLatestSnapshot(snapshot) ? undefined : snapshot.id)"
        >
          <span class="snapshot-chip__primary">{{ snapshotChipPrimary(snapshot) }}</span>
          <span class="snapshot-chip__secondary">{{ snapshotChipSecondary(snapshot) }}</span>
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
  Container,
  ExternalLink,
  FlaskConical,
  GitCompareArrows,
  GitPullRequest,
  LayoutDashboard,
  LineChart,
  Package,
  Rocket,
  Settings,
  ShieldAlert,
} from 'lucide-vue-next'
import { computed, onMounted, onUnmounted, provide, ref, watch } from 'vue'
import { RouterLink, RouterView, useRoute, useRouter } from 'vue-router'

import { api, type EnhancedRef, type RefSummary, type Repository, type Snapshot } from '@/api/client'
import BranchPRSelector from '@/components/BranchPRSelector.vue'
import { relativeTime } from '@/lib/datetime'
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
const latestSnapshot = computed(() => snapshots.value.find(isSuccessfulSnapshot) ?? snapshots.value[0] ?? null)
provide('latestSnapshot', latestSnapshot)
// Tabs need the ref list for baseline pickers (coverage new-code lens).
provide('refs', refs)
const snapshotChips = computed(() => {
  const visibleIndexes: number[] = []
  const mandatoryIndexes = new Set<number>()

  const latestIndex = latestSnapshot.value
    ? snapshots.value.findIndex((snapshot) => snapshot.id === latestSnapshot.value?.id)
    : -1
  const selectedIndex = selectedSnapshotId.value
    ? snapshots.value.findIndex((snapshot) => snapshot.id === selectedSnapshotId.value)
    : -1

  if (latestIndex >= 0) {
    mandatoryIndexes.add(latestIndex)
  }

  if (selectedIndex >= 0) {
    mandatoryIndexes.add(selectedIndex)
  }

  for (let index = 0; index < snapshots.value.length && visibleIndexes.length < 6; index += 1) {
    visibleIndexes.push(index)
  }

  for (const index of mandatoryIndexes) {
    if (!visibleIndexes.includes(index)) {
      visibleIndexes.push(index)
    }
  }

  visibleIndexes.sort((left, right) => left - right)

  while (visibleIndexes.length > 6) {
    const removableIndex = [...visibleIndexes].reverse().find((index) => !mandatoryIndexes.has(index))
    if (removableIndex === undefined) {
      break
    }
    visibleIndexes.splice(visibleIndexes.indexOf(removableIndex), 1)
  }

  return visibleIndexes.map((index) => snapshots.value[index])
})
const selectedPRNumber = computed(() => {
  if (selectedRef.value?.ref_type !== 'pull_request') {
    return ''
  }

  return extractPullRequestNumber(selectedRef.value.name)
})
const compareMenuRef = ref<HTMLElement | null>(null)
const compareMenuOpen = ref(false)
const compareBaseRefName = ref('')
const compareTargetRefName = ref('')

function canonicalComparableRefName(name: string) {
  const trimmed = name.trim()
  if (trimmed.startsWith('refs/heads/')) {
    return trimmed.slice('refs/heads/'.length)
  }
  if (trimmed.startsWith('refs/tags/')) {
    return trimmed.slice('refs/tags/'.length)
  }
  return trimmed
}

function sameComparableRef(left: string, right: string) {
  const leftName = left.trim()
  const rightName = right.trim()
  if (!leftName || !rightName) {
    return false
  }
  return leftName === rightName || canonicalComparableRefName(leftName) === canonicalComparableRefName(rightName)
}

const compareRefOptions = computed(() => {
  const current = selectedRefName.value
  if (!current || current === 'No refs available') {
    return []
  }

  return refs.value.filter((item) => !sameComparableRef(item.name, current))
})

const compareTargetOptions = computed(() => refs.value.filter((item) => !sameComparableRef(item.name, compareBaseRefName.value)))

const canRunCompare = computed(() => {
  return compareBaseRefName.value.length > 0
    && compareTargetRefName.value.length > 0
    && !sameComparableRef(compareBaseRefName.value, compareTargetRefName.value)
})

function preferredCompareTarget(source: string) {
  const candidates = refs.value.filter((item) => !sameComparableRef(item.name, source))
  if (candidates.length === 0) {
    return ''
  }

  const defaultBranch = repo.value?.default_branch || ''
  const defaultBranchRef = candidates.find((item) => sameComparableRef(item.name, defaultBranch))
  if (defaultBranchRef) {
    return defaultBranchRef.name
  }

  return candidates.find((item) => item.ref_type === 'branch')?.name
    || candidates.find((item) => item.ref_type === 'pull_request')?.name
    || candidates.find((item) => item.ref_type === 'tag')?.name
    || ''
}

function syncCompareSelection() {
  const current = selectedRefName.value
  compareBaseRefName.value = current === 'No refs available' ? '' : current
  if (!compareTargetOptions.value.some((item) => item.name === compareTargetRefName.value)) {
    compareTargetRefName.value = preferredCompareTarget(compareBaseRefName.value)
  }
}

function selectCompareBase(name: string) {
  compareBaseRefName.value = name
  if (sameComparableRef(compareBaseRefName.value, compareTargetRefName.value) || !compareTargetOptions.value.some((item) => item.name === compareTargetRefName.value)) {
    compareTargetRefName.value = preferredCompareTarget(compareBaseRefName.value)
  }
}

function selectCompareTarget(name: string) {
  compareTargetRefName.value = name
}

function toggleCompareMenu() {
  if (!compareMenuOpen.value) {
    syncCompareSelection()
  }
  compareMenuOpen.value = !compareMenuOpen.value
}

function runCompare() {
  if (!canRunCompare.value) {
    return
  }

  const query: Record<string, string> = {
    base: compareBaseRefName.value,
    head: compareTargetRefName.value,
  }

  if (selectedSnapshotId.value) {
    if (sameComparableRef(compareBaseRefName.value, selectedRefName.value)) {
      query.base_snapshot = selectedSnapshotId.value
    }
    if (sameComparableRef(compareTargetRefName.value, selectedRefName.value)) {
      query.head_snapshot = selectedSnapshotId.value
    }
  }

  compareMenuOpen.value = false
  void router.push({ name: 'repo-compare', params: route.params, query })
}

function handleCompareMenuDocumentClick(event: MouseEvent) {
  const target = event.target as Node | null
  if (target && compareMenuRef.value && !compareMenuRef.value.contains(target)) {
    compareMenuOpen.value = false
  }
}

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
    // Fenced tab (ADR-024 §1): releases are not scoped to the ref/snapshot
    // selector, so the tab renders as a pill between dividers and the
    // selector strip disappears while it is active.
    { label: 'Releases', name: 'repo-releases', icon: Rocket, fenced: true, to: { name: 'repo-releases', params: route.params } },
    { label: 'Deployments', name: 'repo-deployments', icon: Container, fenced: true, badge: 'Soon', to: { name: 'repo-deployments', params: route.params } },
    // Insights and Settings are repo-level like Releases: fencing them drops
    // the ref/snapshot selector strip, which does not apply to them.
    { label: 'Insights', name: 'repo-insights', icon: LineChart, fenced: true, to: { name: 'repo-insights', params: route.params } },
    { label: 'Settings', name: 'repo-settings', icon: Settings, fenced: true, to: { name: 'repo-settings', params: route.params } },
  ]
})

const repoDescription = computed(() => repo.value?.description || '')

const prevParams = ref({ provider: '', slug: '', repoSlug: '' })
onMounted(() => {
  document.addEventListener('click', handleCompareMenuDocumentClick)
  prevParams.value = { provider: provider.value, slug: orgSlug.value, repoSlug: repoSlug.value }
  if (orgStore.orgs.length === 0) {
    void orgStore.fetchOrgs()
  }
  void loadRepoShell()
})

onUnmounted(() => {
  document.removeEventListener('click', handleCompareMenuDocumentClick)
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
    syncCompareSelection()
    stopSnapshotPolling()
    void loadSnapshots()
    void loadSummary()
  },
)

// Fenced tabs are repo-level, not ref-scoped: the ref/snapshot selector strip
// hides while one is active (ADR-024 §1).
const isFencedTabActive = computed(() => {
  if (typeof route.name !== 'string') return false
  return (
    route.name === 'repo-releases'
    || route.name === 'repo-deployments'
    || route.name === 'repo-insights'
    || route.name.startsWith('repo-settings')
  )
})

function isActiveTab(name: string) {
  if (name === 'repo-settings') {
    return typeof route.name === 'string' && route.name.startsWith('repo-settings')
  }
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

function tabCount(name: string): string | number | null {
  if (!summary.value) {
    return null
  }
  const rate = summary.value.coverage_line_rate
  const counts: Record<string, string | number | null> = {
    'repo-vulnerabilities': totalSeverity(summary.value.vulnerabilities),
    'repo-coverage': typeof rate === 'number' ? `${(rate * 100).toFixed(1)}%` : null,
    'repo-tests': summary.value.tests_total ?? null,
    'repo-dependencies': summary.value.components_total,
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

function snapshotChipPrimary(snapshot: Snapshot) {
  return snapshotLabel(snapshot)
}

function snapshotChipSecondary(snapshot: Snapshot) {
  return relativeTime(snapshot.created_at)
}

function isLatestSnapshot(snapshot: Snapshot) {
  return snapshot.id === latestSnapshot.value?.id
}

function isSelectedSnapshot(snapshot: Snapshot) {
  if (selectedSnapshotId.value) {
    return snapshot.id === selectedSnapshotId.value
  }
  return snapshot.id === latestSnapshot.value?.id
}

function isSuccessfulSnapshot(snapshot: Snapshot) {
  // Mirrors the backend's complete-set ('complete', 'active'): the violet
  // "latest" chip and the default selection point at the newest snapshot
  // whose data is actually readable, never a pending/processing one.
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
  if (snapshot.status === 'pending' || snapshot.status === 'processing') {
    // Processing = finalized upload whose SBOM/SARIF ingestion is still
    // running: same amber spinner as pending, the data is not readable yet.
    return 'snapshot-chip--pending'
  }
  if (snapshot.tag) {
    return 'snapshot-chip--release'
  }
  if (isLatestSnapshot(snapshot)) {
    return 'snapshot-chip--latest'
  }
  return 'snapshot-chip--default'
}

function hasPendingSnapshots() {
  return snapshots.value.some((snapshot) => snapshot.status === 'pending' || snapshot.status === 'processing')
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
  transform: translateY(-1px);
  box-shadow:
    0 0 0 1px rgba(255, 255, 255, 0.08),
    0 0 0 3px rgba(96, 165, 250, 0.18),
    0 14px 30px -18px rgba(15, 23, 42, 0.9);
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

.snapshot-chip--latest {
  border-color: rgb(168 85 247 / 0.45);
  background: linear-gradient(180deg, rgb(88 28 135 / 0.3), rgb(30 27 75 / 0.92));
  color: rgb(221 214 254);
}

.snapshot-chip--latest.snapshot-chip--selected {
  border-color: rgb(192 132 252 / 0.72);
  background: linear-gradient(180deg, rgb(126 34 206 / 0.34), rgb(49 46 129 / 0.96));
  color: rgb(245 243 255);
  box-shadow:
    0 0 0 1px rgba(255, 255, 255, 0.08),
    0 0 0 3px rgba(168, 85, 247, 0.22),
    0 14px 30px -18px rgba(88, 28, 135, 0.75);
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
  letter-spacing: 0.03em;
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
