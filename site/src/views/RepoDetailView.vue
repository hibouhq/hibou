<template>
  <div>
    <div
      v-if="loading"
      class="px-5 py-8 text-sm text-gray-500"
    >
      Loading repository details...
    </div>

    <template v-else-if="repo">
      <div class="flex items-center justify-between gap-3 px-4 pt-4">
        <div class="min-w-0 sm:min-w-[280px]">
          <BranchPRSelector
            :refs="refs"
            :selected-ref-name="selectedRefName"
            :default-branch="repo.default_branch"
            :loading="loading"
            @select="selectRef"
          />
        </div>
        <RouterLink
          v-if="selectedPRNumber"
          class="inline-flex items-center justify-center rounded-xl border border-surface-border bg-surface-overlay px-3 py-1.5 text-xs text-gray-300 transition hover:border-accent/50 hover:text-white"
          :to="{ name: 'pr-review', params: { ...route.params, number: selectedPRNumber }, query: { ref: selectedRefName } }"
        >
          View PR Review
        </RouterLink>
      </div>

      <div class="mt-4 border-b border-surface-border-subtle px-4">
        <nav class="flex gap-1 overflow-x-auto">
          <RouterLink
            v-for="tab in tabs"
            :key="tab.name"
            :to="tab.to"
            class="flex items-center gap-1.5 border-b-2 px-3 pb-2.5 pt-1 text-[13px] font-medium transition"
            :class="isActiveTab(tab.name) ? 'border-accent text-accent' : 'border-transparent text-gray-400 hover:text-gray-200'"
          >
            {{ tab.label }}
            <span
              v-if="tabCount(tab.name) !== null"
              class="inline-flex min-w-[1.25rem] items-center justify-center rounded-full bg-surface-overlay px-1.5 text-[10px] leading-[18px]"
              :class="isActiveTab(tab.name) ? 'text-accent' : 'text-gray-500'"
            >
              {{ tabCount(tab.name) }}
            </span>
          </RouterLink>
        </nav>
      </div>

      <div
        v-if="snapshots.length > 0 || snapshotsLoading"
        class="flex items-center gap-2 overflow-x-auto border-b border-surface-border-subtle px-4 py-2"
      >
        <span class="shrink-0 text-[11px] uppercase tracking-[0.14em] text-gray-500">Snapshot</span>
        <button
          class="shrink-0 rounded-full border px-2.5 py-1 text-[11px] font-medium transition"
          :class="!selectedSnapshotId ? 'border-accent/50 bg-accent-muted text-accent' : 'border-surface-border text-gray-400 hover:text-white'"
          type="button"
          @click="selectSnapshot()"
        >
          Latest
        </button>
        <button
          v-for="snapshot in snapshots.slice(0, 6)"
          :key="snapshot.id"
          class="shrink-0 rounded-full border px-2.5 py-1 text-[11px] transition"
          :class="snapshot.id === selectedSnapshotId ? 'border-accent/50 bg-accent-muted text-accent' : 'border-surface-border text-gray-300 hover:text-white'"
          type="button"
          @click="selectSnapshot(snapshot.id)"
        >
          {{ snapshotLabel(snapshot) }}
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
import { computed, onMounted, provide, ref, watch } from 'vue'
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

const forgeUrl = computed(() => orgStore.currentOrg?.forge_url || '')
const repoProviderID = computed(() => repo.value?.provider_id || '')
provide('forgeUrl', forgeUrl)
provide('repoProviderID', repoProviderID)

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
    { label: 'Overview', name: 'repo-overview', to: { name: 'repo-overview', params: route.params, query } },
    { label: 'Weaknesses', name: 'repo-weaknesses', to: { name: 'repo-weaknesses', params: route.params, query } },
    { label: 'Dependencies', name: 'repo-dependencies', to: { name: 'repo-dependencies', params: route.params, query } },
    { label: 'Trends', name: 'repo-trends', to: { name: 'repo-trends', params: route.params, query } },
    { label: 'Malware', name: 'repo-malware', to: { name: 'repo-malware', params: route.params, query } },
    { label: 'Runtime', name: 'repo-runtime', to: { name: 'repo-runtime', params: route.params, query } },
    { label: 'Secrets', name: 'repo-secrets', to: { name: 'repo-secrets', params: route.params, query } },
  ]
})

const prevParams = ref({ provider: '', slug: '', repoSlug: '' })

onMounted(() => {
  prevParams.value = { provider: provider.value, slug: orgSlug.value, repoSlug: repoSlug.value }
  if (orgStore.orgs.length === 0) {
    void orgStore.fetchOrgs()
  }
  void loadRepoShell()
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
    prevParams.value = { provider: pStr, slug: sStr, repoSlug: rStr }
    void loadRepoShell()
  },
)

watch(
  () => selectedRefName.value,
  () => {
    void loadSnapshots()
    void loadSummary()
  },
)

function isActiveTab(name: string) {
  return route.name === name
}

async function loadRepoShell() {
  loading.value = true

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
    snapshots.value = []
    return
  }

  snapshotsLoading.value = true
  try {
    const response = await api.listSnapshots(provider.value, orgSlug.value, repoSlug.value, {
      ref: selectedRefName.value,
      per_page: 12,
    })
    snapshots.value = response.data
  } catch {
    snapshots.value = []
  } finally {
    snapshotsLoading.value = false
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
    'repo-weaknesses': summary.value ? totalSeverity(summary.value.findings) : null,
    'repo-dependencies': summary.value ? summary.value.components_total : null,
    'repo-malware': summary.value ? 0 : null,
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
  if (snapshot.label) {
    return snapshot.label
  }

  return `${snapshot.commit_sha.slice(0, 7)} - ${relativeTime(snapshot.created_at)}`
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
