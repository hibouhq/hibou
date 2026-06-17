<template>
  <div class="space-y-6">
    <section class="rounded-3xl border border-surface-border bg-surface-raised p-6 shadow-[0_24px_80px_-48px_rgba(0,0,0,0.9)]">
      <div class="flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
        <div>
          <h1 class="text-3xl font-semibold tracking-tight text-white">
            Repositories
          </h1>
          <p class="mt-2 text-sm text-gray-400">
            Inventory-backed lifecycle and scan recency for every repository this organization can see.
          </p>
        </div>

        <button
          v-if="canManage"
          class="inline-flex items-center justify-center rounded-2xl border border-surface-border bg-surface-overlay px-4 py-2.5 text-sm text-gray-300 transition hover:border-accent/50 hover:text-white disabled:cursor-not-allowed disabled:opacity-60"
          type="button"
          :disabled="syncing"
          @click="syncNow"
        >
          {{ syncing ? 'Syncing...' : 'Sync now' }}
        </button>
      </div>

      <div class="mt-6 grid gap-4 md:grid-cols-2 xl:grid-cols-5">
        <article
          v-for="item in summaryCards"
          :key="item.label"
          class="rounded-2xl border border-surface-border-subtle bg-surface-overlay p-4"
        >
          <div class="text-xs uppercase tracking-[0.2em] text-gray-500">
            {{ item.label }}
          </div>
          <div class="mt-3 text-3xl font-semibold text-white">
            {{ item.value }}
          </div>
        </article>
      </div>
    </section>

    <section
      v-if="actionError"
      class="rounded-2xl border border-danger/30 bg-danger/10 px-4 py-3 text-sm text-red-200"
    >
      {{ actionError }}
    </section>

    <section
      v-if="actionMessage"
      class="rounded-2xl border border-emerald-500/30 bg-emerald-500/10 px-4 py-3 text-sm text-emerald-100"
    >
      {{ actionMessage }}
    </section>

    <section
      v-if="loading"
      class="rounded-3xl border border-surface-border bg-surface-raised px-6 py-10 text-sm text-gray-500"
    >
      Loading repositories...
    </section>

    <section
      v-else-if="repos.length === 0"
      class="rounded-3xl border border-surface-border bg-surface-raised px-6 py-10 text-sm text-gray-400"
    >
      {{ emptyStateMessage }}
    </section>

    <section
      v-else
      class="overflow-hidden rounded-3xl border border-surface-border bg-surface-raised"
    >
      <div class="border-b border-surface-border-subtle px-6 py-4">
        <h2 class="text-lg font-semibold text-white">
          Accessible repositories
        </h2>
        <p class="mt-1 text-sm text-gray-400">
          Lifecycle badge reflects forge state. Scan recency is shown separately.
        </p>
      </div>

      <ul class="divide-y divide-surface-border-subtle">
        <li
          v-for="repo in repos"
          :key="repoKey(repo)"
          class="px-6 py-5"
        >
          <div class="flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
            <div class="min-w-0 flex-1">
              <div class="flex items-start gap-3">
                <div class="min-w-0 flex-1">
                  <div class="flex flex-wrap items-center gap-2">
                    <ForgeIcon
                      :provider="repo.provider"
                      size="sm"
                      class="mt-0.5 text-gray-400"
                    />
                    <RouterLink
                      v-if="repo.enrolled && repo.slug"
                      :to="`/orgs/${provider}/${slug}/repos/${repo.slug}`"
                      class="truncate text-lg font-medium text-white transition hover:text-accent"
                    >
                      {{ repo.name }}
                    </RouterLink>
                    <span
                      v-else
                      class="truncate text-lg font-medium text-white"
                    >
                      {{ repo.name }}
                    </span>
                    <span
                      :class="statusClass(repo.status)"
                      class="rounded-full border px-2.5 py-1 text-xs font-medium"
                      :aria-label="`${repo.name} is ${statusLabel(repo.status)}`"
                    >
                      {{ statusLabel(repo.status) }}
                    </span>
                    <span class="rounded-full border border-surface-border-subtle bg-surface-overlay px-2.5 py-1 text-xs font-medium text-gray-400">
                      {{ repo.private ? 'Private' : 'Public' }}
                    </span>
                  </div>

                  <div class="mt-1 truncate text-sm text-gray-400">
                    {{ repo.full_name || repo.provider_id }}
                  </div>

                  <div class="mt-3 flex flex-wrap gap-2 text-xs uppercase tracking-[0.16em] text-gray-500">
                    <span class="rounded-full border border-surface-border-subtle bg-surface-overlay px-2.5 py-1">
                      {{ repo.default_branch || 'main' }}
                    </span>
                    <span
                      v-if="repo.outdated"
                      class="rounded-full border border-amber-500/30 bg-amber-500/10 px-2.5 py-1 text-amber-200"
                    >
                      Out of date
                    </span>
                  </div>

                  <p class="mt-3 text-sm text-gray-500">
                    {{ lastScanLabel(repo) }}
                  </p>
                </div>
              </div>
            </div>

            <div class="flex flex-wrap gap-3 lg:justify-end">
              <a
                v-if="repo.html_url && isSafeUrl(repo.html_url)"
                :href="repo.html_url"
                target="_blank"
                rel="noreferrer"
                class="inline-flex items-center justify-center rounded-2xl border border-surface-border bg-surface-overlay px-4 py-2.5 text-sm text-gray-300 transition hover:border-accent/50 hover:text-white"
              >
                Open forge
              </a>
            </div>
          </div>
        </li>
      </ul>
    </section>
  </div>
</template>

<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { RouterLink, useRoute } from 'vue-router'

import { api, type Organization, type RepoLifecycleStatus, type Repository, type SyncReposResponse } from '@/api/client'
import ForgeIcon from '@/components/ForgeIcon.vue'

const route = useRoute()
const provider = computed(() => route.params.provider as string)
const slug = computed(() => route.params.slug as string)
const repos = ref<Repository[]>([])
const org = ref<Organization | null>(null)
const loading = ref(true)
const syncing = ref(false)
const actionError = ref('')
const actionMessage = ref('')

const canManage = computed(() => org.value?.role === 'admin')
const emptyStateMessage = computed(() => (
  canManage.value
    ? 'No repositories discovered yet - install the App or click Sync now.'
    : 'No repositories discovered yet. Ask an org admin to install the App or run a sync.'
))
const summaryCards = computed(() => {
  const counts = countStatuses(repos.value)
  return [
    { label: 'Accessible', value: repos.value.length },
    { label: 'Discovered', value: counts.discovered },
    { label: 'Active', value: counts.active },
    { label: 'Archived', value: counts.archived },
    { label: 'Out of date', value: counts.outdated },
  ]
})

watch(
  [provider, slug],
  async ([newProvider, newSlug]) => {
    if (!newProvider || !newSlug) {
      repos.value = []
      org.value = null
      return
    }

    loading.value = true
    actionError.value = ''
    actionMessage.value = ''

    try {
      const [repoResponse, orgResponse] = await Promise.all([
        api.listRepos(newProvider, newSlug),
        api.getOrg(newProvider, newSlug),
      ])
      repos.value = repoResponse.data
      org.value = orgResponse.data
    } catch (error) {
      repos.value = []
      org.value = null
      actionError.value = error instanceof Error ? error.message : 'Failed to load repositories'
    } finally {
      loading.value = false
    }
  },
  { immediate: true },
)

function repoKey(repo: Repository) {
  return repo.id || repo.provider_id || repo.full_name || repo.name
}

function countStatuses(items: Repository[]) {
  const counts = { discovered: 0, active: 0, archived: 0, deleted: 0, outdated: 0 }
  for (const repo of items) {
    if (repo.status) {
      counts[repo.status] += 1
    }
    if (repo.outdated) {
      counts.outdated += 1
    }
  }
  return counts
}

function statusLabel(status?: RepoLifecycleStatus) {
  switch (status) {
    case 'active':
      return 'Active'
    case 'archived':
      return 'Archived'
    case 'deleted':
      return 'Deleted'
    case 'discovered':
      return 'Discovered'
    default:
      return 'Unknown'
  }
}

function statusClass(status?: RepoLifecycleStatus) {
  switch (status) {
    case 'active':
      return 'border-emerald-500/30 bg-emerald-500/10 text-emerald-200'
    case 'archived':
      return 'border-gray-500/30 bg-white/5 text-gray-300'
    case 'deleted':
      return 'border-rose-500/30 bg-rose-500/10 text-rose-200'
    case 'discovered':
    default:
      return 'border-blue-500/30 bg-blue-500/10 text-blue-200'
  }
}

function lastScanLabel(repo: Repository) {
  if (repo.last_scanned) {
    return `Last scanned: ${new Date(repo.last_scanned).toLocaleString()}`
  }
  if (repo.status === 'archived') {
    return 'Archived in forge inventory.'
  }
  return 'Never'
}

async function syncNow() {
  if (!canManage.value) {
    return
  }

  syncing.value = true
  actionError.value = ''
  actionMessage.value = ''

  try {
    const response = await api.syncRepos(provider.value, slug.value)
    await reloadRepos()
    actionMessage.value = formatSyncSummary(response.data)
  } catch (error) {
    actionError.value = error instanceof Error ? error.message : 'Failed to sync repositories'
  } finally {
    syncing.value = false
  }
}

async function reloadRepos() {
  const response = await api.listRepos(provider.value, slug.value)
  repos.value = response.data
}

function formatSyncSummary(response: SyncReposResponse) {
  return `Sync complete. ${response.summary.active} active, ${response.summary.discovered} discovered, ${response.summary.archived} archived.`
}

function isSafeUrl(url: string) {
  return /^(https?:)?\/\//i.test(url.trim())
}
</script>
