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

    <ScaActionResults
      :provider="provider"
      :slug="slug"
      :results="scaResults"
      :error="scaError"
      @dismiss="dismissSca"
    />

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
        <p class="mt-2 text-xs text-gray-400">
          Enable SCA to read supported manifests and lockfiles on the default branch and match advisories.
          Subsequent pushes are monitored when automatic upkeep is enabled.
          No workflow, SBOM upload or write permission is needed. This does not start a secret scan.
        </p>
        <div
          v-if="canManage && canSelectSca"
          class="mt-3 flex flex-wrap items-center gap-3"
        >
          <button
            type="button"
            class="rounded-xl border border-accent/40 px-3 py-2 text-xs text-accent disabled:cursor-not-allowed disabled:opacity-50"
            :disabled="!scaSelectionValid(selected) || scaBusy.length > 0"
            @click="enableSca(selected)"
          >
            Enable SCA for selected repositories ({{ selected.length }}/{{ MAX_SCA_SELECTION }})
          </button>
          <span class="text-xs text-gray-500">Archived repositories cannot be selected.</span>
        </div>
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
                <input
                  v-if="canManage && scaAction(!!repo.enrolled, repo.sca, repo.components_total)"
                  v-model="selected"
                  type="checkbox"
                  :value="repo.provider_id"
                  :aria-label="`Select ${repo.name} for SCA`"
                  :disabled="!scaAction(!!repo.enrolled, repo.sca, repo.components_total) || !canEnableSca(repo.status, repo.sca) || scaBusy.length > 0 || (!selected.includes(repo.provider_id) && selected.length >= MAX_SCA_SELECTION)"
                  class="mt-1 accent-accent"
                >
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
                  <ScaStatus
                    class="mt-3"
                    :sca="repo.sca"
                    :enrolled="!!repo.enrolled"
                    :can-manage="canManage"
                    :components="repo.components_total"
                  />
                </div>
              </div>
            </div>

            <div class="flex flex-wrap gap-3 lg:justify-end">
              <button
                v-if="canManage && scaAction(!!repo.enrolled, repo.sca, repo.components_total)"
                type="button"
                class="rounded-2xl border border-accent/40 px-4 py-2.5 text-sm text-accent disabled:cursor-not-allowed disabled:opacity-50"
                :disabled="!canEnableSca(repo.status, repo.sca) || scaBusy.length > 0"
                :title="repo.status === 'archived' ? 'Archived repositories cannot enable SCA' : undefined"
                @click="enableSca([repo.provider_id])"
              >
                {{ scaBusy.includes(repo.provider_id) ? 'Requesting…' : scaAction(!!repo.enrolled, repo.sca, repo.components_total) }}
              </button>
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
import { isSafeUrl } from '@/lib/safeUrl'
import { computed, onUnmounted, ref, watch } from 'vue'
import { RouterLink, useRoute } from 'vue-router'

import { api, type Organization, type RepoLifecycleStatus, type Repository, type SyncReposResponse } from '@/api/client'
import ForgeIcon from '@/components/ForgeIcon.vue'
import ScaStatus from '@/components/ScaStatus.vue'
import ScaActionResults from '@/components/ScaActionResults.vue'
import { useScaActions, useScaPolling } from '@/composables/useScaActions'
import { MAX_SCA_SELECTION, canEnableSca, hasInventory, hasReportedFindings, scaAction, scaErrorMessage, scaPending, scaResultCoverage, scaSelectionValid } from '@/lib/sca'

const route = useRoute()
const provider = computed(() => route.params.provider as string)
const slug = computed(() => route.params.slug as string)
const repos = ref<Repository[]>([])
const org = ref<Organization | null>(null)
const loading = ref(true)
const syncing = ref(false)
const actionError = ref('')
const actionMessage = ref('')
const selected = ref<string[]>([])
const { pending: scaBusy, results: scaResults, error: scaError, enable, dismiss: dismissSca } = useScaActions(provider, slug)
let generation = 0
onUnmounted(() => { generation++ })
const scope = computed(() => `${provider.value}/${slug.value}`)
useScaPolling(scope, computed(() => repos.value.some(repo => scaPending(repo.sca))), reloadRepos, error => { scaError.value = scaErrorMessage(error) })

async function enableSca(ids: string[]) {
  if (!canManage.value) return
  const request = generation
  const eligible = ids.filter(id => repos.value.some(repo => repo.provider_id === id && scaAction(!!repo.enrolled, repo.sca, repo.components_total) && canEnableSca(repo.status, repo.sca)))
  if (eligible.length !== ids.length) return
  const results = await enable([...ids])
  if (!results) return
  for (const result of results) {
    const repo = repos.value.find(repo => repo.provider_id === result.provider_id)
    if (repo && result.status !== 'failed') {
      repo.enrolled = true
      repo.slug = result.repo_slug || repo.slug
      repo.sca = scaResultCoverage(result, repo.sca)
    }
  }
  selected.value = selected.value.filter(id => !results.some(result => result.provider_id === id && result.status !== 'failed'))
  await reloadRepos().catch(error => {
    if (request === generation) scaError.value = `Request recorded, but the latest status could not be loaded. ${scaErrorMessage(error)}`
  })
}

const canManage = computed(() => org.value?.role === 'admin')
const canSelectSca = computed(() => repos.value.some(repo => scaAction(!!repo.enrolled, repo.sca, repo.components_total) && canEnableSca(repo.status, repo.sca)))
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
    { label: 'Inventory available', value: repos.value.filter(repo => hasInventory(repo.sca, repo.components_total)).length },
    { label: 'Findings only', value: repos.value.filter(repo => !hasInventory(repo.sca, repo.components_total) && hasReportedFindings(repo.sca)).length },
    ...(repos.value.some(repo => !repo.sca && !repo.components_total) ? [{ label: 'Status unavailable', value: repos.value.filter(repo => !repo.sca && !repo.components_total).length }] : []),
  ]
})

watch(
  [provider, slug],
  async ([newProvider, newSlug]) => {
    const request = ++generation
    selected.value = []
    syncing.value = false
    repos.value = []
    org.value = null
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
      if (request !== generation) return
      repos.value = repoResponse.data
      org.value = orgResponse.data
    } catch (error) {
      if (request !== generation) return
      repos.value = []
      org.value = null
      actionError.value = error instanceof Error ? error.message : 'Failed to load repositories'
    } finally {
      if (request === generation) loading.value = false
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
  const date = repo.sca?.last_assessed || repo.last_scanned
  if (date) {
    return `Last analysis: ${new Date(date).toLocaleString()}`
  }
  if (repo.status === 'archived') {
    return 'Archived in forge inventory.'
  }
  return 'Last analysis not recorded.'
}

async function syncNow() {
  if (!canManage.value) {
    return
  }

  syncing.value = true
  const request = generation
  actionError.value = ''
  actionMessage.value = ''

  try {
    const response = await api.syncRepos(provider.value, slug.value)
    if (request !== generation) return
    await reloadRepos()
    if (request !== generation) return
    if (response.data.outcome === 'scheduled') {
      actionMessage.value = 'Reconciliation scheduled. Existing API backoff is preserved; reload after the worker finishes.'
    } else if (response.data.synced) {
      actionMessage.value = formatSyncSummary(response.data)
    } else {
      actionError.value = formatSyncOutcome(response.data.outcome)
    }
  } catch (error) {
    if (request !== generation) return
    actionError.value = error instanceof Error ? error.message : 'Failed to sync repositories'
  } finally {
    if (request === generation) syncing.value = false
  }
}

async function reloadRepos() {
  const request = generation
  const response = await api.listRepos(provider.value, slug.value)
  if (request === generation) repos.value = response.data
}

function formatSyncSummary(response: SyncReposResponse) {
  return `Sync complete. ${response.summary.active} active, ${response.summary.discovered} discovered, ${response.summary.archived} archived.`
}

function formatSyncOutcome(outcome: SyncReposResponse['outcome']) {
  switch (outcome) {
    case 'provider_not_configured':
      return 'Sync unavailable: this forge is not configured on the server.'
    case 'no_installations':
      return 'Sync found no app installations. The server has no forge App credentials, or the app is not installed anywhere.'
    case 'no_matching_installation':
      return 'No app installation covers this organization. Install the forge app on the organization, then sync again.'
    default:
      return 'Sync did not run.'
  }
}

</script>
