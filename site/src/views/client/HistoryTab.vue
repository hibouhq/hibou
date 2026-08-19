<template>
  <div>
    <!-- Deployment form (compact, matches ClientsTab create form) -->
    <section
      v-if="showDeploymentForm"
      class="mb-4 rounded-md border border-surface-border bg-surface-raised p-4"
    >
      <div class="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
        <div class="flex flex-col gap-1.5">
          <label
            class="text-xs font-medium text-gray-300"
            for="deploy-repo"
          >Repository</label>
          <select
            id="deploy-repo"
            v-model="deploymentForm.repoSlug"
            class="h-8 rounded-md border border-surface-border bg-surface-overlay px-2.5 text-sm text-gray-200 focus:border-accent/50 focus:outline-none"
          >
            <option value="">
              Select repository
            </option>
            <option
              v-for="repo in repos"
              :key="repo.id"
              :value="repo.slug"
            >
              {{ repo.name }}
            </option>
          </select>
        </div>
        <div class="flex flex-col gap-1.5">
          <label
            class="text-xs font-medium text-gray-300"
            for="deploy-release"
          >Release</label>
          <select
            id="deploy-release"
            v-model="deploymentForm.releaseId"
            :disabled="!deploymentForm.repoSlug"
            class="h-8 rounded-md border border-surface-border bg-surface-overlay px-2.5 font-mono text-sm text-gray-200 focus:border-accent/50 focus:outline-none disabled:opacity-50"
          >
            <option value="">
              Select release
            </option>
            <option
              v-for="release in releases"
              :key="release.id"
              :value="release.id"
            >
              {{ release.version }}
            </option>
          </select>
        </div>
        <div class="flex flex-col gap-1.5">
          <label
            class="text-xs font-medium text-gray-300"
            for="deploy-environment"
          >Environment</label>
          <input
            id="deploy-environment"
            v-model="deploymentForm.environment"
            class="h-8 rounded-md border border-surface-border bg-surface-overlay px-2.5 font-mono text-sm text-gray-200 focus:border-accent/50 focus:outline-none"
            type="text"
            placeholder="production"
          >
        </div>
        <div class="flex flex-col gap-1.5">
          <label
            class="text-xs font-medium text-gray-300"
            for="deploy-by"
          >Deployed by</label>
          <input
            id="deploy-by"
            v-model="deploymentForm.deployedBy"
            class="h-8 rounded-md border border-surface-border bg-surface-overlay px-2.5 text-sm text-gray-200 focus:border-accent/50 focus:outline-none"
            type="text"
          >
        </div>
        <div class="flex flex-col gap-1.5 sm:col-span-2">
          <label
            class="text-xs font-medium text-gray-300"
            for="deploy-notes"
          >Notes</label>
          <input
            id="deploy-notes"
            v-model="deploymentForm.notes"
            class="h-8 rounded-md border border-surface-border bg-surface-overlay px-2.5 text-sm text-gray-200 focus:border-accent/50 focus:outline-none"
            type="text"
          >
        </div>
        <div class="flex flex-col gap-1.5">
          <label
            class="text-xs font-medium text-gray-300"
            for="deploy-at"
          >Deployed at</label>
          <input
            id="deploy-at"
            v-model="deploymentForm.deployedAt"
            class="h-8 rounded-md border border-surface-border bg-surface-overlay px-2.5 text-sm text-gray-200 focus:border-accent/50 focus:outline-none"
            type="datetime-local"
          >
        </div>
      </div>
      <div class="mt-4 flex items-center gap-3">
        <button
          class="rounded-md bg-ok-muted px-3 py-1.5 text-sm font-medium text-white transition hover:bg-ok-muted/80 disabled:cursor-not-allowed disabled:opacity-50"
          type="button"
          :disabled="submittingDeployment"
          @click="createDeployment"
        >
          {{ submittingDeployment ? 'Deploying…' : 'Create deployment' }}
        </button>
        <p
          v-if="deploymentError"
          class="text-sm text-danger"
        >
          {{ deploymentError }}
        </p>
      </div>
    </section>

    <!-- Deployments -->
    <section>
      <div class="flex items-baseline justify-between">
        <h2 class="text-base font-semibold text-white">
          Deployments
        </h2>
        <span class="text-xs text-gray-500">Release history and rollout status</span>
      </div>

      <div
        v-if="deployments.length > 0"
        class="mt-3 flex flex-col gap-2"
      >
        <div class="flex flex-wrap items-center gap-1.5">
          <span class="mr-1 text-[11px] uppercase tracking-[0.14em] text-gray-500">Environment</span>
          <button
            v-for="option in environmentOptions"
            :key="`env-${option}`"
            type="button"
            class="rounded-full border px-2.5 py-1 text-xs font-medium transition"
            :class="environmentFilter === option
              ? 'border-accent/60 bg-accent/15 text-accent'
              : 'border-surface-border bg-surface-overlay text-gray-400 hover:border-accent/40 hover:text-gray-200'"
            @click="environmentFilter = option"
          >
            {{ option }}
          </button>
        </div>
        <div class="flex flex-wrap items-center gap-1.5">
          <span class="mr-1 text-[11px] uppercase tracking-[0.14em] text-gray-500">Status</span>
          <button
            v-for="option in STATUS_OPTIONS"
            :key="`status-${option}`"
            type="button"
            class="rounded-full border px-2.5 py-1 text-xs font-medium capitalize transition"
            :class="statusFilter === option
              ? 'border-accent/60 bg-accent/15 text-accent'
              : 'border-surface-border bg-surface-overlay text-gray-400 hover:border-accent/40 hover:text-gray-200'"
            @click="statusFilter = option"
          >
            {{ option === 'all' ? 'all' : option.replace('_', ' ') }}
          </button>
        </div>
      </div>

      <div
        v-if="deploymentsLoading"
        class="mt-3 text-sm text-gray-500"
      >
        Loading deployments…
      </div>
      <div
        v-else-if="deployments.length === 0"
        class="mt-3 rounded-md border border-dashed border-surface-border px-6 py-8 text-center"
      >
        <Rocket class="mx-auto h-7 w-7 text-gray-600" />
        <p class="mt-2 text-sm font-medium text-gray-300">
          No deployments recorded yet
        </p>
        <p class="mx-auto mt-1 max-w-md text-sm text-gray-500">
          Record one here, or assign this client to a release from a repository's Releases tab.
        </p>
      </div>
      <div
        v-else-if="filteredDeployments.length === 0"
        class="mt-3 rounded-md border border-dashed border-surface-border px-6 py-8 text-center text-sm text-gray-500"
      >
        No deployments match the current filters.
      </div>
      <div
        v-else
        class="mt-3 overflow-hidden rounded-md border border-surface-border"
      >
        <div class="overflow-x-auto">
          <table class="min-w-full divide-y divide-surface-border-subtle text-sm">
            <thead class="bg-surface-overlay text-left text-xs uppercase tracking-[0.14em] text-gray-500">
              <tr>
                <th class="px-4 py-2.5 font-medium">
                  Release
                </th>
                <th class="px-4 py-2.5 font-medium">
                  Environment
                </th>
                <th class="px-4 py-2.5 font-medium">
                  Status
                </th>
                <th class="px-4 py-2.5 font-medium">
                  Deployed
                </th>
                <th class="px-4 py-2.5 font-medium">
                  By
                </th>
                <th class="px-4 py-2.5 font-medium">
                  Notes
                </th>
              </tr>
            </thead>
            <tbody class="divide-y divide-surface-border-subtle">
              <tr
                v-for="deployment in filteredDeployments"
                :key="deployment.id"
                class="transition hover:bg-surface-overlay/50"
              >
                <td class="px-4 py-2.5 font-mono text-xs text-gray-200">
                  {{ deployment.release_version || deployment.release_id }}
                </td>
                <td class="px-4 py-2.5">
                  <span class="rounded-full bg-surface-overlay px-2 py-0.5 font-mono text-[11px] text-gray-300">{{ deployment.environment }}</span>
                </td>
                <td class="px-4 py-2.5">
                  <span
                    :class="statusClass(deployment.status)"
                    class="rounded-full border px-2 py-0.5 text-[11px] font-medium capitalize"
                  >
                    {{ deployment.status.replace('_', ' ') }}
                  </span>
                </td>
                <td
                  class="px-4 py-2.5 text-gray-400"
                  :title="formatDateTime(deployment.deployed_at)"
                >
                  {{ relativeTime(deployment.deployed_at) }}
                </td>
                <td class="px-4 py-2.5 text-gray-300">
                  {{ deployment.deployed_by || 'System' }}
                </td>
                <td class="max-w-xs truncate px-4 py-2.5 text-xs text-gray-500">
                  {{ deployment.notes || '—' }}
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
    </section>
  </div>
</template>

<script setup lang="ts">
import { Rocket } from 'lucide-vue-next'
import { computed, inject, reactive, ref, watch, type Ref } from 'vue'
import { useRoute } from 'vue-router'

import { api, type Deployment, type Release, type Repository } from '@/api/client'
import { formatDateTime, relativeTime } from '@/lib/datetime'

const route = useRoute()

const deployments = inject<Ref<Deployment[]>>('clientDeployments', ref([]))
const repos = inject<Ref<Repository[]>>('clientRepos', ref([]))
const deploymentsLoading = inject<Ref<boolean>>('clientDeploymentsLoading', ref(false))
const showDeploymentForm = inject<Ref<boolean>>('showDeploymentForm', ref(false))
const reloadClientDetail = inject<() => Promise<void>>('reloadClientDetail', async () => {})

const provider = computed(() => route.params.provider as string)
const slug = computed(() => route.params.slug as string)
const clientSlug = computed(() => route.params.clientSlug as string)

const releases = ref<Release[]>([])
const submittingDeployment = ref(false)
const deploymentError = ref('')

// datetime-local semantics are LOCAL wall-clock time; toISOString() is UTC.
// Shift by the timezone offset so the prefill shows the user's current time
// and round-trips through `new Date(value)` (which parses as local) intact.
function localDatetimeValue(date = new Date()) {
  return new Date(date.getTime() - date.getTimezoneOffset() * 60_000).toISOString().slice(0, 16)
}

const deploymentForm = reactive({
  repoSlug: '',
  releaseId: '',
  environment: '',
  deployedBy: '',
  notes: '',
  deployedAt: localDatetimeValue(),
})

const STATUS_OPTIONS = ['all', 'active', 'superseded', 'rolled_back'] as const

const environmentFilter = ref('all')
const statusFilter = ref<string>('all')

const environmentOptions = computed(() => [
  'all',
  ...[...new Set(deployments.value.map((deployment) => deployment.environment))].sort(),
])

const filteredDeployments = computed(() =>
  deployments.value
    .filter((deployment) => {
      if (environmentFilter.value !== 'all' && deployment.environment !== environmentFilter.value) return false
      if (statusFilter.value !== 'all' && deployment.status.toLowerCase() !== statusFilter.value) return false
      return true
    })
    .sort((a, b) => new Date(b.deployed_at).getTime() - new Date(a.deployed_at).getTime()),
)

// Reset the environment filter if the selected environment disappears after a reload.
watch(environmentOptions, (options) => {
  if (!options.includes(environmentFilter.value)) {
    environmentFilter.value = 'all'
  }
})

watch(
  () => deploymentForm.repoSlug,
  async (repoSlug) => {
    deploymentForm.releaseId = ''
    releases.value = []
    if (!repoSlug) {
      deploymentError.value = ''
      return
    }
    deploymentError.value = ''
    try {
      const response = await api.listReleases(provider.value, slug.value, repoSlug, { per_page: 100 })
      releases.value = response.data
    } catch (loadError) {
      releases.value = []
      deploymentError.value = loadError instanceof Error ? loadError.message : 'Failed to load releases'
    }
  },
)

async function createDeployment() {
  deploymentError.value = ''

  const releaseId = deploymentForm.releaseId.trim()
  const environment = deploymentForm.environment.trim()
  if (!releaseId || !environment) {
    deploymentError.value = 'Release and environment are required'
    return
  }

  submittingDeployment.value = true
  try {
    await api.createDeployment(provider.value, slug.value, clientSlug.value, {
      release_id: releaseId,
      environment,
      deployed_by: deploymentForm.deployedBy.trim() || undefined,
      notes: deploymentForm.notes.trim() || undefined,
      deployed_at: deploymentForm.deployedAt ? new Date(deploymentForm.deployedAt).toISOString() : undefined,
    })

    showDeploymentForm.value = false
    deploymentForm.releaseId = ''
    deploymentForm.notes = ''
    deploymentForm.deployedBy = ''
    await reloadClientDetail()
  } catch (error) {
    deploymentError.value = error instanceof Error ? error.message : 'Failed to create deployment'
  } finally {
    submittingDeployment.value = false
  }
}

function statusClass(status: string) {
  switch (status.toLowerCase()) {
    case 'active':
      return 'border-ok/40 text-ok'
    case 'rolled_back':
      return 'border-warning/40 text-warning'
    case 'superseded':
      return 'border-surface-border text-gray-400'
    default:
      return 'border-surface-border text-gray-300'
  }
}
</script>
