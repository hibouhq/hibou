<template>
  <section class="space-y-6">
    <div class="rounded-3xl border border-surface-border bg-surface-raised p-6 shadow-[0_24px_80px_-48px_rgba(0,0,0,0.9)]">
      <div v-if="loading" class="text-sm text-gray-500">
        Loading client details...
      </div>

      <template v-else>
        <div v-if="error" class="rounded-2xl border border-danger/30 bg-danger/10 px-4 py-3 text-sm text-red-200">
          {{ error }}
        </div>

        <div v-if="client" :class="['space-y-6', error ? 'mt-6' : '']">
          <div class="flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
            <div>
              <p class="text-xs uppercase tracking-[0.2em] text-gray-500">Client</p>
              <h1 class="mt-2 text-3xl font-semibold tracking-tight text-white">
                {{ client.name }}
              </h1>
              <div class="mt-3 flex flex-wrap items-center gap-3">
                <span :class="clientTypeClass(client.client_type)" class="rounded-full px-3 py-1 text-xs font-medium uppercase tracking-[0.16em]">
                  {{ client.client_type }}
                </span>
                <span :class="activeVersionBadgeClass" class="rounded-full px-4 py-1.5 text-sm font-medium tracking-[0.08em]">
                  {{ activeVersion ? `Active ${activeVersion}` : 'No active version' }}
                </span>
              </div>
              <div class="mt-3 flex flex-wrap items-center gap-3 text-sm text-gray-400">
                <span>{{ client.contact_name || 'No contact owner' }}</span>
                <span>{{ client.contact_email || 'No contact email' }}</span>
              </div>
              <div class="mt-4 flex flex-wrap gap-2">
                <template v-if="clientLabelEntries(client).length > 0">
                  <span
                    v-for="[key, value] in clientLabelEntries(client)"
                    :key="`header-${key}`"
                    class="inline-flex max-w-full items-center gap-2 rounded-full border border-surface-border bg-surface-overlay px-3 py-1.5 text-sm text-gray-300"
                  >
                    <span class="font-medium text-gray-100">{{ key }}:</span>
                    <a
                      v-if="isSafeUrl(value)"
                      :href="value"
                      class="truncate text-accent transition hover:text-white hover:underline"
                      target="_blank"
                      rel="noreferrer"
                    >
                      {{ value }}
                    </a>
                    <span
                      v-else
                      class="truncate"
                    >
                      {{ value }}
                    </span>
                  </span>
                </template>
                <p v-else class="text-sm text-gray-500">No labels configured for this client.</p>
              </div>
            </div>

            <button
              class="inline-flex items-center justify-center rounded-2xl border border-surface-border bg-surface-overlay px-4 py-2.5 text-sm text-gray-300 transition hover:border-accent/50 hover:text-white"
              type="button"
              @click="showDeploymentForm = !showDeploymentForm"
            >
              {{ showDeploymentForm ? 'Cancel' : 'New Deployment' }}
            </button>
          </div>

          <section v-if="showDeploymentForm" class="rounded-3xl border border-surface-border-subtle bg-surface-overlay/70 p-5">
            <div class="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
              <label class="space-y-2 text-sm text-gray-300">
                <span class="block text-xs uppercase tracking-[0.2em] text-gray-500">Repository</span>
                <select v-model="deploymentForm.repoSlug" class="w-full rounded-2xl border border-surface-border bg-surface-overlay px-4 py-3 text-sm text-gray-100">
                  <option value="">Select repository</option>
                  <option v-for="repo in repos" :key="repo.id" :value="repo.slug">{{ repo.name }}</option>
                </select>
              </label>

              <label class="space-y-2 text-sm text-gray-300">
                <span class="block text-xs uppercase tracking-[0.2em] text-gray-500">Release</span>
                <select v-model="deploymentForm.releaseId" class="w-full rounded-2xl border border-surface-border bg-surface-overlay px-4 py-3 text-sm text-gray-100">
                  <option value="">Select release</option>
                  <option v-for="release in releases" :key="release.id" :value="release.id">{{ release.version }}</option>
                </select>
              </label>

              <label class="space-y-2 text-sm text-gray-300">
                <span class="block text-xs uppercase tracking-[0.2em] text-gray-500">Environment</span>
                <input v-model="deploymentForm.environment" class="w-full rounded-2xl border border-surface-border bg-surface-overlay px-4 py-3 text-sm text-gray-100" type="text">
              </label>

              <label class="space-y-2 text-sm text-gray-300">
                <span class="block text-xs uppercase tracking-[0.2em] text-gray-500">Deployed By</span>
                <input v-model="deploymentForm.deployedBy" class="w-full rounded-2xl border border-surface-border bg-surface-overlay px-4 py-3 text-sm text-gray-100" type="text">
              </label>
            </div>

            <div class="mt-4 grid gap-4 md:grid-cols-[minmax(0,1fr)_220px_auto]">
              <label class="space-y-2 text-sm text-gray-300">
                <span class="block text-xs uppercase tracking-[0.2em] text-gray-500">Notes</span>
                <input v-model="deploymentForm.notes" class="w-full rounded-2xl border border-surface-border bg-surface-overlay px-4 py-3 text-sm text-gray-100" type="text">
              </label>

              <label class="space-y-2 text-sm text-gray-300">
                <span class="block text-xs uppercase tracking-[0.2em] text-gray-500">Deployed At</span>
                <input v-model="deploymentForm.deployedAt" class="w-full rounded-2xl border border-surface-border bg-surface-overlay px-4 py-3 text-sm text-gray-100" type="datetime-local">
              </label>

              <button
                class="mt-auto rounded-2xl border border-accent/30 bg-accent-muted px-5 py-3 text-sm font-medium text-accent transition hover:border-accent/50 hover:text-white disabled:cursor-not-allowed disabled:opacity-50"
                type="button"
                :disabled="submittingDeployment"
                @click="createDeployment"
              >
                {{ submittingDeployment ? 'Deploying...' : 'Create Deployment' }}
              </button>
            </div>

            <p v-if="deploymentError" class="mt-3 text-sm text-danger">{{ deploymentError }}</p>
          </section>

          <section class="grid gap-4 md:grid-cols-2">
            <div class="rounded-2xl border border-surface-border-subtle bg-surface-overlay/70 p-4">
              <p class="text-xs uppercase tracking-[0.2em] text-gray-500">Labels</p>
              <div
                v-if="clientLabelEntries(client).length > 0"
                class="mt-3 space-y-2 text-sm text-gray-300"
              >
                <div
                  v-for="[key, value] in clientLabelEntries(client)"
                  :key="`card-${key}`"
                  class="flex flex-wrap items-start gap-2"
                >
                  <span class="font-medium text-gray-100">{{ key }}:</span>
                  <a
                    v-if="isSafeUrl(value)"
                    :href="value"
                    class="break-all text-accent transition hover:text-white hover:underline"
                    target="_blank"
                    rel="noreferrer"
                  >
                    {{ value }}
                  </a>
                  <span
                    v-else
                    class="break-all"
                  >
                    {{ value }}
                  </span>
                </div>
              </div>
              <div
                v-else
                class="mt-2 text-sm text-gray-500"
              >
                No labels
              </div>
            </div>
            <div class="rounded-2xl border border-surface-border-subtle bg-surface-overlay/70 p-4">
              <p class="text-xs uppercase tracking-[0.2em] text-gray-500">Client Type</p>
              <div class="mt-2">
                <span :class="clientTypeClass(client.client_type)" class="rounded-full px-3 py-1 text-xs font-medium uppercase tracking-[0.16em]">
                  {{ client.client_type }}
                </span>
              </div>
            </div>
          </section>
        </div>

        <div v-else-if="!error" class="text-sm text-gray-500">
          Client not found.
        </div>
      </template>
    </div>

    <section class="rounded-3xl border border-surface-border bg-surface-raised p-6">
      <div>
        <h2 class="text-xl font-semibold text-white">Impact Analysis</h2>
        <p class="mt-2 text-sm text-gray-400">
          Vulnerabilities currently affecting this client's active deployments.
        </p>
      </div>

      <div class="mt-6 overflow-hidden rounded-2xl border border-surface-border-subtle">
        <div v-if="impactLoading" class="px-4 py-10 text-sm text-gray-500">
          Loading impact analysis...
        </div>
        <div v-else-if="impact.length === 0" class="px-4 py-10 text-sm text-gray-500">
          No active-deployment vulnerabilities found for this client.
        </div>
        <div v-else class="overflow-x-auto">
          <table class="min-w-full divide-y divide-surface-border-subtle text-sm">
            <thead class="bg-surface-overlay text-left text-xs uppercase tracking-[0.18em] text-gray-500">
              <tr>
                <th class="px-4 py-3 font-medium">Severity</th>
                <th class="px-4 py-3 font-medium">Canonical ID</th>
                <th class="px-4 py-3 font-medium">Component</th>
                <th class="px-4 py-3 font-medium">Release</th>
              </tr>
            </thead>
            <tbody class="divide-y divide-surface-border-subtle">
              <tr v-for="item in impact" :key="`${item.canonical_id}-${item.component_name}-${item.release_version}`" class="transition hover:bg-white/5">
                <td class="px-4 py-4">
                  <span :class="['rounded-full px-2.5 py-1 text-xs font-medium', severityClass(item.severity)]">{{ item.severity }}</span>
                </td>
                <td class="px-4 py-4 font-mono text-xs text-accent">{{ item.canonical_id }}</td>
                <td class="px-4 py-4 text-gray-300">{{ item.component_name }}</td>
                <td class="px-4 py-4 text-gray-300">{{ item.release_version }}</td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
    </section>

    <section class="rounded-3xl border border-surface-border bg-surface-raised p-6">
      <div>
        <h2 class="text-xl font-semibold text-white">Deployments</h2>
        <p class="mt-2 text-sm text-gray-400">
          Release history and rollout status for this client.
        </p>
      </div>

      <div class="mt-6 overflow-hidden rounded-2xl border border-surface-border-subtle">
        <div v-if="deploymentsLoading" class="px-4 py-10 text-sm text-gray-500">
          Loading deployments...
        </div>
        <div v-else-if="deployments.length === 0" class="px-4 py-10 text-sm text-gray-500">
          No deployments recorded yet.
        </div>
        <div v-else class="overflow-x-auto">
          <table class="min-w-full divide-y divide-surface-border-subtle text-sm">
            <thead class="bg-surface-overlay text-left text-xs uppercase tracking-[0.18em] text-gray-500">
              <tr>
                <th class="px-4 py-3 font-medium">Release</th>
                <th class="px-4 py-3 font-medium">Environment</th>
                <th class="px-4 py-3 font-medium">Status</th>
                <th class="px-4 py-3 font-medium">Date</th>
                <th class="px-4 py-3 font-medium">Deployed By</th>
              </tr>
            </thead>
            <tbody class="divide-y divide-surface-border-subtle">
              <tr v-for="deployment in deployments" :key="deployment.id" class="transition hover:bg-white/5">
                <td class="px-4 py-4 text-gray-300">{{ deployment.release_version || deployment.release_id }}</td>
                <td class="px-4 py-4 text-gray-300">{{ deployment.environment }}</td>
                <td class="px-4 py-4">
                  <span :class="statusClass(deployment.status)" class="rounded-full px-2.5 py-1 text-xs font-medium uppercase tracking-[0.14em]">
                    {{ deployment.status }}
                  </span>
                </td>
                <td class="px-4 py-4 text-gray-400">{{ formatDate(deployment.deployed_at) }}</td>
                <td class="px-4 py-4 text-gray-300">{{ deployment.deployed_by || 'System' }}</td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
    </section>
  </section>
</template>

<script setup lang="ts">
import { computed, reactive, ref, watch } from 'vue'
import { useRoute } from 'vue-router'

import { api, type Client, type Deployment, type Release, type Repository } from '@/api/client'

const route = useRoute()

const client = ref<Client | null>(null)
const deployments = ref<Deployment[]>([])
const impact = ref<Array<{ canonical_id: string; severity: string; component_name: string; release_version: string }>>([])
const repos = ref<Repository[]>([])
const releases = ref<Release[]>([])
const loading = ref(true)
const deploymentsLoading = ref(true)
const impactLoading = ref(true)
const error = ref('')
const showDeploymentForm = ref(false)
const submittingDeployment = ref(false)
const deploymentError = ref('')
const deploymentForm = reactive({
  repoSlug: '',
  releaseId: '',
  environment: '',
  deployedBy: '',
  notes: '',
  deployedAt: new Date().toISOString().slice(0, 16),
})

const provider = computed(() => route.params.provider as string)
const slug = computed(() => route.params.slug as string)
const clientSlug = computed(() => route.params.clientSlug as string)
const activeDeployment = computed(
  () =>
    deployments.value.find(
      (deployment) =>
        deployment.status.toLowerCase() === 'active',
    ) ?? null,
)
const activeVersion = computed(() => activeDeployment.value?.release_version || null)
const activeVersionBadgeClass = computed(() =>
  activeVersion.value ? 'bg-emerald-500/15 text-emerald-300' : 'bg-white/5 text-gray-400',
)

watch(
  () => [provider.value, slug.value, clientSlug.value],
  () => {
    void loadClientDetail()
  },
  { immediate: true },
)

watch(
  () => deploymentForm.repoSlug,
  async (repoSlug) => {
    deploymentForm.releaseId = ''
    releases.value = []
    if (!repoSlug) {
      error.value = ''
      return
    }
    error.value = ''
    try {
      const response = await api.listReleases(provider.value, slug.value, repoSlug, { per_page: 100 })
      releases.value = response.data
    } catch (loadError) {
      releases.value = []
      error.value = loadError instanceof Error ? loadError.message : 'Failed to load releases'
    }
  },
)

async function loadClientDetail() {
  loading.value = true
  deploymentsLoading.value = true
  impactLoading.value = true
  error.value = ''

  try {
    const [clientResponse, deploymentsResponse, impactResponse, reposResponse] = await Promise.all([
      api.getClient(provider.value, slug.value, clientSlug.value),
      api.listClientDeployments(provider.value, slug.value, clientSlug.value, { per_page: 100 }),
      api.getClientImpact(provider.value, slug.value, clientSlug.value),
      api.listRepos(provider.value, slug.value),
    ])

    client.value = clientResponse.data
    deployments.value = deploymentsResponse.data
    impact.value = impactResponse.data.vulnerabilities
    repos.value = reposResponse.data
  } catch (loadError) {
    client.value = null
    deployments.value = []
    impact.value = []
    repos.value = []
    error.value = loadError instanceof Error ? loadError.message : 'Failed to load client details'
  } finally {
    loading.value = false
    deploymentsLoading.value = false
    impactLoading.value = false
  }
}

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
    await loadClientDetail()
  } catch (error) {
    deploymentError.value = error instanceof Error ? error.message : 'Failed to create deployment'
  } finally {
    submittingDeployment.value = false
  }
}

function formatDate(value?: string) {
  if (!value) {
    return 'N/A'
  }
  return new Date(value).toLocaleString()
}

function isSafeUrl(url: string) {
  return /^https?:\/\//i.test(url.trim())
}

function clientLabelEntries(currentClient: Client) {
  return Object.entries(currentClient.labels || {})
}

function severityClass(level: string) {
  return `sev-${level.toLowerCase()}`
}

function statusClass(status: string) {
  switch (status.toLowerCase()) {
    case 'active':
      return 'bg-emerald-500/10 text-emerald-300'
    case 'rolled_back':
      return 'bg-warning/15 text-warning'
    case 'superseded':
      return 'bg-white/5 text-gray-400'
    default:
      return 'bg-white/5 text-gray-300'
  }
}

function clientTypeClass(clientType: string) {
  return clientType === 'internal' ? 'bg-amber-500/10 text-amber-300' : 'bg-sky-500/10 text-sky-300'
}
</script>
