<template>
  <div class="pb-8">
    <div
      v-if="loading"
      class="py-8 text-sm text-gray-500"
    >
      Loading client details…
    </div>

    <template v-else>
      <div
        v-if="error"
        class="rounded-md border border-danger/30 bg-danger/10 px-4 py-3 text-sm text-red-200"
      >
        {{ error }}
      </div>

      <template v-if="client">
        <!-- Header (GitHub-style, matches repo/org detail) -->
        <div class="flex flex-wrap items-start justify-between gap-3 pt-1">
          <div class="min-w-0">
            <h1 class="flex flex-wrap items-center gap-x-2 gap-y-1 text-xl">
              <Building2 class="h-5 w-5 shrink-0 text-gray-500" />
              <RouterLink
                :to="`/orgs/${provider}/${slug}`"
                class="text-accent transition hover:underline"
              >
                {{ slug }}
              </RouterLink>
              <span class="text-gray-600">/</span>
              <RouterLink
                :to="`/orgs/${provider}/${slug}/clients`"
                class="text-accent transition hover:underline"
              >
                clients
              </RouterLink>
              <span class="text-gray-600">/</span>
              <span class="font-semibold text-white">{{ client.name }}</span>
              <span
                class="ml-1 rounded-full border px-2 py-0.5 text-[11px] font-medium capitalize"
                :class="client.client_type === 'internal' ? 'border-amber-500/40 text-amber-300' : 'border-sky-500/40 text-sky-300'"
              >
                {{ client.client_type }}
              </span>
            </h1>
            <div class="mt-1.5 flex flex-wrap items-center gap-x-4 gap-y-1 text-sm text-gray-400">
              <span
                v-if="client.contact_name"
                class="inline-flex items-center gap-1.5"
              >
                <UserRound class="h-3.5 w-3.5 text-gray-500" />
                {{ client.contact_name }}
              </span>
              <a
                v-if="client.contact_email"
                :href="`mailto:${client.contact_email}`"
                class="inline-flex items-center gap-1.5 font-mono text-xs text-gray-400 transition hover:text-accent"
              >
                <Mail class="h-3.5 w-3.5 text-gray-500" />
                {{ client.contact_email }}
              </a>
              <span
                v-if="!client.contact_name && !client.contact_email"
                class="text-gray-600"
              >No contact configured</span>
            </div>
            <div
              v-if="clientLabelEntries(client).length > 0"
              class="mt-2.5 flex flex-wrap gap-1.5"
            >
              <span
                v-for="[key, value] in clientLabelEntries(client)"
                :key="`label-${key}`"
                class="inline-flex max-w-full items-center gap-1 rounded-full bg-surface-overlay px-2 py-0.5 text-[11px] text-gray-300"
              >
                <span class="font-medium text-gray-200">{{ key }}:</span>
                <a
                  v-if="isSafeUrl(value)"
                  :href="value"
                  class="truncate text-accent transition hover:underline"
                  target="_blank"
                  rel="noreferrer"
                >{{ value }}</a>
                <span
                  v-else
                  class="truncate"
                >{{ value }}</span>
              </span>
            </div>
          </div>

          <button
            class="inline-flex shrink-0 items-center gap-1.5 rounded-md bg-accent px-3 py-1.5 text-xs font-medium text-white transition hover:bg-accent/90"
            type="button"
            @click="showDeploymentForm = !showDeploymentForm"
          >
            <Plus
              class="h-3.5 w-3.5 transition-transform"
              :class="showDeploymentForm ? 'rotate-45' : ''"
            />
            {{ showDeploymentForm ? 'Cancel' : 'New deployment' }}
          </button>
        </div>

        <!-- Deployment form (compact, matches ClientsTab create form) -->
        <section
          v-if="showDeploymentForm"
          class="mt-4 rounded-md border border-surface-border bg-surface-raised p-4"
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

        <!-- Stat rail (org-dashboard style) -->
        <div class="mt-4 grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
          <div class="rounded-md border border-surface-border bg-surface-raised px-4 py-3">
            <p class="text-[11px] uppercase tracking-[0.14em] text-gray-500">
              Active version
            </p>
            <p
              class="mt-1 truncate font-mono text-xl font-semibold"
              :class="activeVersion ? 'text-emerald-300' : 'text-gray-600'"
            >
              {{ activeVersion || 'none' }}
            </p>
          </div>
          <div class="rounded-md border border-surface-border bg-surface-raised px-4 py-3">
            <p class="text-[11px] uppercase tracking-[0.14em] text-gray-500">
              Open vulnerabilities
            </p>
            <div class="mt-1 flex items-baseline gap-2.5">
              <span
                class="text-xl font-semibold"
                :class="impact.length > 0 ? 'text-white' : 'text-gray-600'"
              >{{ impact.length }}</span>
              <span
                v-for="(count, severity) in impactSeverityCounts"
                :key="severity"
                class="text-xs font-medium"
                :class="severityTextClass(severity)"
              >{{ count }} {{ severity }}</span>
            </div>
          </div>
          <div class="rounded-md border border-surface-border bg-surface-raised px-4 py-3">
            <p class="text-[11px] uppercase tracking-[0.14em] text-gray-500">
              Deployments
            </p>
            <p
              class="mt-1 text-xl font-semibold"
              :class="deployments.length > 0 ? 'text-white' : 'text-gray-600'"
            >
              {{ deployments.length }}
            </p>
          </div>
          <div class="rounded-md border border-surface-border bg-surface-raised px-4 py-3">
            <p class="text-[11px] uppercase tracking-[0.14em] text-gray-500">
              Environments
            </p>
            <div class="mt-1 flex flex-wrap items-baseline gap-x-2 gap-y-1">
              <span
                class="text-xl font-semibold"
                :class="environments.length > 0 ? 'text-white' : 'text-gray-600'"
              >{{ environments.length }}</span>
              <span
                v-for="environment in environments"
                :key="environment"
                class="rounded-full bg-surface-overlay px-2 py-0.5 font-mono text-[11px] text-gray-300"
              >{{ environment }}</span>
            </div>
          </div>
        </div>

        <!-- Impact analysis -->
        <section class="mt-6">
          <div class="flex items-baseline justify-between">
            <h2 class="text-base font-semibold text-white">
              Impact analysis
            </h2>
            <span class="text-xs text-gray-500">Vulnerabilities affecting active deployments</span>
          </div>
          <div
            v-if="impactLoading"
            class="mt-3 text-sm text-gray-500"
          >
            Loading impact analysis…
          </div>
          <div
            v-else-if="impact.length === 0"
            class="mt-3 rounded-md border border-dashed border-surface-border px-6 py-8 text-center"
          >
            <ShieldCheck class="mx-auto h-7 w-7 text-emerald-500/60" />
            <p class="mt-2 text-sm text-gray-400">
              No open vulnerabilities reach this client's active deployments.
            </p>
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
                      Severity
                    </th>
                    <th class="px-4 py-2.5 font-medium">
                      Advisory
                    </th>
                    <th class="px-4 py-2.5 font-medium">
                      Component
                    </th>
                    <th class="px-4 py-2.5 font-medium">
                      Release
                    </th>
                  </tr>
                </thead>
                <tbody class="divide-y divide-surface-border-subtle">
                  <tr
                    v-for="item in impact"
                    :key="`${item.canonical_id}-${item.component_name}-${item.release_version}`"
                    class="transition hover:bg-surface-overlay/50"
                  >
                    <td class="px-4 py-2.5">
                      <span :class="['rounded-full px-2 py-0.5 text-[11px] font-medium', severityClass(item.severity)]">{{ item.severity }}</span>
                    </td>
                    <td class="px-4 py-2.5 font-mono text-xs">
                      <a
                        v-if="advisoryUrl(item.canonical_id)"
                        :href="advisoryUrl(item.canonical_id)"
                        target="_blank"
                        rel="noopener noreferrer"
                        class="text-accent transition hover:underline"
                      >{{ item.canonical_id }}</a>
                      <span
                        v-else
                        class="text-gray-300"
                      >{{ item.canonical_id }}</span>
                    </td>
                    <td class="px-4 py-2.5 text-gray-300">
                      {{ item.component_name }}
                    </td>
                    <td class="px-4 py-2.5 font-mono text-xs text-gray-300">
                      {{ item.release_version }}
                    </td>
                  </tr>
                </tbody>
              </table>
            </div>
          </div>
        </section>

        <!-- Deployments -->
        <section class="mt-6">
          <div class="flex items-baseline justify-between">
            <h2 class="text-base font-semibold text-white">
              Deployments
            </h2>
            <span class="text-xs text-gray-500">Release history and rollout status</span>
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
                    v-for="deployment in deployments"
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
      </template>

      <div
        v-else-if="!error"
        class="py-8 text-sm text-gray-500"
      >
        Client not found.
      </div>
    </template>
  </div>
</template>

<script setup lang="ts">
import { Building2, Mail, Plus, Rocket, ShieldCheck, UserRound } from 'lucide-vue-next'
import { computed, reactive, ref, watch } from 'vue'
import { RouterLink, useRoute } from 'vue-router'

import { api, type Client, type Deployment, type Release, type Repository } from '@/api/client'
import { formatDateTime, relativeTime } from '@/lib/datetime'
import { advisoryUrl } from '@/lib/findingDisplay'

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

const environments = computed(() =>
  [...new Set(deployments.value.map((deployment) => deployment.environment))].sort(),
)

const IMPACT_SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'info']

const impactSeverityCounts = computed(() => {
  const counts: Record<string, number> = {}
  for (const item of impact.value) {
    const severity = item.severity.toLowerCase()
    counts[severity] = (counts[severity] ?? 0) + 1
  }
  const ordered: Record<string, number> = {}
  for (const severity of IMPACT_SEVERITY_ORDER) {
    if (counts[severity]) ordered[severity] = counts[severity]
  }
  return ordered
})

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
    repos.value = reposResponse.data.filter((repo) => repo.enrolled ?? true)
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

function isSafeUrl(url: string) {
  return /^https?:\/\//i.test(url.trim())
}

function clientLabelEntries(currentClient: Client) {
  return Object.entries(currentClient.labels || {})
}

function severityClass(level: string) {
  return `sev-${level.toLowerCase()}`
}

function severityTextClass(severity: string) {
  switch (severity) {
    case 'critical':
      return 'text-danger'
    case 'high':
      return 'text-orange-400'
    case 'medium':
      return 'text-amber-300'
    case 'low':
      return 'text-sky-300'
    default:
      return 'text-gray-400'
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
