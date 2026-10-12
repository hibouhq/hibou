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
            @click="toggleDeploymentForm"
          >
            <Plus
              class="h-3.5 w-3.5 transition-transform"
              :class="showDeploymentForm ? 'rotate-45' : ''"
            />
            {{ showDeploymentForm ? 'Cancel' : 'New deployment' }}
          </button>
        </div>

        <!-- Tabs -->
        <div class="mt-4 border-b border-surface-border">
          <nav class="flex items-center gap-0.5 overflow-x-auto">
            <RouterLink
              v-for="tab in tabs"
              :key="tab.name"
              :to="{ name: tab.name, params: route.params }"
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
                v-if="tab.count !== null"
                class="inline-flex min-w-[1.25rem] items-center justify-center rounded-full px-1.5 text-[10px] leading-[18px]"
                :class="isActiveTab(tab.name) ? 'bg-accent/15 text-accent' : 'bg-surface-overlay text-gray-500'"
              >{{ tab.count }}</span>
            </RouterLink>
          </nav>
        </div>

        <div class="pt-4">
          <RouterView />
        </div>
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
import { isSafeUrl } from '@/lib/safeUrl'
import { Building2, History, LayoutDashboard, Mail, Plus, UserRound } from 'lucide-vue-next'
import { computed, provide, ref, watch } from 'vue'
import { RouterLink, RouterView, useRoute, useRouter } from 'vue-router'

import { api, type Client, type Deployment, type Repository } from '@/api/client'

type ImpactItem = {
  canonical_id: string
  severity: string
  component_name: string
  release_version: string
}

const route = useRoute()
const router = useRouter()

const client = ref<Client | null>(null)
const deployments = ref<Deployment[]>([])
const impact = ref<ImpactItem[]>([])
const repos = ref<Repository[]>([])
const loading = ref(true)
const deploymentsLoading = ref(true)
const impactLoading = ref(true)
const error = ref('')
const showDeploymentForm = ref(false)

provide('client', client)
provide('clientDeployments', deployments)
provide('clientImpact', impact)
provide('clientRepos', repos)
provide('clientDeploymentsLoading', deploymentsLoading)
provide('clientImpactLoading', impactLoading)
provide('reloadClientDetail', loadClientDetail)
provide('showDeploymentForm', showDeploymentForm)

const provider = computed(() => route.params.provider as string)
const slug = computed(() => route.params.slug as string)
const clientSlug = computed(() => route.params.clientSlug as string)

const tabs = computed(() => [
  { label: 'Overview', name: 'client-overview', icon: LayoutDashboard, count: null },
  { label: 'History', name: 'client-history', icon: History, count: deploymentsLoading.value ? null : deployments.value.length },
])

function isActiveTab(name: string) {
  return route.name === name
}

function toggleDeploymentForm() {
  if (route.name !== 'client-history') {
    showDeploymentForm.value = true
    void router.push({ name: 'client-history', params: route.params })
    return
  }
  showDeploymentForm.value = !showDeploymentForm.value
}

watch(
  () => [provider.value, slug.value, clientSlug.value],
  () => {
    // Route params clear before this view unmounts when navigating away;
    // don't fire requests against /clients/undefined.
    if (!provider.value || !slug.value || !clientSlug.value) {
      return
    }
    void loadClientDetail()
  },
  { immediate: true },
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


function clientLabelEntries(currentClient: Client) {
  return Object.entries(currentClient.labels || {})
}
</script>
