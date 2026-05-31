<template>
  <div class="space-y-6">
    <section class="rounded-3xl border border-surface-border bg-surface-raised p-6 shadow-[0_24px_80px_-48px_rgba(0,0,0,0.9)]">
      <div
        v-if="loading"
        class="text-sm text-gray-500"
      >
        Loading organization dashboard...
      </div>

      <div
        v-else-if="error"
        class="rounded-2xl border border-danger/30 bg-danger/10 px-4 py-3 text-sm text-red-200"
      >
        {{ error }}
      </div>

      <template v-else-if="org && dashboard">
        <div class="flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
          <div>
            <div class="mb-3 flex flex-wrap items-center gap-3">
              <ForgeIcon
                :provider="org.provider"
                size="lg"
                class="text-gray-300"
              />
              <h1 class="text-3xl font-semibold tracking-tight text-white">
                {{ org.display_name || org.name }}
              </h1>
            </div>
            <p class="text-sm text-gray-400">
              {{ org.provider }} / {{ org.slug }}
            </p>
          </div>

          <div class="flex flex-wrap gap-2 text-xs uppercase tracking-[0.18em] text-gray-500">
            <span
              v-for="item in vulnerabilityBadges"
              :key="`vulnerabilities-${item.key}`"
              :class="['rounded-full px-3 py-1 font-medium', severityClass(item.key)]"
            >
              {{ item.key }} {{ item.value }} vulnerabilities
            </span>
          </div>
        </div>

        <div class="mt-6 grid gap-4 md:grid-cols-2 xl:grid-cols-4">
          <article class="rounded-2xl border border-surface-border-subtle bg-surface-overlay p-4">
            <div class="text-xs uppercase tracking-[0.2em] text-gray-500">
              Repositories
            </div>
            <div class="mt-3 text-3xl font-semibold text-white">
              {{ dashboard.repos.length }}
            </div>
          </article>
          <article class="rounded-2xl border border-surface-border-subtle bg-surface-overlay p-4">
            <div class="text-xs uppercase tracking-[0.2em] text-gray-500">
              Vulnerabilities
            </div>
            <div class="mt-3 text-3xl font-semibold text-white">
              {{ totalVulnerabilities }}
            </div>
          </article>
          <article class="rounded-2xl border border-surface-border-subtle bg-surface-overlay p-4">
            <div class="text-xs uppercase tracking-[0.2em] text-gray-500">
              Components
            </div>
            <div class="mt-3 text-3xl font-semibold text-white">
              {{ dashboard.totals.components_total }}
            </div>
          </article>
        </div>
      </template>
    </section>

    <section class="overflow-hidden rounded-3xl border border-surface-border bg-surface-raised">
      <div class="flex items-center justify-between border-b border-surface-border-subtle px-6 py-4">
        <div>
          <h2 class="text-lg font-semibold text-white">
            Top-risk repositories
          </h2>
          <p class="mt-1 text-sm text-gray-400">
            Repositories ranked by critical and high-severity findings.
          </p>
        </div>
      </div>

      <div
        v-if="!loading && dashboard && dashboard.repos.length === 0"
        class="px-6 py-10 text-sm text-gray-500"
      >
        No repositories have been synchronized for this organization yet.
      </div>

      <div
        v-else-if="dashboard"
        class="overflow-x-auto"
      >
        <table class="min-w-full divide-y divide-surface-border-subtle text-sm">
          <thead class="bg-surface-overlay/80 text-left text-xs uppercase tracking-[0.18em] text-gray-500">
            <tr>
              <th class="px-6 py-4 font-medium">
                Repository
              </th>
              <th class="px-6 py-4 font-medium">
                Vulnerabilities
              </th>
              <th class="px-6 py-4 font-medium">
                Components
              </th>
              <th class="px-6 py-4 font-medium">
                Last scan
              </th>
            </tr>
          </thead>
          <tbody class="divide-y divide-surface-border-subtle">
            <tr
              v-for="entry in dashboard.repos"
              :key="entry.repo_id"
              class="transition hover:bg-white/5"
            >
              <td class="px-6 py-4">
                <RouterLink
                  :to="`/orgs/${provider}/${slug}/repos/${entry.repo_slug}`"
                  class="flex items-center gap-3 text-white transition hover:text-accent"
                >
                  <ForgeIcon
                    :provider="entry.provider"
                    size="sm"
                    class="text-gray-400"
                  />
                  <div>
                    <div class="font-medium">
                      {{ entry.repo_name }}
                    </div>
                    <div class="text-xs uppercase tracking-[0.18em] text-gray-500">
                      {{ entry.repo_slug }}
                    </div>
                  </div>
                </RouterLink>
              </td>
              <td class="px-6 py-4">
                <div class="flex flex-wrap gap-2">
                  <span
                    v-for="item in toSeverityItems(entry.vulnerabilities)"
                    :key="`${entry.repo_id}-vulnerability-${item.key}`"
                    :class="['rounded-full px-2.5 py-1 text-xs font-medium', severityClass(item.key)]"
                  >
                    {{ item.key }} {{ item.value }}
                  </span>
                </div>
              </td>
              <td class="px-6 py-4 text-gray-300">
                {{ entry.components_total }}
              </td>
              <td class="px-6 py-4 text-gray-400">
                {{ formatDate(entry.last_scan) }}
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </section>
  </div>
</template>

<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { RouterLink, useRoute } from 'vue-router'

import { api, type OrgDashboard, type Organization, type SeverityCounts } from '@/api/client'
import ForgeIcon from '@/components/ForgeIcon.vue'

const route = useRoute()
const provider = computed(() => route.params.provider as string)
const slug = computed(() => route.params.slug as string)
const org = ref<Organization | null>(null)
const dashboard = ref<OrgDashboard | null>(null)
const loading = ref(true)
const error = ref('')

const severityOrder: Array<keyof SeverityCounts> = ['critical', 'high', 'medium', 'low', 'info']

const vulnerabilityBadges = computed(() => toSeverityItems(dashboard.value?.totals.vulnerabilities))
const totalVulnerabilities = computed(() => sumCounts(dashboard.value?.totals.vulnerabilities))

watch(
  [provider, slug],
  async ([newProvider, newSlug]) => {
    if (!newProvider || !newSlug) {
      org.value = null
      dashboard.value = null
      return
    }

    loading.value = true
    error.value = ''

    try {
      const [orgRes, dashboardRes] = await Promise.all([
        api.getOrg(newProvider, newSlug),
        api.getOrgDashboard(newProvider, newSlug),
      ])

      org.value = orgRes.data
      dashboard.value = dashboardRes.data
    } catch {
      org.value = null
      dashboard.value = null
      error.value = 'Unable to load organization dashboard.'
    } finally {
      loading.value = false
    }
  },
  { immediate: true },
)

function toSeverityItems(counts?: SeverityCounts | null) {
  return severityOrder
    .map((key) => ({ key, value: counts?.[key] ?? 0 }))
    .filter((item) => item.value > 0)
}

function sumCounts(counts?: SeverityCounts | null) {
  return severityOrder.reduce((total, key) => total + (counts?.[key] ?? 0), 0)
}

function severityClass(level: keyof SeverityCounts) {
  return `sev-${level}`
}

function formatDate(value?: string) {
  if (!value) {
    return 'No scans yet'
  }

  return new Date(value).toLocaleString()
}
</script>
