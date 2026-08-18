<template>
  <div>
    <div
      v-if="loading"
      class="px-5 py-8 text-sm text-gray-500"
    >
      Loading organization...
    </div>

    <template v-else-if="org">
      <!-- Org header (GitHub-style) -->
      <div class="px-4 pt-5">
        <h1 class="flex flex-wrap items-center gap-x-2 gap-y-1 text-xl">
          <ForgeIcon
            :provider="org.provider"
            size="md"
            class="text-gray-400"
          />
          <span class="font-semibold text-white">{{ org.display_name || org.name }}</span>
          <span class="ml-1 rounded-full border border-surface-border px-2 py-0.5 text-[11px] font-medium text-gray-400">
            Organization
          </span>
        </h1>
        <p class="mt-1 text-sm text-gray-500">
          {{ org.provider }} / {{ org.slug }}
        </p>
      </div>

      <!-- Tabs; Clients is the rollout side, not an analysis lens — fenced
           pill, matching the repo-level Releases tab (ADR-024 §1/§7). -->
      <div class="mt-4 border-b border-surface-border px-2">
        <nav class="flex items-center gap-0.5 overflow-x-auto">
          <template
            v-for="tab in tabs"
            :key="tab.name"
          >
            <template v-if="tab.fenced">
              <span
                aria-hidden="true"
                class="mx-1.5 mb-1.5 h-5 w-px shrink-0 bg-surface-border"
              />
              <RouterLink
                :to="{ name: tab.name, params: route.params }"
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
              </RouterLink>
              <span
                aria-hidden="true"
                class="mx-1.5 mb-1.5 h-5 w-px shrink-0 bg-surface-border"
              />
            </template>
            <RouterLink
              v-else
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
          </template>
        </nav>
      </div>

      <div class="px-4 pt-4">
        <RouterView />
      </div>
    </template>

    <div
      v-else
      class="px-5 py-8 text-sm text-gray-500"
    >
      Organization not found.
    </div>
  </div>
</template>

<script setup lang="ts">
import { LayoutDashboard, LineChart, Package, Settings, ShieldAlert, Users } from 'lucide-vue-next'
import { computed, provide, ref, watch } from 'vue'
import { RouterLink, RouterView, useRoute } from 'vue-router'

import { api, type OrgDashboard, type Organization, type SeverityCounts } from '@/api/client'
import ForgeIcon from '@/components/ForgeIcon.vue'

const route = useRoute()
const provider = computed(() => route.params.provider as string)
const slug = computed(() => route.params.slug as string)

const org = ref<Organization | null>(null)
const dashboard = ref<OrgDashboard | null>(null)
const loading = ref(true)

provide('org', org)
provide('orgDashboard', dashboard)

const severityOrder: Array<keyof SeverityCounts> = ['critical', 'high', 'medium', 'low', 'info']
const vulnTotal = computed(() => {
  const counts = dashboard.value?.totals.vulnerabilities
  return counts ? severityOrder.reduce((total, key) => total + (counts[key] ?? 0), 0) : null
})
const componentsTotal = computed(() => dashboard.value?.totals.components_total ?? null)

const tabs = computed(() => [
  { label: 'Overview', name: 'org-overview', icon: LayoutDashboard, count: null },
  { label: 'Vulnerabilities', name: 'org-vulnerabilities', icon: ShieldAlert, count: vulnTotal.value },
  { label: 'Dependencies', name: 'org-dependencies', icon: Package, count: componentsTotal.value },
  { label: 'Clients', name: 'org-clients', icon: Users, count: null, fenced: true },
  { label: 'Insights', name: 'org-insights', icon: LineChart, count: null },
  { label: 'Settings', name: 'org-settings', icon: Settings, count: null },
])

function isActiveTab(name: string) {
  if (name === 'org-settings') {
    return typeof route.name === 'string' && route.name.startsWith('org-settings')
  }
  return route.name === name
}

watch(
  [provider, slug],
  async ([newProvider, newSlug]) => {
    if (!newProvider || !newSlug) {
      org.value = null
      dashboard.value = null
      return
    }

    loading.value = true
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
    } finally {
      loading.value = false
    }
  },
  { immediate: true },
)
</script>
