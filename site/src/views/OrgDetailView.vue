<template>
  <div>
    <div
      v-if="loading"
      class="px-5 py-8 text-sm text-gray-500"
    >
      Loading organization...
    </div>

    <template v-else-if="org">
      <div class="border-b border-surface-border px-2">
        <nav
          class="flex w-full items-center gap-0.5"
          aria-label="Organization navigation"
        >
          <RouterLink
            v-for="tab in visibleTabs"
            :key="tab.name"
            :to="{ name: tab.name, params: route.params }"
            class="group flex shrink-0 items-center gap-1.5 whitespace-nowrap border-b-2 px-2 py-2 text-sm transition lg:px-3"
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
          <div
            v-if="overflowTabs.length"
            ref="moreMenuRef"
            class="relative ml-auto"
          >
            <button
              ref="moreMenuTriggerRef"
              class="flex items-center gap-1.5 border-b-2 px-2 py-2 text-sm transition lg:px-3"
              :class="hasActiveOverflowTab
                ? 'border-accent font-semibold text-white'
                : 'border-transparent text-gray-400 hover:border-surface-border hover:text-gray-200'"
              type="button"
              aria-controls="organization-more-links"
              :aria-expanded="moreMenuOpen"
              @click.stop="moreMenuOpen = !moreMenuOpen"
            >
              {{ activeOverflowTab?.label || 'More' }}
              <ChevronDown class="h-4 w-4" />
            </button>
            <div
              v-if="moreMenuOpen"
              id="organization-more-links"
              class="absolute right-0 top-[calc(100%+0.25rem)] z-30 min-w-48 rounded-md border border-surface-border bg-surface-overlay py-1 shadow-2xl"
              @keydown.esc.prevent.stop="closeMoreMenu(true)"
            >
              <RouterLink
                v-for="tab in overflowTabs"
                :key="tab.name"
                :to="{ name: tab.name, params: route.params }"
                class="flex items-center gap-2 px-3 py-2 text-sm transition hover:bg-surface-muted"
                :class="isActiveTab(tab.name) ? 'font-semibold text-white' : 'text-gray-300'"
                @click="closeMoreMenu()"
              >
                <component
                  :is="tab.icon"
                  class="h-4 w-4 text-gray-500"
                />
                {{ tab.label }}
                <span
                  v-if="tab.count !== null"
                  class="ml-auto text-[10px] text-gray-500"
                >{{ tab.count }}</span>
              </RouterLink>
            </div>
          </div>
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
import { Bug, ChevronDown, LayoutDashboard, LineChart, ListChecks, Package, Radar, Scale, Settings, ShieldAlert, Users } from 'lucide-vue-next'
import { computed, onMounted, onUnmounted, provide, ref, watch } from 'vue'
import { RouterLink, RouterView, useRoute } from 'vue-router'

import { api, type OrgDashboard, type Organization, type SeverityCounts } from '@/api/client'
import { visibleRepoTabCount } from '@/lib/repoTabs'
import { useAuthStore } from '@/stores/auth'

const route = useRoute()
const provider = computed(() => route.params.provider as string)
const slug = computed(() => route.params.slug as string)

const org = ref<Organization | null>(null)
const dashboard = ref<OrgDashboard | null>(null)
const loading = ref(true)
const viewportWidth = ref(typeof window === 'undefined' ? 1360 : window.innerWidth)
const moreMenuRef = ref<HTMLElement | null>(null)
const moreMenuTriggerRef = ref<HTMLButtonElement | null>(null)
const moreMenuOpen = ref(false)

provide('org', org)
provide('orgDashboard', dashboard)

const severityOrder: Array<keyof SeverityCounts> = ['critical', 'high', 'medium', 'unknown', 'low', 'info']
const vulnTotal = computed(() => {
  const counts = dashboard.value?.totals.vulnerabilities
  return counts ? severityOrder.reduce((total, key) => total + (counts[key] ?? 0), 0) : null
})
const componentsTotal = computed(() => dashboard.value?.totals.components_total ?? null)

const auth = useAuthStore()

// The CVE triage queue is instance-wide: only instance admins and
// instance-scoped triagers can open it, so the tab is hidden for others.
const tabs = computed(() => [
  { label: 'Overview', name: 'org-overview', icon: LayoutDashboard, count: null },
  { label: 'Vulnerabilities', name: 'org-vulnerabilities', icon: ShieldAlert, count: vulnTotal.value },
  { label: 'CWE', name: 'org-cwes', icon: Bug, count: null },
  { label: 'Dependencies', name: 'org-dependencies', icon: Package, count: componentsTotal.value },
  { label: 'Licenses', name: 'org-licenses', icon: Scale, count: null },
  ...(auth.user?.can_triage_cves ? [{ label: 'Triage', name: 'org-triage', icon: ListChecks, count: null }] : []),
  { label: 'Scanners', name: 'org-scanners', icon: Radar, count: null },
  { label: 'Clients', name: 'org-clients', icon: Users, count: null },
  { label: 'Insights', name: 'org-insights', icon: LineChart, count: null },
  { label: 'Settings', name: 'org-settings', icon: Settings, count: null },
])

const visibleTabs = computed(() => tabs.value.slice(0, visibleRepoTabCount(viewportWidth.value)))
const overflowTabs = computed(() => tabs.value.slice(visibleTabs.value.length))
const hasActiveOverflowTab = computed(() => overflowTabs.value.some((tab) => isActiveTab(tab.name)))
const activeOverflowTab = computed(() => overflowTabs.value.find((tab) => isActiveTab(tab.name)))

function isActiveTab(name: string) {
  if (name === 'org-settings') {
    return typeof route.name === 'string' && route.name.startsWith('org-settings')
  }
  return route.name === name
}

function updateViewportWidth() {
  viewportWidth.value = window.innerWidth
}

function closeMoreMenu(restoreFocus = false) {
  moreMenuOpen.value = false
  if (restoreFocus) {
    moreMenuTriggerRef.value?.focus()
  }
}

function handleDocumentClick(event: MouseEvent) {
  const target = event.target as Node | null
  if (target && moreMenuRef.value && !moreMenuRef.value.contains(target)) {
    closeMoreMenu(true)
  }
}

onMounted(() => {
  document.addEventListener('click', handleDocumentClick)
  window.addEventListener('resize', updateViewportWidth)
})

onUnmounted(() => {
  document.removeEventListener('click', handleDocumentClick)
  window.removeEventListener('resize', updateViewportWidth)
})

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
