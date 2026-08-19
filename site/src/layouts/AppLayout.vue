<template>
  <div class="min-h-screen bg-surface text-[#e6edf3]">
    <header class="fixed inset-x-0 top-[var(--app-banner-height,0px)] z-50 h-14 border-b border-surface-border bg-surface-raised/95 backdrop-blur">
      <div class="flex h-full items-center gap-3 px-4">
        <div class="flex items-center gap-3">
          <button
            class="flex h-9 w-9 items-center justify-center rounded-lg border border-surface-border bg-surface-overlay text-gray-300 transition hover:border-accent/50 hover:text-white"
            type="button"
            aria-label="Open navigation menu"
            :aria-expanded="isDrawerOpen"
            @click.stop="isDrawerOpen = !isDrawerOpen"
          >
            <Menu class="h-5 w-5" />
          </button>

          <RouterLink
            to="/orgs"
            class="flex items-center gap-3 text-sm font-semibold text-white"
          >
            <span class="flex h-8 w-8 items-center justify-center rounded-xl border border-surface-border bg-surface-overlay shadow-[0_0_0_1px_rgba(255,255,255,0.02)]">
              <svg
                viewBox="0 0 32 32"
                class="h-5 w-5 text-accent"
                fill="none"
                xmlns="http://www.w3.org/2000/svg"
              >
                <path
                  d="M8 24V12L12 8L16 12L20 8L24 12V24L16 28L8 24Z"
                  stroke="currentColor"
                  stroke-width="2"
                  stroke-linejoin="round"
                />
                <circle
                  cx="13"
                  cy="16"
                  r="2"
                  fill="currentColor"
                />
                <circle
                  cx="19"
                  cy="16"
                  r="2"
                  fill="currentColor"
                />
                <path
                  d="M16 18L14.5 20H17.5L16 18Z"
                  fill="currentColor"
                />
              </svg>
            </span>
            <span class="hidden sm:inline">Hibou</span>
          </RouterLink>

          <div class="flex items-center gap-1.5 text-sm">
            <template v-if="currentOrgSlug && currentOrgProvider">
              <div
                ref="orgMenuRef"
                class="relative flex items-center gap-1"
              >
                <RouterLink
                  :to="`/orgs/${currentOrgProvider}/${currentOrgSlug}`"
                  class="max-w-[10rem] truncate text-gray-300 transition hover:text-white"
                >
                  {{ currentOrgName }}
                </RouterLink>
                <button
                  v-if="orgStore.orgs.length > 1"
                  class="rounded p-0.5 text-gray-400 transition hover:bg-surface-overlay hover:text-white"
                  type="button"
                  @click.stop="toggleOrgMenu"
                >
                  <ChevronDown class="h-3.5 w-3.5" />
                </button>
                <div
                  v-if="isOrgMenuOpen"
                  class="absolute left-0 top-[calc(100%+0.5rem)] z-50 w-64 overflow-hidden rounded-xl border border-surface-border bg-surface-overlay shadow-2xl"
                >
                  <div
                    v-if="orgStore.orgs.length >= 5"
                    class="border-b border-surface-border-subtle p-2"
                  >
                    <input
                      v-model="orgSearch"
                      type="search"
                      placeholder="Find an organization..."
                      class="w-full rounded-md border border-surface-border bg-surface-raised px-2.5 py-1.5 text-xs text-gray-100 placeholder:text-gray-500 focus:border-accent/50 focus:outline-none"
                    >
                  </div>
                  <div class="max-h-64 overflow-auto p-1">
                    <RouterLink
                      v-for="orgItem in filteredOrgList"
                      :key="orgItem.id"
                      :to="`/orgs/${orgItem.provider}/${orgItem.slug}`"
                      class="flex items-center gap-2 rounded-md px-2.5 py-1.5 text-sm transition"
                      :class="orgItem.slug === currentOrgSlug && orgItem.provider === currentOrgProvider
                        ? 'bg-accent-muted text-white'
                        : 'text-gray-300 hover:bg-surface-raised hover:text-white'"
                      @click="isOrgMenuOpen = false"
                    >
                      <Building2 class="h-3.5 w-3.5 shrink-0 text-gray-500" />
                      <span class="truncate">{{ orgItem.display_name || orgItem.name }}</span>
                    </RouterLink>
                  </div>
                </div>
              </div>
            </template>
            <template v-if="currentRepoSlug">
              <span class="text-gray-500">/</span>
              <div
                ref="repoMenuRef"
                class="relative flex items-center gap-1"
              >
                <Lock
                  v-if="currentRepoIsPrivate"
                  class="h-3.5 w-3.5 shrink-0 text-gray-400"
                  :aria-label="`${currentRepoVisibilityLabel} repository`"
                />
                <RouterLink
                  :to="`/orgs/${currentOrgProvider}/${currentOrgSlug}/repos/${currentRepoSlug}`"
                  class="max-w-[14rem] truncate font-semibold text-white transition hover:text-accent"
                  :title="currentRepoIsPrivate ? `${currentRepoVisibilityLabel} repository` : undefined"
                >
                  {{ currentRepoSlug }}
                </RouterLink>
                <button
                  class="rounded p-0.5 text-gray-400 transition hover:bg-surface-overlay hover:text-white"
                  type="button"
                  @click.stop="toggleRepoMenu"
                >
                  <ChevronDown class="h-3.5 w-3.5" />
                </button>
                <div
                  v-if="isRepoMenuOpen"
                  class="absolute left-0 top-[calc(100%+0.5rem)] z-50 w-64 overflow-hidden rounded-xl border border-surface-border bg-surface-overlay shadow-2xl"
                >
                  <div
                    v-if="repoList.length >= 5"
                    class="border-b border-surface-border-subtle p-2"
                  >
                    <input
                      v-model="repoSearch"
                      type="search"
                      placeholder="Find a repository..."
                      class="w-full rounded-md border border-surface-border bg-surface-raised px-2.5 py-1.5 text-xs text-gray-100 placeholder:text-gray-500 focus:border-accent/50 focus:outline-none"
                    >
                  </div>
                  <div class="max-h-64 overflow-auto p-1">
                    <div
                      v-if="repoListLoading"
                      class="px-3 py-4 text-xs text-gray-500"
                    >
                      Loading...
                    </div>
                    <RouterLink
                      v-for="repoItem in filteredRepoList"
                      :key="repoItem.id"
                      :to="`/orgs/${currentOrgProvider}/${currentOrgSlug}/repos/${repoItem.slug}`"
                      class="flex items-center gap-2 rounded-md px-2.5 py-1.5 text-sm text-gray-300 transition hover:bg-surface-raised hover:text-white"
                      @click="isRepoMenuOpen = false"
                    >
                      <BookOpen class="h-3.5 w-3.5 shrink-0 text-gray-500" />
                      <span class="truncate">{{ repoItem.name }}</span>
                    </RouterLink>
                  </div>
                </div>
              </div>
            </template>
          </div>
        </div>

        <div class="ml-auto hidden sm:block">
          <button
            type="button"
            class="flex w-56 items-center gap-2 rounded-md border border-surface-border bg-surface-overlay px-2.5 py-1.5 text-sm text-gray-400 transition hover:border-accent/50 hover:text-gray-200 disabled:cursor-not-allowed disabled:opacity-60 lg:w-64"
            :disabled="!searchOrgSlug || !searchOrgProvider"
            @click="searchPaletteOpen = true"
          >
            <Search class="h-4 w-4 shrink-0 text-gray-500" />
            <span class="min-w-0 flex-1 truncate text-left">{{ searchOrgSlug ? 'Search…' : 'Select an org' }}</span>
            <span class="hidden shrink-0 rounded border border-surface-border-subtle px-1 text-[10px] text-gray-500 lg:inline">⌘K</span>
          </button>
        </div>

        <div class="ml-auto flex items-center gap-3">
          <div
            ref="notifMenuRef"
            class="relative"
          >
            <button
              class="relative flex h-9 w-9 items-center justify-center rounded-lg border border-surface-border bg-surface-overlay text-gray-300 transition hover:border-accent/50 hover:text-white"
              :class="isNotifMenuOpen ? 'border-accent/50 text-white' : ''"
              type="button"
              aria-label="Notifications"
              title="Notifications"
              :aria-expanded="isNotifMenuOpen"
              @click.stop="toggleNotifMenu"
            >
              <Bell class="h-5 w-5" />
              <span
                v-if="notificationsStore.unreadCount > 0"
                class="absolute -right-1 -top-1 inline-flex min-w-5 items-center justify-center rounded-full bg-danger px-1.5 text-[10px] font-semibold leading-5 text-white"
              >
                {{ Math.min(notificationsStore.unreadCount, 99) }}
              </span>
            </button>

            <NotificationPanel
              v-if="isNotifMenuOpen"
              @close="isNotifMenuOpen = false"
            />
          </div>

          <div
            ref="userMenuRef"
            class="relative"
          >
            <button
              class="flex items-center gap-3 rounded-xl border border-surface-border bg-surface-overlay px-2.5 py-1.5 transition hover:border-accent/50"
              type="button"
              @click.stop="toggleUserMenu"
            >
              <span class="hidden text-sm text-gray-300 sm:block">{{ authStore.user?.display_name || 'User' }}</span>
              <img
                v-if="authStore.user?.avatar_url"
                :src="authStore.user.avatar_url"
                :alt="authStore.user.display_name"
                class="h-8 w-8 rounded-full border border-surface-border object-cover"
              >
              <span
                v-else
                class="flex h-8 w-8 items-center justify-center rounded-full border border-surface-border bg-surface-raised text-xs font-semibold uppercase text-gray-200"
              >
                {{ userInitials }}
              </span>
            </button>

            <div
              v-if="isUserMenuOpen"
              class="absolute right-0 top-[calc(100%+0.5rem)] z-50 w-56 overflow-hidden rounded-2xl border border-surface-border bg-surface-overlay shadow-2xl"
            >
              <div class="border-b border-surface-border-subtle px-4 py-3">
                <div class="truncate text-sm font-medium text-white">
                  {{ authStore.user?.display_name || 'User' }}
                </div>
                <div class="truncate text-xs text-gray-500">
                  {{ authStore.user?.email }}
                </div>
              </div>
              <div class="p-2">
                <RouterLink
                  class="flex rounded-xl px-3 py-2 text-sm text-gray-300 transition hover:bg-accent-muted hover:text-white"
                  to="/settings"
                  @click="isUserMenuOpen = false"
                >
                  API Keys
                </RouterLink>
                <button
                  class="flex w-full rounded-xl px-3 py-2 text-left text-sm text-gray-300 transition hover:bg-accent-muted hover:text-white"
                  type="button"
                  @click="openInstallCli"
                >
                  Install CLI
                </button>
                <button
                  class="flex w-full rounded-xl px-3 py-2 text-left text-sm text-gray-300 transition hover:bg-danger/15 hover:text-white"
                  type="button"
                  @click="handleLogout"
                >
                  Logout
                </button>
              </div>
              <!-- Version + update indicator -->
              <div
                v-if="serverVersion"
                class="border-t border-surface-border-subtle px-4 py-2.5"
              >
                <div class="flex items-center justify-between gap-2 text-xs">
                  <a
                    v-if="serverVersion.current_url"
                    :href="serverVersion.current_url"
                    target="_blank"
                    rel="noopener noreferrer"
                    class="font-mono text-gray-500 transition hover:text-gray-300 hover:underline"
                    title="View release notes"
                    @click="isUserMenuOpen = false"
                  >{{ serverVersion.current }}</a>
                  <span
                    v-else
                    class="font-mono text-gray-500"
                  >{{ serverVersion.current }}</span>
                  <a
                    v-if="serverVersion.update_available"
                    :href="serverVersion.release_url"
                    target="_blank"
                    rel="noopener noreferrer"
                    class="inline-flex items-center gap-1 rounded-full bg-accent-muted px-2 py-0.5 font-medium text-accent transition hover:text-white"
                    @click="isUserMenuOpen = false"
                  >
                    <span class="h-1.5 w-1.5 rounded-full bg-accent" />
                    Update to {{ serverVersion.latest }}
                  </a>
                  <span
                    v-else
                    class="text-gray-600"
                  >Up to date</span>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </header>

    <SearchPalette
      v-if="searchOrgSlug && searchOrgProvider"
      :open="searchPaletteOpen"
      :provider="searchOrgProvider"
      :slug="searchOrgSlug"
      @close="searchPaletteOpen = false"
    />

    <!-- Hidden, context-scoped navigation drawer -->
    <Transition
      enter-active-class="transition-opacity duration-150"
      enter-from-class="opacity-0"
      leave-active-class="transition-opacity duration-150"
      leave-to-class="opacity-0"
    >
      <div
        v-if="isDrawerOpen"
        class="fixed inset-0 z-[60] bg-black/50"
        @click="isDrawerOpen = false"
      />
    </Transition>
    <Transition
      enter-active-class="transition-transform duration-200 ease-out"
      enter-from-class="-translate-x-full"
      leave-active-class="transition-transform duration-150 ease-in"
      leave-to-class="-translate-x-full"
    >
      <aside
        v-if="isDrawerOpen"
        ref="drawerRef"
        class="fixed bottom-0 left-0 top-0 z-[61] flex w-[19rem] max-w-[85vw] flex-col rounded-r-xl border-r border-surface-border bg-surface-raised"
      >
        <!-- GitHub-style drawer header: brand left, close right -->
        <div class="flex items-center justify-between px-4 pb-2 pt-4">
          <RouterLink
            to="/orgs"
            class="flex items-center gap-2 text-sm font-semibold text-white"
            @click="isDrawerOpen = false"
          >
            <svg
              viewBox="0 0 32 32"
              class="h-6 w-6 text-gray-200"
              fill="none"
              xmlns="http://www.w3.org/2000/svg"
            >
              <path
                d="M8 24V12L12 8L16 12L20 8L24 12V24L16 28L8 24Z"
                stroke="currentColor"
                stroke-width="2"
                stroke-linejoin="round"
              />
              <circle
                cx="13"
                cy="16"
                r="2"
                fill="currentColor"
              />
              <circle
                cx="19"
                cy="16"
                r="2"
                fill="currentColor"
              />
              <path
                d="M16 18L14.5 20H17.5L16 18Z"
                fill="currentColor"
              />
            </svg>
            Hibou
          </RouterLink>
          <button
            class="rounded-md p-1.5 text-gray-400 transition hover:bg-surface-overlay hover:text-white"
            type="button"
            aria-label="Close navigation menu"
            @click="isDrawerOpen = false"
          >
            <X class="h-4 w-4" />
          </button>
        </div>

        <nav class="flex-1 overflow-y-auto px-2 pb-4">
          <template
            v-for="(section, sectionIndex) in navSections"
            :key="sectionIndex"
          >
            <div
              v-if="sectionIndex > 0"
              class="mx-2 my-2 border-t border-surface-border-subtle"
            />
            <div
              v-if="section.title"
              class="flex items-center gap-2 px-2 pb-1 pt-1.5"
            >
              <component
                :is="section.titleIcon"
                v-if="section.titleIcon"
                class="h-3.5 w-3.5 shrink-0 text-gray-500"
              />
              <span class="truncate text-xs font-semibold text-gray-500">{{ section.title }}</span>
            </div>
            <RouterLink
              v-for="item in section.items"
              :key="item.label"
              :to="item.to"
              class="flex items-center gap-2.5 rounded-md px-2 py-1.5 text-sm transition"
              :class="isActive(item)
                ? 'bg-surface-overlay font-medium text-white'
                : 'font-normal text-gray-300 hover:bg-surface-overlay/60 hover:text-white'"
            >
              <component
                :is="item.icon"
                class="h-4 w-4 shrink-0"
                :class="isActive(item) ? 'text-gray-300' : 'text-gray-500'"
              />
              <span class="truncate">{{ item.label }}</span>
            </RouterLink>
          </template>
        </nav>
      </aside>
    </Transition>

    <main class="min-h-screen px-4 pb-6 pt-[calc(4.75rem+var(--app-banner-height,0px))] sm:px-6">
      <div class="mx-auto max-w-7xl">
        <RouterView />
      </div>
    </main>

    <InstallCliModal
      v-if="isInstallCliOpen"
      @close="isInstallCliOpen = false"
    />
  </div>
</template>

<script setup lang="ts">
import {
  Activity,
  Bell,
  Building2,
  BookOpen,
  Container,
  ChevronDown,
  FlaskConical,
  LayoutDashboard,
  LineChart,
  Lock,
  Menu,
  Package,
  Rocket,
  Search,
  Settings,
  ShieldAlert,
  Users,
  X,
} from 'lucide-vue-next'
import { computed, onBeforeUnmount, onMounted, ref, watch } from 'vue'
import { RouterLink, RouterView, useRoute, useRouter } from 'vue-router'

import { api, type Repository, type ServerVersion } from '@/api/client'
import InstallCliModal from '@/components/InstallCliModal.vue'
import NotificationPanel from '@/components/NotificationPanel.vue'
import SearchPalette from '@/components/SearchPalette.vue'
import { useAuthStore } from '@/stores/auth'
import { useNotificationsStore } from '@/stores/notifications'
import { useOrgStore } from '@/stores/org'

const authStore = useAuthStore()
const notificationsStore = useNotificationsStore()
const orgStore = useOrgStore()
const route = useRoute()
const router = useRouter()

const isDrawerOpen = ref(false)
const drawerRef = ref<HTMLElement | null>(null)
const isUserMenuOpen = ref(false)
const userMenuRef = ref<HTMLElement | null>(null)
const isInstallCliOpen = ref(false)
const serverVersion = ref<ServerVersion | null>(null)
const isNotifMenuOpen = ref(false)
const notifMenuRef = ref<HTMLElement | null>(null)
const isOrgMenuOpen = ref(false)
const orgMenuRef = ref<HTMLElement | null>(null)
const orgSearch = ref('')
const isRepoMenuOpen = ref(false)
const repoMenuRef = ref<HTMLElement | null>(null)
const repoList = ref<Repository[]>([])
const repoListLoading = ref(false)
// Current repo's visibility, fetched for the breadcrumb lock icon. The route only
// carries the slug string, so the repo object is loaded separately here.
const currentRepoMeta = ref<Repository | null>(null)
const currentRepoIsPrivate = computed(() => {
  const meta = currentRepoMeta.value
  return !!meta && (meta.private === true || (meta.visibility ?? 'public') !== 'public')
})
const currentRepoVisibilityLabel = computed(() => {
  const v = currentRepoMeta.value?.visibility
  return v === 'internal' ? 'Internal' : 'Private'
})

async function loadCurrentRepoMeta() {
  if (!currentRepoSlug.value || !currentOrgProvider.value || !currentOrgSlug.value) {
    currentRepoMeta.value = null
    return
  }
  try {
    const res = await api.getRepo(currentOrgProvider.value, currentOrgSlug.value, currentRepoSlug.value)
    currentRepoMeta.value = res.data
  } catch {
    currentRepoMeta.value = null
  }
}
const repoSearch = ref('')
const searchPaletteOpen = ref(false)

const currentOrgSlug = computed(() => {
  if (typeof route.params.slug === 'string') {
    return route.params.slug
  }

  return orgStore.currentOrg?.slug || ''
})

const currentOrgProvider = computed(() => {
  if (typeof route.params.provider === 'string') {
    return route.params.provider
  }

  return orgStore.currentOrg?.provider || ''
})

const currentRepoSlug = computed(() => {
  if (typeof route.params.repoSlug === 'string') {
    return route.params.repoSlug
  }
  return ''
})

const currentOrg = computed(() => {
  if (!currentOrgSlug.value || !currentOrgProvider.value) {
    return orgStore.currentOrg
  }

  return orgStore.orgs.find((entry) => entry.slug === currentOrgSlug.value && entry.provider === currentOrgProvider.value) || orgStore.currentOrg
})

const searchOrgSlug = computed(() => currentOrgSlug.value || orgStore.currentOrg?.slug || '')
const searchOrgProvider = computed(() => currentOrgProvider.value || orgStore.currentOrg?.provider || '')

const filteredRepoList = computed(() => {
  const query = repoSearch.value.trim().toLowerCase()
  if (!query) {
    return repoList.value
  }

  return repoList.value.filter((repoItem) => (
    repoItem.name.toLowerCase().includes(query) || repoItem.slug.toLowerCase().includes(query)
  ))
})

const filteredOrgList = computed(() => {
  const query = orgSearch.value.trim().toLowerCase()
  if (!query) {
    return orgStore.orgs
  }

  return orgStore.orgs.filter((org) => (
    (org.display_name || org.name || org.slug).toLowerCase().includes(query)
  ))
})

const currentOrgName = computed(() => {
  if (!currentOrg.value) {
    return orgStore.currentOrg?.display_name || orgStore.currentOrg?.name || 'Select organization'
  }

  const org = currentOrg.value
  return org?.display_name || org?.name || 'Select organization'
})

const userInitials = computed(() => {
  const displayName = authStore.user?.display_name?.trim()
  if (!displayName) {
    return 'HB'
  }

  return displayName
    .split(/\s+/)
    .slice(0, 2)
    .map((part) => part[0]?.toUpperCase() || '')
    .join('')
})

interface NavItem { label: string; icon: unknown; to: string }
interface NavSection { title?: string; titleIcon?: unknown; items: NavItem[] }

const navSections = computed<NavSection[]>(() => {
  const sections: NavSection[] = []
  const hasOrg = Boolean(currentOrgSlug.value && currentOrgProvider.value)

  // Global destinations first, GitHub-drawer style.
  sections.push({
    items: [{ label: 'Organizations', icon: Building2, to: '/orgs' }],
  })

  if (hasOrg) {
    const orgBase = `/orgs/${currentOrgProvider.value}/${currentOrgSlug.value}`
    sections.push({
      title: currentOrgName.value,
      titleIcon: Building2,
      items: [
        { label: 'Overview', icon: LayoutDashboard, to: `${orgBase}/overview` },
        { label: 'Vulnerabilities', icon: ShieldAlert, to: `${orgBase}/vulnerabilities` },
        { label: 'Dependencies', icon: Package, to: `${orgBase}/dependencies` },
        { label: 'Repositories', icon: BookOpen, to: `${orgBase}/repos` },
        { label: 'Clients', icon: Users, to: `${orgBase}/clients` },
        { label: 'Teams', icon: Users, to: `${orgBase}/teams` },
        { label: 'Insights', icon: LineChart, to: `${orgBase}/insights` },
        { label: 'Settings', icon: Settings, to: `${orgBase}/settings` },
      ],
    })

    if (currentRepoSlug.value) {
      const repoBase = `${orgBase}/repos/${currentRepoSlug.value}`
      sections.push({
        title: currentRepoSlug.value,
        titleIcon: BookOpen,
        items: [
          { label: 'Overview', icon: LayoutDashboard, to: `${repoBase}/overview` },
          { label: 'Vulnerabilities', icon: ShieldAlert, to: `${repoBase}/vulnerabilities` },
          { label: 'Coverage', icon: Activity, to: `${repoBase}/coverage` },
          { label: 'Tests', icon: FlaskConical, to: `${repoBase}/tests` },
          { label: 'Dependencies', icon: Package, to: `${repoBase}/dependencies` },
          { label: 'Releases', icon: Rocket, to: `${repoBase}/releases` },
          { label: 'Deployments', icon: Container, to: `${repoBase}/deployments` },
          { label: 'Insights', icon: LineChart, to: `${repoBase}/insights` },
          { label: 'Settings', icon: Settings, to: `${repoBase}/settings` },
        ],
      })
    }
  }

  sections.push({ items: [{ label: 'API keys', icon: Settings, to: '/settings' }] })
  return sections
})

onMounted(async () => {
  if (orgStore.orgs.length === 0) {
    await orgStore.fetchOrgs()
  }

  syncCurrentOrg()
  await notificationsStore.fetchUnreadCount()
  notificationsStore.connect()

  document.addEventListener('click', handleDocumentClick)
  window.addEventListener('keydown', handleGlobalKeydown)

  try {
    const res = await api.getServerVersion()
    serverVersion.value = res.data
  } catch {
    // Version display is non-essential; ignore failures.
  }
})

function openInstallCli() {
  isInstallCliOpen.value = true
  isUserMenuOpen.value = false
}

onBeforeUnmount(() => {
  document.removeEventListener('click', handleDocumentClick)
  window.removeEventListener('keydown', handleGlobalKeydown)
  notificationsStore.disconnect()
})

watch(
  () => [route.params.provider, route.params.slug, route.params.repoSlug, route.query.q],
  () => {
    syncCurrentOrg()
    isDrawerOpen.value = false
    orgSearch.value = ''
    isOrgMenuOpen.value = false
    repoList.value = []
    repoSearch.value = ''
    isRepoMenuOpen.value = false
    void loadCurrentRepoMeta()
  },
  { immediate: true },
)

watch(
  () => orgStore.orgs,
  () => {
    syncCurrentOrg()
  },
  { deep: true },
)

function syncCurrentOrg() {
  const routeSlug = typeof route.params.slug === 'string' ? route.params.slug : ''
  const routeProvider = typeof route.params.provider === 'string' ? route.params.provider : ''
  const matchedOrg = orgStore.orgs.find((entry) => entry.slug === routeSlug && entry.provider === routeProvider)

  if (matchedOrg) {
    orgStore.setCurrentOrg(matchedOrg)
    return
  }

  if (!orgStore.currentOrg && orgStore.orgs[0]) {
    orgStore.setCurrentOrg(orgStore.orgs[0])
  }
}

function toggleUserMenu() {
  isUserMenuOpen.value = !isUserMenuOpen.value
}

function toggleNotifMenu() {
  isNotifMenuOpen.value = !isNotifMenuOpen.value
}

function toggleOrgMenu() {
  isOrgMenuOpen.value = !isOrgMenuOpen.value
}

async function toggleRepoMenu() {
  isRepoMenuOpen.value = !isRepoMenuOpen.value
  if (!isRepoMenuOpen.value || repoList.value.length > 0 || !currentOrgProvider.value || !currentOrgSlug.value) {
    return
  }

  repoListLoading.value = true
  try {
    const response = await api.listRepos(currentOrgProvider.value, currentOrgSlug.value)
    repoList.value = response.data.filter((repo) => repo.enrolled ?? true)
  } catch {
    repoList.value = []
  } finally {
    repoListLoading.value = false
  }
}

function handleDocumentClick(event: MouseEvent) {
  const target = event.target as Node | null

  if (target && userMenuRef.value && !userMenuRef.value.contains(target)) {
    isUserMenuOpen.value = false
  }

  if (target && orgMenuRef.value && !orgMenuRef.value.contains(target)) {
    isOrgMenuOpen.value = false
  }

  if (target && repoMenuRef.value && !repoMenuRef.value.contains(target)) {
    isRepoMenuOpen.value = false
  }

  if (target && notifMenuRef.value && !notifMenuRef.value.contains(target)) {
    isNotifMenuOpen.value = false
  }
}

function isActive(item: { to: string }) {
  if (item.to === '/settings') {
    return route.path.startsWith('/settings')
  }

  if (item.to === '/orgs') {
    return route.path === '/orgs'
  }

  return route.path === item.to || route.path.startsWith(`${item.to}/`)
}

async function handleLogout() {
  isUserMenuOpen.value = false
  await authStore.logout()
  await router.push('/login')
}

function handleGlobalKeydown(event: KeyboardEvent) {
  if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === 'k') {
    event.preventDefault()
    searchPaletteOpen.value = true
  }
  if (event.key === 'Escape' && isDrawerOpen.value) {
    isDrawerOpen.value = false
  }
}
</script>
