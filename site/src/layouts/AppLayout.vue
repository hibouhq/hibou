<template>
  <div class="min-h-screen bg-surface text-[#e6edf3]">
    <header class="fixed inset-x-0 top-0 z-50 h-14 border-b border-surface-border bg-surface-raised/95 backdrop-blur">
      <div class="flex h-full items-center gap-3 px-4">
        <div class="flex items-center gap-3">
          <button
            class="flex h-9 w-9 items-center justify-center rounded-lg border border-surface-border bg-surface-overlay text-gray-300 transition hover:border-accent/50 hover:text-white md:hidden"
            type="button"
            aria-label="Toggle navigation"
            @click="isMobileNavOpen = !isMobileNavOpen"
          >
            <Menu
              v-if="!isMobileNavOpen"
              class="h-5 w-5"
            />
            <X
              v-else
              class="h-5 w-5"
            />
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
                <RouterLink
                  :to="`/orgs/${currentOrgProvider}/${currentOrgSlug}/repos/${currentRepoSlug}`"
                  class="max-w-[14rem] truncate font-semibold text-white transition hover:text-accent"
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

        <div class="hidden min-w-0 flex-1 px-4 md:flex md:justify-center">
          <label class="flex w-full max-w-xl items-center gap-2 rounded-lg border border-surface-border bg-surface-overlay px-3 py-1.5 text-sm text-gray-300 transition focus-within:border-accent/50 focus-within:text-white">
            <Search class="h-4 w-4 shrink-0 text-gray-500" />
            <input
              ref="searchInputRef"
              v-model="searchDraft"
              type="search"
              :disabled="!searchOrgSlug || !searchOrgProvider"
              :placeholder="searchPlaceholder"
              class="w-full bg-transparent text-sm text-gray-100 placeholder:text-gray-500 focus:outline-none disabled:cursor-not-allowed"
              @input="handleSearchInput"
              @keydown.enter.prevent="submitSearch(true)"
            >
            <span class="rounded-md border border-surface-border-subtle px-2 py-0.5 text-[10px] uppercase tracking-[0.16em] text-gray-500">
              Ctrl/Cmd K
            </span>
          </label>
        </div>

        <div class="ml-auto flex items-center gap-3">
          <button
            class="relative flex h-9 w-9 items-center justify-center rounded-lg border border-surface-border bg-surface-overlay text-gray-300 transition hover:border-accent/50 hover:text-white"
            type="button"
            aria-label="Notifications"
            title="Notifications"
          >
            <Bell class="h-5 w-5" />
            <span
              v-if="notificationsStore.unreadCount > 0"
              class="absolute -right-1 -top-1 inline-flex min-w-5 items-center justify-center rounded-full bg-danger px-1.5 text-[10px] font-semibold leading-5 text-white"
            >
              {{ Math.min(notificationsStore.unreadCount, 99) }}
            </span>
          </button>

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
                  class="flex w-full rounded-xl px-3 py-2 text-left text-sm text-gray-300 transition hover:bg-danger/15 hover:text-white"
                  type="button"
                  @click="handleLogout"
                >
                  Logout
                </button>
              </div>
            </div>
          </div>
        </div>
      </div>
    </header>

    <div
      v-if="isMobile && isMobileNavOpen"
      class="fixed inset-0 z-40 bg-black/60 md:hidden"
      @click="isMobileNavOpen = false"
    />

    <aside
      class="fixed bottom-0 left-0 top-14 z-40 flex flex-col border-r border-surface-border bg-surface-raised transition-transform duration-200"
      :class="[
        isMobile
          ? isMobileNavOpen
            ? 'translate-x-0 w-[200px]'
            : '-translate-x-full w-[200px]'
          : 'translate-x-0',
        !isMobile && isRailCollapsed ? 'w-14' : !isMobile ? 'w-[200px]' : '',
      ]"
    >
      <nav class="flex-1 space-y-1 px-2 py-3">
        <RouterLink
          v-for="item in navItems"
          :key="item.label"
          :to="item.to"
          class="group relative flex items-center gap-3 rounded-xl px-3 py-2.5 text-sm text-gray-400 transition hover:bg-white/5 hover:text-gray-100"
          :class="isActive(item) ? 'bg-accent-muted text-accent' : ''"
          @click="isMobileNavOpen = false"
        >
          <component
            :is="item.icon"
            class="h-5 w-5 shrink-0"
          />
          <span
            v-if="!isRailCollapsed || isMobile"
            class="truncate"
          >{{ item.label }}</span>
          <span
            v-else
            class="pointer-events-none absolute left-[calc(100%+0.75rem)] hidden rounded-lg border border-surface-border bg-surface-overlay px-2 py-1 text-xs text-gray-100 shadow-xl group-hover:flex"
          >
            {{ item.label }}
          </span>
        </RouterLink>
      </nav>

      <div
        v-if="!isMobile"
        class="border-t border-surface-border-subtle p-2"
      >
        <button
          class="flex w-full items-center justify-center rounded-xl px-3 py-2 text-gray-400 transition hover:bg-white/5 hover:text-white"
          type="button"
          @click="isRailCollapsed = !isRailCollapsed"
        >
          <ChevronRight
            v-if="isRailCollapsed"
            class="h-5 w-5"
          />
          <ChevronLeft
            v-else
            class="h-5 w-5"
          />
        </button>
      </div>
    </aside>

    <main
      class="min-h-screen px-4 pb-6 pt-[4.75rem] transition-[margin] duration-200 sm:px-6"
      :style="mainContentStyle"
    >
      <div class="mx-auto max-w-7xl">
        <RouterView />
      </div>
    </main>
  </div>
</template>

<script setup lang="ts">
import {
  Bell,
  Building2,
  BookOpen,
  ChevronDown,
  ChevronLeft,
  ChevronRight,
  LayoutDashboard,
  Menu,
  Search,
  ScrollText,
  Settings,
  Users,
  X,
} from 'lucide-vue-next'
import { computed, onBeforeUnmount, onMounted, ref, watch } from 'vue'
import { RouterLink, RouterView, useRoute, useRouter } from 'vue-router'

import { api, type Repository } from '@/api/client'
import { useAuthStore } from '@/stores/auth'
import { useNotificationsStore } from '@/stores/notifications'
import { useOrgStore } from '@/stores/org'

const authStore = useAuthStore()
const notificationsStore = useNotificationsStore()
const orgStore = useOrgStore()
const route = useRoute()
const router = useRouter()

const isMobile = ref(false)
const isMobileNavOpen = ref(false)
const isRailCollapsed = ref(true)
const isUserMenuOpen = ref(false)
const userMenuRef = ref<HTMLElement | null>(null)
const isOrgMenuOpen = ref(false)
const orgMenuRef = ref<HTMLElement | null>(null)
const orgSearch = ref('')
const isRepoMenuOpen = ref(false)
const repoMenuRef = ref<HTMLElement | null>(null)
const repoList = ref<Repository[]>([])
const repoListLoading = ref(false)
const repoSearch = ref('')
const searchInputRef = ref<HTMLInputElement | null>(null)
const searchDraft = ref('')
let searchDebounce: number | undefined

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
const searchPlaceholder = computed(() => (
  searchOrgSlug.value && searchOrgProvider.value
    ? 'Search vulnerabilities, components, findings, or clients'
    : 'Select an organization to search'
))

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

const navItems = computed(() => {
  const orgBase = currentOrgSlug.value && currentOrgProvider.value ? `/orgs/${currentOrgProvider.value}/${currentOrgSlug.value}` : '/orgs'

  return [
    { label: 'Dashboard', icon: LayoutDashboard, to: orgBase },
    { label: 'Repositories', icon: BookOpen, to: currentOrgSlug.value ? `${orgBase}/repos` : '/orgs' },
    { label: 'Clients', icon: Users, to: currentOrgSlug.value ? `${orgBase}/clients` : '/orgs' },
    { label: 'Teams', icon: Users, to: currentOrgSlug.value ? `${orgBase}/teams` : '/orgs' },
    { label: 'Audit Logs', icon: ScrollText, to: currentOrgSlug.value ? `${orgBase}/audit` : '/orgs' },
    { label: 'Settings', icon: Settings, to: '/settings' },
  ]
})

const mainContentStyle = computed(() => ({
  marginLeft: isMobile.value ? '0' : isRailCollapsed.value ? '56px' : '200px',
}))

onMounted(async () => {
  if (orgStore.orgs.length === 0) {
    await orgStore.fetchOrgs()
  }

  syncViewportState()
  syncCurrentOrg()
  await notificationsStore.fetchUnreadCount()
  notificationsStore.connect()

  window.addEventListener('resize', syncViewportState)
  document.addEventListener('click', handleDocumentClick)
  window.addEventListener('keydown', handleGlobalKeydown)
})

onBeforeUnmount(() => {
  window.removeEventListener('resize', syncViewportState)
  document.removeEventListener('click', handleDocumentClick)
  window.removeEventListener('keydown', handleGlobalKeydown)
  if (searchDebounce) {
    window.clearTimeout(searchDebounce)
  }
  notificationsStore.disconnect()
})

watch(
  () => [route.params.provider, route.params.slug, route.params.repoSlug, route.query.q],
  () => {
    syncCurrentOrg()
    isMobileNavOpen.value = false
    orgSearch.value = ''
    isOrgMenuOpen.value = false
    repoList.value = []
    repoSearch.value = ''
    isRepoMenuOpen.value = false

    if (typeof route.query.q === 'string') {
      searchDraft.value = route.query.q
    } else if (route.name !== 'search') {
      searchDraft.value = ''
    }
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

function syncViewportState() {
  const width = window.innerWidth

  isMobile.value = width < 768
  if (isMobile.value) {
    isRailCollapsed.value = true
    return
  }

  isMobileNavOpen.value = false
  isRailCollapsed.value = width < 1024
}

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
    repoList.value = response.data
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

function handleSearchInput() {
  if (searchDebounce) {
    window.clearTimeout(searchDebounce)
  }

  const trimmed = searchDraft.value.trim()
  if (trimmed.length < 2) {
    return
  }

  searchDebounce = window.setTimeout(() => {
    void submitSearch(false)
  }, 300)
}

async function submitSearch(push = false) {
  const query = searchDraft.value.trim()
  if (query.length < 2 || !searchOrgSlug.value || !searchOrgProvider.value) {
    return
  }

  const location = {
    name: 'search',
    params: { provider: searchOrgProvider.value, slug: searchOrgSlug.value },
    query: { q: query },
  }

  if (push || route.name !== 'search') {
    await router.push(location)
    return
  }

  await router.replace(location)
}

function handleGlobalKeydown(event: KeyboardEvent) {
  if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === 'k') {
    event.preventDefault()
    searchInputRef.value?.focus()
    searchInputRef.value?.select()
  }
}
</script>
