<template>
  <div class="flex h-screen bg-gray-950 text-gray-100">
    <aside class="flex w-64 flex-shrink-0 flex-col border-r border-gray-800">
      <div class="border-b border-gray-800 px-4 py-5">
        <h1 class="text-lg font-bold tracking-tight">
          Hibou
        </h1>
      </div>

      <div class="border-b border-gray-800 px-3 py-3">
        <select
          v-model="selectedOrgSlug"
          class="w-full rounded border border-gray-700 bg-gray-900 px-2 py-1.5 text-sm"
        >
          <option value="" disabled>
            Select organization
          </option>
          <option v-for="org in orgStore.orgs" :key="org.id" :value="org.slug">
            {{ org.display_name || org.name }}
          </option>
        </select>
      </div>

      <nav class="flex-1 space-y-1 px-3 py-4">
        <RouterLink to="/" class="nav-link" active-class="nav-link-active">
          <span>Dashboard</span>
        </RouterLink>
        <RouterLink to="/orgs" class="nav-link" active-class="nav-link-active">
          <span>Organizations</span>
        </RouterLink>
        <RouterLink
          v-if="selectedOrgSlug"
          :to="`/orgs/${selectedOrgSlug}/repos`"
          class="nav-link"
          active-class="nav-link-active"
        >
          <span>Repositories</span>
        </RouterLink>
        <RouterLink
          v-if="selectedOrgSlug"
          :to="`/orgs/${selectedOrgSlug}/teams`"
          class="nav-link"
          active-class="nav-link-active"
        >
          <span>Teams</span>
        </RouterLink>
        <RouterLink to="/uploads" class="nav-link" active-class="nav-link-active">
          <span>Uploads</span>
        </RouterLink>
        <RouterLink to="/settings" class="nav-link" active-class="nav-link-active">
          <span>Settings</span>
        </RouterLink>
      </nav>

      <div class="border-t border-gray-800 px-3 py-3">
        <div class="flex items-center justify-between gap-3">
          <span class="truncate text-sm text-gray-400">{{ authStore.user?.display_name }}</span>
          <button class="text-sm text-gray-500 hover:text-gray-300" @click="handleLogout">
            Logout
          </button>
        </div>
      </div>
    </aside>

    <main class="flex-1 overflow-auto p-6">
      <RouterView />
    </main>
  </div>
</template>

<script setup lang="ts">
import { onMounted, ref, watch } from 'vue'
import { RouterLink, RouterView, useRoute, useRouter } from 'vue-router'

import { useAuthStore } from '@/stores/auth'
import { useOrgStore } from '@/stores/org'

const authStore = useAuthStore()
const orgStore = useOrgStore()
const route = useRoute()
const router = useRouter()
const selectedOrgSlug = ref('')

onMounted(async () => {
  await orgStore.fetchOrgs()

  const routeSlug = typeof route.params.slug === 'string' ? route.params.slug : ''
  const initialOrg = orgStore.orgs.find((org) => org.slug === routeSlug) ?? orgStore.orgs[0]

  if (initialOrg) {
    selectedOrgSlug.value = initialOrg.slug
    orgStore.setCurrentOrg(initialOrg)
  }
})

watch(
  () => route.params.slug,
  (slug) => {
    if (typeof slug !== 'string') {
      return
    }

    const org = orgStore.orgs.find((entry) => entry.slug === slug)
    if (org) {
      selectedOrgSlug.value = org.slug
      orgStore.setCurrentOrg(org)
    }
  },
  { immediate: true },
)

watch(selectedOrgSlug, (slug) => {
  const org = orgStore.orgs.find((entry) => entry.slug === slug)
  if (org) {
    orgStore.setCurrentOrg(org)
  }
})

async function handleLogout() {
  await authStore.logout()
  await router.push('/login')
}
</script>

<style scoped>
.nav-link {
  @apply flex items-center rounded-md px-3 py-2 text-sm text-gray-400 transition-colors hover:bg-gray-800/50 hover:text-gray-100;
}

.nav-link-active {
  @apply bg-gray-800 text-gray-100;
}
</style>