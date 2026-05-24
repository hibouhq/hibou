<template>
  <div>
    <h2 class="mb-4 text-2xl font-bold">
      Repositories
    </h2>
    <div v-if="loading" class="text-gray-500">
      Loading...
    </div>
    <div v-else-if="repos.length === 0" class="text-gray-500">
      No repositories synced yet.
    </div>
    <ul v-else class="space-y-2">
      <li v-for="repo in repos" :key="repo.id">
        <RouterLink
          :to="`/orgs/${provider}/${slug}/repos/${repo.slug}`"
          class="block rounded-lg border border-gray-800 bg-gray-900 p-4 transition-colors hover:border-gray-600"
        >
          <div class="flex items-center gap-2 font-medium">
            <ForgeIcon :provider="repo.provider" size="sm" class="text-gray-400" />
            {{ repo.name }}
          </div>
          <div class="ml-[22px] text-sm text-gray-500">
            {{ repo.default_branch }}
          </div>
        </RouterLink>
      </li>
    </ul>
  </div>
</template>

<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { RouterLink, useRoute } from 'vue-router'

import { api, type Repository } from '@/api/client'
import ForgeIcon from '@/components/ForgeIcon.vue'

const route = useRoute()
const provider = computed(() => route.params.provider as string)
const slug = computed(() => route.params.slug as string)
const repos = ref<Repository[]>([])
const loading = ref(true)

watch(
  [provider, slug],
  async ([newProvider, newSlug]) => {
    loading.value = true
    try {
      const res = await api.listRepos(newProvider, newSlug)
      repos.value = res.data
    } catch {
      repos.value = []
    } finally {
      loading.value = false
    }
  },
  { immediate: true },
)
</script>
