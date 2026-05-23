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
          :to="`/orgs/${slug}/repos/${repo.slug}`"
          class="block rounded-lg border border-gray-800 bg-gray-900 p-4 transition-colors hover:border-gray-600"
        >
          <div class="font-medium">
            {{ repo.name }}
          </div>
          <div class="text-sm text-gray-500">
            {{ repo.provider }} · {{ repo.default_branch }}
          </div>
        </RouterLink>
      </li>
    </ul>
  </div>
</template>

<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { RouterLink, useRoute } from 'vue-router'

import { api, type Repository } from '@/api/client'

const route = useRoute()
const slug = route.params.slug as string
const repos = ref<Repository[]>([])
const loading = ref(true)

onMounted(async () => {
  try {
    const res = await api.listRepos(slug)
    repos.value = res.data
  } catch {
    repos.value = []
  } finally {
    loading.value = false
  }
})
</script>