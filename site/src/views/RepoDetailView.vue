<template>
  <div>
    <h2 class="mb-4 text-2xl font-bold">
      {{ repo?.name || 'Repository' }}
    </h2>
    <div v-if="!repo" class="text-gray-500">
      Loading...
    </div>
    <div v-else>
      <div class="mb-6 grid grid-cols-2 gap-4">
        <div class="rounded-lg border border-gray-800 bg-gray-900 p-4">
          <div class="text-sm text-gray-500">
            Provider
          </div>
          <div>{{ repo.provider }}</div>
        </div>
        <div class="rounded-lg border border-gray-800 bg-gray-900 p-4">
          <div class="text-sm text-gray-500">
            Default Branch
          </div>
          <div>{{ repo.default_branch }}</div>
        </div>
      </div>
      <div class="space-y-4">
        <div
          v-for="tab in tabs"
          :key="tab"
          class="rounded-lg border border-gray-800 bg-gray-900 p-4"
        >
          <h3 class="mb-1 font-medium">
            {{ tab }}
          </h3>
          <p class="text-sm text-gray-500">
            Coming soon.
          </p>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { useRoute } from 'vue-router'

import { api, type Repository } from '@/api/client'

const route = useRoute()
const repo = ref<Repository | null>(null)
const tabs = ['Weaknesses', 'Dependencies', 'Runtime', 'Secrets']

onMounted(async () => {
  try {
    const res = await api.getRepo(route.params.slug as string, route.params.repoSlug as string)
    repo.value = res.data
  } catch {
    repo.value = null
  }
})
</script>