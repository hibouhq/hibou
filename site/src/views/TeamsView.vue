<template>
  <div>
    <h2 class="mb-4 text-2xl font-bold">
      Teams
    </h2>
    <div v-if="loading" class="text-gray-500">
      Loading...
    </div>
    <div v-else-if="teams.length === 0" class="text-gray-500">
      No teams yet.
    </div>
    <ul v-else class="space-y-2">
      <li
        v-for="team in teams"
        :key="team.id"
        class="rounded-lg border border-gray-800 bg-gray-900 p-4"
      >
        <div class="font-medium">
          {{ team.name }}
        </div>
        <div class="text-sm text-gray-500">
          {{ team.slug }}
        </div>
      </li>
    </ul>
  </div>
</template>

<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { useRoute } from 'vue-router'

import { api, type Team } from '@/api/client'

const route = useRoute()
const teams = ref<Team[]>([])
const loading = ref(true)

onMounted(async () => {
  try {
    const res = await api.listTeams(route.params.slug as string)
    teams.value = res.data
  } catch {
    teams.value = []
  } finally {
    loading.value = false
  }
})
</script>