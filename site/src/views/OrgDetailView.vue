<template>
  <div>
    <h2 class="mb-4 text-2xl font-bold">
      {{ org?.display_name || org?.name || 'Organization' }}
    </h2>
    <p v-if="!org" class="text-gray-500">
      Loading...
    </p>
    <div v-else class="text-gray-400">
      <p>Slug: {{ org.slug }}</p>
    </div>
  </div>
</template>

<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { useRoute } from 'vue-router'

import { api, type Organization } from '@/api/client'

const route = useRoute()
const org = ref<Organization | null>(null)

onMounted(async () => {
  try {
    const res = await api.getOrg(route.params.slug as string)
    org.value = res.data
  } catch {
    org.value = null
  }
})
</script>