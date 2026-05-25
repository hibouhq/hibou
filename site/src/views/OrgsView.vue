<template>
  <div>
    <h2 class="mb-4 text-2xl font-bold">
      Organizations
    </h2>
    <div
      v-if="loading"
      class="text-gray-500"
    >
      Loading...
    </div>
    <div
      v-else-if="orgs.length === 0"
      class="text-gray-500"
    >
      No organizations found.
    </div>
    <ul
      v-else
      class="space-y-2"
    >
      <li
        v-for="org in orgs"
        :key="org.id"
      >
        <RouterLink
          :to="`/orgs/${org.provider}/${org.slug}`"
          class="block rounded-lg border border-gray-800 bg-gray-900 p-4 transition-colors hover:border-gray-600"
        >
          <div class="flex items-center gap-2 font-medium text-white">
            <ForgeIcon
              :provider="org.provider"
              size="sm"
              class="text-gray-400"
            />
            {{ org.display_name || org.name }}
          </div>
          <div class="mt-1 text-sm text-gray-500">
            {{ org.provider }} / {{ org.slug }}
          </div>
        </RouterLink>
      </li>
    </ul>
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted } from 'vue'
import { RouterLink } from 'vue-router'

import ForgeIcon from '@/components/ForgeIcon.vue'
import { useOrgStore } from '@/stores/org'

const orgStore = useOrgStore()
const orgs = computed(() => orgStore.orgs)
const loading = computed(() => orgStore.loading)

onMounted(async () => {
  if (orgStore.orgs.length === 0 && !orgStore.loading) {
    await orgStore.fetchOrgs()
  }
})
</script>
