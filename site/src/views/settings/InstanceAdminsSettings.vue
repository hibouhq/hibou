<template>
  <div class="space-y-5">
    <div>
      <h2 class="text-lg font-semibold text-white">
        Instance administrators
      </h2>
      <p class="mt-1 text-sm text-gray-400">
        Who can manage instance-wide settings (announcement banners, instance audit). Distinct from organization and repository admin roles.
      </p>
    </div>

    <div
      v-if="loadError"
      class="rounded-md border border-danger/30 bg-danger/10 px-4 py-3 text-sm text-red-200"
    >
      {{ loadError }}
    </div>

    <template v-else>
      <div
        v-if="loading"
        class="py-6 text-sm text-gray-500"
      >
        Loading administrators…
      </div>

      <div
        v-else
        class="overflow-hidden rounded-md border border-surface-border"
      >
        <ul class="divide-y divide-surface-border-subtle">
          <li
            v-for="admin in admins"
            :key="admin"
            class="flex items-center gap-2.5 px-4 py-2.5"
          >
            <ShieldCheck class="h-4 w-4 shrink-0 text-accent" />
            <span class="font-mono text-sm text-gray-200">{{ admin }}</span>
            <span
              v-if="admin === currentEmail"
              class="rounded-full border border-surface-border px-2 py-0.5 text-[10px] font-medium text-gray-400"
            >you</span>
          </li>
          <li
            v-if="admins.length === 0"
            class="px-4 py-6 text-center text-sm text-gray-500"
          >
            No instance administrators configured.
          </li>
        </ul>
      </div>

      <div class="rounded-md border border-surface-border bg-surface-raised p-4 text-sm text-gray-400">
        <p class="flex items-center gap-2 font-medium text-gray-300">
          <Info class="h-4 w-4 shrink-0 text-gray-500" />
          This list is managed by the deployment, not from this page.
        </p>
        <p class="mt-2">
          It comes from a Secret mounted into the server (or the
          <code class="rounded bg-surface-overlay px-1.5 py-0.5 font-mono text-xs">HIBOU_INSTANCE_ADMINS</code>
          setting) and is re-read live — changes to the Secret take effect within about a minute, no restart needed.
          Every addition and removal is recorded in the
          <RouterLink
            :to="{ name: 'settings-instance-audit' }"
            class="text-accent transition hover:underline"
          >
            instance audit log
          </RouterLink>.
        </p>
      </div>
    </template>
  </div>
</template>

<script setup lang="ts">
import { Info, ShieldCheck } from 'lucide-vue-next'
import { computed, onMounted, ref } from 'vue'
import { RouterLink } from 'vue-router'

import { api } from '@/api/client'
import { useAuthStore } from '@/stores/auth'

const auth = useAuthStore()
const admins = ref<string[]>([])
const loading = ref(true)
const loadError = ref('')

const currentEmail = computed(() => (auth.user?.email ?? '').toLowerCase())

onMounted(async () => {
  try {
    const response = await api.listInstanceAdmins()
    admins.value = response.data ?? []
  } catch (error) {
    loadError.value = error instanceof Error ? error.message : 'Failed to load administrators'
  } finally {
    loading.value = false
  }
})
</script>
