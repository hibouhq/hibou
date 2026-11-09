<template>
  <section class="space-y-5">
    <header class="flex items-start justify-between gap-4">
      <div>
        <h2 class="text-lg font-semibold text-white">
          Forge delivery
        </h2>
        <p class="mt-1 text-sm text-gray-400">
          Forge metadata freshness is separate from uploaded analysis and published checks.
        </p>
      </div>
      <button
        class="rounded-md border border-surface-border px-3 py-1.5 text-sm text-gray-300 hover:bg-surface-raised disabled:opacity-50"
        :disabled="loading"
        @click="load"
      >
        {{ loading ? 'Loading…' : 'Reload' }}
      </button>
    </header>
    <p
      v-if="error"
      role="alert"
      class="rounded-md border border-danger/30 bg-danger/10 p-4 text-sm text-red-200"
    >
      {{ error }}
    </p>
    <p
      v-if="!loading && !error && !forges.length"
      class="text-sm text-gray-500"
    >
      No forges configured.
    </p>
    <article
      v-for="forge in forges"
      :key="forge.provider"
      class="overflow-hidden rounded-md border border-surface-border"
    >
      <header class="flex items-center justify-between border-b border-surface-border-subtle bg-surface-raised px-4 py-3">
        <h3 class="font-mono text-sm text-white">
          {{ forge.provider }}
        </h3>
        <span class="rounded border border-surface-border px-2 py-0.5 text-xs uppercase tracking-wide text-accent">{{ forge.mode }}</span>
      </header>
      <p
        v-if="forge.mode === 'webhook'"
        class="p-4 text-sm text-gray-400"
      >
        Webhook delivery is enabled. No periodic metadata reconciliation is configured.
      </p>
      <template v-else>
        <p class="px-4 py-3 text-xs text-gray-400">
          {{ forge.mode === 'poll' ? 'Inbound webhooks are disabled.' : 'Webhooks and API reconciliation are enabled.' }}
          Polling cannot inspect commits pushed and removed between observations. Use CI or webhooks when every-push scanning is required.
        </p>
        <p
          v-if="!forge.scopes.length"
          class="px-4 pb-4 text-sm text-amber-300"
        >
          Waiting for the reconciliation worker to initialize.
        </p>
        <div
          v-else
          class="overflow-x-auto"
        >
          <table class="w-full text-left text-xs">
            <thead class="border-y border-surface-border-subtle text-gray-500">
              <tr>
                <th class="px-4 py-2">
                  Scope / capability
                </th><th class="px-4 py-2">
                  Last success
                </th><th class="px-4 py-2">
                  Next attempt
                </th><th class="px-4 py-2">
                  State
                </th>
              </tr>
            </thead>
            <tbody class="divide-y divide-surface-border-subtle">
              <tr
                v-for="scope in forge.scopes"
                :key="scope.id"
              >
                <td class="px-4 py-3">
                  <p class="text-gray-200">
                    {{ scope.kind.replaceAll('_', ' ') }}
                  </p>
                  <p class="mt-1 font-mono text-[10px] text-gray-500">
                    {{ scope.scope }}
                  </p>
                </td>
                <td class="whitespace-nowrap px-4 py-3 text-gray-400">
                  {{ formatDate(scope.last_success_at) }}
                </td>
                <td class="whitespace-nowrap px-4 py-3 text-gray-400">
                  {{ formatDate(scope.next_due_at) }}
                </td>
                <td class="max-w-md px-4 py-3">
                  <p
                    v-if="scope.last_error"
                    class="break-words text-red-300"
                  >
                    {{ scope.last_error }}
                  </p>
                  <p
                    v-else-if="!scope.last_success_at"
                    class="text-amber-300"
                  >
                    Not reconciled yet
                  </p>
                  <p
                    v-else-if="Date.parse(scope.next_due_at) < observedAt"
                    class="text-amber-300"
                  >
                    Due; waiting for worker / API budget
                  </p>
                  <p
                    v-else
                    class="text-emerald-300"
                  >
                    Last observation completed
                  </p>
                  <p
                    v-if="scope.note"
                    class="mt-1 text-amber-300"
                  >
                    {{ scope.note }}
                  </p>
                  <p
                    v-if="scope.gate_pending"
                    class="mt-1 text-amber-300"
                  >
                    Metadata applied; check publication is pending.
                  </p>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </template>
    </article>
    <p class="text-xs text-gray-500">
      Mode and permissions are deployment-managed. An Actions permission error affects build detection; it does not prove that uploaded analysis failed.
      Successful unchanged polling runs are sampled hourly; material changes and errors are retained.
    </p>
  </section>
</template>

<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { api, type ForgeDeliveryStatus } from '@/api/client'

const forges = ref<ForgeDeliveryStatus[]>([])
const loading = ref(false)
const error = ref('')
const observedAt = ref(Date.now())

function formatDate(value: string | null): string {
  return value ? new Date(value).toLocaleString() : 'Never'
}

async function load(): Promise<void> {
  loading.value = true
  error.value = ''
  try {
    const response = await api.getForgeDeliveryStatus()
    forges.value = response.data
    observedAt.value = Date.now()
  } catch (cause) {
    error.value = cause instanceof Error ? cause.message : 'Failed to load forge delivery status'
  } finally {
    loading.value = false
  }
}

onMounted(load)
</script>
