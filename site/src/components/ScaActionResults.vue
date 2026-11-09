<template>
  <section
    v-if="!dismissed && (error || results.length)"
    class="rounded-xl border bg-surface-raised px-4 py-3 text-xs"
    :class="hasErrors ? 'border-amber-500/25' : 'border-surface-border'"
    aria-live="polite"
    aria-label="Dependency analysis request"
  >
    <div class="flex items-start gap-2.5">
      <component
        :is="hasErrors ? CircleAlert : CircleCheck"
        class="mt-0.5 h-4 w-4 shrink-0"
        :class="hasErrors ? 'text-amber-300' : 'text-gray-400'"
        aria-hidden="true"
      />
      <div class="min-w-0 flex-1">
        <h2 class="font-medium text-gray-200">
          {{ error ? 'Dependency analysis unavailable' : hasErrors ? 'Some repositories need attention' : 'Dependency analysis requested' }}
        </h2>
        <p
          v-if="error"
          class="mt-1 max-w-3xl leading-relaxed text-gray-400"
        >
          {{ error }}
        </p>
        <ul
          v-if="results.length"
          class="mt-1.5 space-y-1"
        >
          <li
            v-for="result in results"
            :key="result.provider_id"
            class="flex flex-wrap gap-x-2 gap-y-0.5 leading-relaxed"
          >
            <span class="font-mono text-gray-400">{{ result.provider_id }}</span>
            <span :class="result.status === 'failed' ? 'text-amber-200/90' : 'text-gray-400'">{{ result.status === 'failed' ? result.error ? scaErrorMessage(new Error(result.error)) : 'Request failed. Check repository access and retry.' : result.job_id ? 'Analysis queued' : 'Existing inventory available' }}</span>
            <RouterLink
              v-if="result.status !== 'failed' && result.repo_slug"
              :to="{ name: 'repo-dependencies', params: { provider, slug, repoSlug: result.repo_slug } }"
              class="font-medium text-accent hover:underline"
            >
              Open dependencies →
            </RouterLink>
          </li>
        </ul>
      </div>
      <button
        type="button"
        class="-mr-1 rounded p-1 text-gray-500 transition hover:bg-surface-overlay hover:text-gray-200"
        aria-label="Dismiss dependency analysis notice"
        @click="dismiss"
      >
        <X
          class="h-4 w-4"
          aria-hidden="true"
        />
      </button>
    </div>
  </section>
</template>

<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { CircleAlert, CircleCheck, X } from 'lucide-vue-next'
import { RouterLink } from 'vue-router'
import type { ScaEnableResult } from '@/api/client'
import { scaErrorMessage } from '@/lib/sca'

const props = defineProps<{ provider: string; slug: string; results: ScaEnableResult[]; error: string }>()
const emit = defineEmits<{ dismiss: [] }>()
const dismissed = ref(false)
const hasErrors = computed(() => !!props.error || props.results.some(result => result.status === 'failed'))
watch([() => props.error, () => props.results], () => { dismissed.value = false })
function dismiss() {
  dismissed.value = true
  emit('dismiss')
}
</script>
