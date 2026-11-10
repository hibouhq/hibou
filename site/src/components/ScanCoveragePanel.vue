<template>
  <section class="rounded-xl border border-surface-border bg-surface-raised/40 p-4">
    <div class="flex items-baseline justify-between gap-2">
      <h2 class="text-sm font-semibold text-white">
        Scan coverage
      </h2>
      <span
        v-if="coverage?.previous_commit_sha"
        class="text-[11px] text-gray-500"
        :title="`Compared with the previous snapshot of this branch, ${coverage.previous_commit_sha}`"
      >
        vs <span class="font-mono">{{ shortSha(coverage.previous_commit_sha) }}</span>
      </span>
    </div>

    <p
      v-if="loading"
      class="mt-3 text-xs text-gray-500"
    >
      Loading coverage…
    </p>
    <p
      v-else-if="error"
      class="mt-3 text-xs text-red-200"
      role="alert"
    >
      {{ error }}
    </p>
    <p
      v-else-if="!coverage || coverage.producers.length === 0"
      class="mt-3 text-xs text-gray-500"
    >
      No producer runs recorded for this snapshot.
    </p>
    <ul
      v-else
      class="mt-3 divide-y divide-surface-border-subtle"
    >
      <li
        v-for="producer in coverage.producers"
        :key="producer.producer"
        class="min-w-0 py-3 first:pt-0 last:pb-0"
      >
        <div class="space-y-2">
          <div class="flex items-start gap-2">
            <span
              class="mt-1 h-2 w-2 shrink-0 rounded-full"
              :class="dotClass(producer)"
              aria-hidden="true"
            />
            <h3 class="min-w-0 break-words text-xs font-medium leading-relaxed text-gray-200 [overflow-wrap:anywhere]">
              {{ producerLabel(producer.producer) }}
            </h3>
          </div>
          <span
            class="ml-4 inline-flex rounded border px-1.5 py-0.5 text-[11px]"
            :class="producer.status === 'missing' || producer.outcome === 'partial'
              ? 'border-amber-500/25 bg-amber-500/5 text-amber-200'
              : producer.outcome === 'failed'
                ? 'border-danger/25 bg-danger/5 text-red-200'
                : 'border-surface-border-subtle text-gray-400'"
          >{{ stateLabel(producer) }}</span>
        </div>
        <p
          v-if="producer.status === 'missing'"
          class="mt-2 text-xs leading-relaxed text-amber-200/80"
        >
          Ran on <span class="font-mono">{{ shortSha(coverage.previous_commit_sha) }}</span>, not on this snapshot. Its findings were not re-checked.
        </p>
        <details class="mt-2 text-xs">
          <summary class="cursor-pointer text-gray-400 hover:text-gray-200">
            Run details
          </summary>
          <div class="mt-2 space-y-2 break-words leading-relaxed text-gray-400 [overflow-wrap:anywhere]">
            <p class="font-mono text-[11px]">
              {{ producer.producer }}
            </p>
            <p>{{ detailLine(producer) }}</p>
            <ul
              v-if="producer.detail"
              class="max-h-60 space-y-2 overflow-y-auto"
            >
              <li
                v-for="(detail, index) in producer.detail.split(';').map(value => value.trim()).filter(Boolean)"
                :key="index"
              >
                {{ detail }}
              </li>
            </ul>
          </div>
        </details>
        <details
          v-if="producer.skipped_files.length > 0"
          class="mt-1 text-[11px]"
        >
          <summary class="cursor-pointer text-amber-300/90 hover:text-amber-200">
            {{ producer.skipped_files.length }} {{ producer.skipped_files.length === 1 ? 'file' : 'files' }} not analysed
          </summary>
          <ul class="mt-1 max-h-40 space-y-0.5 overflow-y-auto pl-3">
            <li
              v-for="skipped in producer.skipped_files"
              :key="skipped.path"
              class="flex gap-2"
            >
              <span
                class="min-w-0 flex-1 break-words font-mono text-gray-300 [overflow-wrap:anywhere]"
              >{{ skipped.path }}</span>
              <span class="shrink-0 text-gray-500">{{ reasonLabel(skipped.reason) }}</span>
            </li>
          </ul>
        </details>
      </li>
    </ul>
  </section>
</template>

<script setup lang="ts">
import { ref, watch } from 'vue'

import { api, type SnapshotProducerRuns } from '@/api/client'
import { dotClass, detailLine, producerLabel, reasonLabel, shortSha, stateLabel } from '@/lib/scanCoverage'

const props = defineProps<{
  provider: string
  slug: string
  repoSlug: string
  snapshotId: string
}>()

const coverage = ref<SnapshotProducerRuns | null>(null)
const loading = ref(false)
const error = ref('')
let generation = 0

watch(
  () => [props.provider, props.slug, props.repoSlug, props.snapshotId],
  () => {
    void load()
  },
  { immediate: true },
)

async function load() {
  const request = ++generation
  coverage.value = null
  error.value = ''
  if (!props.provider || !props.slug || !props.repoSlug || !props.snapshotId) {
    loading.value = false
    return
  }
  loading.value = true
  try {
    const response = await api.getSnapshotProducerRuns(props.provider, props.slug, props.repoSlug, props.snapshotId)
    if (request === generation) coverage.value = response.data
  } catch {
    if (request === generation) error.value = 'Could not load scan coverage. Refresh to try again.'
  } finally {
    if (request === generation) loading.value = false
  }
}

</script>
