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
      v-else-if="!coverage || coverage.producers.length === 0"
      class="mt-3 text-xs text-gray-500"
    >
      No producer runs recorded for this snapshot.
    </p>
    <ul
      v-else
      class="mt-3 space-y-1.5"
    >
      <li
        v-for="producer in coverage.producers"
        :key="producer.producer"
        class="rounded-lg border px-2.5 py-2"
        :class="producer.status === 'missing' ? 'border-amber-500/30 bg-amber-500/[0.06]' : 'border-surface-border-subtle bg-surface-overlay/40'"
      >
        <div class="flex items-center gap-2">
          <span
            class="h-2 w-2 shrink-0 rounded-full"
            :class="dotClass(producer)"
          />
          <span class="min-w-0 flex-1 truncate font-mono text-xs text-gray-200">{{ producer.producer }}</span>
          <span
            class="shrink-0 text-[11px]"
            :class="producer.status === 'missing' || producer.outcome === 'failed' ? 'text-amber-300' : 'text-gray-500'"
          >{{ stateLabel(producer) }}</span>
        </div>
        <p
          v-if="producer.status === 'missing'"
          class="mt-1 text-[11px] text-amber-200/80"
        >
          Ran on <span class="font-mono">{{ shortSha(coverage.previous_commit_sha) }}</span>, not on this snapshot. Its findings were not re-checked.
        </p>
        <p
          v-else
          class="mt-1 text-[11px] text-gray-500"
        >
          {{ detailLine(producer) }}
        </p>
        <p
          v-if="producer.detail"
          class="mt-1 truncate text-[11px] text-gray-500"
          :title="producer.detail"
        >
          {{ producer.detail }}
        </p>
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
                class="min-w-0 flex-1 truncate font-mono text-gray-300"
                :title="skipped.path"
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
import { dotClass, detailLine, reasonLabel, shortSha, stateLabel } from '@/lib/scanCoverage'

const props = defineProps<{
  provider: string
  slug: string
  repoSlug: string
  snapshotId: string
}>()

const coverage = ref<SnapshotProducerRuns | null>(null)
const loading = ref(false)

watch(
  () => [props.provider, props.slug, props.repoSlug, props.snapshotId],
  () => {
    void load()
  },
  { immediate: true },
)

async function load() {
  if (!props.provider || !props.slug || !props.repoSlug || !props.snapshotId) {
    coverage.value = null
    return
  }
  loading.value = true
  try {
    const response = await api.getSnapshotProducerRuns(props.provider, props.slug, props.repoSlug, props.snapshotId)
    coverage.value = response.data
  } catch {
    coverage.value = null
  } finally {
    loading.value = false
  }
}

</script>
