<template>
  <div class="overflow-hidden rounded-lg border border-surface-border-subtle bg-surface">
    <div class="flex items-center gap-2 border-b border-surface-border-subtle bg-surface-overlay px-3 py-1.5">
      <span class="min-w-0 flex-1 truncate font-mono text-[11px] text-gray-400">{{ path }}<span v-if="startLine">:{{ startLine }}</span></span>
      <span
        v-if="commitSha"
        class="font-mono text-[11px] text-gray-600"
      >{{ commitSha.slice(0, 7) }}</span>
      <a
        v-if="blobUrl"
        :href="blobUrl"
        target="_blank"
        rel="noopener noreferrer"
        class="text-[11px] text-accent underline underline-offset-2"
      >Open in forge</a>
    </div>

    <p
      v-if="loading"
      class="px-3 py-4 text-xs text-gray-500"
    >
      Loading source…
    </p>
    <p
      v-else-if="error"
      class="px-3 py-4 text-xs text-gray-500"
    >
      {{ error }}
    </p>
    <pre
      v-else
      class="overflow-x-auto px-0 py-2 text-[12px] leading-relaxed"
    ><code><span
      v-for="row in rows"
      :key="row.number"
      class="grid grid-cols-[3.5rem_1fr] hover:bg-white/[0.02]"
      :class="row.highlighted ? 'bg-danger/10' : ''"
    ><span
      class="select-none border-r pr-2 text-right font-mono text-[11px]"
      :class="row.highlighted ? 'border-danger/40 text-danger' : 'border-surface-border-subtle text-gray-600'"
    >{{ row.number }}</span><span class="whitespace-pre px-3 font-mono text-gray-300">{{ row.text || ' ' }}</span></span></code></pre>
  </div>
</template>

<script setup lang="ts">
import { computed, ref, watch } from 'vue'

import { api } from '@/api/client'
import { forgeBlobAtCommitUrl } from '@/lib/forgeLinks'

// The offending lines, in place. Source is streamed from the forge by the same
// endpoint the coverage view uses — nothing about a file's contents is stored,
// and the forge token stays server-side.
const props = defineProps<{
  provider: string
  slug: string
  repoSlug: string
  snapshotId: string
  path: string
  startLine?: number
  endLine?: number
  repoHtmlUrl?: string
  forgeProvider?: string
}>()

/** Lines of context kept on each side of the finding. */
const CONTEXT_LINES = 4

const content = ref('')
const commitSha = ref('')
const loading = ref(true)
const error = ref('')

watch(() => [props.snapshotId, props.path], load, { immediate: true })

async function load() {
  if (!props.snapshotId || !props.path) {
    loading.value = false
    error.value = 'No file recorded for this finding.'
    return
  }
  loading.value = true
  error.value = ''
  try {
    const response = await api.getCoverageSource(props.provider, props.slug, props.repoSlug, props.snapshotId, props.path)
    content.value = response.data?.content ?? ''
    commitSha.value = response.data?.commit_sha ?? ''
  } catch (loadError) {
    content.value = ''
    // A missing blob is ordinary — the commit can be gone, the file moved, or
    // no forge is connected — so it reads as a note, not as a failure.
    const reason = loadError instanceof Error ? loadError.message : 'the source could not be fetched'
    error.value = `Source preview unavailable — ${reason}.`
  } finally {
    loading.value = false
  }
}

const rows = computed(() => {
  if (!content.value) return []
  const start = props.startLine ?? 0
  const end = props.endLine ?? props.startLine ?? 0
  const from = start ? Math.max(1, start - CONTEXT_LINES) : 1
  const to = end ? end + CONTEXT_LINES : CONTEXT_LINES * 2

  return content.value
    .split('\n')
    .map((text, index) => ({ number: index + 1, text, highlighted: Boolean(start) && index + 1 >= start && index + 1 <= (end || start) }))
    .filter((row) => row.number >= from && row.number <= to)
})

const blobUrl = computed(() => forgeBlobAtCommitUrl(props.repoHtmlUrl, props.forgeProvider ?? props.provider, commitSha.value, props.path))
</script>
