<template>
  <Teleport to="body">
    <div
      class="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4"
      @click.self="emit('close')"
      @keydown.escape="emit('close')"
    >
      <div class="flex h-[85vh] w-full max-w-5xl flex-col overflow-hidden rounded-xl border border-surface-border bg-surface-raised shadow-2xl">
        <div class="flex items-center justify-between gap-3 border-b border-surface-border-subtle px-4 py-3">
          <div class="min-w-0">
            <div class="truncate font-mono text-sm text-gray-100">
              {{ path }}
            </div>
            <div class="mt-0.5 text-xs text-gray-500">
              <template v-if="source">
                {{ coveredCount }}/{{ source.lines.length }} instrumented lines covered ·
                <a
                  v-if="commitUrl"
                  :href="commitUrl"
                  target="_blank"
                  rel="noopener noreferrer"
                  class="font-mono transition hover:text-white hover:underline"
                  :title="`Open commit on ${forgeName}`"
                >{{ shortSha }}</a>
                <span v-else>{{ shortSha }}</span>
              </template>
            </div>
          </div>
          <div class="flex items-center gap-3">
            <span class="flex items-center gap-1.5 text-[11px] text-gray-500">
              <span class="h-2.5 w-2.5 rounded-sm bg-emerald-500/60" /> covered
              <span
                class="partial-coverage-swatch ml-2 h-2.5 w-2.5 rounded-sm"
                title="Line ran, but some branches never took both outcomes"
              /> partial
              <span class="ml-2 h-2.5 w-2.5 rounded-sm bg-red-500/60" /> uncovered
            </span>
            <a
              v-if="blobUrl"
              :href="blobUrl"
              target="_blank"
              rel="noopener noreferrer"
              class="inline-flex items-center gap-1.5 rounded-md border border-surface-border px-2 py-1.5 text-xs text-gray-400 transition hover:text-white"
              :title="`Open ${path} on ${forgeName}`"
            >
              <ExternalLink class="h-3.5 w-3.5" />
              <span class="hidden sm:inline">{{ forgeName }}</span>
            </a>
            <button
              type="button"
              class="rounded-md border border-surface-border p-1.5 text-gray-400 transition hover:text-white"
              aria-label="Close"
              @click="emit('close')"
            >
              <X class="h-4 w-4" />
            </button>
          </div>
        </div>

        <div
          v-if="loading"
          class="flex flex-1 items-center justify-center text-sm text-gray-500"
        >
          Loading source…
        </div>
        <div
          v-else-if="error"
          class="flex flex-1 items-center justify-center px-6 text-center text-sm text-gray-400"
        >
          {{ error }}
        </div>
        <div
          v-else-if="source"
          class="flex-1 overflow-auto"
        >
          <table class="w-full border-collapse font-mono text-xs leading-relaxed">
            <tbody>
              <tr
                v-for="row in rows"
                :key="row.number"
                :class="rowClass(row)"
                :title="rowTitle(row)"
              >
                <td class="w-12 select-none border-r border-surface-border-subtle px-2 text-right align-top text-[11px] text-gray-600 tabular-nums">
                  {{ row.number }}
                </td>
                <td
                  class="w-16 select-none whitespace-nowrap border-r border-surface-border-subtle px-2 text-right align-top text-[11px] tabular-nums"
                  :class="hitsClass(row)"
                >
                  <template v-if="row.hits !== null">
                    {{ row.hits }}×<span
                      v-if="isPartial(row)"
                      class="ml-1 text-amber-300/90"
                    >{{ row.branchesCovered }}/{{ row.branchesValid }}</span>
                  </template>
                </td>
                <td class="whitespace-pre px-3 align-top text-gray-200">
                  {{ row.text || ' ' }}
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
    </div>
  </Teleport>
</template>

<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref, watch } from 'vue'
import { ExternalLink, X } from 'lucide-vue-next'

import { api, type CoverageSource } from '@/api/client'
import { forgeBlobAtCommitUrl, forgeCommitUrl, forgeLabel } from '@/lib/forgeLinks'

interface SourceRow {
  number: number
  text: string
  hits: number | null
  branchesCovered: number
  branchesValid: number
}

function isPartial(row: SourceRow): boolean {
  return row.hits !== null && row.hits > 0 && row.branchesValid > 0 && row.branchesCovered < row.branchesValid
}

const props = defineProps<{
  provider: string
  slug: string
  repoSlug: string
  snapshotId: string
  path: string
  repoHtmlUrl?: string
}>()

const emit = defineEmits<{ (e: 'close'): void }>()

const loading = ref(true)
const error = ref('')
const source = ref<CoverageSource | null>(null)

const rows = computed<SourceRow[]>(() => {
  if (!source.value) return []
  const byNumber = new Map(source.value.lines.map((line) => [line.number, line]))
  return source.value.content.split('\n').map((text, index) => {
    const line = byNumber.get(index + 1)
    return {
      number: index + 1,
      text,
      hits: line ? line.hits : null,
      branchesCovered: line?.branches_covered ?? 0,
      branchesValid: line?.branches_valid ?? 0,
    }
  })
})

const coveredCount = computed(() => (source.value?.lines ?? []).filter((line) => line.hits > 0).length)
const shortSha = computed(() => source.value?.commit_sha.slice(0, 7) ?? '')
const forgeName = computed(() => forgeLabel(props.provider))
const commitUrl = computed(() => forgeCommitUrl(props.repoHtmlUrl, props.provider, source.value?.commit_sha ?? ''))
const blobUrl = computed(() => forgeBlobAtCommitUrl(props.repoHtmlUrl, props.provider, source.value?.commit_sha ?? '', props.path))

watch(() => [props.snapshotId, props.path], load, { immediate: true })

async function load() {
  loading.value = true
  error.value = ''
  source.value = null
  try {
    const response = await api.getCoverageSource(props.provider, props.slug, props.repoSlug, props.snapshotId, props.path)
    source.value = response.data ?? null
    if (!source.value) error.value = 'No source returned.'
  } catch (err) {
    error.value = err instanceof Error ? err.message : 'Failed to load source from the forge.'
  } finally {
    loading.value = false
  }
}

function rowClass(row: SourceRow): string {
  if (row.hits === null) return ''
  if (isPartial(row)) return 'partial-coverage-row shadow-[inset_3px_0_0_0_theme(colors.amber.400)]'
  if (row.hits > 0) return 'bg-emerald-500/15 shadow-[inset_3px_0_0_0_theme(colors.emerald.400)]'
  return 'bg-red-500/15 shadow-[inset_3px_0_0_0_theme(colors.red.500)]'
}

function hitsClass(row: SourceRow): string {
  if (row.hits === null) return 'text-gray-700'
  if (isPartial(row)) return 'text-amber-300'
  return row.hits > 0 ? 'text-emerald-300' : 'text-red-300'
}

// Explanation for a partially covered line: the line ran, but a condition never took both outcomes.
function rowTitle(row: SourceRow): string {
  if (!isPartial(row)) return ''
  return `Partially covered: ${row.branchesCovered} of ${row.branchesValid} branches taken`
}

function onKeydown(event: KeyboardEvent) {
  if (event.key === 'Escape') emit('close')
}
onMounted(() => document.addEventListener('keydown', onKeydown))
onUnmounted(() => document.removeEventListener('keydown', onKeydown))
</script>

<style scoped>
/* Partial coverage: the covered tint striped with the warning tint so the
   line reads "covered, but not fully". */
.partial-coverage-row {
  background-image: repeating-linear-gradient(
    135deg,
    rgb(16 185 129 / 0.16) 0px,
    rgb(16 185 129 / 0.16) 8px,
    rgb(245 158 11 / 0.10) 8px,
    rgb(245 158 11 / 0.10) 16px
  );
}

.partial-coverage-swatch {
  background-image: repeating-linear-gradient(
    135deg,
    rgb(16 185 129 / 0.6) 0px,
    rgb(16 185 129 / 0.6) 3px,
    rgb(245 158 11 / 0.55) 3px,
    rgb(245 158 11 / 0.55) 6px
  );
}
</style>
