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
                {{ coveredCount }}/{{ source.lines.length }} instrumented lines covered · {{ shortSha }}
              </template>
            </div>
          </div>
          <div class="flex items-center gap-3">
            <span class="flex items-center gap-1.5 text-[11px] text-gray-500">
              <span class="h-2.5 w-2.5 rounded-sm bg-emerald-500/60" /> covered
              <span class="ml-2 h-2.5 w-2.5 rounded-sm bg-red-500/60" /> uncovered
            </span>
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
              >
                <td class="w-12 select-none border-r border-surface-border-subtle px-2 text-right align-top text-[11px] text-gray-600 tabular-nums">
                  {{ row.number }}
                </td>
                <td
                  class="w-12 select-none border-r border-surface-border-subtle px-2 text-right align-top text-[11px] tabular-nums"
                  :class="hitsClass(row)"
                >
                  {{ row.hits === null ? '' : `${row.hits}×` }}
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
import { X } from 'lucide-vue-next'

import { api, type CoverageSource } from '@/api/client'

interface SourceRow {
  number: number
  text: string
  hits: number | null
}

const props = defineProps<{
  provider: string
  slug: string
  repoSlug: string
  snapshotId: string
  path: string
}>()

const emit = defineEmits<{ (e: 'close'): void }>()

const loading = ref(true)
const error = ref('')
const source = ref<CoverageSource | null>(null)

const rows = computed<SourceRow[]>(() => {
  if (!source.value) return []
  const hits = new Map(source.value.lines.map((line) => [line.number, line.hits]))
  return source.value.content.split('\n').map((text, index) => ({
    number: index + 1,
    text,
    hits: hits.get(index + 1) ?? null,
  }))
})

const coveredCount = computed(() => (source.value?.lines ?? []).filter((line) => line.hits > 0).length)
const shortSha = computed(() => source.value?.commit_sha.slice(0, 7) ?? '')

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
  if (row.hits > 0) return 'bg-emerald-500/15 shadow-[inset_3px_0_0_0_theme(colors.emerald.400)]'
  return 'bg-red-500/15 shadow-[inset_3px_0_0_0_theme(colors.red.500)]'
}

function hitsClass(row: SourceRow): string {
  if (row.hits === null) return 'text-gray-700'
  return row.hits > 0 ? 'text-emerald-300' : 'text-red-300'
}

function onKeydown(event: KeyboardEvent) {
  if (event.key === 'Escape') emit('close')
}
onMounted(() => document.addEventListener('keydown', onKeydown))
onUnmounted(() => document.removeEventListener('keydown', onKeydown))
</script>
