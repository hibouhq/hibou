<template>
  <div
    ref="rootRef"
    class="relative"
  >
    <button
      type="button"
      class="inline-flex max-w-[14rem] items-center gap-1.5 rounded-md border px-3 py-1.5 text-sm transition"
      :class="open || activePreset
        ? 'border-accent/40 bg-accent-muted text-accent'
        : 'border-surface-border bg-surface-raised text-gray-300 hover:border-surface-border-subtle hover:text-gray-100'"
      aria-haspopup="true"
      :aria-expanded="open"
      :title="activePreset ? `Preset: ${activePreset.name}` : 'Saved searches'"
      @click.stop="toggle"
    >
      <Bookmark class="h-3.5 w-3.5 shrink-0" />
      <span class="truncate">{{ activePreset?.name ?? 'Presets' }}</span>
      <span class="text-xs">▾</span>
    </button>

    <Transition
      enter-active-class="transition duration-150 ease-out"
      enter-from-class="translate-y-1 opacity-0"
      enter-to-class="translate-y-0 opacity-100"
      leave-active-class="transition duration-100 ease-in"
      leave-from-class="translate-y-0 opacity-100"
      leave-to-class="translate-y-1 opacity-0"
    >
      <div
        v-if="open"
        class="absolute right-0 top-[calc(100%+0.5rem)] z-30 w-72 overflow-hidden rounded-lg border border-surface-border bg-surface-raised shadow-lg"
      >
        <div class="px-3 pb-1 pt-2.5 text-xs font-medium tracking-[0.12em] text-gray-500">
          Built-in
        </div>
        <div
          role="listbox"
          class="py-1"
        >
          <button
            v-for="preset in builtins"
            :key="preset.id"
            role="option"
            type="button"
            :aria-selected="preset.id === activePreset?.id"
            :title="preset.description"
            :disabled="!isApplicable(preset)"
            class="flex w-full items-center justify-between px-3 py-2 text-left text-sm transition disabled:cursor-not-allowed disabled:opacity-40"
            :class="preset.id === activePreset?.id ? 'bg-accent-muted text-accent' : 'text-gray-300 hover:bg-surface-overlay hover:text-gray-100'"
            @click="apply(preset)"
          >
            <span class="truncate">{{ preset.name }}</span>
            <span v-if="preset.id === activePreset?.id">✓</span>
          </button>
        </div>

        <div class="mx-3 my-1 border-t border-surface-border-subtle" />
        <div class="px-3 pb-1 pt-2 text-xs font-medium tracking-[0.12em] text-gray-500">
          Saved
        </div>
        <p
          v-if="loadError"
          class="px-3 py-2 text-xs text-danger"
          :title="loadError"
        >
          Saved presets could not be loaded.
        </p>
        <p
          v-else-if="savedEntries.length === 0"
          class="px-3 py-2 text-xs text-gray-500"
        >
          No saved presets yet.
        </p>
        <div
          v-else
          role="listbox"
          class="max-h-64 overflow-y-auto py-1"
        >
          <div
            v-for="preset in savedEntries"
            :key="preset.id"
            class="group flex items-center"
            :class="preset.id === activePreset?.id ? 'bg-accent-muted' : 'hover:bg-surface-overlay'"
          >
            <button
              role="option"
              type="button"
              :aria-selected="preset.id === activePreset?.id"
              :title="isApplicable(preset) ? preset.query : 'Uses filters this list does not have'"
              :disabled="!isApplicable(preset)"
              class="flex min-w-0 flex-1 items-center justify-between px-3 py-2 text-left text-sm transition disabled:cursor-not-allowed disabled:opacity-40"
              :class="preset.id === activePreset?.id ? 'text-accent' : 'text-gray-300 hover:text-gray-100'"
              @click="apply(preset)"
            >
              <span class="truncate">{{ preset.name }}</span>
              <span v-if="preset.id === activePreset?.id">✓</span>
            </button>
            <button
              type="button"
              class="mr-1.5 rounded p-1 text-gray-500 opacity-0 transition hover:text-danger focus:opacity-100 group-hover:opacity-100"
              :aria-label="`Delete preset ${preset.name}`"
              title="Delete preset"
              @click.stop="removePreset(preset)"
            >
              <Trash2 class="h-3.5 w-3.5" />
            </button>
          </div>
        </div>

        <div class="border-t border-surface-border-subtle">
          <button
            type="button"
            class="flex w-full items-center gap-2 px-3 py-2 text-left text-sm text-gray-300 transition hover:bg-surface-overlay hover:text-gray-100 disabled:cursor-not-allowed disabled:opacity-40"
            :disabled="!canSave"
            :title="saveHint"
            @click="saveCurrent"
          >
            <BookmarkPlus class="h-3.5 w-3.5" />
            Save current query…
          </button>
        </div>
      </div>
    </Transition>

    <PresetDialog
      :open="dialog.open"
      :mode="dialog.mode"
      :query="dialog.query"
      :filters="filters"
      :preset-name="dialog.presetName"
      :existing-presets="presets"
      :busy="dialog.busy"
      :error="dialog.error"
      @save="savePreset"
      @delete="deletePreset"
      @cancel="dialog.open = false"
    />
  </div>
</template>

<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, ref } from 'vue'
import { Bookmark, BookmarkPlus, Trash2 } from 'lucide-vue-next'

import PresetDialog from './PresetDialog.vue'

import type { SearchPresetSurface } from '@/api/client'
import { useSearchPresets } from '@/composables/useSearchPresets'
import { useToast } from '@/composables/useToast'
import type { FilterBarFilter } from '@/lib/filterBarQuery'
import {
  barStateFromQuery,
  canonicalBarQuery,
  findActivePreset,
  findPresetByName,
  type PresetEntry,
} from '@/lib/searchPresets'

const props = defineProps<{
  surface: SearchPresetSurface
  filters: FilterBarFilter[]
  builtins: PresetEntry[]
  // The bar text for the current view state.
  query: string
}>()

const emit = defineEmits<{
  (event: 'apply', query: string): void
}>()

const { presets, loadError, load, create, update, remove } = useSearchPresets(props.surface)
const toast = useToast()

const open = ref(false)
const rootRef = ref<HTMLElement | null>(null)

const savedEntries = computed<PresetEntry[]>(() => presets.value.map(preset => ({
  id: preset.id,
  name: preset.name,
  query: preset.query,
  builtin: false,
})))
const activePreset = computed(() => findActivePreset([...props.builtins, ...savedEntries.value], props.query, props.filters))
const canSave = computed(() => props.query.trim().length > 0
  && canonicalBarQuery(props.query, props.filters) !== undefined
  && !activePreset.value)
const saveHint = computed(() => {
  if (activePreset.value) return `Already saved as “${activePreset.value.name}”`
  return canSave.value ? props.query : 'Type a valid query first'
})

function isApplicable(preset: PresetEntry) {
  return barStateFromQuery(preset.query, props.filters) !== undefined
}

function toggle() {
  open.value = !open.value
}

function apply(preset: PresetEntry) {
  open.value = false
  emit('apply', preset.query)
}

const dialog = ref({
  open: false,
  mode: 'save' as 'save' | 'delete',
  query: '',
  presetId: '',
  presetName: '',
  busy: false,
  error: '',
})

function saveCurrent() {
  if (!canSave.value) return
  open.value = false
  dialog.value = { open: true, mode: 'save', query: props.query.trim(), presetId: '', presetName: '', busy: false, error: '' }
}

function removePreset(preset: PresetEntry) {
  open.value = false
  dialog.value = { open: true, mode: 'delete', query: preset.query, presetId: preset.id, presetName: preset.name, busy: false, error: '' }
}

async function runDialog(action: () => Promise<string>) {
  dialog.value = { ...dialog.value, busy: true, error: '' }
  try {
    const message = await action()
    dialog.value = { ...dialog.value, open: false, busy: false }
    toast.success(message)
  } catch (error) {
    dialog.value = { ...dialog.value, busy: false, error: error instanceof Error ? error.message : 'Something went wrong' }
  }
}

function savePreset(name: string) {
  const { query } = dialog.value
  const existing = findPresetByName(presets.value, name)
  void runDialog(async () => {
    if (existing) await update(existing.id, existing.name, query)
    else await create(name, query)
    return `Saved preset “${existing?.name ?? name}”`
  })
}

function deletePreset() {
  const { presetId, presetName } = dialog.value
  void runDialog(async () => {
    await remove(presetId)
    return `Deleted preset “${presetName}”`
  })
}

function handleDocumentPointer(event: MouseEvent) {
  const target = event.target as Node | null
  if (target && rootRef.value && !rootRef.value.contains(target)) {
    open.value = false
  }
}

function handleKeydown(event: KeyboardEvent) {
  if (event.key === 'Escape') open.value = false
}

onMounted(() => {
  void load()
  document.addEventListener('mousedown', handleDocumentPointer)
  document.addEventListener('keydown', handleKeydown)
})

onBeforeUnmount(() => {
  document.removeEventListener('mousedown', handleDocumentPointer)
  document.removeEventListener('keydown', handleKeydown)
})
</script>
