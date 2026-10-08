<template>
  <Teleport to="body">
    <div
      v-if="open"
      class="fixed inset-0 z-[80] flex items-center justify-center bg-black/60 p-4"
      @click.self="emit('cancel')"
    >
      <form
        ref="formRef"
        class="w-full max-w-lg overflow-hidden rounded-xl border border-surface-border bg-surface-raised shadow-2xl focus:outline-none"
        :role="mode === 'delete' ? 'alertdialog' : 'dialog'"
        aria-modal="true"
        aria-labelledby="preset-dialog-title"
        tabindex="-1"
        @keydown.esc.prevent="emit('cancel')"
        @submit.prevent="submit"
      >
        <div class="flex items-center gap-2 border-b border-surface-border-subtle px-4 py-3">
          <component
            :is="mode === 'delete' ? Trash2 : BookmarkPlus"
            class="h-4 w-4"
            :class="mode === 'delete' ? 'text-danger' : 'text-accent'"
            aria-hidden="true"
          />
          <h3
            id="preset-dialog-title"
            class="text-sm font-semibold text-white"
          >
            {{ mode === 'delete' ? 'Delete search preset' : 'Save search preset' }}
          </h3>
        </div>

        <div class="space-y-4 px-4 py-4">
          <div v-if="mode === 'delete'">
            <div class="text-[11px] uppercase tracking-wide text-gray-500">
              Name
            </div>
            <div class="mt-1.5 text-sm font-medium text-gray-100">
              {{ presetName }}
            </div>
          </div>

          <div>
            <div class="text-[11px] uppercase tracking-wide text-gray-500">
              Query
            </div>
            <div class="mt-1.5 whitespace-pre-wrap break-words rounded-md border border-surface-border bg-surface-overlay px-3 py-2 text-sm leading-6">
              <span
                v-for="(segment, index) in segments"
                :key="index"
                :class="segment.className"
              >{{ segment.text }}</span>
            </div>
          </div>

          <label
            v-if="mode === 'save'"
            class="block"
          >
            <span class="text-[11px] uppercase tracking-wide text-gray-500">Name</span>
            <input
              ref="nameRef"
              v-model="name"
              type="text"
              autocomplete="off"
              maxlength="80"
              placeholder="e.g. Critical dependencies"
              class="mt-1.5 w-full rounded-md border border-surface-border bg-surface-overlay px-3 py-[5px] text-sm text-gray-100 placeholder:text-gray-600 focus:border-accent focus:outline-none focus:ring-1 focus:ring-inset focus:ring-accent"
            >
          </label>

          <p
            v-if="mode === 'save' && existing"
            class="flex items-start gap-1.5 text-xs text-amber-300"
          >
            <TriangleAlert
              class="mt-px h-3.5 w-3.5 shrink-0"
              aria-hidden="true"
            />
            <span>
              <span class="font-medium text-amber-100">{{ existing.name }}</span> already exists — saving replaces its query.
            </span>
          </p>
          <p
            v-if="error"
            role="alert"
            class="text-xs text-danger"
          >
            {{ error }}
          </p>
        </div>

        <div class="flex items-center justify-end gap-2 border-t border-surface-border-subtle px-4 py-3">
          <button
            type="button"
            class="rounded-md border border-surface-border px-3 py-1.5 text-xs font-medium text-gray-300 transition hover:bg-surface-overlay"
            @click="emit('cancel')"
          >
            Cancel
          </button>
          <button
            type="submit"
            :disabled="!canSubmit"
            class="rounded-md border px-3 py-1.5 text-xs font-semibold transition disabled:cursor-not-allowed disabled:opacity-50"
            :class="submitClass"
          >
            {{ submitLabel }}
          </button>
        </div>
      </form>
    </div>
  </Teleport>
</template>

<script setup lang="ts">
import { computed, nextTick, ref, watch } from 'vue'
import { BookmarkPlus, Trash2, TriangleAlert } from 'lucide-vue-next'

import { highlightBarQuery, type FilterBarFilter } from '@/lib/filterBarQuery'
import { findPresetByName } from '@/lib/searchPresets'

const props = withDefaults(defineProps<{
  open: boolean
  mode: 'save' | 'delete'
  query: string
  filters: FilterBarFilter[]
  presetName?: string
  existingPresets?: { id: string; name: string }[]
  busy: boolean
  error: string
}>(), {
  presetName: '',
  existingPresets: () => [],
})

const emit = defineEmits<{
  (event: 'save', name: string): void
  (event: 'delete'): void
  (event: 'cancel'): void
}>()

const name = ref('')
const nameRef = ref<HTMLInputElement | null>(null)
const formRef = ref<HTMLFormElement | null>(null)

const segments = computed(() => highlightBarQuery(props.query, props.filters))
const existing = computed(() => (name.value.trim() ? findPresetByName(props.existingPresets, name.value) : undefined))
const canSubmit = computed(() => !props.busy && (props.mode === 'delete' || name.value.trim().length > 0))

const submitLabel = computed(() => {
  if (props.mode === 'delete') return props.busy ? 'Deleting…' : 'Delete'
  if (props.busy) return 'Saving…'
  return existing.value ? 'Replace' : 'Save'
})

const submitClass = computed(() => {
  if (props.mode === 'delete') return 'border-danger/60 bg-danger/15 text-danger hover:bg-danger/25'
  return existing.value
    ? 'border-amber-500/60 bg-amber-500/15 text-amber-200 hover:bg-amber-500/25'
    : 'border-accent/60 bg-accent/15 text-accent hover:bg-accent/25'
})

watch(() => props.open, async (open) => {
  if (!open) return
  name.value = ''
  await nextTick()
  // Focus the name field to save, or the dialog itself to delete, so Enter
  // and Escape work without reaching for the mouse.
  if (props.mode === 'save') nameRef.value?.focus()
  else formRef.value?.focus()
})

function submit() {
  if (!canSubmit.value) return
  if (props.mode === 'delete') emit('delete')
  else emit('save', name.value.trim())
}
</script>
