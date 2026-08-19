<template>
  <Teleport to="body">
    <div
      v-if="active"
      class="fixed inset-0 z-[80] flex items-center justify-center bg-black/60 p-4"
      @click.self="dismiss"
    >
      <div
        :key="active.id"
        class="w-full max-w-md overflow-hidden rounded-xl border border-surface-border bg-surface-raised shadow-2xl"
        role="alertdialog"
        aria-modal="true"
        :aria-label="active.title"
        @keydown.esc.prevent="dismiss"
      >
        <div class="border-b border-surface-border-subtle px-4 py-3">
          <h3 class="text-sm font-semibold text-white">
            {{ active.title }}
          </h3>
          <p
            v-if="active.message"
            class="mt-1 whitespace-pre-line text-xs text-gray-400"
          >
            {{ active.message }}
          </p>
        </div>

        <form
          class="space-y-3 px-4 py-4"
          @submit.prevent="confirm"
        >
          <label
            v-if="active.requireText"
            class="block"
          >
            <span class="text-[11px] uppercase tracking-wide text-gray-500">
              Type <span class="font-mono normal-case text-gray-300">{{ active.requireText }}</span> to confirm
            </span>
            <input
              ref="fieldRef"
              v-model="typed"
              type="text"
              autocomplete="off"
              spellcheck="false"
              class="mt-1.5 w-full rounded-md border border-surface-border bg-surface-overlay px-3 py-2 font-mono text-sm text-gray-100 focus:border-accent/60 focus:outline-none"
            >
          </label>

          <label
            v-else-if="active.input"
            class="block"
          >
            <span class="text-[11px] uppercase tracking-wide text-gray-500">
              {{ active.input.label }}
            </span>
            <input
              ref="fieldRef"
              v-model="typed"
              type="text"
              autocomplete="off"
              :placeholder="active.input.placeholder"
              class="mt-1.5 w-full rounded-md border border-surface-border bg-surface-overlay px-3 py-2 text-sm text-gray-100 placeholder:text-gray-600 focus:border-accent/60 focus:outline-none"
            >
          </label>

          <div class="flex items-center justify-end gap-2 pt-1">
            <button
              type="button"
              class="rounded-md border border-surface-border px-3 py-1.5 text-xs font-medium text-gray-300 transition hover:bg-surface-overlay"
              @click="dismiss"
            >
              {{ active.cancelLabel ?? 'Cancel' }}
            </button>
            <button
              ref="confirmRef"
              type="submit"
              :disabled="!confirmEnabled"
              class="rounded-md border px-3 py-1.5 text-xs font-medium transition disabled:cursor-not-allowed disabled:opacity-50"
              :class="active.tone === 'danger'
                ? 'border-danger/50 text-danger hover:bg-danger/10'
                : 'border-accent/50 text-accent hover:bg-accent/10'"
            >
              {{ active.confirmLabel ?? 'Confirm' }}
            </button>
          </div>
        </form>
      </div>
    </div>
  </Teleport>
</template>

<script setup lang="ts">
import { computed, nextTick, ref, watch } from 'vue'

import { useDialog } from '@/composables/useDialog'

const { active, settle } = useDialog()

const typed = ref('')
const fieldRef = ref<HTMLInputElement | null>(null)
const confirmRef = ref<HTMLButtonElement | null>(null)

const confirmEnabled = computed(() => {
  if (!active.value) return false
  if (active.value.requireText) return typed.value.trim() === active.value.requireText
  if (active.value.input?.required) return typed.value.trim() !== ''
  return true
})

watch(
  () => active.value?.id,
  async (id) => {
    if (id === undefined) return
    typed.value = ''
    await nextTick()
    // Focus the text field when one is shown, else the confirm button, so
    // Escape/Enter work without reaching for the mouse.
    if (fieldRef.value) fieldRef.value.focus()
    else confirmRef.value?.focus()
  },
)

function confirm() {
  if (!confirmEnabled.value) return
  settle({ confirmed: true, value: typed.value.trim() })
}

function dismiss() {
  settle({ confirmed: false, value: '' })
}
</script>
