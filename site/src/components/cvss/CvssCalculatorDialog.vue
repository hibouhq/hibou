<template>
  <Teleport to="body">
    <div
      v-if="vector"
      class="fixed inset-0 z-[70] flex items-start justify-center overflow-y-auto bg-black/60 px-4 py-10 backdrop-blur-sm"
      @click.self="emit('close')"
      @keydown.esc="emit('close')"
    >
      <div
        class="w-full max-w-4xl rounded-2xl border border-surface-border bg-surface-raised shadow-2xl"
        role="dialog"
        aria-modal="true"
        aria-label="CVSS calculator"
      >
        <header class="flex items-center gap-3 border-b border-surface-border-subtle px-5 py-3">
          <h2 class="text-sm font-semibold text-white">
            CVSS calculator
          </h2>
          <span
            v-if="title"
            class="truncate text-xs text-gray-500"
          >{{ title }}</span>
          <RouterLink
            :to="{ name: 'tool-cvss', hash: `#${vector}` }"
            class="ml-auto text-xs text-accent hover:underline"
            @click="emit('close')"
          >
            Open in Tools
          </RouterLink>
          <button
            type="button"
            class="rounded-md p-1 text-gray-400 transition hover:text-white"
            aria-label="Close"
            @click="emit('close')"
          >
            <X class="h-4 w-4" />
          </button>
        </header>
        <div class="px-5 py-4">
          <CvssCalculator
            :model-value="vector"
            in-dialog
          />
        </div>
      </div>
    </div>
  </Teleport>
</template>

<script setup lang="ts">
import { X } from 'lucide-vue-next'

import CvssCalculator from '@/components/cvss/CvssCalculator.vue'

// Explains a stored vector in place: every metric, its value and what it
// means. Read-only; the Tools page is where vectors are built.
defineProps<{
  /** The vector to explain; the dialog is open while it is set. */
  vector: string
  title?: string
}>()

const emit = defineEmits<{ (event: 'close'): void }>()
</script>
