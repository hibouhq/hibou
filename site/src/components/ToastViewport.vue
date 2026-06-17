<template>
  <Teleport to="body">
    <div class="pointer-events-none fixed inset-x-0 top-4 z-[90] flex justify-center px-4 sm:justify-end">
      <TransitionGroup
        enter-active-class="transition duration-200 ease-out"
        enter-from-class="translate-y-2 opacity-0 sm:translate-x-3 sm:translate-y-0"
        enter-to-class="translate-y-0 opacity-100"
        leave-active-class="transition duration-150 ease-in"
        leave-from-class="opacity-100"
        leave-to-class="translate-y-1 opacity-0 sm:translate-x-3 sm:translate-y-0"
        tag="div"
        class="flex w-full max-w-sm flex-col gap-3"
      >
        <section
          v-for="toast in toasts"
          :key="toast.id"
          :class="toneClass(toast.tone)"
          class="pointer-events-auto overflow-hidden rounded-2xl border bg-surface-overlay/95 p-4 shadow-[0_24px_80px_-42px_rgba(0,0,0,0.9)] backdrop-blur"
        >
          <div class="flex items-start gap-3">
            <div
              :class="iconClass(toast.tone)"
              class="mt-0.5 flex h-9 w-9 shrink-0 items-center justify-center rounded-xl border"
            >
              <CheckCircle2
                v-if="toast.tone === 'success'"
                class="h-4.5 w-4.5"
              />
              <CircleAlert
                v-else-if="toast.tone === 'error'"
                class="h-4.5 w-4.5"
              />
              <Sparkles
                v-else
                class="h-4.5 w-4.5"
              />
            </div>

            <div class="min-w-0 flex-1">
              <p class="text-sm font-medium text-white">
                {{ toast.title }}
              </p>
              <p
                v-if="toast.description"
                class="mt-1 text-sm text-gray-400"
              >
                {{ toast.description }}
              </p>
            </div>

            <button
              class="rounded-lg p-1 text-gray-500 transition hover:bg-surface-raised hover:text-white"
              type="button"
              @click="dismiss(toast.id)"
            >
              <X class="h-4 w-4" />
            </button>
          </div>
        </section>
      </TransitionGroup>
    </div>
  </Teleport>
</template>

<script setup lang="ts">
import { CheckCircle2, CircleAlert, Sparkles, X } from 'lucide-vue-next'

import { useToast, type ToastTone } from '@/composables/useToast'

const { dismiss, toasts } = useToast()

function toneClass(tone: ToastTone) {
  switch (tone) {
    case 'success':
      return 'border-emerald-500/25'
    case 'error':
      return 'border-danger/30'
    default:
      return 'border-surface-border'
  }
}

function iconClass(tone: ToastTone) {
  switch (tone) {
    case 'success':
      return 'border-emerald-500/30 bg-emerald-500/10 text-emerald-200'
    case 'error':
      return 'border-danger/30 bg-danger/10 text-red-200'
    default:
      return 'border-accent/25 bg-accent/10 text-accent'
  }
}
</script>