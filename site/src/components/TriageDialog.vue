<template>
  <Teleport to="body">
    <div
      class="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4"
      @click.self="cancel"
    >
      <div
        ref="panelRef"
        class="w-full max-w-lg overflow-hidden rounded-xl border border-surface-border bg-surface-raised shadow-2xl"
        role="dialog"
        aria-modal="true"
        :aria-label="title"
      >
        <div class="border-b border-surface-border-subtle px-4 py-3">
          <h3 class="text-sm font-semibold text-white">
            {{ title }}
          </h3>
          <p class="mt-1 text-xs text-gray-400">
            {{ resultingDescription }}
          </p>
        </div>

        <div class="space-y-3 px-4 py-4">
          <div v-if="presets.length > 0">
            <p class="mb-1.5 text-[11px] uppercase tracking-wide text-gray-500">
              Common reasons
            </p>
            <div class="flex flex-wrap gap-1.5">
              <button
                v-for="preset in presets"
                :key="preset"
                type="button"
                class="rounded-md border border-surface-border bg-surface-overlay px-2 py-1 text-[11px] text-gray-300 transition hover:border-accent/50 hover:text-white"
                @click="reason = preset"
              >
                {{ preset }}
              </button>
            </div>
          </div>

          <label class="block">
            <span class="text-[11px] uppercase tracking-wide text-gray-500">
              Reason <span class="text-danger">*</span>
            </span>
            <textarea
              ref="textareaRef"
              v-model="reason"
              rows="4"
              class="mt-1.5 w-full resize-y rounded-md border border-surface-border bg-surface-overlay px-3 py-2 text-sm text-gray-100 placeholder:text-gray-600 focus:border-accent/60 focus:outline-none"
              placeholder="Why is this acceptable? This is recorded in the audit log and shown to reviewers."
              @keydown.meta.enter.prevent="submit"
              @keydown.ctrl.enter.prevent="submit"
            />
          </label>

          <label class="block">
            <span class="text-[11px] uppercase tracking-wide text-gray-500">
              Expires (optional)
            </span>
            <input
              v-model="expiresAt"
              type="date"
              :min="tomorrow"
              class="mt-1.5 w-full rounded-md border border-surface-border bg-surface-overlay px-3 py-2 text-sm text-gray-100 focus:border-accent/60 focus:outline-none"
            >
            <span class="mt-1 block text-[11px] text-gray-500">
              After this date the finding reappears and counts against the gate again.
            </span>
          </label>

          <p
            v-if="error"
            class="rounded-md border border-danger/40 bg-danger/10 px-3 py-2 text-xs text-red-200"
          >
            {{ error }}
          </p>
        </div>

        <div class="flex items-center justify-end gap-2 border-t border-surface-border-subtle px-4 py-3">
          <button
            type="button"
            class="rounded-md border border-surface-border px-3 py-1.5 text-xs font-medium text-gray-400 transition hover:text-white"
            @click="cancel"
          >
            Cancel
          </button>
          <button
            type="button"
            class="rounded-md bg-accent px-3 py-1.5 text-xs font-medium text-white transition hover:bg-accent/90 disabled:cursor-not-allowed disabled:opacity-50"
            :disabled="submitting || reason.trim().length === 0"
            @click="submit"
          >
            {{ submitting ? 'Applying…' : confirmLabel }}
          </button>
        </div>
      </div>
    </div>
  </Teleport>
</template>

<script setup lang="ts">
import { computed, nextTick, onMounted, onUnmounted, ref } from 'vue'

import { REASON_PRESETS, triageStateInfo, type TriageState } from '@/lib/triage'

const props = defineProps<{
  /** The acceptance status being applied: 'accepted' | 'false_positive'. */
  status: 'accepted' | 'false_positive'
  /** How many findings this decision covers. */
  count: number
  /** Error from a failed submit, rendered in-dialog so the typed reason survives. */
  error?: string
  submitting?: boolean
}>()

const emit = defineEmits<{
  (e: 'cancel'): void
  (e: 'confirm', payload: { reason: string; expiresAt?: string }): void
}>()

const reason = ref('')
const expiresAt = ref('')
const textareaRef = ref<HTMLTextAreaElement | null>(null)
const panelRef = ref<HTMLElement | null>(null)

const resultingState = computed<TriageState>(() => (props.status === 'false_positive' ? 'false_positive' : 'accepted_risk'))
const resultingDescription = computed(() => triageStateInfo(resultingState.value).description)
const presets = computed(() => REASON_PRESETS[props.status] ?? [])

const title = computed(() => {
  const action = props.status === 'false_positive' ? 'Mark false positive' : 'Accept risk'
  const noun = props.count === 1 ? 'finding' : 'findings'
  return `${action} on ${props.count} ${noun}`
})
const confirmLabel = computed(() => (props.status === 'false_positive' ? 'Mark false positive' : 'Accept risk'))

// Minimum selectable expiry is tomorrow: an expiry of today would already be
// past by the server's check.
const tomorrow = computed(() => {
  const date = new Date()
  date.setDate(date.getDate() + 1)
  return date.toISOString().slice(0, 10)
})

function cancel() {
  emit('cancel')
}

function submit() {
  const trimmed = reason.value.trim()
  if (!trimmed || props.submitting) return
  emit('confirm', {
    reason: trimmed,
    // Send end-of-day so a date picked today is unambiguously in the future.
    expiresAt: expiresAt.value ? new Date(`${expiresAt.value}T23:59:59`).toISOString() : undefined,
  })
}

// Focus trap: Tab cycles inside the dialog. Without it, tabbing walks the page
// behind the modal, which is both confusing and an accessibility failure.
function focusableElements(): HTMLElement[] {
  if (!panelRef.value) return []
  return [...panelRef.value.querySelectorAll<HTMLElement>(
    'button:not([disabled]), textarea, input, [href], select, [tabindex]:not([tabindex="-1"])',
  )].filter((element) => element.offsetParent !== null)
}

function onKeydown(event: KeyboardEvent) {
  if (event.key === 'Escape') {
    cancel()
    return
  }
  if (event.key !== 'Tab') return
  const focusable = focusableElements()
  if (focusable.length === 0) return
  const first = focusable[0]
  const last = focusable[focusable.length - 1]
  const active = document.activeElement as HTMLElement | null
  // Wrap at both ends, and pull focus back in if it escaped the panel.
  if (event.shiftKey && (active === first || !panelRef.value?.contains(active))) {
    event.preventDefault()
    last.focus()
  } else if (!event.shiftKey && (active === last || !panelRef.value?.contains(active))) {
    event.preventDefault()
    first.focus()
  }
}

onMounted(() => {
  document.addEventListener('keydown', onKeydown)
  void nextTick(() => textareaRef.value?.focus())
})
onUnmounted(() => document.removeEventListener('keydown', onKeydown))
</script>
