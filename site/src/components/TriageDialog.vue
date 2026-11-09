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

        <div class="max-h-[70vh] space-y-3 overflow-y-auto px-4 py-4">
          <!-- ADR-053 §4a: a finding with a vulnerability identifier answers
               the VEX question first; the answer is the exported statement. -->
          <fieldset
            v-if="statementMode"
            class="grid gap-2 sm:grid-cols-2"
          >
            <legend class="mb-1.5 text-[11px] uppercase tracking-wide text-gray-500">
              Does this vulnerability affect the product?
            </legend>
            <label
              v-for="option in decisionOptions"
              :key="option.kind"
              class="flex cursor-pointer gap-2 rounded-md border px-3 py-2 transition"
              :class="decision === option.kind ? 'border-accent/60 bg-accent/10' : 'border-surface-border bg-surface-overlay hover:border-accent/40'"
            >
              <input
                v-model="decision"
                type="radio"
                name="triage-decision"
                :value="option.kind"
                class="mt-0.5 accent-[--color-accent]"
              >
              <span>
                <span class="block text-sm font-medium text-gray-100">{{ option.label }}</span>
                <span class="mt-0.5 block text-[11px] leading-snug text-gray-400">{{ option.detail }}</span>
              </span>
            </label>
          </fieldset>

          <!-- Waiving a known-exploited vulnerability stays possible — the
               waiver IS the sanctioned unblock path — but never accidental. -->
          <div
            v-if="exploited"
            class="flex gap-2.5 rounded-md border border-danger/40 bg-danger/10 px-3 py-2.5"
          >
            <Flame class="mt-0.5 h-4 w-4 shrink-0 text-danger" />
            <p class="text-xs leading-relaxed text-red-200">
              <strong class="font-semibold">This vulnerability is actively exploited in the wild.</strong>
              {{ decision === 'risk_accepted'
                ? 'Accepting it merges code carrying a known-exploited vulnerability. An expiry is required, and the waiver is recorded with your name and shown on every gate it unblocks.'
                : 'A not-affected statement on an exploited vulnerability is what clients will read — make the justification and evidence stand on their own.' }}
            </p>
          </div>

          <div
            v-if="liveCredential && decision === 'risk_accepted'"
            class="flex gap-2.5 rounded-md border border-danger/40 bg-danger/10 px-3 py-2.5"
          >
            <KeyRound class="mt-0.5 h-4 w-4 shrink-0 text-danger" />
            <p class="text-xs leading-relaxed text-red-200">
              <strong class="font-semibold">A validator confirmed this credential is live.</strong>
              Accepting the risk leaves a working credential in the history; revoke it if you can. An expiry is required.
            </p>
          </div>

          <fieldset
            v-if="showVEX"
            class="space-y-1.5"
          >
            <legend class="mb-1.5 text-[11px] uppercase tracking-wide text-gray-500">
              Justification <span
                v-if="justificationRequired"
                class="text-danger"
              >*</span>
            </legend>
            <label
              v-for="justification in VEX_JUSTIFICATIONS"
              :key="justification.value"
              class="flex cursor-pointer gap-2 rounded-md border px-3 py-1.5 transition"
              :class="vexJustification === justification.value ? 'border-accent/60 bg-accent/10' : 'border-surface-border bg-surface-overlay hover:border-accent/40'"
            >
              <input
                v-model="vexJustification"
                type="radio"
                name="triage-justification"
                :value="justification.value"
                class="mt-0.5 accent-[--color-accent]"
              >
              <span>
                <span class="block text-xs font-medium text-gray-100">{{ justification.label }}</span>
                <span class="block text-[11px] text-gray-400">{{ justification.hint }}</span>
              </span>
            </label>
          </fieldset>

          <p
            v-if="statementMode && batchNote"
            class="rounded-md border border-surface-border-subtle bg-surface-overlay px-3 py-2 text-[11px] text-gray-400"
          >
            {{ batchNote }}
          </p>
          <p
            v-else-if="!statementMode && count === 1"
            class="rounded-md border border-surface-border-subtle bg-surface-overlay px-3 py-2 text-[11px] text-gray-500"
          >
            This finding has no vulnerability identifier (it names a rule, not a CVE), so no VEX statement is written.
          </p>

          <div v-if="presets.length > 0">
            <p class="mb-1.5 text-[11px] uppercase tracking-wide text-gray-500">
              {{ statementMode && decision === 'false_positive' ? 'Common evidence' : 'Common reasons' }}
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
              {{ reasonLabel }} <span
                v-if="reasonRequired"
                class="text-danger"
              >*</span>
            </span>
            <textarea
              ref="textareaRef"
              v-model="reason"
              rows="4"
              class="mt-1.5 w-full resize-y rounded-md border border-surface-border bg-surface-overlay px-3 py-2 text-sm text-gray-100 placeholder:text-gray-600 focus:border-accent/60 focus:outline-none"
              :placeholder="reasonPlaceholder"
              @keydown.meta.enter.prevent="submit"
              @keydown.ctrl.enter.prevent="submit"
            />
          </label>

          <label class="block">
            <span class="text-[11px] uppercase tracking-wide text-gray-500">
              Labels (optional, comma-separated)
            </span>
            <input
              v-model="labelsInput"
              type="text"
              placeholder="waiting-upstream-fix, q3-review"
              class="mt-1.5 w-full rounded-md border border-surface-border bg-surface-overlay px-3 py-2 text-sm text-gray-100 placeholder:text-gray-600 focus:border-accent/60 focus:outline-none"
            >
            <span class="mt-1 block text-[11px] text-gray-500">
              For tracking and filtering — labels never change gate or VEX behavior.
            </span>
          </label>

          <label
            v-if="showExpiry"
            class="block"
          >
            <span class="text-[11px] uppercase tracking-wide text-gray-500">
              Expires <span
                v-if="expiryRequired"
                class="text-danger"
              >*</span><template v-else>
                (optional)
              </template>
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
            :disabled="submitting || problem !== ''"
            :title="problem || undefined"
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
import { Flame, KeyRound } from 'lucide-vue-next'
import { computed, nextTick, onMounted, onUnmounted, ref } from 'vue'

import type { AcceptanceReasonKind, VexJustification } from '@/api/client'
import { reasonPresets, triageDecisionProblem, triageStateInfo, VEX_JUSTIFICATIONS, type TriageConfirmPayload, type TriageState } from '@/lib/triage'

const props = defineProps<{
  /** The decision the dialog opens on (ADR-023). */
  kind: AcceptanceReasonKind
  /** How many findings this decision covers. */
  count: number
  /** The decision writes a VEX statement: a dependency finding with an advisory (ADR-053 §4a). */
  statement?: boolean
  /** A batch partly off-page: it may hold such findings, so the VEX question is asked but the justification stays optional. */
  statementUnknown?: boolean
  /** Error from a failed submit, rendered in-dialog so the typed reason survives. */
  error?: string
  submitting?: boolean
  /** True when the advisory is on a known-exploited catalog (ADR-032). */
  exploited?: boolean
  /** A secret a validator confirmed live: accepting its risk needs an expiry. */
  liveCredential?: boolean
}>()

const emit = defineEmits<{
  (e: 'cancel'): void
  (e: 'confirm', payload: TriageConfirmPayload): void
}>()

const decision = ref<AcceptanceReasonKind>(props.kind)
const reason = ref('')
const labelsInput = ref('')
const vexJustification = ref<'' | VexJustification>('')
// An exploited waiver or a live credential defaults to a 30-day expiry so the
// acceptance resurfaces for review instead of standing forever.
const expiresAt = ref(props.exploited || props.liveCredential ? thirtyDaysOut() : '')

function thirtyDaysOut(): string {
  const date = new Date()
  date.setDate(date.getDate() + 30)
  return date.toISOString().slice(0, 10)
}
const textareaRef = ref<HTMLTextAreaElement | null>(null)
const panelRef = ref<HTMLElement | null>(null)

const statementMode = computed(() => props.statement === true || props.statementUnknown === true)
const decisionOptions = [
  {
    kind: 'false_positive' as const,
    label: 'Not affected',
    detail: 'Wrong detection, or present but not exploitable here. Exported as not_affected with its justification; excluded from risk.',
  },
  {
    kind: 'risk_accepted' as const,
    label: 'Affected — risk accepted',
    detail: 'Real, deliberately not fixed now. Exported as affected with your action statement; still counts as risk.',
  },
]

const resultingState = computed<TriageState>(() => (decision.value === 'false_positive' ? 'false_positive' : 'accepted_risk'))
const resultingDescription = computed(() => (statementMode.value
  ? 'The answer is written as a VEX statement on the advisory.'
  : triageStateInfo(resultingState.value).description))
const presets = computed(() => reasonPresets(decision.value, statementMode.value))
// A justification exists only on a not_affected statement (ADR-053 §4a).
const showVEX = computed(() => statementMode.value && decision.value === 'false_positive')
const justificationRequired = computed(() => showVEX.value && props.statement === true)
// Expiry is a risk concept; a not-affected decision does not expire (ADR-023).
const showExpiry = computed(() => decision.value === 'risk_accepted')
const expiryRequired = computed(() => showExpiry.value && (props.exploited === true || props.liveCredential === true))
const reasonRequired = computed(() => !showVEX.value)

const reasonLabel = computed(() => {
  if (!statementMode.value) return 'Reason'
  return decision.value === 'false_positive' ? 'Evidence (optional)' : 'Action statement'
})
const reasonPlaceholder = computed(() => {
  if (!statementMode.value) return 'Why is this acceptable? This is recorded in the audit log and shown to reviewers.'
  return decision.value === 'false_positive'
    ? 'What shows it: a call-graph result, a configuration, a link. Exported with the statement.'
    : 'What is being done about it, and by when. Exported as the statement\'s action.'
})

const batchNote = computed(() => {
  if (props.statementUnknown && !props.statement) {
    return 'Part of the selection is not loaded here. If it holds dependency findings with an advisory, the server refuses a not-affected decision without a justification.'
  }
  if (props.count > 1) {
    return 'The statement is written for the dependency findings with an advisory in this selection; the others keep the reason only.'
  }
  return ''
})

const problem = computed(() => triageDecisionProblem({
  kind: decision.value,
  statement: statementMode.value,
  justificationRequired: justificationRequired.value,
  justification: vexJustification.value,
  reason: reason.value,
  expiresAt: showExpiry.value ? expiresAt.value : '',
  expiryRequired: expiryRequired.value,
}))

const title = computed(() => {
  const action = decision.value === 'false_positive' ? (statementMode.value ? 'Mark not affected' : 'Mark false positive') : 'Accept risk'
  const noun = props.count === 1 ? 'finding' : 'findings'
  return `${action} on ${props.count} ${noun}`
})
const confirmLabel = computed(() => {
  if (decision.value === 'risk_accepted') return 'Accept risk'
  return statementMode.value ? 'Mark not affected' : 'Mark false positive'
})

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
  if (problem.value || props.submitting) return
  emit('confirm', {
    kind: decision.value,
    reason: reason.value.trim(),
    labels: labelsInput.value.split(',').map((label) => label.trim()).filter(Boolean),
    vexJustification: showVEX.value && vexJustification.value ? vexJustification.value : undefined,
    // Send end-of-day so a date picked today is unambiguously in the future.
    expiresAt: showExpiry.value && expiresAt.value ? new Date(`${expiresAt.value}T23:59:59`).toISOString() : undefined,
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
