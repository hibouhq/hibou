<template>
  <Teleport to="body">
    <div
      class="fixed inset-0 z-[80] flex items-center justify-center bg-black/60 p-4"
      @click.self="emit('cancel')"
    >
      <div
        class="flex max-h-[90vh] w-full max-w-lg flex-col overflow-hidden rounded-xl border border-surface-border bg-surface-raised shadow-2xl"
        role="dialog"
        aria-modal="true"
        aria-label="Revoke the secret"
      >
        <div class="border-b border-surface-border-subtle px-4 py-3">
          <h3 class="text-sm font-semibold text-white">
            {{ resolved ? 'Record rotation' : 'Revoke the secret' }}
          </h3>
          <p class="mt-1 text-xs text-gray-400">
            A leaked secret resolves when its revocation is attested or a validator confirms it dead — never because it left the code.
          </p>
        </div>

        <div class="min-h-0 flex-1 space-y-4 overflow-y-auto px-4 py-4">
          <section class="space-y-2">
            <label class="flex items-center gap-2 text-sm text-gray-100">
              <input
                v-model="checklist.revoked"
                type="checkbox"
                class="h-3.5 w-3.5 accent-[--color-accent]"
              >
              Revoked at the provider
            </label>
            <div
              v-if="checklist.revoked"
              class="grid gap-2 pl-5 sm:grid-cols-2"
            >
              <label class="block sm:col-span-2">
                <span class="text-[11px] uppercase tracking-wide text-gray-500">Where <span class="text-danger">*</span></span>
                <input
                  v-model="checklist.revoked_where"
                  type="text"
                  placeholder="AWS IAM, GitHub token settings, Stripe dashboard…"
                  class="mt-1 w-full rounded-md border border-surface-border bg-surface-overlay px-3 py-1.5 text-sm text-gray-100 placeholder:text-gray-600 focus:border-accent/60 focus:outline-none"
                >
              </label>
              <label class="block">
                <span class="text-[11px] uppercase tracking-wide text-gray-500">By whom</span>
                <input
                  v-model="checklist.revoked_by"
                  type="text"
                  placeholder="Who revoked it"
                  class="mt-1 w-full rounded-md border border-surface-border bg-surface-overlay px-3 py-1.5 text-sm text-gray-100 placeholder:text-gray-600 focus:border-accent/60 focus:outline-none"
                >
              </label>
              <label class="block">
                <span class="text-[11px] uppercase tracking-wide text-gray-500">Link or ticket</span>
                <input
                  v-model="checklist.reference"
                  type="text"
                  placeholder="SEC-123 or a URL"
                  class="mt-1 w-full rounded-md border border-surface-border bg-surface-overlay px-3 py-1.5 text-sm text-gray-100 placeholder:text-gray-600 focus:border-accent/60 focus:outline-none"
                >
              </label>
            </div>
          </section>

          <fieldset class="space-y-1.5">
            <legend class="mb-1 text-[11px] uppercase tracking-wide text-gray-500">
              Rotation
            </legend>
            <div class="flex flex-wrap gap-x-4 gap-y-1 text-sm text-gray-200">
              <label
                v-for="option in rotationOptions"
                :key="option.value"
                class="flex items-center gap-2"
              >
                <input
                  v-model="checklist.rotation"
                  type="radio"
                  name="secret-rotation"
                  :value="option.value"
                  class="accent-[--color-accent]"
                >
                {{ option.label }}
              </label>
            </div>
            <input
              v-if="checklist.rotation !== ''"
              v-model="checklist.rotation_note"
              type="text"
              :placeholder="checklist.rotation === 'not_needed' ? 'Why no new credential is needed (required)' : 'Where the new credential is deployed (optional)'"
              class="w-full rounded-md border border-surface-border bg-surface-overlay px-3 py-1.5 text-sm text-gray-100 placeholder:text-gray-600 focus:border-accent/60 focus:outline-none"
            >
          </fieldset>

          <section class="space-y-1.5">
            <label class="flex items-center gap-2 text-sm text-gray-100">
              <input
                v-model="exposureAssessed"
                type="checkbox"
                class="h-3.5 w-3.5 accent-[--color-accent]"
              >
              Exposure assessed
            </label>
            <textarea
              v-if="exposureAssessed"
              v-model="checklist.exposure_note"
              rows="2"
              placeholder="Who could read it: repository visibility, forks, how long it sat in history, access logs checked"
              class="w-full resize-y rounded-md border border-surface-border bg-surface-overlay px-3 py-1.5 text-sm text-gray-100 placeholder:text-gray-600 focus:border-accent/60 focus:outline-none"
            />
          </section>

          <label class="flex items-start gap-2 text-sm text-gray-100">
            <input
              v-model="checklist.owner_external"
              type="checkbox"
              class="mt-0.5 h-3.5 w-3.5 accent-[--color-accent]"
            >
            <span>
              The credential belongs to someone else
              <span class="block text-[11px] text-gray-500">A vendor or a client: its owner has to be told.</span>
            </span>
          </label>

          <label class="block">
            <span class="text-[11px] uppercase tracking-wide text-gray-500">Comment</span>
            <textarea
              v-model="comment"
              rows="2"
              placeholder="Anything else the audit log should say"
              class="mt-1 w-full resize-y rounded-md border border-surface-border bg-surface-overlay px-3 py-1.5 text-sm text-gray-100 placeholder:text-gray-600 focus:border-accent/60 focus:outline-none"
            />
          </label>

          <p
            v-if="!checklist.revoked && !resolved"
            class="rounded-md border border-surface-border-subtle bg-surface-overlay px-3 py-2 text-[11px] text-gray-400"
          >
            Without the revocation this records rotation and exposure only; the secret stays open.
          </p>

          <section v-if="attestations.length > 0">
            <p class="mb-1.5 text-[11px] uppercase tracking-wide text-gray-500">
              Recorded
            </p>
            <ul class="space-y-1.5">
              <li
                v-for="attestation in attestations"
                :key="attestation.id"
                class="rounded-md border border-surface-border-subtle px-3 py-2 text-xs text-gray-300"
              >
                <span class="text-gray-500">{{ formatDateTime(attestation.attested_at) }}</span>
                <span
                  v-for="step in attestationSteps(attestation)"
                  :key="step"
                  class="ml-1.5 rounded-full bg-surface-overlay px-2 py-0.5 text-[11px] text-gray-300"
                >{{ step }}</span>
                <p
                  v-if="attestation.note"
                  class="mt-1 text-gray-400"
                >
                  {{ attestation.note }}
                </p>
              </li>
            </ul>
          </section>
          <p
            v-else-if="loadError"
            class="text-[11px] text-gray-500"
          >
            {{ loadError }}
          </p>

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
            @click="emit('cancel')"
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
            {{ submitting ? 'Recording…' : checklist.revoked ? 'Record revocation' : 'Record' }}
          </button>
        </div>
      </div>
    </div>
  </Teleport>
</template>

<script setup lang="ts">
import { computed, onMounted, onUnmounted, reactive, ref } from 'vue'

import type { Vulnerability } from '@/api/client'
import { incidentsApi, type SecretAttestation, type SecretChecklist } from '@/api/incidents'
import { formatDateTime } from '@/lib/datetime'

const props = defineProps<{
  provider: string
  slug: string
  repoSlug: string
  finding: Pick<Vulnerability, 'id' | 'status'>
}>()

const emit = defineEmits<{
  cancel: []
  /** `revoked` is true when the attestation resolved the secret. */
  done: [revoked: boolean]
}>()

const resolved = computed(() => props.finding.status === 'resolved')

const checklist = reactive<SecretChecklist>({
  revoked: !resolved.value,
  revoked_where: '',
  revoked_by: '',
  reference: '',
  rotation: '',
  rotation_note: '',
  exposure: '',
  exposure_note: '',
  owner_external: false,
})
const exposureAssessed = computed({
  get: () => checklist.exposure === 'assessed',
  set: (value: boolean) => { checklist.exposure = value ? 'assessed' : '' },
})
const comment = ref('')
const submitting = ref(false)
const error = ref('')
const attestations = ref<SecretAttestation[]>([])
const loadError = ref('')

const rotationOptions = [
  { value: '' as const, label: 'Not yet' },
  { value: 'rotated' as const, label: 'New credential deployed' },
  { value: 'not_needed' as const, label: 'Not needed' },
]

// Mirrors the server's checklist rules so the button says why it is disabled.
const problem = computed(() => {
  if (checklist.revoked && !checklist.revoked_where.trim()) return 'Say where the credential was revoked.'
  if (checklist.rotation === 'not_needed' && !checklist.rotation_note.trim()) return 'Say why no new credential is needed.'
  if (!checklist.revoked && checklist.rotation === '' && checklist.exposure === '') return 'Record at least one step.'
  return ''
})

function attestationSteps(attestation: SecretAttestation): string[] {
  const steps: string[] = []
  if (attestation.revoked) steps.push(`revoked${attestation.revoked_where ? ` at ${attestation.revoked_where}` : ''}`)
  if (attestation.rotation === 'rotated') steps.push('rotated')
  if (attestation.rotation === 'not_needed') steps.push('rotation not needed')
  if (attestation.exposure === 'assessed') steps.push('exposure assessed')
  if (attestation.owner_external) steps.push('external owner')
  return steps
}

async function loadAttestations() {
  try {
    const res = await incidentsApi.secretAttestations(props.provider, props.slug, props.repoSlug, props.finding.id)
    attestations.value = res.data ?? []
  } catch (err) {
    loadError.value = err instanceof Error ? `Previous attestations unavailable: ${err.message}` : 'Previous attestations unavailable'
  }
}

async function submit() {
  if (problem.value || submitting.value) return
  submitting.value = true
  error.value = ''
  try {
    await incidentsApi.attestSecret(props.provider, props.slug, props.repoSlug, props.finding.id, {
      ...checklist,
      revoked_where: checklist.revoked ? checklist.revoked_where.trim() : '',
      revoked_by: checklist.revoked ? checklist.revoked_by.trim() : '',
      reference: checklist.revoked ? checklist.reference.trim() : '',
      rotation_note: checklist.rotation ? checklist.rotation_note.trim() : '',
      exposure_note: checklist.exposure ? checklist.exposure_note.trim() : '',
    }, comment.value.trim())
    emit('done', checklist.revoked)
  } catch (err) {
    error.value = err instanceof Error ? err.message : 'Failed to record the attestation'
  } finally {
    submitting.value = false
  }
}

function onKeydown(event: KeyboardEvent) {
  if (event.key === 'Escape') emit('cancel')
}

onMounted(() => {
  document.addEventListener('keydown', onKeydown)
  void loadAttestations()
})
onUnmounted(() => document.removeEventListener('keydown', onKeydown))
</script>
