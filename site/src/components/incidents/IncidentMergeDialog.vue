<template>
  <Teleport to="body">
    <div
      class="fixed inset-0 z-[80] flex items-center justify-center bg-black/60 p-4"
      @click.self="emit('cancel')"
    >
      <form
        ref="formRef"
        class="flex max-h-[90vh] w-full max-w-2xl flex-col overflow-hidden rounded-xl border border-surface-border bg-surface-raised shadow-2xl focus:outline-none"
        role="dialog"
        aria-modal="true"
        aria-labelledby="merge-dialog-title"
        tabindex="-1"
        @keydown.esc.prevent="emit('cancel')"
        @submit.prevent="submit"
      >
        <div class="flex items-center gap-2 border-b border-surface-border-subtle px-4 py-3">
          <GitMerge
            class="h-4 w-4 text-accent"
            aria-hidden="true"
          />
          <h3
            id="merge-dialog-title"
            class="text-sm font-semibold text-white"
          >
            Merge #{{ incident.number }} into another incident
          </h3>
          <span class="ml-auto text-xs text-gray-500">Step {{ survivor ? 2 : 1 }} of 2</span>
        </div>

        <!-- Step 1: choose the incident that survives -->
        <div
          v-if="!survivor"
          class="min-h-0 flex-1 overflow-y-auto px-4 py-4"
        >
          <p class="text-sm text-gray-300">
            Choose the incident that stays. Only incidents of the same kind on the same repository are listed.
          </p>
          <input
            ref="searchRef"
            v-model="search"
            type="search"
            placeholder="Filter by number, title or identifier"
            class="mt-3 w-full rounded-md border border-surface-border bg-surface-overlay px-3 py-1.5 text-sm text-gray-100 placeholder:text-gray-600 focus:border-accent focus:outline-none"
          >
          <p
            v-if="loading"
            class="mt-4 text-sm text-gray-500"
          >
            Loading incidents…
          </p>
          <p
            v-else-if="error"
            class="mt-4 text-sm text-danger"
          >
            {{ error }}
          </p>
          <p
            v-else-if="shown.length === 0"
            class="mt-4 text-sm text-gray-500"
          >
            {{ candidates.length === 0 ? 'No other incident of this kind on this repository.' : 'No incident matches.' }}
          </p>
          <ul
            v-else
            class="mt-3 divide-y divide-surface-border-subtle rounded-md border border-surface-border"
          >
            <li
              v-for="candidate in shown"
              :key="candidate.number"
            >
              <button
                type="button"
                class="flex w-full items-start gap-3 px-3 py-2.5 text-left transition"
                :class="candidate.compatible ? 'hover:bg-surface-overlay' : 'cursor-not-allowed opacity-60'"
                :disabled="!candidate.compatible"
                @click="choose(candidate)"
              >
                <span class="font-mono text-xs text-gray-400">#{{ candidate.number }}</span>
                <span class="min-w-0 flex-1">
                  <span class="block truncate text-sm text-gray-100">{{ candidate.title }}</span>
                  <span
                    v-if="candidate.subject"
                    class="font-mono text-[11px] text-gray-500"
                  >{{ candidate.subject }}</span>
                  <span
                    v-if="!candidate.compatible"
                    class="block text-xs text-amber-300"
                  >Cannot merge: {{ candidate.reason }}</span>
                </span>
                <IncidentStatusPill
                  :status="candidate.state"
                  :label="STATE_LABELS[candidate.state]"
                />
              </button>
            </li>
          </ul>
        </div>

        <!-- Step 2: confirm -->
        <div
          v-else
          class="min-h-0 flex-1 space-y-4 overflow-y-auto px-4 py-4"
        >
          <div class="grid items-stretch gap-2 sm:grid-cols-[1fr_auto_1fr]">
            <div class="rounded-lg border border-danger/30 bg-danger/5 p-3">
              <div class="text-[11px] uppercase tracking-[0.12em] text-gray-500">
                Absorbed
              </div>
              <div class="mt-1 text-sm text-gray-100">
                <span class="font-mono text-gray-400">#{{ incident.number }}</span> {{ incident.title }}
              </div>
              <div
                v-if="ownSubject"
                class="mt-0.5 font-mono text-[11px] text-gray-500"
              >
                {{ ownSubject }}
              </div>
            </div>
            <ArrowRight
              class="h-5 w-5 self-center justify-self-center text-gray-500 max-sm:rotate-90"
              aria-hidden="true"
            />
            <div class="rounded-lg border border-accent/40 bg-accent/5 p-3">
              <div class="text-[11px] uppercase tracking-[0.12em] text-gray-500">
                Stays
              </div>
              <div class="mt-1 text-sm text-gray-100">
                <span class="font-mono text-gray-400">#{{ survivor.number }}</span> {{ survivor.title }}
              </div>
              <div
                v-if="survivor.subject"
                class="mt-0.5 font-mono text-[11px] text-gray-500"
              >
                {{ survivor.subject }}
              </div>
            </div>
          </div>

          <ul class="list-disc space-y-1 pl-5 text-sm text-gray-300">
            <li>The timeline, notices sent and completed actions of #{{ incident.number }} move to #{{ survivor.number }}.</li>
            <li>Its pending actions are dropped; #{{ survivor.number }} is recomputed from its own subject{{ survivor.state === 'closed' ? ' and reopens' : '' }}.</li>
            <li>#{{ incident.number }} stays readable, marked as merged.</li>
            <li class="font-medium text-amber-200">
              A merge cannot be undone.
            </li>
          </ul>

          <label class="block text-xs font-medium text-gray-300">
            Reason
            <textarea
              ref="reasonRef"
              v-model="reason"
              rows="2"
              required
              placeholder="The same vulnerability under its GHSA id, opened twice, …"
              class="mt-1.5 w-full rounded-md border border-surface-border bg-surface-overlay px-3 py-1.5 text-sm text-gray-100 placeholder:text-gray-600 focus:border-accent focus:outline-none"
            />
          </label>
          <p
            v-if="fourEyes"
            class="text-xs text-gray-400"
          >
            Four-eyes is on: this proposes the merge, and another person applies it.
          </p>
          <p
            v-if="error"
            class="text-sm text-danger"
          >
            {{ error }}
          </p>
        </div>

        <div class="flex items-center justify-end gap-2 border-t border-surface-border-subtle px-4 py-3">
          <button
            v-if="survivor"
            type="button"
            class="mr-auto rounded-md px-3 py-1.5 text-xs text-gray-400 transition hover:text-white"
            @click="survivor = null"
          >
            Back
          </button>
          <button
            type="button"
            class="rounded-md border border-surface-border px-3 py-1.5 text-xs text-gray-300 transition hover:text-white"
            @click="emit('cancel')"
          >
            Cancel
          </button>
          <button
            v-if="survivor"
            type="submit"
            class="rounded-md bg-danger px-3 py-1.5 text-xs font-medium text-white transition hover:bg-danger/90 disabled:opacity-50"
            :disabled="busy || !reason.trim()"
          >
            {{ fourEyes ? `Propose merging into #${survivor.number}` : `Merge into #${survivor.number}` }}
          </button>
        </div>
      </form>
    </div>
  </Teleport>
</template>

<script setup lang="ts">
import { ArrowRight, GitMerge } from 'lucide-vue-next'
import { computed, nextTick, onMounted, ref } from 'vue'

import { incidentsApi, STATE_LABELS, type IncidentSummary, type MergeCandidate } from '@/api/incidents'
import IncidentStatusPill from '@/components/incidents/IncidentStatusPill.vue'
import { errorText } from '@/lib/incidentView'

// A merge cannot be undone: the survivor is picked from the incidents that
// can take it (same kind, same repository, the same vulnerability for an
// exploited one), then confirmed with what moves and why.
const props = defineProps<{
  provider: string
  slug: string
  incident: IncidentSummary
  ownSubject?: string
  fourEyes: boolean
}>()
const emit = defineEmits<{ cancel: []; merged: [into: number]; proposed: [] }>()

const candidates = ref<MergeCandidate[]>([])
const loading = ref(true)
const busy = ref(false)
const error = ref('')
const search = ref('')
const reason = ref('')
const survivor = ref<MergeCandidate | null>(null)
const formRef = ref<HTMLFormElement | null>(null)
const searchRef = ref<HTMLInputElement | null>(null)
const reasonRef = ref<HTMLTextAreaElement | null>(null)

// Mergeable first, then by number, newest first.
const shown = computed(() => {
  const needle = search.value.trim().toLowerCase().replace(/^#/, '')
  return candidates.value
    .filter(candidate => !needle
      || String(candidate.number) === needle
      || candidate.title.toLowerCase().includes(needle)
      || candidate.subject.toLowerCase().includes(needle))
    .sort((a, b) => Number(b.compatible) - Number(a.compatible) || b.number - a.number)
})

onMounted(async () => {
  searchRef.value?.focus()
  try {
    const response = await incidentsApi.mergeCandidates(props.provider, props.slug, props.incident.number)
    candidates.value = response.data
  } catch (loadError) {
    error.value = errorText(loadError, 'Failed to list incidents')
  } finally {
    loading.value = false
  }
})

async function choose(candidate: MergeCandidate) {
  if (!candidate.compatible) return
  survivor.value = candidate
  error.value = ''
  await nextTick()
  reasonRef.value?.focus()
}

async function submit() {
  if (!survivor.value || !reason.value.trim()) return
  busy.value = true
  error.value = ''
  try {
    const response = await incidentsApi.merge(props.provider, props.slug, props.incident.number, survivor.value.number, reason.value.trim())
    if (response.data.proposed) emit('proposed')
    else emit('merged', response.data.merged_into)
  } catch (mergeError) {
    error.value = errorText(mergeError, 'Failed to merge')
  } finally {
    busy.value = false
  }
}
</script>
