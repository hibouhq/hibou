<template>
  <section :class="ui.card">
    <h2 :class="ui.heading">
      Actions
    </h2>
    <p class="mt-1 text-xs text-gray-500">
      Derived from the decision and the scope. The incident closes itself once every required action is done or waived.
    </p>

    <p
      v-if="error"
      :class="[ui.error, 'mt-3']"
    >
      {{ error }}
    </p>

    <template
      v-for="group in groups"
      :key="group.title"
    >
      <h3
        v-if="group.actions.length > 0"
        class="mt-4 text-xs font-medium uppercase tracking-[0.14em] text-gray-500"
      >
        {{ group.title }}
      </h3>
      <ul
        v-if="group.actions.length > 0"
        class="mt-2 divide-y divide-surface-border-subtle rounded-md border border-surface-border"
      >
        <li
          v-for="action in group.actions"
          :id="`action-${action.id}`"
          :key="action.id"
          class="px-3 py-2.5 transition"
        >
          <div class="flex flex-wrap items-start justify-between gap-2">
            <div class="min-w-0">
              <div class="flex flex-wrap items-center gap-2">
                <RouterLink
                  v-if="subjectLink(action)"
                  :to="subjectLink(action)!.to"
                  class="text-sm font-medium text-gray-100 underline decoration-gray-600 underline-offset-2 transition hover:decoration-gray-300"
                  :title="`Open ${subjectLink(action)!.label}`"
                >
                  {{ action.label }}
                </RouterLink>
                <span
                  v-else
                  class="text-sm font-medium text-gray-100"
                >{{ action.label }}</span>
                <IncidentStatusPill :status="action.state" />
                <span class="font-mono text-[11px] text-gray-500">{{ action.kind }}</span>
                <span
                  v-if="action.automatic"
                  class="rounded-full bg-surface-overlay px-1.5 text-[10px] text-gray-500"
                >automatic</span>
              </div>
              <div class="mt-0.5 flex flex-wrap gap-x-3 text-xs text-gray-500">
                <span v-if="action.state === 'pending' && nullTime(action.due_at)">
                  due <CountdownText :at="nullTime(action.due_at)" />
                </span>
                <span v-if="nullTime(action.done_at)">
                  done <DateTime :value="nullTime(action.done_at)" /> by {{ nameOf(nullUUID(action.done_by)) }}
                </span>
                <span v-if="action.state === 'waived'">
                  waived by {{ nameOf(nullUUID(action.waived_by)) }}: <AutolinkedText
                    :text="nullString(action.waived_reason)"
                    :provider="provider"
                    :slug="slug"
                  />
                </span>
                <span v-if="nullUUID(action.assignee_id)">
                  assigned to {{ nameOf(nullUUID(action.assignee_id)) }}
                </span>
              </div>
              <dl
                v-if="evidenceEntries(action.evidence).length > 0"
                class="mt-1 flex flex-wrap gap-x-3 gap-y-0.5 text-[11px]"
              >
                <div
                  v-for="[key, value] in evidenceEntries(action.evidence)"
                  :key="key"
                  class="flex gap-1"
                >
                  <dt class="text-gray-500">
                    {{ key }}:
                  </dt>
                  <dd class="break-all text-gray-300">
                    <AutolinkedText
                      :text="String(value)"
                      :provider="provider"
                      :slug="slug"
                    />
                  </dd>
                </div>
              </dl>
              <p
                v-if="waiverProposal(action)"
                class="mt-1 text-xs text-amber-200"
              >
                Waiver proposed by {{ nameOf(waiverProposal(action)?.by ?? null) }}: {{ waiverProposal(action)?.reason }}
              </p>
            </div>

            <div class="flex flex-wrap gap-1.5">
              <button
                v-if="isFiling(action.kind)"
                type="button"
                :class="ui.secondary"
                :disabled="busy"
                @click="loadDraft(action)"
              >
                Filing draft
              </button>
              <a
                v-if="portal(action)"
                :href="portal(action)!.url"
                target="_blank"
                rel="noopener noreferrer"
                :class="ui.secondary"
                :title="`File it on the ${portal(action)!.recipient}`"
              >
                <span class="inline-flex items-center gap-1"><ExternalLink class="h-3 w-3" /> Open portal</span>
              </a>
              <template v-if="detail.can_manage && action.state === 'pending'">
                <button
                  v-if="isFiling(action.kind)"
                  type="button"
                  :class="ui.secondary"
                  @click="openForm(action, 'file')"
                >
                  Record filing
                </button>
                <button
                  v-else-if="action.kind === 'client_notice'"
                  type="button"
                  :class="ui.secondary"
                  @click="emit('notice', action.subject_id)"
                >
                  Send notice
                </button>
                <button
                  v-else-if="!action.automatic"
                  type="button"
                  :class="ui.secondary"
                  @click="openForm(action, 'complete')"
                >
                  Complete
                </button>
                <button
                  v-if="waiverProposal(action) && waiverProposal(action)?.by !== currentUserId"
                  type="button"
                  :class="ui.primary"
                  :disabled="busy"
                  @click="approveWaiver(action)"
                >
                  Approve waiver
                </button>
                <button
                  v-else-if="!waiverProposal(action)"
                  type="button"
                  :class="ui.danger"
                  :disabled="busy"
                  @click="waive(action)"
                >
                  Waive
                </button>
              </template>
              <button
                v-if="detail.can_manage && action.state !== 'pending'"
                type="button"
                :class="ui.secondary"
                :disabled="busy"
                @click="reopen(action)"
              >
                Reopen
              </button>
            </div>
          </div>

          <!-- Record filing / complete -->
          <form
            v-if="formFor === action.id"
            class="mt-2 grid gap-3 rounded-md bg-surface-overlay/40 p-3 sm:grid-cols-2"
            @submit.prevent="submitForm(action)"
          >
            <label
              v-if="formOp === 'file'"
              :class="ui.label"
            >
              Reference
              <input
                v-model="form.reference"
                required
                type="text"
                :class="ui.input"
                placeholder="The platform's submission reference"
              >
            </label>
            <label
              v-if="formOp === 'file'"
              :class="ui.label"
            >
              Filed at
              <input
                v-model="form.filed_at"
                type="datetime-local"
                :class="ui.input"
              >
            </label>
            <label
              v-else
              :class="ui.label"
            >
              Note
              <input
                v-model="form.note"
                type="text"
                :class="ui.input"
              >
            </label>
            <div class="flex items-center gap-2 sm:col-span-2">
              <button
                type="submit"
                :class="ui.primary"
                :disabled="busy || (formOp === 'file' && !form.reference.trim())"
              >
                {{ formOp === 'file' ? 'Record filing' : 'Complete' }}
              </button>
              <button
                type="button"
                :class="ui.secondary"
                @click="formFor = ''"
              >
                Cancel
              </button>
            </div>
          </form>

          <!-- Filing draft -->
          <div
            v-if="draft && draftFor === action.id"
            class="mt-2 rounded-md border border-surface-border bg-surface-overlay/40 p-3"
          >
            <div class="flex items-center justify-between gap-2">
              <span class="text-xs font-medium text-gray-300">Filing draft · {{ humanize(draft.step) }}</span>
              <div class="flex gap-1.5">
                <button
                  type="button"
                  :class="ui.secondary"
                  @click="copyDraft"
                >
                  <span class="inline-flex items-center gap-1"><Copy class="h-3 w-3" /> Copy</span>
                </button>
                <button
                  type="button"
                  :class="ui.secondary"
                  @click="draftFor = ''"
                >
                  Close
                </button>
              </div>
            </div>
            <pre class="mt-2 max-h-80 overflow-auto whitespace-pre-wrap font-mono text-xs text-gray-200">{{ draft.text }}</pre>
          </div>
        </li>
      </ul>
    </template>

    <p
      v-if="groups.every(group => group.actions.length === 0)"
      class="mt-3 text-sm text-gray-500"
    >
      No actions yet: they follow the decision.
    </p>
  </section>
</template>

<script setup lang="ts">
import { Copy, ExternalLink } from 'lucide-vue-next'
import { computed, reactive, ref } from 'vue'
import { RouterLink, type RouteLocationRaw } from 'vue-router'

import {
  incidentsApi,
  isFiling,
  nullString,
  nullTime,
  nullUUID,
  type FilingDraft,
  type IncidentAction,
  type IncidentDetail,
} from '@/api/incidents'
import DateTime from '@/components/DateTime.vue'
import AutolinkedText from '@/components/incidents/AutolinkedText.vue'
import CountdownText from '@/components/incidents/CountdownText.vue'
import IncidentStatusPill from '@/components/incidents/IncidentStatusPill.vue'
import { ui } from '@/components/incidents/ui'
import { useDialog } from '@/composables/useDialog'
import { useToast } from '@/composables/useToast'
import { errorText, evidenceEntries, filingPortal, filingStep, fromLocalInput, groupActions, humanize, toLocalInput, waiverProposal } from '@/lib/incidentView'

const props = defineProps<{
  provider: string
  slug: string
  detail: IncidentDetail
  currentUserId: string
  names: Record<string, string>
}>()
const emit = defineEmits<{ changed: []; notice: [clientId: string] }>()

const { promptDialog } = useDialog()
const toast = useToast()

const busy = ref(false)
const error = ref('')
const formFor = ref('')
const formOp = ref<'file' | 'complete'>('complete')
const form = reactive({ reference: '', note: '', filed_at: '' })
const draft = ref<FilingDraft | null>(null)
const draftFor = ref('')

const groups = computed(() => {
  const { required, optional } = groupActions(props.detail.actions)
  return [
    { title: 'Required', actions: required },
    { title: 'Optional', actions: optional },
  ]
})

const number = computed(() => props.detail.incident.number)

function portal(action: IncidentAction) {
  return filingPortal(action.kind, props.detail.regimes)
}

// Where an action's subject lives: a release or ref's findings, a client's
// page, a component in the dependencies.
function subjectLink(action: IncidentAction): { label: string; to: RouteLocationRaw } | null {
  const repoSlug = props.detail.incident.repo_slug
  const params = { provider: props.provider, slug: props.slug }
  if (action.subject_type === 'client') {
    const client = props.detail.scope.flatMap(row => row.clients).find(entry => entry.id === action.subject_id)
    return client ? { label: client.name, to: { name: 'client-overview', params: { ...params, clientSlug: client.slug } } } : null
  }
  if (!repoSlug) return null
  if (action.subject_type === 'release' || action.subject_type === 'ref') {
    const row = props.detail.scope.find(entry => entry.subject_type === action.subject_type && entry.subject_id === action.subject_id)
    if (!row?.label) return null
    return { label: row.label, to: { name: 'repo-vulnerabilities', params: { ...params, repoSlug }, query: { ref: row.label } } }
  }
  if (action.subject_type === 'component' && action.subject_id) {
    return { label: 'component', to: { name: 'repo-dependencies', params: { ...params, repoSlug }, query: { component: action.subject_id } } }
  }
  return null
}

function nameOf(id: string | null) {
  if (!id) return 'someone'
  return props.names[id] ?? `${id.slice(0, 8)}…`
}

function openForm(action: IncidentAction, op: 'file' | 'complete') {
  Object.assign(form, { reference: '', note: '', filed_at: toLocalInput(new Date()) })
  formOp.value = op
  formFor.value = action.id
}

async function run(task: () => Promise<unknown>, fallback: string) {
  busy.value = true
  error.value = ''
  try {
    const result = await task()
    emit('changed')
    return { ok: true, result }
  } catch (taskError) {
    error.value = errorText(taskError, fallback)
    return { ok: false, result: null }
  } finally {
    busy.value = false
  }
}

async function submitForm(action: IncidentAction) {
  const op = formOp.value
  const { ok } = await run(() => incidentsApi.action(props.provider, props.slug, number.value, action.id, op, op === 'file'
    ? { reference: form.reference.trim(), filed_at: fromLocalInput(form.filed_at) }
    : { note: form.note.trim() || undefined }), 'Failed to update the action')
  if (ok) formFor.value = ''
}

async function waive(action: IncidentAction) {
  const reason = await promptDialog({
    title: `Waive "${action.label}"`,
    message: 'Waiving is the sanctioned exception: audited, and four-eyed when the organization requires it.',
    confirmLabel: 'Waive',
    tone: 'danger',
    input: { label: 'Reason', required: true },
  })
  if (!reason?.trim()) return
  const { ok, result } = await run(() => incidentsApi.action(props.provider, props.slug, number.value, action.id, 'waive', { reason: reason.trim() }), 'Failed to waive the action')
  const updated = (result as { data?: IncidentAction } | null)?.data
  if (ok && updated?.state === 'pending') {
    toast.info('Waiver proposed', "Waiting for another person's approval.")
  }
}

async function approveWaiver(action: IncidentAction) {
  const proposal = waiverProposal(action)
  await run(() => incidentsApi.action(props.provider, props.slug, number.value, action.id, 'waive', { approve: true, reason: proposal?.reason }), 'Failed to approve the waiver')
}

async function reopen(action: IncidentAction) {
  const reason = await promptDialog({
    title: `Reopen "${action.label}"`,
    confirmLabel: 'Reopen',
    input: { label: 'Reason', required: true },
  })
  if (!reason?.trim()) return
  await run(() => incidentsApi.action(props.provider, props.slug, number.value, action.id, 'reopen', { reason: reason.trim() }), 'Failed to reopen the action')
}

async function loadDraft(action: IncidentAction) {
  busy.value = true
  error.value = ''
  try {
    const response = await incidentsApi.filingDraft(props.provider, props.slug, number.value, filingStep(action.kind, props.detail.regimes))
    draft.value = response.data
    draftFor.value = action.id
  } catch (draftError) {
    error.value = errorText(draftError, 'Failed to load the filing draft')
  } finally {
    busy.value = false
  }
}

async function copyDraft() {
  if (!draft.value) return
  try {
    await navigator.clipboard.writeText(draft.value.text)
    toast.success('Draft copied')
  } catch {
    toast.error('Copy failed', 'Select the text and copy it by hand.')
  }
}
</script>
