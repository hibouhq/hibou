<template>
  <section
    ref="root"
    :class="ui.card"
  >
    <div class="flex flex-wrap items-center justify-between gap-2">
      <h2 :class="ui.heading">
        Deliveries
      </h2>
      <button
        v-if="canSend && !formOpen"
        type="button"
        :class="ui.secondary"
        @click="openForm()"
      >
        Send notice
      </button>
    </div>
    <p class="mt-1 text-xs text-gray-500">
      Documents are stored as sent, under their digest; a delivery records that this document was
      handed to this channel for this recipient at this time.
    </p>

    <p
      v-if="error"
      :class="[ui.error, 'mt-3']"
    >
      {{ error }}
    </p>

    <!-- Send notice -->
    <form
      v-if="formOpen"
      class="mt-3 space-y-3 rounded-md bg-surface-overlay/40 p-3"
      @submit.prevent="send"
    >
      <fieldset>
        <legend class="text-xs font-medium text-gray-300">
          Clients
        </legend>
        <p
          v-if="candidates.length === 0"
          class="mt-1.5 text-xs text-gray-500"
        >
          No client in scope.
        </p>
        <div
          v-else
          class="mt-1.5 flex flex-wrap gap-x-4 gap-y-1.5"
        >
          <label
            v-for="client in candidates"
            :key="client.id"
            class="inline-flex items-center gap-1.5 text-xs text-gray-300"
          >
            <input
              v-model="form.client_ids"
              type="checkbox"
              class="h-3.5 w-3.5 accent-accent"
              :value="client.id"
            >
            {{ client.name }}
            <span
              v-if="owed.includes(client.id)"
              class="text-[10px] text-amber-300"
            >notice owed</span>
          </label>
        </div>
      </fieldset>
      <label :class="[ui.label, 'max-w-xs']">
        Channel
        <select
          v-model="form.channel"
          :class="ui.input"
        >
          <option value="">
            Client's own
          </option>
          <option
            v-for="channel in CHANNELS"
            :key="channel"
            :value="channel"
          >
            {{ humanize(channel) }}
          </option>
        </select>
      </label>
      <label :class="ui.label">
        Measures
        <textarea
          v-model="form.measures"
          rows="3"
          :class="ui.textarea"
          placeholder="What users can do: upgrade path, workaround, configuration change"
        />
      </label>
      <label :class="ui.label">
        Evidence{{ form.channel === 'manual' ? '' : ' (manual channel only)' }}
        <textarea
          v-model="form.evidence"
          rows="2"
          :required="form.channel === 'manual'"
          :disabled="form.channel !== 'manual'"
          :class="ui.textarea"
          placeholder="How and when it was sent, by whom"
        />
      </label>
      <div class="flex items-center gap-2">
        <button
          type="submit"
          :class="ui.primary"
          :disabled="busy || form.client_ids.length === 0 || (form.channel === 'manual' && !form.evidence.trim())"
        >
          {{ busy ? 'Sending…' : 'Send' }}
        </button>
        <button
          type="button"
          :class="ui.secondary"
          @click="formOpen = false"
        >
          Cancel
        </button>
      </div>
    </form>

    <p
      v-if="detail.deliveries.length === 0"
      class="mt-3 text-sm text-gray-500"
    >
      Nothing delivered yet.
    </p>
    <ul
      v-else
      class="mt-3 divide-y divide-surface-border-subtle rounded-md border border-surface-border"
    >
      <li
        v-for="delivery in detail.deliveries"
        :key="delivery.id"
        class="px-3 py-2.5"
      >
        <div class="flex flex-wrap items-start justify-between gap-2">
          <div class="min-w-0">
            <div class="flex flex-wrap items-center gap-2 text-sm">
              <RouterLink
                v-if="nullString(delivery.client_slug)"
                :to="{ name: 'client-overview', params: { provider, slug, clientSlug: nullString(delivery.client_slug) } }"
                class="font-medium text-accent transition hover:underline"
              >
                {{ nullString(delivery.client_name) }}
              </RouterLink>
              <span
                v-else
                class="font-medium text-gray-100"
              >{{ delivery.recipient || 'Recipient' }}</span>
              <IncidentStatusPill :status="delivery.status" />
              <span class="text-xs text-gray-400">{{ delivery.channel }}</span>
              <span
                v-if="delivery.recipient"
                class="font-mono text-[11px] text-gray-500"
              >{{ delivery.recipient }}</span>
            </div>
            <div class="mt-0.5 flex flex-wrap gap-x-3 text-xs text-gray-500">
              <span>created {{ formatDateTime(delivery.created_at) }}</span>
              <span v-if="nullTime(delivery.sent_at)">sent {{ formatDateTime(nullTime(delivery.sent_at) as string) }}</span>
              <span v-if="nullTime(delivery.acknowledged_at)">acknowledged {{ formatDateTime(nullTime(delivery.acknowledged_at) as string) }}</span>
            </div>
            <p
              v-if="delivery.error"
              class="mt-1 text-xs text-danger"
            >
              {{ delivery.error }}
            </p>
            <ul
              v-if="delivery.documents.length > 0"
              class="mt-1.5 space-y-0.5 text-xs"
            >
              <li
                v-for="document in delivery.documents"
                :key="document.sha256"
                class="flex flex-wrap items-center gap-2"
              >
                <a
                  :href="incidentsApi.documentUrl(provider, slug, detail.incident.number, document.sha256)"
                  class="inline-flex items-center gap-1 text-accent transition hover:underline"
                >
                  <FileDown class="h-3 w-3" />
                  {{ document.filename || document.kind }}
                </a>
                <span class="font-mono text-[10px] text-gray-500">{{ document.sha256.slice(0, 12) }}</span>
                <template v-if="verification[delivery.id]">
                  <span
                    v-for="result in verification[delivery.id].documents.filter(entry => entry.sha256 === document.sha256)"
                    :key="`${result.sha256}-v`"
                    :class="documentVerified(result) ? 'text-green-300' : 'text-danger'"
                  >
                    {{ documentVerified(result) ? 'verified' : (result.error || result.note || 'mismatch') }}
                  </span>
                </template>
              </li>
            </ul>
            <p
              v-if="verification[delivery.id]"
              class="mt-1 text-xs"
              :class="verification[delivery.id].verified ? 'text-green-300' : 'text-danger'"
            >
              {{ verification[delivery.id].verified ? 'Stored documents match their digests.' : 'Verification failed.' }}
            </p>
          </div>
          <div class="flex gap-1.5">
            <button
              v-if="delivery.documents.length > 0"
              type="button"
              :class="ui.secondary"
              :disabled="busy"
              @click="verify(delivery.id)"
            >
              Verify
            </button>
            <button
              v-if="detail.can_manage && delivery.status === 'pending_approval'"
              type="button"
              :class="ui.primary"
              :disabled="busy"
              @click="approve(delivery.id)"
            >
              Approve &amp; send
            </button>
          </div>
        </div>
      </li>
    </ul>
  </section>
</template>

<script setup lang="ts">
import { FileDown } from 'lucide-vue-next'
import { computed, nextTick, reactive, ref, watch } from 'vue'
import { RouterLink } from 'vue-router'

import {
  incidentOpen,
  incidentsApi,
  nullString,
  nullTime,
  type DeliverInput,
  type IncidentDetail,
  type VerifyResult,
} from '@/api/incidents'
import IncidentStatusPill from '@/components/incidents/IncidentStatusPill.vue'
import { ui } from '@/components/incidents/ui'
import { useToast } from '@/composables/useToast'
import { formatDateTime } from '@/lib/datetime'
import { errorText, humanize, pendingNoticeClientIds } from '@/lib/incidentView'

const props = withDefaults(defineProps<{
  provider: string
  slug: string
  detail: IncidentDetail
  clientNames: Record<string, string>
  noticeRequest?: { clientId: string; seq: number } | null
}>(), { noticeRequest: null })
const emit = defineEmits<{ changed: [] }>()

const CHANNELS = ['email', 'webhook', 'portal', 'manual'] as const

const toast = useToast()
const root = ref<HTMLElement | null>(null)
const busy = ref(false)
const error = ref('')
const formOpen = ref(false)
const verification = ref<Record<string, VerifyResult>>({})
const form = reactive({
  client_ids: [] as string[],
  channel: '' as NonNullable<DeliverInput['channel']>,
  measures: '',
  evidence: '',
})

const canSend = computed(() => props.detail.can_manage && incidentOpen(props.detail.incident.state))
const owed = computed(() => pendingNoticeClientIds(props.detail.actions))

// Clients owed a notice first, then every client the scope names.
const candidates = computed(() => {
  const seen = new Map<string, string>()
  for (const id of owed.value) seen.set(id, props.clientNames[id] ?? id)
  for (const row of props.detail.scope) {
    if (row.subject_type === 'client') seen.set(row.subject_id, row.label || props.clientNames[row.subject_id] || row.subject_id)
    for (const client of row.clients) seen.set(client.id, client.name)
  }
  return [...seen].map(([id, name]) => ({ id, name }))
})

watch(() => props.noticeRequest?.seq, async () => {
  if (!props.noticeRequest) return
  openForm([props.noticeRequest.clientId])
  await nextTick()
  root.value?.scrollIntoView({ behavior: 'smooth', block: 'start' })
})

function openForm(clientIds?: string[]) {
  Object.assign(form, { client_ids: clientIds ?? [...owed.value], channel: '', measures: '', evidence: '' })
  formOpen.value = true
}

function documentVerified(result: VerifyResult['documents'][number]) {
  return result.stored_matches_digest && result.rerendered_matches !== false && !result.error
}

async function send() {
  busy.value = true
  error.value = ''
  try {
    const response = await incidentsApi.deliver(props.provider, props.slug, props.detail.incident.number, {
      client_ids: form.client_ids,
      channel: form.channel,
      measures: form.measures.trim() || undefined,
      evidence: form.channel === 'manual' ? form.evidence.trim() : undefined,
    })
    const count = response.data?.length ?? 0
    toast.success(count === 1 ? 'Notice recorded' : `${count} notices recorded`)
    formOpen.value = false
    emit('changed')
  } catch (sendError) {
    error.value = errorText(sendError, 'Failed to send the notice')
  } finally {
    busy.value = false
  }
}

async function approve(deliveryId: string) {
  busy.value = true
  error.value = ''
  try {
    await incidentsApi.approveDelivery(props.provider, props.slug, props.detail.incident.number, deliveryId)
    emit('changed')
  } catch (approveError) {
    error.value = errorText(approveError, 'Failed to approve the delivery')
  } finally {
    busy.value = false
  }
}

async function verify(deliveryId: string) {
  busy.value = true
  error.value = ''
  try {
    const response = await incidentsApi.verifyDelivery(props.provider, props.slug, props.detail.incident.number, deliveryId)
    verification.value = { ...verification.value, [deliveryId]: response.data }
  } catch (verifyError) {
    error.value = errorText(verifyError, 'Failed to verify the delivery')
  } finally {
    busy.value = false
  }
}
</script>
