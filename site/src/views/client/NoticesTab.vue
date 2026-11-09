<template>
  <div class="space-y-6">
    <!-- Delivery settings -->
    <section>
      <div class="flex flex-wrap items-center justify-between gap-2 border-b border-surface-border pb-2">
        <h2 class="text-base font-semibold text-white">
          Delivery settings
        </h2>
        <span
          v-if="delivery"
          class="text-xs text-gray-500"
        >
          Notices go by <span class="font-medium text-gray-300">{{ CHANNEL_LABELS[delivery.effective_channel] }}</span>
        </span>
      </div>
      <p class="mt-2 text-sm text-gray-400">
        How this client receives security notices when an incident affects a release it runs.
        Automatic picks the webhook when one is set, otherwise email to the security contacts.
      </p>

      <div
        v-if="deliveryLoading"
        class="mt-4 text-sm text-gray-500"
      >
        Loading delivery settings…
      </div>
      <div
        v-else-if="deliveryError"
        class="mt-4 rounded-md border border-danger/30 bg-danger/10 px-4 py-3 text-sm text-red-200"
      >
        {{ deliveryError }}
      </div>
      <form
        v-else-if="delivery"
        class="mt-4 space-y-5"
        @submit.prevent="saveDelivery"
      >
        <div>
          <div class="flex items-center justify-between">
            <span class="text-xs font-medium text-gray-400">Security contacts</span>
            <button
              v-if="isOrgAdmin"
              type="button"
              class="inline-flex items-center gap-1 text-xs text-accent hover:underline"
              @click="addContact"
            >
              <Plus class="h-3.5 w-3.5" />
              Add contact
            </button>
          </div>
          <p
            v-if="form.contacts.length === 0"
            class="mt-2 rounded-md border border-dashed border-surface-border px-4 py-3 text-xs text-gray-500"
          >
            No security contact. Email notices cannot be sent until one is added.
          </p>
          <div
            v-else
            class="mt-2 space-y-2"
          >
            <div
              v-for="(contact, index) in form.contacts"
              :key="index"
              class="grid gap-2 sm:grid-cols-[minmax(0,1fr)_minmax(0,1.3fr)_minmax(0,1fr)_auto]"
            >
              <input
                v-model="contact.name"
                type="text"
                placeholder="Name"
                aria-label="Contact name"
                :disabled="!isOrgAdmin"
                class="h-8 rounded-md border border-surface-border bg-surface-overlay px-2.5 text-sm text-gray-200 focus:border-accent/50 focus:outline-none disabled:opacity-60"
              >
              <input
                v-model="contact.email"
                type="email"
                placeholder="security@client.example"
                aria-label="Contact email"
                required
                :disabled="!isOrgAdmin"
                class="h-8 rounded-md border border-surface-border bg-surface-overlay px-2.5 font-mono text-xs text-gray-200 focus:border-accent/50 focus:outline-none disabled:opacity-60"
              >
              <input
                v-model="contact.role"
                type="text"
                placeholder="Role (e.g. CISO)"
                aria-label="Contact role"
                :disabled="!isOrgAdmin"
                class="h-8 rounded-md border border-surface-border bg-surface-overlay px-2.5 text-sm text-gray-200 focus:border-accent/50 focus:outline-none disabled:opacity-60"
              >
              <button
                v-if="isOrgAdmin"
                type="button"
                class="inline-flex h-8 w-8 items-center justify-center rounded-md text-gray-500 transition hover:bg-surface-overlay hover:text-danger"
                title="Remove contact"
                @click="form.contacts.splice(index, 1)"
              >
                <Trash2 class="h-4 w-4" />
              </button>
            </div>
          </div>
        </div>

        <div class="grid gap-4 sm:grid-cols-2">
          <label class="block">
            <span class="text-xs font-medium text-gray-400">Channel</span>
            <select
              v-model="form.channel"
              :disabled="!isOrgAdmin"
              class="mt-1 h-8 w-full rounded-md border border-surface-border bg-surface-overlay px-2 text-sm text-gray-200 focus:border-accent/50 focus:outline-none disabled:opacity-60"
            >
              <option value="">
                Automatic ({{ CHANNEL_LABELS[delivery.effective_channel] }})
              </option>
              <option
                v-for="channel in CHANNELS"
                :key="channel"
                :value="channel"
              >
                {{ CHANNEL_LABELS[channel] }}
              </option>
            </select>
          </label>
        </div>

        <div class="grid gap-4 sm:grid-cols-2">
          <label class="block">
            <span class="text-xs font-medium text-gray-400">Webhook URL</span>
            <input
              v-model="form.webhookUrl"
              type="url"
              placeholder="https://client.example/hooks/security"
              :disabled="!isOrgAdmin"
              class="mt-1 h-8 w-full rounded-md border border-surface-border bg-surface-overlay px-2.5 font-mono text-xs text-gray-200 focus:border-accent/50 focus:outline-none disabled:opacity-60"
            >
            <span class="mt-1 block text-[11px] text-gray-500">https only. The body is signed with the secret (HMAC).</span>
          </label>
          <label class="block">
            <span class="text-xs font-medium text-gray-400">
              Webhook secret
              <span
                v-if="delivery.webhook_secret_set"
                class="ml-1 rounded-full border border-ok/40 px-1.5 py-0.5 text-[10px] text-ok"
              >set</span>
            </span>
            <input
              v-model="form.webhookSecret"
              type="password"
              autocomplete="new-password"
              :placeholder="delivery.webhook_secret_set ? 'Leave empty to keep the current secret' : 'Shared secret'"
              :disabled="!isOrgAdmin"
              class="mt-1 h-8 w-full rounded-md border border-surface-border bg-surface-overlay px-2.5 font-mono text-xs text-gray-200 focus:border-accent/50 focus:outline-none disabled:opacity-60"
            >
            <span class="mt-1 block text-[11px] text-gray-500">Write-only. Re-enter it when you change the URL.</span>
          </label>
        </div>

        <div
          v-if="isOrgAdmin"
          class="flex items-center gap-3"
        >
          <button
            type="submit"
            class="rounded-md bg-accent px-3 py-1.5 text-xs font-medium text-white transition hover:bg-accent/90 disabled:cursor-not-allowed disabled:opacity-50"
            :disabled="saving"
          >
            {{ saving ? 'Saving…' : 'Save delivery settings' }}
          </button>
          <span
            v-if="formError"
            class="text-xs text-danger"
          >{{ formError }}</span>
        </div>
        <p
          v-else
          class="text-xs text-gray-500"
        >
          Only organization admins can change delivery settings.
        </p>
      </form>
    </section>

    <!-- Portal tokens -->
    <section v-if="isOrgAdmin">
      <div class="flex flex-wrap items-center justify-between gap-2 border-b border-surface-border pb-2">
        <h2 class="text-base font-semibold text-white">
          Portal tokens
        </h2>
      </div>
      <p class="mt-2 text-sm text-gray-400">
        A portal token lets this client fetch its notices and documents itself. It is bound to this client and can read nothing else.
      </p>

      <form
        class="mt-4 flex flex-wrap items-center gap-2"
        @submit.prevent="createToken"
      >
        <input
          v-model="tokenName"
          type="text"
          placeholder="Token name (e.g. client SOC)"
          aria-label="Token name"
          class="h-8 w-64 rounded-md border border-surface-border bg-surface-overlay px-2.5 text-sm text-gray-200 focus:border-accent/50 focus:outline-none"
        >
        <button
          type="submit"
          class="inline-flex items-center gap-1.5 rounded-md bg-accent px-3 py-1.5 text-xs font-medium text-white transition hover:bg-accent/90 disabled:cursor-not-allowed disabled:opacity-50"
          :disabled="creatingToken || !tokenName.trim()"
        >
          <KeyRound class="h-3.5 w-3.5" />
          {{ creatingToken ? 'Creating…' : 'Create token' }}
        </button>
      </form>

      <div
        v-if="issuedToken"
        class="mt-4 space-y-3 rounded-md border border-ok/40 bg-ok/5 px-4 py-3"
      >
        <p class="text-xs text-gray-300">
          Copy the token now: it is shown once. Give it to the client with the URLs below.
        </p>
        <div class="flex items-center gap-2">
          <code class="min-w-0 flex-1 truncate rounded bg-surface-overlay px-2 py-1.5 font-mono text-xs text-gray-200">{{ issuedToken }}</code>
          <button
            type="button"
            class="inline-flex items-center gap-1.5 rounded-md border border-surface-border bg-surface-overlay px-2.5 py-1.5 text-xs text-gray-300 transition hover:text-white"
            @click="copy(issuedToken)"
          >
            <Copy class="h-3.5 w-3.5" />
            Copy
          </button>
        </div>
        <pre class="overflow-x-auto rounded bg-surface-overlay px-3 py-2 font-mono text-[11px] leading-relaxed text-gray-300">{{ portalSnippet }}</pre>
        <div class="flex justify-end gap-2">
          <button
            type="button"
            class="inline-flex items-center gap-1.5 rounded-md border border-surface-border bg-surface-overlay px-2.5 py-1.5 text-xs text-gray-300 transition hover:text-white"
            @click="copy(portalSnippet)"
          >
            <Copy class="h-3.5 w-3.5" />
            Copy instructions
          </button>
          <button
            type="button"
            class="rounded-md px-2.5 py-1.5 text-xs text-gray-400 transition hover:text-white"
            @click="issuedToken = ''"
          >
            Done
          </button>
        </div>
      </div>

      <div
        v-if="tokensLoading"
        class="mt-4 text-sm text-gray-500"
      >
        Loading tokens…
      </div>
      <p
        v-else-if="tokens.length === 0"
        class="mt-4 text-xs text-gray-500"
      >
        No portal token yet.
      </p>
      <div
        v-else
        class="mt-4 overflow-hidden rounded-md border border-surface-border"
      >
        <table class="min-w-full divide-y divide-surface-border-subtle text-sm">
          <thead class="bg-surface-overlay text-left text-xs uppercase tracking-[0.14em] text-gray-500">
            <tr>
              <th class="px-4 py-2.5 font-medium">
                Name
              </th>
              <th class="px-4 py-2.5 font-medium">
                Created
              </th>
              <th class="px-4 py-2.5 font-medium">
                Last used
              </th>
              <th class="px-4 py-2.5 font-medium" />
            </tr>
          </thead>
          <tbody class="divide-y divide-surface-border-subtle">
            <tr
              v-for="token in tokens"
              :key="token.id"
              :class="token.revoked ? 'opacity-60' : ''"
            >
              <td class="px-4 py-2.5 text-gray-200">
                {{ token.name }}
              </td>
              <td
                class="px-4 py-2.5 text-xs text-gray-400"
                :title="formatDateTime(token.created_at)"
              >
                {{ relativeTime(token.created_at) }}
              </td>
              <td class="px-4 py-2.5 text-xs text-gray-400">
                {{ token.last_used_at ? relativeTime(token.last_used_at) : 'never' }}
              </td>
              <td class="px-4 py-2.5 text-right">
                <span
                  v-if="token.revoked"
                  class="text-xs text-gray-500"
                >revoked</span>
                <button
                  v-else
                  type="button"
                  class="text-xs text-danger hover:underline disabled:opacity-50"
                  :disabled="revokingId === token.id"
                  @click="revokeToken(token)"
                >
                  Revoke
                </button>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </section>

    <!-- Notices received -->
    <section>
      <div class="flex flex-wrap items-center justify-between gap-2 border-b border-surface-border pb-2">
        <h2 class="text-base font-semibold text-white">
          Notices received
        </h2>
        <span class="text-xs text-gray-500">{{ notices.length }} total</span>
      </div>
      <div
        v-if="noticesLoading"
        class="mt-4 text-sm text-gray-500"
      >
        Loading notices…
      </div>
      <div
        v-else-if="noticesError"
        class="mt-4 rounded-md border border-danger/30 bg-danger/10 px-4 py-3 text-sm text-red-200"
      >
        {{ noticesError }}
      </div>
      <div
        v-else-if="notices.length === 0"
        class="mt-4 rounded-md border border-dashed border-surface-border px-6 py-8 text-center"
      >
        <Inbox class="mx-auto h-7 w-7 text-gray-600" />
        <p class="mt-2 text-sm text-gray-400">
          This client has not been sent any security notice.
        </p>
      </div>
      <div
        v-else
        class="mt-4 overflow-hidden rounded-md border border-surface-border"
      >
        <div class="overflow-x-auto">
          <table class="min-w-full divide-y divide-surface-border-subtle text-sm">
            <thead class="bg-surface-overlay text-left text-xs uppercase tracking-[0.14em] text-gray-500">
              <tr>
                <th class="px-4 py-2.5 font-medium">
                  Incident
                </th>
                <th class="px-4 py-2.5 font-medium">
                  Channel
                </th>
                <th class="px-4 py-2.5 font-medium">
                  Status
                </th>
                <th class="px-4 py-2.5 font-medium">
                  Sent
                </th>
                <th class="px-4 py-2.5 font-medium">
                  Acknowledged
                </th>
                <th class="px-4 py-2.5 font-medium">
                  Documents
                </th>
              </tr>
            </thead>
            <tbody class="divide-y divide-surface-border-subtle">
              <tr
                v-for="notice in notices"
                :key="notice.id"
                class="transition hover:bg-surface-overlay/50"
              >
                <td class="px-4 py-2.5">
                  <RouterLink
                    :to="{ name: 'incident-detail', params: { provider, slug, number: String(notice.incident_number) } }"
                    class="text-accent hover:underline"
                  >
                    #{{ notice.incident_number }} {{ notice.incident_title }}
                  </RouterLink>
                </td>
                <td class="px-4 py-2.5 text-xs text-gray-300">
                  {{ CHANNEL_LABELS[notice.channel] ?? notice.channel }}
                </td>
                <td class="px-4 py-2.5">
                  <span
                    class="rounded-full border px-2 py-0.5 text-[11px]"
                    :class="statusClass(notice.status)"
                    :title="notice.error || undefined"
                  >{{ STATUS_LABELS[notice.status] ?? notice.status }}</span>
                </td>
                <td class="px-4 py-2.5 text-xs text-gray-400">
                  {{ timeOrDash(notice.sent_at) }}
                </td>
                <td class="px-4 py-2.5 text-xs text-gray-400">
                  {{ timeOrDash(notice.acknowledged_at) }}
                </td>
                <td class="px-4 py-2.5 text-xs text-gray-400">
                  {{ notice.documents?.length ?? 0 }}
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
    </section>
  </div>
</template>

<script setup lang="ts">
import { Copy, Inbox, KeyRound, Plus, Trash2 } from 'lucide-vue-next'
import { computed, reactive, ref, watch } from 'vue'
import { RouterLink, useRoute } from 'vue-router'

import type { SqlNullTime } from '@/api/client'
import {
  incidentsApi,
  nullTime,
  type ClientDelivery,
  type ClientIncidentDelivery,
  type PortalToken,
  type SecurityContact,
} from '@/api/incidents'
import { useDialog } from '@/composables/useDialog'
import { useOrgRole } from '@/composables/useOrgRole'
import { useToast } from '@/composables/useToast'
import { formatDateTime, relativeTime } from '@/lib/datetime'

type Channel = ClientDelivery['effective_channel']

const CHANNELS: Channel[] = ['email', 'webhook', 'portal', 'manual']
const CHANNEL_LABELS: Record<Channel, string> = {
  email: 'Email',
  webhook: 'Webhook',
  portal: 'Portal',
  manual: 'Manual',
}
const STATUS_LABELS: Record<ClientIncidentDelivery['status'], string> = {
  pending_approval: 'Awaiting approval',
  sent: 'Sent',
  failed: 'Failed',
  acknowledged: 'Acknowledged',
}

const route = useRoute()
const toast = useToast()
const { confirmDialog } = useDialog()
const { isOrgAdmin } = useOrgRole()

const provider = computed(() => route.params.provider as string)
const slug = computed(() => route.params.slug as string)
const clientSlug = computed(() => route.params.clientSlug as string)

const delivery = ref<ClientDelivery | null>(null)
const deliveryLoading = ref(true)
const deliveryError = ref('')
const saving = ref(false)
const formError = ref('')
const form = reactive<{ contacts: SecurityContact[]; channel: ClientDelivery['channel']; webhookUrl: string; webhookSecret: string }>({
  contacts: [],
  channel: '',
  webhookUrl: '',
  webhookSecret: '',
})

const tokens = ref<PortalToken[]>([])
const tokensLoading = ref(false)
const tokenName = ref('')
const creatingToken = ref(false)
const issuedToken = ref('')
const revokingId = ref('')

const notices = ref<ClientIncidentDelivery[]>([])
const noticesLoading = ref(true)
const noticesError = ref('')

const portalSnippet = computed(() => {
  const base = `${window.location.origin}/api/v1/portal/notices`
  return [
    '# List the notices sent to you',
    `curl -H 'Authorization: Bearer ${issuedToken.value}' ${base}`,
    '',
    '# Download one document of a notice',
    `curl -H 'Authorization: Bearer ${issuedToken.value}' ${base}/{deliveryID}/documents/{sha256}`,
  ].join('\n')
})

function fillForm(value: ClientDelivery) {
  form.contacts = value.security_contacts.map((contact) => ({ name: contact.name ?? '', email: contact.email, role: contact.role ?? '' }))
  form.channel = value.channel
  form.webhookUrl = value.webhook_url ?? ''
  form.webhookSecret = ''
}

function addContact() {
  form.contacts.push({ name: '', email: '', role: '' })
}

function timeOrDash(value: SqlNullTime) {
  const iso = nullTime(value)
  return iso ? formatDateTime(iso) : '—'
}

function statusClass(status: string) {
  switch (status) {
    case 'acknowledged':
      return 'border-ok/40 bg-ok/10 text-ok'
    case 'sent':
      return 'border-accent/40 bg-accent/10 text-accent'
    case 'failed':
      return 'border-danger/40 bg-danger/10 text-danger'
    default:
      return 'border-warn/40 bg-warn/10 text-warn'
  }
}

async function copy(text: string) {
  try {
    await navigator.clipboard.writeText(text)
    toast.success('Copied to clipboard')
  } catch {
    toast.error('Copy failed', 'Select the text and copy it by hand.')
  }
}

async function loadDelivery() {
  deliveryLoading.value = true
  deliveryError.value = ''
  try {
    const res = await incidentsApi.getClientDelivery(provider.value, slug.value, clientSlug.value)
    delivery.value = res.data
    fillForm(res.data)
  } catch (caught) {
    delivery.value = null
    deliveryError.value = caught instanceof Error ? caught.message : 'Unable to load delivery settings.'
  } finally {
    deliveryLoading.value = false
  }
}

async function saveDelivery() {
  formError.value = ''
  const webhookUrl = form.webhookUrl.trim()
  if (webhookUrl && !webhookUrl.startsWith('https://')) {
    formError.value = 'The webhook URL must start with https://.'
    return
  }
  if (form.channel === 'webhook' && !webhookUrl) {
    formError.value = 'The webhook channel needs a webhook URL.'
    return
  }
  saving.value = true
  try {
    const res = await incidentsApi.putClientDelivery(provider.value, slug.value, clientSlug.value, {
      security_contacts: form.contacts
        .filter((contact) => contact.email.trim())
        .map((contact) => ({ name: contact.name?.trim() ?? '', email: contact.email.trim(), role: contact.role?.trim() ?? '' })),
      channel: form.channel,
      webhook_url: webhookUrl || undefined,
      webhook_secret: form.webhookSecret || undefined,
    })
    delivery.value = res.data
    fillForm(res.data)
    toast.success('Delivery settings saved')
  } catch (caught) {
    formError.value = caught instanceof Error ? caught.message : 'Unable to save delivery settings.'
  } finally {
    saving.value = false
  }
}

async function loadTokens() {
  tokensLoading.value = true
  try {
    const res = await incidentsApi.listPortalTokens(provider.value, slug.value, clientSlug.value)
    tokens.value = res.data
  } catch (caught) {
    tokens.value = []
    toast.error('Unable to load portal tokens', caught instanceof Error ? caught.message : undefined)
  } finally {
    tokensLoading.value = false
  }
}

async function createToken() {
  const name = tokenName.value.trim()
  if (!name) return
  creatingToken.value = true
  try {
    const res = await incidentsApi.createPortalToken(provider.value, slug.value, clientSlug.value, name)
    issuedToken.value = res.data.token
    tokenName.value = ''
    await loadTokens()
  } catch (caught) {
    toast.error('Unable to create the token', caught instanceof Error ? caught.message : undefined)
  } finally {
    creatingToken.value = false
  }
}

async function revokeToken(token: PortalToken) {
  if (!(await confirmDialog({ title: `Revoke "${token.name}"?`, message: 'The client can no longer fetch its notices with it.', confirmLabel: 'Revoke token', tone: 'danger' }))) return
  revokingId.value = token.id
  try {
    await incidentsApi.revokePortalToken(provider.value, slug.value, clientSlug.value, token.id)
    await loadTokens()
  } catch (caught) {
    toast.error('Unable to revoke the token', caught instanceof Error ? caught.message : undefined)
  } finally {
    revokingId.value = ''
  }
}

async function loadNotices() {
  noticesLoading.value = true
  noticesError.value = ''
  try {
    const res = await incidentsApi.listClientDeliveries(provider.value, slug.value, clientSlug.value)
    notices.value = res.data ?? []
  } catch (caught) {
    notices.value = []
    noticesError.value = caught instanceof Error ? caught.message : 'Unable to load notices.'
  } finally {
    noticesLoading.value = false
  }
}

watch(
  [provider, slug, clientSlug],
  () => {
    if (!provider.value || !slug.value || !clientSlug.value) return
    issuedToken.value = ''
    void loadDelivery()
    void loadNotices()
  },
  { immediate: true },
)

// The role arrives with the org list, possibly after this tab mounts.
watch(
  [isOrgAdmin, clientSlug],
  ([admin]) => {
    if (admin && clientSlug.value) void loadTokens()
  },
  { immediate: true },
)
</script>
