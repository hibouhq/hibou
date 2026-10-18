<template>
  <div class="flex min-h-screen items-center justify-center bg-gray-950 px-4 py-10">
    <div class="w-full max-w-lg rounded-lg border border-gray-800 bg-gray-900 p-8">
      <h1 class="text-xl font-bold text-gray-100">
        Approve a sign-in
      </h1>

      <!-- Outcome -->
      <div
        v-if="outcome === 'approved'"
        role="status"
        class="mt-6 rounded-md border border-emerald-800 bg-emerald-950/40 px-4 py-3 text-sm text-emerald-200"
      >
        <p class="font-medium">
          Approved. You can return to your terminal.
        </p>
        <p class="mt-1 text-emerald-300/80">
          The token "{{ tokenName }}" is listed under Settings › API Keys, where you can revoke it at any time.
        </p>
      </div>
      <div
        v-else-if="outcome === 'denied'"
        role="status"
        class="mt-6 rounded-md border border-gray-700 bg-gray-800/60 px-4 py-3 text-sm text-gray-300"
      >
        Denied. The device that asked will not get a token.
      </div>

      <!-- Code entry -->
      <form
        v-else-if="!request"
        class="mt-6 space-y-4"
        @submit.prevent="lookup"
      >
        <div
          v-if="linkCode"
          role="note"
          class="rounded-md border border-amber-800/60 bg-amber-950/30 px-4 py-3 text-sm text-amber-200"
        >
          You opened a sign-in link. Type the code your own terminal or IDE is showing right now; do not copy it
          from the link or from a message someone sent you.
        </div>
        <p class="text-sm text-gray-400">
          Enter the code shown by <code class="text-gray-300">hibou login</code> or your IDE.
        </p>
        <p class="text-sm font-medium text-amber-200">
          Only approve if you started this sign-in yourself on this device.
        </p>
        <input
          v-model="typedCode"
          aria-label="Code"
          autocomplete="off"
          autocapitalize="characters"
          spellcheck="false"
          placeholder="XXXX-XXXX"
          maxlength="12"
          class="w-full rounded-lg border border-surface-border bg-surface-overlay px-3 py-2 text-center font-mono text-2xl tracking-[0.3em] text-gray-100 placeholder:text-gray-700"
        >
        <p
          v-if="error"
          role="alert"
          class="text-sm text-red-300"
        >
          {{ error }}
        </p>
        <button
          type="submit"
          :disabled="busy || typedCode.trim().length === 0"
          class="w-full rounded-md bg-ok-muted px-3 py-2 text-sm font-medium text-white transition hover:bg-ok-muted/80 disabled:cursor-not-allowed disabled:opacity-50"
        >
          {{ busy ? 'Checking…' : 'Continue' }}
        </button>
      </form>

      <!-- Review -->
      <div
        v-else
        class="mt-6 space-y-6"
      >
        <div>
          <p class="text-sm text-gray-400">
            Check that this code matches the one on your device:
          </p>
          <p class="mt-2 text-center font-mono text-3xl font-semibold tracking-[0.3em] text-gray-100">
            {{ request.user_code }}
          </p>
        </div>

        <dl class="grid grid-cols-[auto,1fr] gap-x-4 gap-y-1 text-sm">
          <dt class="text-gray-500">
            Client
          </dt>
          <dd class="text-gray-200">
            {{ request.client_label }}
          </dd>
          <dt class="text-gray-500">
            Device
          </dt>
          <dd class="break-all text-gray-200">
            {{ request.client_name || 'not given' }}
            <span class="block text-xs text-gray-500">reported by the device (unverified)</span>
          </dd>
          <dt class="text-gray-500">
            From
          </dt>
          <dd class="text-gray-200">
            <span class="font-mono">{{ request.requester_ip }}</span>
            <span class="block text-xs text-gray-500">IP address as seen by the server (best effort; a proxy or VPN changes it)</span>
          </dd>
          <dt class="text-gray-500">
            Started
          </dt>
          <dd class="text-gray-200">
            {{ startedAgo }}
          </dd>
        </dl>

        <div
          role="note"
          class="rounded-md border border-amber-800/60 bg-amber-950/30 px-4 py-3 text-sm text-amber-200"
        >
          Only approve if you started this sign-in yourself on this device, in the last few minutes. Someone who
          sends you a link or a code is asking for access to your account.
        </div>

        <fieldset>
          <legend class="mb-2 text-sm font-medium text-gray-200">
            Access
          </legend>
          <p class="mb-2 text-xs text-gray-500">
            Only what the device asked for, or less, is offered.
          </p>
          <div class="space-y-2">
            <label
              v-for="preset in request.presets"
              :key="preset.key"
              class="flex cursor-pointer items-start gap-3 rounded-lg border px-3 py-2"
              :class="selectedPreset === preset.key ? 'border-accent bg-accent-muted/40' : 'border-surface-border bg-surface-overlay'"
            >
              <input
                v-model="selectedPreset"
                type="radio"
                name="preset"
                :value="preset.key"
                class="mt-1 accent-accent"
              >
              <span>
                <span class="block text-sm font-medium text-gray-100">{{ PRESET_LABELS[preset.key].title }}</span>
                <span class="block text-xs text-gray-400">{{ PRESET_LABELS[preset.key].hint }}</span>
                <span class="mt-1 block font-mono text-[11px] text-gray-500">{{ grantSummary(preset.permissions) }}</span>
              </span>
            </label>
          </div>
        </fieldset>

        <div>
          <label
            for="device-expiry"
            class="mb-1.5 block text-sm font-medium text-gray-200"
          >Expires</label>
          <select
            id="device-expiry"
            v-model="expiryDays"
            class="w-full rounded-lg border border-surface-border bg-surface-overlay px-3 py-2 text-sm text-gray-200"
          >
            <option
              v-for="days in EXPIRY_DAYS"
              :key="days"
              :value="days"
            >
              In {{ days }} days
            </option>
          </select>
        </div>

        <div>
          <div class="mb-1.5 text-sm font-medium text-gray-200">
            Organizations
          </div>
          <p class="mb-2 text-xs text-gray-500">
            The token works in every organization you belong to, with your role there, now and after you join
            new ones. Each organization can restrict these tokens.
          </p>
          <p
            v-if="request.orgs.length === 0"
            class="text-sm text-gray-400"
          >
            You are not a member of any organization yet.
          </p>
          <ul
            v-else
            class="max-h-48 divide-y divide-surface-border-subtle overflow-y-auto rounded-lg border border-surface-border"
          >
            <li
              v-for="org in request.orgs"
              :key="`${org.provider}/${org.slug}`"
              class="flex items-center justify-between gap-3 px-3 py-2 text-sm"
            >
              <span class="truncate text-gray-200">{{ org.name }}</span>
              <span
                class="shrink-0 text-xs"
                :class="org.policy === 'allow' ? 'text-gray-400' : 'text-amber-300'"
              >
                {{ orgAccess(org) }}
              </span>
            </li>
          </ul>
        </div>

        <p
          v-if="error"
          role="alert"
          class="text-sm text-red-300"
        >
          {{ error }}
        </p>

        <div class="flex gap-3">
          <button
            type="button"
            :disabled="busy"
            class="flex-1 rounded-md bg-ok-muted px-3 py-2 text-sm font-medium text-white transition hover:bg-ok-muted/80 disabled:cursor-not-allowed disabled:opacity-50"
            @click="approve"
          >
            Approve
          </button>
          <button
            type="button"
            :disabled="busy"
            class="flex-1 rounded-md border border-surface-border bg-surface-overlay px-3 py-2 text-sm text-gray-200 transition hover:text-white disabled:opacity-50"
            @click="deny"
          >
            Deny
          </button>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'

import {
  api,
  type DeviceLoginOrgReach,
  type DeviceLoginPreset,
  type DeviceLoginRequest,
  type TokenAccessLevel,
  type TokenCapability,
} from '@/api/client'
import { defaultDevicePreset, normalizeUserCode, userCodesMatch } from '@/lib/deviceLogin'

const PRESET_LABELS: Record<DeviceLoginPreset, { title: string; hint: string }> = {
  cli: { title: 'CLI', hint: 'Upload scans, check gates and secrets, read findings. Cannot triage or change settings.' },
  triage: { title: 'Read-only + triage', hint: 'Read everything, and accept, dismiss or dispute findings from the editor. Triage also needs the org admin role.' },
  'read-only': { title: 'Read-only', hint: 'Read findings, coverage and gates. Changes nothing.' },
}
const EXPIRY_DAYS = [30, 90, 180, 365]

const route = useRoute()
const router = useRouter()
// A code from verification_uri_complete is never looked up or shown: the user
// must type the code their own device shows, and it must match the link. A
// link someone else sent then leads nowhere without that person's device.
const linkCode = ref(typeof route.query.user_code === 'string' ? route.query.user_code : '')
const typedCode = ref('')
const request = ref<DeviceLoginRequest | null>(null)
const selectedPreset = ref<DeviceLoginPreset>('read-only')
const expiryDays = ref(90)
const busy = ref(false)
const error = ref('')
const outcome = ref<'approved' | 'denied' | null>(null)
const tokenName = ref('')

const startedAgo = computed(() => {
  if (!request.value) return ''
  const minutes = Math.max(0, Math.round((Date.now() - new Date(request.value.created_at).getTime()) / 60_000))
  return minutes === 0 ? 'just now' : `${minutes} minute${minutes === 1 ? '' : 's'} ago`
})

function grantSummary(permissions: Partial<Record<TokenCapability, TokenAccessLevel>>): string {
  return Object.entries(permissions)
    .filter(([, level]) => level && level !== 'none')
    .map(([capability, level]) => `${capability}:${level}`)
    .sort()
    .join(' ')
}

function orgAccess(org: DeviceLoginOrgReach): string {
  if (org.policy === 'deny') return 'blocked by this organization'
  if (org.policy === 'read_only' && org.effective_role !== org.role) return `${org.role} → read-only here`
  return org.role
}

// Server errors are matched to fixed text; nothing from a response or the URL
// is rendered as markup.
function describe(err: unknown): string {
  const message = err instanceof Error ? err.message : ''
  if (/invalid or has expired/i.test(message)) return 'This code is invalid or has expired. Start the sign-in again.'
  if (/HTTP 429/.test(message) || /rate|too many/i.test(message)) return 'Too many attempts. Wait a minute and try again.'
  return message || 'Something went wrong. Try again.'
}

async function lookup() {
  error.value = ''
  if (linkCode.value && !userCodesMatch(typedCode.value, linkCode.value)) {
    // Forget the link: if the user started a new sign-in, the next attempt
    // looks up the code they typed.
    linkCode.value = ''
    void router.replace({ query: {} })
    error.value = normalizeUserCode(typedCode.value)
      ? 'This code does not match the link you opened. Only approve a code your own device is showing; if it is, press Continue again.'
      : 'Type the code exactly as your device shows it (XXXX-XXXX).'
    return
  }
  busy.value = true
  try {
    const res = await api.getDeviceLogin(typedCode.value.trim())
    request.value = res.data
    selectedPreset.value = defaultDevicePreset(
      res.data.client_id,
      res.data.requested_preset,
      res.data.presets.map((preset) => preset.key),
    )
  } catch (err) {
    error.value = describe(err)
  } finally {
    busy.value = false
  }
}

async function approve() {
  if (!request.value) return
  busy.value = true
  error.value = ''
  try {
    const res = await api.approveDeviceLogin({
      user_code: request.value.user_code,
      preset: selectedPreset.value,
      expires_at: new Date(Date.now() + expiryDays.value * 86_400_000).toISOString(),
    })
    tokenName.value = res.data.token_name
    outcome.value = 'approved'
  } catch (err) {
    error.value = describe(err)
  } finally {
    busy.value = false
  }
}

async function deny() {
  if (!request.value) return
  busy.value = true
  error.value = ''
  try {
    await api.denyDeviceLogin(request.value.user_code)
    outcome.value = 'denied'
  } catch (err) {
    error.value = describe(err)
  } finally {
    busy.value = false
  }
}
</script>
