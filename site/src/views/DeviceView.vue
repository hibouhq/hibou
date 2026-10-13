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
        <p class="text-sm text-gray-400">
          Enter the code shown by <code class="text-gray-300">hibou login</code> or your IDE.
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
            Check that this code matches the one in your terminal:
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
          </dd>
          <dt class="text-gray-500">
            From
          </dt>
          <dd class="font-mono text-gray-200">
            {{ request.requester_ip }}
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
          Approve only if you started this sign-in yourself in the last few minutes. Someone who sends you
          this link is asking for access to your account.
        </div>

        <fieldset>
          <legend class="mb-2 text-sm font-medium text-gray-200">
            Access
          </legend>
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
import { computed, onMounted, ref } from 'vue'
import { useRoute } from 'vue-router'

import {
  api,
  type DeviceLoginOrgReach,
  type DeviceLoginPreset,
  type DeviceLoginRequest,
  type TokenAccessLevel,
  type TokenCapability,
} from '@/api/client'

const PRESET_LABELS: Record<DeviceLoginPreset, { title: string; hint: string }> = {
  cli: { title: 'CLI', hint: 'Upload scans, check gates and secrets, read findings. Cannot triage or change settings.' },
  'read-only': { title: 'Read-only', hint: 'Read findings, coverage and gates. Changes nothing.' },
}
const EXPIRY_DAYS = [30, 90, 180, 365]

const route = useRoute()
const typedCode = ref(typeof route.query.user_code === 'string' ? route.query.user_code : '')
const request = ref<DeviceLoginRequest | null>(null)
const selectedPreset = ref<DeviceLoginPreset>('cli')
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
  if (/HTTP 429/.test(message) || /rate/i.test(message)) return 'Too many attempts. Wait a minute and try again.'
  return message || 'Something went wrong. Try again.'
}

async function lookup() {
  busy.value = true
  error.value = ''
  try {
    const res = await api.getDeviceLogin(typedCode.value.trim())
    request.value = res.data
    selectedPreset.value = res.data.requested_preset
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

onMounted(() => {
  // A prefilled link still shows the code for comparison before any approval:
  // looking it up changes nothing.
  if (typedCode.value) {
    void lookup()
  }
})
</script>
