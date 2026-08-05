<script setup lang="ts">
import { computed, ref } from 'vue'
import { useRoute } from 'vue-router'

import { KeyRound, RefreshCw, ShieldAlert, Trash2 } from 'lucide-vue-next'

import type { ApiKey, TokenScope, UnscopedKeyExposure } from '@/api/client'
import { api } from '@/api/client'

const route = useRoute()
const provider = computed(() => route.params.provider as string)
const slug = computed(() => route.params.slug as string)

const loading = ref(true)
const isAdmin = ref(true)
const error = ref('')
const orgKeys = ref<ApiKey[]>([])
const exposure = ref<UnscopedKeyExposure[]>([])
const busyKeyID = ref('')
const issued = ref<{ key: string; name: string } | null>(null)

async function load() {
  loading.value = true
  error.value = ''
  try {
    const [keys, unscoped] = await Promise.all([
      api.listOrgApiKeys(provider.value, slug.value),
      api.listOrgTokenExposure(provider.value, slug.value),
    ])
    orgKeys.value = keys.data ?? []
    exposure.value = unscoped.data ?? []
    isAdmin.value = true
  } catch (loadError) {
    // A 403 just means the viewer is not an org admin — that is a state, not
    // an error.
    if (loadError instanceof Error && /admin|forbidden|403/i.test(loadError.message)) {
      isAdmin.value = false
    } else {
      error.value = loadError instanceof Error ? loadError.message : 'Failed to load access data'
    }
  } finally {
    loading.value = false
  }
}

async function rotate(key: ApiKey) {
  if (!window.confirm(`Rotate "${key.name}"? The current secret stops working immediately.`)) return
  busyKeyID.value = key.id
  try {
    const response = await api.rotateOrgApiKey(provider.value, slug.value, key.id)
    issued.value = { key: response.data.key, name: response.data.api_key.name }
    await load()
  } catch (rotateError) {
    error.value = rotateError instanceof Error ? rotateError.message : 'Failed to rotate the token'
  } finally {
    busyKeyID.value = ''
  }
}

async function revoke(key: ApiKey) {
  if (!window.confirm(`Revoke "${key.name}"? Anything using it stops working immediately.`)) return
  busyKeyID.value = key.id
  try {
    await api.deleteOrgApiKey(provider.value, slug.value, key.id)
    await load()
  } catch (revokeError) {
    error.value = revokeError instanceof Error ? revokeError.message : 'Failed to revoke the token'
  } finally {
    busyKeyID.value = ''
  }
}

function scopeSummary(key: ApiKey): string {
  const scopes = key.scopes
  if (!scopes || typeof scopes !== 'object' || Array.isArray(scopes)) return 'malformed scope — denied everything'
  const repos = scopes.repos?.mode === 'all' ? 'all repos' : `${(scopes.repos?.slugs ?? []).length} repo(s)`
  const grants = Object.entries((scopes as TokenScope).permissions ?? {})
    .filter(([, level]) => level && level !== 'none')
    .map(([capability, level]) => `${capability}:${level}`)
    .sort()
  return `${repos} · ${grants.join(', ') || 'no permissions'}`
}

function formatDate(value?: string): string {
  if (!value) return 'never'
  return new Date(value).toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' })
}

void load()
</script>

<template>
  <div class="space-y-6 pb-8">
    <div
      v-if="loading"
      class="py-12 text-center text-sm text-gray-500"
    >
      Loading access data…
    </div>

    <div
      v-else-if="!isAdmin"
      class="rounded-2xl border border-surface-border bg-surface-raised px-6 py-12 text-center"
    >
      <div class="mx-auto flex h-12 w-12 items-center justify-center rounded-full border border-surface-border bg-surface-overlay">
        <KeyRound class="h-5 w-5 text-gray-500" />
      </div>
      <p class="mt-3 text-sm text-gray-300">
        Organization access is visible to org admins only.
      </p>
    </div>

    <template v-else>
      <p
        v-if="error"
        class="rounded-lg border border-red-500/30 bg-red-500/10 px-4 py-2 text-sm text-red-300"
      >
        {{ error }}
      </p>

      <div
        v-if="issued"
        class="rounded-2xl border border-surface-border bg-emerald-500/5 px-5 py-4"
      >
        <p class="text-sm font-medium text-white">
          New secret for {{ issued.name }} — copy it now, it is shown once.
        </p>
        <code class="mt-2 block overflow-x-auto rounded-lg border border-surface-border bg-surface-overlay px-3 py-2 font-mono text-xs text-emerald-300">{{ issued.key }}</code>
      </div>

      <section class="overflow-hidden rounded-2xl border border-surface-border bg-surface-raised">
        <div class="border-b border-surface-border-subtle px-5 py-4">
          <h2 class="text-base font-semibold text-white">
            Organization-owned tokens
          </h2>
          <p class="mt-0.5 text-sm text-gray-400">
            Survive their creator leaving; any org admin can rotate or revoke them. Create new ones under
            <RouterLink
              :to="{ name: 'settings-api-keys' }"
              class="text-accent hover:underline"
            >
              Settings → API keys
            </RouterLink>.
          </p>
        </div>
        <p
          v-if="orgKeys.length === 0"
          class="px-5 py-6 text-sm text-gray-500"
        >
          No organization-owned tokens.
        </p>
        <ul v-else>
          <li
            v-for="key in orgKeys"
            :key="key.id"
            class="flex flex-wrap items-center justify-between gap-3 border-b border-surface-border-subtle px-5 py-3 last:border-b-0"
          >
            <div class="min-w-0">
              <div class="text-sm font-medium text-white">
                {{ key.name }}
              </div>
              <div class="mt-0.5 font-mono text-xs text-gray-500">
                {{ scopeSummary(key) }}
              </div>
              <div class="mt-0.5 text-xs text-gray-500">
                Last used {{ formatDate(key.last_used_at) }} · expires {{ formatDate(key.expires_at) }}
              </div>
            </div>
            <div class="flex shrink-0 gap-2">
              <button
                type="button"
                :disabled="busyKeyID === key.id"
                class="flex items-center gap-1.5 rounded-lg border border-surface-border bg-surface-overlay px-3 py-1.5 text-xs text-gray-300 transition hover:text-white disabled:opacity-50"
                @click="rotate(key)"
              >
                <RefreshCw class="h-3.5 w-3.5" />
                Rotate
              </button>
              <button
                type="button"
                :disabled="busyKeyID === key.id"
                class="flex items-center gap-1.5 rounded-lg border border-surface-border bg-surface-overlay px-3 py-1.5 text-xs text-red-400 transition hover:border-red-500/40 hover:text-red-300 disabled:opacity-50"
                @click="revoke(key)"
              >
                <Trash2 class="h-3.5 w-3.5" />
                Revoke
              </button>
            </div>
          </li>
        </ul>
      </section>

      <section class="overflow-hidden rounded-2xl border border-surface-border bg-surface-raised">
        <div class="border-b border-surface-border-subtle px-5 py-4">
          <div class="flex items-center gap-2">
            <ShieldAlert class="h-4 w-4 text-amber-400" />
            <h2 class="text-base font-semibold text-white">
              Unscoped-token exposure
            </h2>
          </div>
          <p class="mt-0.5 text-sm text-gray-400">
            Legacy full-access tokens owned by members of this organization. Each can do everything its
            owner can — across this org and any other. They cannot be minted anymore; ask their owners to
            restrict them (Settings → API keys → Restrict…) or let them expire.
          </p>
        </div>
        <p
          v-if="exposure.length === 0"
          class="px-5 py-6 text-sm text-emerald-300"
        >
          No unscoped tokens — every member token is scoped. 🎉
        </p>
        <ul v-else>
          <li
            v-for="key in exposure"
            :key="key.id"
            class="flex flex-wrap items-center justify-between gap-3 border-b border-surface-border-subtle px-5 py-3 last:border-b-0"
          >
            <div class="min-w-0">
              <div class="flex items-center gap-2">
                <span class="text-sm font-medium text-white">{{ key.name }}</span>
                <span class="rounded-full bg-amber-500/15 px-2 py-0.5 text-[11px] font-medium text-amber-300">unscoped</span>
              </div>
              <div class="mt-0.5 text-xs text-gray-500">
                Owned by {{ key.member_display || key.member_email }} ·
                last used {{ formatDate(key.last_used_at) }} ·
                {{ key.expires_at ? `expires ${formatDate(key.expires_at)}` : 'no expiry' }}
              </div>
            </div>
          </li>
        </ul>
      </section>
    </template>
  </div>
</template>
