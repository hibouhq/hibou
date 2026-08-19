<script setup lang="ts">
import { computed, ref } from 'vue'

import { AlertTriangle, Check, ChevronDown, ChevronUp, Copy, KeyRound, Pencil, RefreshCw, Trash2 } from 'lucide-vue-next'

import type { ApiKey, Organization, TokenScope } from '@/api/client'
import { api } from '@/api/client'
import { useDialog } from '@/composables/useDialog'
import TokenScopeEditor from '@/components/TokenScopeEditor.vue'

const { confirmDialog } = useDialog()
const keys = ref<ApiKey[]>([])
const loading = ref(true)
const listError = ref('')

const creating = ref(false)
// editing holds the key an open form mutates; null means the form creates.
const editing = ref<ApiKey | null>(null)
const submitting = ref(false)
const formError = ref('')
const name = ref('')
const description = ref('')
const expiresInDays = ref('90')
const owner = ref<'user' | 'org'>('user')
const scope = ref<TokenScope>(emptyScope())
const expandedKeyID = ref('')

// Orgs the user belongs to: resolves an org-owned key back to its provider+slug
// route, and bounds which org lists we try to read (non-admins just get a 403
// that we swallow).
const orgs = ref<Organization[]>([])
const orgByID = new Map<string, Organization>()
const orgBySlug = new Map<string, Organization>()

// The raw secret is held only long enough to show it once. Nothing re-fetches it.
const issued = ref<{ key: string; name: string; rotated: boolean; pending?: boolean } | null>(null)
const copied = ref(false)
const busyKeyID = ref('')

// Expiry is mandatory for scoped tokens (ADR-020) — no "never" option.
// 'custom' opens a date picker for a precise expiration date (ADR-022).
const EXPIRY_CHOICES = [
  { value: '30', label: '30 days' },
  { value: '90', label: '90 days' },
  { value: '180', label: '180 days' },
  { value: '365', label: '1 year' },
  { value: 'custom', label: 'Custom date…' },
]

const customExpiryDate = ref('')

// The picker floor: tomorrow, local time (an expiry today would be near-dead
// on arrival).
const minExpiryDate = computed(() => {
  const tomorrow = new Date(Date.now() + 86_400_000)
  return `${tomorrow.getFullYear()}-${String(tomorrow.getMonth() + 1).padStart(2, '0')}-${String(tomorrow.getDate()).padStart(2, '0')}`
})

function emptyScope(): TokenScope {
  return { org: '', repos: { mode: 'list', slugs: [] }, permissions: {} }
}

const scopeIsUsable = computed(() => {
  const grants = Object.values(scope.value.permissions).filter((level) => level && level !== 'none')
  if (!scope.value.org || grants.length === 0) return false
  return scope.value.repos.mode === 'all' || (scope.value.repos.slugs ?? []).length > 0
})

const customExpiryValid = computed(() =>
  expiresInDays.value !== 'custom' || (customExpiryDate.value >= minExpiryDate.value))

const canSubmit = computed(() => name.value.trim().length > 0 && scopeIsUsable.value && customExpiryValid.value && !submitting.value)

async function load() {
  loading.value = true
  listError.value = ''
  try {
    if (orgs.value.length === 0) {
      const response = await api.listOrgs().catch(() => ({ data: [] as Organization[] }))
      orgs.value = response.data ?? []
      for (const org of orgs.value) {
        orgByID.set(org.id, org)
        orgBySlug.set(org.slug, org)
      }
    }

    const [personal, ...orgLists] = await Promise.all([
      api.listApiKeys(),
      // Admin-only lists: a 403 just means "not an admin there", not an error.
      ...orgs.value.map((org) => api.listOrgApiKeys(org.provider, org.slug).catch(() => ({ data: [] as ApiKey[] }))),
    ])
    keys.value = [...(personal.data ?? []), ...orgLists.flatMap((list) => list.data ?? [])]
      .sort((a, b) => b.created_at.localeCompare(a.created_at))
  } catch (error) {
    listError.value = error instanceof Error ? error.message : 'Failed to load API keys'
  } finally {
    loading.value = false
  }
}

function openCreate() {
  editing.value = null
  name.value = ''
  description.value = ''
  expiresInDays.value = '90'
  customExpiryDate.value = ''
  owner.value = 'user'
  scope.value = emptyScope()
  formError.value = ''
  creating.value = true
}

// openEdit prefills the form from an existing key. For a legacy unscoped key
// this is the "Restrict this token…" flow: the empty editor forces a real
// scope (and the now-mandatory expiry) onto it without changing the secret.
function openEdit(key: ApiKey) {
  editing.value = key
  name.value = key.name
  description.value = key.description
  expiresInDays.value = key.expires_at ? 'keep' : '90'
  customExpiryDate.value = ''
  owner.value = key.owner_type === 'org' ? 'org' : 'user'
  scope.value = structuredClone(usableScope(key)) ?? emptyScope()
  formError.value = ''
  creating.value = true
}

function keyOrg(key: ApiKey): Organization | undefined {
  if (key.owner_id && orgByID.has(key.owner_id)) return orgByID.get(key.owner_id)
  const slug = usableScope(key)?.org
  return slug ? orgBySlug.get(slug) : undefined
}

function expiryTimestamp(): string | undefined {
  if (expiresInDays.value === 'keep') return undefined
  if (expiresInDays.value === 'custom') {
    // End of the selected local day: "expires March 3rd" means all of March
    // 3rd still works.
    return new Date(`${customExpiryDate.value}T23:59:59`).toISOString()
  }
  const days = Number(expiresInDays.value) || 90
  return new Date(Date.now() + days * 86_400_000).toISOString()
}

async function submit() {
  if (!canSubmit.value) return

  const org = orgBySlug.get(scope.value.org)
  if (owner.value === 'org' && !org) {
    formError.value = 'Select an organization for an org-owned token'
    return
  }

  submitting.value = true
  formError.value = ''
  try {
    if (editing.value) {
      const body = {
        name: name.value.trim(),
        description: description.value.trim(),
        scopes: scope.value,
        expires_at: expiryTimestamp(),
      }
      if (editing.value.owner_type === 'org' && org) {
        await api.updateOrgApiKey(org.provider, org.slug, editing.value.id, body)
      } else {
        await api.updateApiKey(editing.value.id, body)
      }
    } else {
      const body = {
        name: name.value.trim(),
        description: description.value.trim(),
        scopes: scope.value,
        expires_at: expiryTimestamp() ?? new Date(Date.now() + 90 * 86_400_000).toISOString(),
      }
      const response = owner.value === 'org' && org
        ? await api.createOrgApiKey(org.provider, org.slug, body)
        : await api.createApiKey(body)
      issued.value = {
        key: response.data.key,
        name: response.data.api_key.name,
        rotated: false,
        pending: response.data.api_key.approval_status === 'pending',
      }
      copied.value = false
    }
    creating.value = false
    editing.value = null
    await load()
  } catch (error) {
    formError.value = error instanceof Error ? error.message : 'Failed to save the token'
  } finally {
    submitting.value = false
  }
}

async function rotate(key: ApiKey) {
  if (!(await confirmDialog({ title: `Rotate "${key.name}"?`, message: 'The current secret stops working immediately.', confirmLabel: 'Rotate key', tone: 'danger' }))) return

  const org = key.owner_type === 'org' ? keyOrg(key) : undefined
  if (key.owner_type === 'org' && !org) {
    listError.value = 'Cannot resolve the owning organization for this token'
    return
  }

  busyKeyID.value = key.id
  try {
    const response = org
      ? await api.rotateOrgApiKey(org.provider, org.slug, key.id)
      : await api.rotateApiKey(key.id)
    issued.value = { key: response.data.key, name: response.data.api_key.name, rotated: true }
    copied.value = false
    await load()
  } catch (error) {
    listError.value = error instanceof Error ? error.message : 'Failed to rotate the token'
  } finally {
    busyKeyID.value = ''
  }
}

async function revoke(key: ApiKey) {
  if (!(await confirmDialog({ title: `Revoke "${key.name}"?`, message: 'Anything using it stops working immediately.', confirmLabel: 'Revoke key', tone: 'danger' }))) return

  const org = key.owner_type === 'org' ? keyOrg(key) : undefined
  if (key.owner_type === 'org' && !org) {
    listError.value = 'Cannot resolve the owning organization for this token'
    return
  }

  busyKeyID.value = key.id
  try {
    if (org) await api.deleteOrgApiKey(org.provider, org.slug, key.id)
    else await api.deleteApiKey(key.id)
    await load()
  } catch (error) {
    listError.value = error instanceof Error ? error.message : 'Failed to revoke the token'
  } finally {
    busyKeyID.value = ''
  }
}

async function copyIssued() {
  if (!issued.value) return
  try {
    await navigator.clipboard.writeText(issued.value.key)
    copied.value = true
  } catch {
    copied.value = false
  }
}

// Keys minted before ADR-020 can hold a bare array (`[]`, `["all"]`) in `scopes`.
// The server treats any present document as scoped and denies everything, so the
// UI must say that rather than trust the shape and throw.
function usableScope(key: ApiKey): TokenScope | null {
  const scopes = key.scopes
  if (!scopes || typeof scopes !== 'object' || Array.isArray(scopes)) return null
  if (typeof scopes.repos !== 'object' || scopes.repos === null) return null
  return scopes
}

function isMalformed(key: ApiKey): boolean {
  return Boolean(key.scopes) && usableScope(key) === null
}

function scopeSummary(key: ApiKey): string {
  if (!key.scopes) return 'Unscoped — full account access'

  const scopes = usableScope(key)
  if (!scopes) return 'Malformed scope — this token is denied everything'

  const repos = scopes.repos.mode === 'all' ? 'all repos' : `${(scopes.repos.slugs ?? []).length} repo(s)`
  const grants = Object.entries(scopes.permissions ?? {})
    .filter(([, level]) => level && level !== 'none')
    .map(([capability, level]) => `${capability}:${level}`)
    .sort()
  return `${scopes.org} · ${repos} · ${grants.join(', ') || 'no permissions'}`
}

function isReadOnly(key: ApiKey): boolean {
  const scopes = usableScope(key)
  if (!scopes) return false
  return !Object.values(scopes.permissions ?? {}).some((level) => level === 'write')
}

function grantedPermissions(key: ApiKey): Array<[string, string]> {
  const scopes = usableScope(key)
  if (!scopes) return []
  return Object.entries(scopes.permissions ?? {})
    .filter(([, level]) => level && level !== 'none')
    .sort(([a], [b]) => a.localeCompare(b)) as Array<[string, string]>
}

function formatDate(value?: string): string {
  if (!value) return '—'
  return new Date(value).toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' })
}

function isExpired(key: ApiKey): boolean {
  return Boolean(key.expires_at) && new Date(key.expires_at as string).getTime() < Date.now()
}

function expiresSoon(key: ApiKey): boolean {
  if (!key.expires_at) return false
  const remaining = new Date(key.expires_at).getTime() - Date.now()
  return remaining > 0 && remaining < 14 * 86_400_000
}

// A token nobody has used in a long while is a liability, not an asset.
function isStale(key: ApiKey): boolean {
  if (!key.last_used_at) return false
  return Date.now() - new Date(key.last_used_at).getTime() > 90 * 86_400_000
}

void load()
</script>

<template>
  <section class="overflow-hidden rounded-2xl border border-surface-border bg-surface-raised">
    <div class="flex flex-wrap items-center justify-between gap-4 border-b border-surface-border-subtle px-6 py-4">
      <div>
        <h2 class="text-lg font-semibold text-white">
          API keys
        </h2>
        <p class="mt-0.5 text-sm text-gray-400">
          Fine-grained, scoped tokens for CI, the CLI, and agents.
        </p>
      </div>
      <button
        type="button"
        class="rounded-lg border border-accent bg-accent-muted px-3 py-2 text-sm font-medium text-white transition hover:bg-accent"
        @click="openCreate"
      >
        New token
      </button>
    </div>

    <div
      v-if="issued"
      class="border-b border-surface-border-subtle bg-emerald-500/5 px-6 py-4"
    >
      <div class="flex items-start gap-3">
        <AlertTriangle class="mt-0.5 h-4 w-4 shrink-0 text-amber-400" />
        <div class="min-w-0 flex-1">
          <p class="text-sm font-medium text-white">
            {{ issued.rotated ? 'New secret for' : 'Token created:' }} {{ issued.name }}
          </p>
          <p class="mt-0.5 text-xs text-gray-400">
            Copy it now — this is the only time it is shown. It cannot be retrieved again.
          </p>
          <p
            v-if="issued.pending"
            class="mt-1 text-xs font-medium text-amber-300"
          >
            Pending approval: this token will not authenticate until an org admin approves it
            (Organization → Access → Organization-owned tokens).
          </p>
          <div class="mt-2 flex items-center gap-2">
            <code class="min-w-0 flex-1 overflow-x-auto rounded-lg border border-surface-border bg-surface-overlay px-3 py-2 font-mono text-xs text-emerald-300">{{ issued.key }}</code>
            <button
              type="button"
              class="flex shrink-0 items-center gap-1.5 rounded-lg border border-surface-border bg-surface-overlay px-3 py-2 text-xs text-gray-300 transition hover:text-white"
              @click="copyIssued"
            >
              <component
                :is="copied ? Check : Copy"
                class="h-3.5 w-3.5"
              />
              {{ copied ? 'Copied' : 'Copy' }}
            </button>
          </div>
        </div>
        <button
          type="button"
          class="shrink-0 text-xs text-gray-500 transition hover:text-gray-300"
          @click="issued = null"
        >
          Dismiss
        </button>
      </div>
    </div>

    <form
      v-if="creating"
      class="space-y-5 border-b border-surface-border-subtle px-6 py-5"
      @submit.prevent="submit"
    >
      <div class="grid gap-4 sm:grid-cols-2">
        <div>
          <label
            for="token-name"
            class="mb-1.5 block text-sm font-medium text-gray-200"
          >Name</label>
          <input
            id="token-name"
            v-model="name"
            type="text"
            placeholder="prod-ci-uploader"
            class="w-full rounded-lg border border-surface-border bg-surface-overlay px-3 py-2 text-sm text-gray-200 placeholder:text-gray-600"
          >
        </div>
        <div>
          <label
            for="token-expiry"
            class="mb-1.5 block text-sm font-medium text-gray-200"
          >Expires</label>
          <select
            id="token-expiry"
            v-model="expiresInDays"
            class="w-full rounded-lg border border-surface-border bg-surface-overlay px-3 py-2 text-sm text-gray-200"
          >
            <option
              v-if="editing?.expires_at"
              value="keep"
            >
              Keep current ({{ formatDate(editing.expires_at) }})
            </option>
            <option
              v-for="choice in EXPIRY_CHOICES"
              :key="choice.value"
              :value="choice.value"
            >
              {{ choice.label }}
            </option>
          </select>
          <input
            v-if="expiresInDays === 'custom'"
            v-model="customExpiryDate"
            type="date"
            :min="minExpiryDate"
            aria-label="Custom expiration date"
            class="mt-2 w-full rounded-lg border border-surface-border bg-surface-overlay px-3 py-2 text-sm text-gray-200 [color-scheme:dark]"
          >
          <p
            v-if="expiresInDays === 'custom' && !customExpiryValid"
            class="mt-1 text-xs text-amber-300"
          >
            Pick a date from tomorrow onward.
          </p>
        </div>
      </div>

      <p
        v-if="editing"
        class="text-sm text-gray-400"
      >
        Editing <span class="font-medium text-white">{{ editing.name }}</span> — the secret is unchanged.
        <span v-if="!editing.scopes">This legacy token currently has full account access; saving applies the scope below.</span>
      </p>

      <div v-if="!editing">
        <div class="mb-1.5 text-sm font-medium text-gray-200">
          Owner
        </div>
        <div class="flex gap-2">
          <button
            type="button"
            class="rounded-lg border px-3 py-1.5 text-sm transition"
            :class="owner === 'user'
              ? 'border-accent bg-accent-muted text-white'
              : 'border-surface-border bg-surface-overlay text-gray-300 hover:text-white'"
            @click="owner = 'user'"
          >
            Personal
          </button>
          <button
            type="button"
            class="rounded-lg border px-3 py-1.5 text-sm transition"
            :class="owner === 'org'
              ? 'border-accent bg-accent-muted text-white'
              : 'border-surface-border bg-surface-overlay text-gray-300 hover:text-white'"
            @click="owner = 'org'"
          >
            Organization-owned
          </button>
        </div>
        <p class="mt-1.5 text-xs text-gray-500">
          {{ owner === 'org'
            ? 'Owned by the organization the scope targets: survives your departure, and any org admin can rotate or revoke it. If you are not an org admin, the token is created as a pending request and works only once an admin approves it. Right for CI and shared agents.'
            : 'Owned by you and dies with your account. Right for your own automation.' }}
        </p>
      </div>

      <div>
        <label
          for="token-description"
          class="mb-1.5 block text-sm font-medium text-gray-200"
        >Description <span class="font-normal text-gray-500">(optional)</span></label>
        <input
          id="token-description"
          v-model="description"
          type="text"
          placeholder="Uploads coverage from the release pipeline — owned by the platform team"
          class="w-full rounded-lg border border-surface-border bg-surface-overlay px-3 py-2 text-sm text-gray-200 placeholder:text-gray-600"
        >
      </div>

      <TokenScopeEditor v-model="scope" />

      <p
        v-if="formError"
        class="text-sm text-red-400"
      >
        {{ formError }}
      </p>

      <div class="flex items-center gap-2">
        <button
          type="submit"
          :disabled="!canSubmit"
          class="rounded-lg border border-accent bg-accent-muted px-4 py-2 text-sm font-medium text-white transition enabled:hover:bg-accent disabled:cursor-not-allowed disabled:opacity-50"
        >
          {{ submitting ? 'Saving…' : editing ? 'Save changes' : 'Create token' }}
        </button>
        <button
          type="button"
          class="rounded-lg border border-surface-border bg-surface-overlay px-4 py-2 text-sm text-gray-300 transition hover:text-white"
          @click="creating = false; editing = null"
        >
          Cancel
        </button>
      </div>
    </form>

    <p
      v-if="listError"
      class="border-b border-surface-border-subtle px-6 py-3 text-sm text-red-400"
    >
      {{ listError }}
    </p>

    <div
      v-if="loading"
      class="px-6 py-12 text-center text-sm text-gray-500"
    >
      Loading tokens…
    </div>

    <div
      v-else-if="keys.length === 0"
      class="px-6 py-12 text-center"
    >
      <div class="mx-auto flex h-12 w-12 items-center justify-center rounded-full border border-surface-border bg-surface-overlay">
        <KeyRound class="h-5 w-5 text-gray-500" />
      </div>
      <p class="mt-3 text-sm text-gray-300">
        No API keys yet.
      </p>
      <p class="mt-1 text-xs text-gray-500">
        Create a scoped token for CI, the CLI, or an agent.
      </p>
    </div>

    <ul v-else>
      <li
        v-for="key in keys"
        :key="key.id"
        class="flex flex-wrap items-start justify-between gap-4 border-b border-surface-border-subtle px-6 py-4 last:border-b-0"
      >
        <div class="min-w-0 flex-1">
          <div class="flex flex-wrap items-center gap-2">
            <span class="text-sm font-medium text-white">{{ key.name }}</span>
            <span
              v-if="!key.scopes"
              class="rounded-full bg-amber-500/15 px-2 py-0.5 text-[11px] font-medium text-amber-300"
              title="A legacy token with the full access of the account that created it"
            >unscoped</span>
            <span
              v-else-if="isMalformed(key)"
              class="rounded-full bg-red-500/15 px-2 py-0.5 text-[11px] font-medium text-red-300"
              title="The stored scope is not a valid scope document, so this token is denied everything. Rotate it with a real scope or revoke it."
            >malformed scope</span>
            <span
              v-else-if="isReadOnly(key)"
              class="rounded-full bg-emerald-500/15 px-2 py-0.5 text-[11px] font-medium text-emerald-300"
            >read-only</span>
            <span
              v-if="key.owner_type === 'org'"
              class="rounded-full bg-blue-500/15 px-2 py-0.5 text-[11px] font-medium text-blue-300"
            >org-owned</span>
            <span
              v-if="key.approval_status === 'pending'"
              class="rounded-full bg-amber-500/15 px-2 py-0.5 text-[11px] font-medium text-amber-300"
              title="Fails authentication until an org admin approves it"
            >pending approval</span>
            <span
              v-else-if="key.approval_status === 'rejected'"
              class="rounded-full bg-red-500/15 px-2 py-0.5 text-[11px] font-medium text-red-300"
              title="An org admin rejected this token; it will never authenticate"
            >rejected</span>
            <span
              v-if="isExpired(key)"
              class="rounded-full bg-red-500/15 px-2 py-0.5 text-[11px] font-medium text-red-300"
            >expired</span>
            <span
              v-else-if="expiresSoon(key)"
              class="rounded-full bg-orange-500/15 px-2 py-0.5 text-[11px] font-medium text-orange-300"
              :title="`Expires ${formatDate(key.expires_at)} — rotate or extend before then`"
            >expires soon</span>
            <span
              v-else-if="isStale(key)"
              class="rounded-full bg-gray-500/15 px-2 py-0.5 text-[11px] font-medium text-gray-400"
              title="Not used in over 90 days"
            >stale</span>
          </div>
          <p
            v-if="key.description"
            class="mt-0.5 text-xs text-gray-400"
          >
            {{ key.description }}
          </p>
          <p class="mt-1 font-mono text-xs text-gray-500">
            {{ scopeSummary(key) }}
          </p>
          <p class="mt-1 text-xs text-gray-500">
            Last used {{ key.last_used_at ? formatDate(key.last_used_at) : 'never' }} ·
            {{ key.expires_at ? `expires ${formatDate(key.expires_at)}` : 'no expiry' }} ·
            created {{ formatDate(key.created_at) }}
          </p>
        </div>
        <div class="flex shrink-0 gap-2">
          <button
            v-if="key.scopes"
            type="button"
            class="flex items-center gap-1.5 rounded-lg border border-surface-border bg-surface-overlay px-3 py-1.5 text-xs text-gray-300 transition hover:text-white"
            @click="expandedKeyID = expandedKeyID === key.id ? '' : key.id"
          >
            <component
              :is="expandedKeyID === key.id ? ChevronUp : ChevronDown"
              class="h-3.5 w-3.5"
            />
            Scope
          </button>
          <button
            type="button"
            :disabled="busyKeyID === key.id"
            class="flex items-center gap-1.5 rounded-lg border px-3 py-1.5 text-xs transition disabled:opacity-50"
            :class="key.scopes
              ? 'border-surface-border bg-surface-overlay text-gray-300 hover:text-white'
              : 'border-amber-500/40 bg-amber-500/10 text-amber-300 hover:text-amber-200'"
            :title="key.scopes ? 'Edit name, description, scope, or expiry — the secret is unchanged' : 'Apply a scope to this full-access legacy token without changing its secret'"
            @click="openEdit(key)"
          >
            <Pencil class="h-3.5 w-3.5" />
            {{ key.scopes ? 'Edit' : 'Restrict…' }}
          </button>
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

        <div
          v-if="expandedKeyID === key.id && usableScope(key)"
          class="w-full rounded-lg border border-surface-border bg-surface-overlay px-4 py-3"
        >
          <div class="grid gap-4 sm:grid-cols-2">
            <div>
              <div class="mb-1 text-xs font-medium uppercase tracking-wide text-gray-500">
                Repositories
              </div>
              <p
                v-if="usableScope(key)?.repos.mode === 'all'"
                class="text-sm text-gray-300"
              >
                All repositories in {{ usableScope(key)?.org }}, including ones enrolled later.
              </p>
              <ul
                v-else
                class="max-h-32 space-y-0.5 overflow-y-auto"
              >
                <li
                  v-for="slug in usableScope(key)?.repos.slugs ?? []"
                  :key="slug"
                  class="font-mono text-xs text-gray-300"
                >
                  {{ usableScope(key)?.org }}/{{ slug }}
                </li>
              </ul>
            </div>
            <div>
              <div class="mb-1 text-xs font-medium uppercase tracking-wide text-gray-500">
                Permissions
              </div>
              <ul class="space-y-0.5">
                <li
                  v-for="[capability, level] in grantedPermissions(key)"
                  :key="capability"
                  class="flex items-center gap-2 text-xs"
                >
                  <span class="font-mono text-gray-300">{{ capability }}</span>
                  <span
                    class="rounded-full px-1.5 py-0.5 text-[10px] font-medium"
                    :class="level === 'write' ? 'bg-amber-500/15 text-amber-300' : 'bg-emerald-500/15 text-emerald-300'"
                  >{{ level }}</span>
                </li>
                <li
                  v-if="grantedPermissions(key).length === 0"
                  class="text-xs text-gray-500"
                >
                  Nothing granted — this token can do nothing.
                </li>
              </ul>
            </div>
          </div>
        </div>
      </li>
    </ul>
  </section>
</template>
