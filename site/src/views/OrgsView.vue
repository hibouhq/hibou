<template>
  <div class="space-y-6">
    <section class="overflow-hidden rounded-[2rem] border border-surface-border bg-surface-raised shadow-[0_32px_90px_-52px_rgba(0,0,0,0.92)]">
      <div class="relative px-6 py-7 sm:px-8">
        <div class="absolute inset-x-0 top-0 h-px bg-gradient-to-r from-transparent via-accent/70 to-transparent" />

        <div class="flex flex-col gap-5 lg:flex-row lg:items-end lg:justify-between">
          <div class="max-w-2xl">
            <div class="inline-flex items-center gap-2 rounded-full border border-accent/20 bg-accent/10 px-3 py-1 text-[11px] font-medium uppercase tracking-[0.22em] text-accent">
              <Sparkles class="h-3.5 w-3.5" />
              Onboarding
            </div>
            <h1 class="mt-4 text-3xl font-semibold tracking-tight text-white sm:text-[2.1rem]">
              Organizations
            </h1>
            <p class="mt-3 text-sm leading-6 text-gray-400 sm:text-[15px]">
              Connect forge accounts, import installed organizations, or create a workspace manually without leaving the Hibou flow.
            </p>
          </div>

          <div class="flex flex-wrap gap-3">
            <button
              v-if="hasOrgs"
              class="inline-flex items-center justify-center gap-2 rounded-2xl border border-surface-border bg-surface-overlay px-4 py-2.5 text-sm font-medium text-gray-200 transition hover:border-accent/40 hover:text-white"
              type="button"
              @click="toggleOnboardingPanel"
            >
              <Plus class="h-4 w-4" />
              {{ shouldShowOnboarding ? 'Hide add organization' : 'Add organization' }}
            </button>
            <button
              class="inline-flex items-center justify-center gap-2 rounded-2xl border border-accent/30 bg-accent/12 px-4 py-2.5 text-sm font-medium text-white transition hover:border-accent/60 hover:bg-accent/18"
              type="button"
              @click="openManualCreate"
            >
              <Building2 class="h-4 w-4" />
              Manual create
            </button>
          </div>
        </div>
      </div>
    </section>

    <section
      v-if="loadingInitial"
      class="grid gap-4 lg:grid-cols-[minmax(0,1.3fr)_minmax(20rem,0.9fr)]"
    >
      <div class="rounded-[2rem] border border-surface-border bg-surface-raised p-7">
        <div class="animate-pulse space-y-4">
          <div class="h-4 w-28 rounded-full bg-surface-overlay" />
          <div class="h-10 w-3/5 rounded-2xl bg-surface-overlay" />
          <div class="h-4 w-4/5 rounded-full bg-surface-overlay" />
          <div class="grid gap-3 pt-4 sm:grid-cols-2">
            <div class="h-24 rounded-3xl bg-surface-overlay" />
            <div class="h-24 rounded-3xl bg-surface-overlay" />
          </div>
        </div>
      </div>
      <div class="rounded-[2rem] border border-surface-border bg-surface-raised p-7">
        <div class="animate-pulse space-y-3">
          <div class="h-5 w-32 rounded-full bg-surface-overlay" />
          <div class="h-16 rounded-3xl bg-surface-overlay" />
          <div class="h-16 rounded-3xl bg-surface-overlay" />
          <div class="h-16 rounded-3xl bg-surface-overlay" />
        </div>
      </div>
    </section>

    <section
      v-else-if="listError && !hasOrgs"
      class="rounded-[2rem] border border-danger/30 bg-danger/10 p-6"
    >
      <div class="flex flex-col gap-4 sm:flex-row sm:items-start sm:justify-between">
        <div class="flex items-start gap-3">
          <div class="flex h-11 w-11 items-center justify-center rounded-2xl border border-danger/30 bg-danger/10 text-red-200">
            <TriangleAlert class="h-5 w-5" />
          </div>
          <div>
            <h2 class="text-lg font-medium text-white">
              We couldn’t load your organizations
            </h2>
            <p class="mt-1 text-sm text-red-100/90">
              {{ listError }}
            </p>
          </div>
        </div>
        <button
          class="inline-flex items-center justify-center rounded-2xl border border-danger/30 bg-danger/10 px-4 py-2 text-sm font-medium text-red-100 transition hover:bg-danger/15"
          type="button"
          @click="reloadPageData"
        >
          Retry
        </button>
      </div>
    </section>

    <Transition
      enter-active-class="transition duration-200 ease-out"
      enter-from-class="translate-y-2 opacity-0"
      enter-to-class="translate-y-0 opacity-100"
      leave-active-class="transition duration-150 ease-in"
      leave-from-class="opacity-100"
      leave-to-class="translate-y-1 opacity-0"
    >
      <section
        v-if="shouldShowOnboarding"
        class="grid gap-4 lg:grid-cols-[minmax(0,1.15fr)_minmax(22rem,0.95fr)]"
      >
        <article class="relative overflow-hidden rounded-[2rem] border border-surface-border bg-surface-raised p-7 shadow-[0_30px_90px_-58px_rgba(88,166,255,0.4)]">
          <div class="absolute inset-y-0 right-0 w-40 bg-[radial-gradient(circle_at_top_right,rgba(88,166,255,0.16),transparent_68%)]" />
          <div class="relative flex h-full flex-col justify-between gap-6">
            <div>
              <div class="inline-flex items-center gap-2 rounded-full border border-surface-border-subtle bg-surface-overlay px-3 py-1 text-[11px] uppercase tracking-[0.18em] text-gray-400">
                <ShieldCheck class="h-3.5 w-3.5 text-accent" />
                P0 org onboarding
              </div>
              <h2 class="mt-4 text-2xl font-semibold tracking-tight text-white">
                Install the Hibou App, then import the account you already control.
              </h2>
              <p class="mt-3 max-w-xl text-sm leading-6 text-gray-400">
                We only show forge accounts tied to your recorded installer identity. If access is still pending, sign back in after the forge grant lands.
              </p>
            </div>

            <div class="grid gap-3 sm:grid-cols-[auto,1fr] sm:items-end">
              <a
                :href="hibouAppInstallUrl"
                target="_blank"
                rel="noreferrer"
                class="inline-flex items-center justify-center gap-2 rounded-2xl border border-accent/30 bg-accent/12 px-4 py-3 text-sm font-medium text-white transition hover:border-accent/60 hover:bg-accent/18"
              >
                <ArrowUpRight class="h-4 w-4" />
                Install the Hibou App
              </a>
              <div class="rounded-2xl border border-surface-border-subtle bg-surface-overlay px-4 py-3 text-sm text-gray-400">
                <div class="font-medium text-gray-200">
                  Current provider
                </div>
                <div class="mt-1">
                  {{ preferredProviderLabel }}. {{ installLinkHint }}
                </div>
              </div>
            </div>
          </div>
        </article>

        <article class="rounded-[2rem] border border-surface-border bg-surface-raised p-6">
          <div class="flex items-start justify-between gap-4">
            <div>
              <h2 class="text-lg font-semibold text-white">
                Import available accounts
              </h2>
              <p class="mt-1 text-sm text-gray-400">
                Installed accounts appear here with their claim state.
              </p>
            </div>
            <div class="rounded-full border border-surface-border-subtle bg-surface-overlay px-3 py-1 text-xs uppercase tracking-[0.18em] text-gray-500">
              {{ onboardable.length }} total
            </div>
          </div>

          <div
            v-if="onboardingError"
            class="mt-5 rounded-2xl border border-danger/30 bg-danger/10 px-4 py-3 text-sm text-red-100"
          >
            {{ onboardingError }}
          </div>

          <div
            v-else-if="onboardableLoading && !onboardable.length"
            class="mt-5 space-y-3"
          >
            <div
              v-for="index in 3"
              :key="index"
              class="animate-pulse rounded-3xl border border-surface-border-subtle bg-surface-overlay p-4"
            >
              <div class="h-4 w-24 rounded-full bg-surface-raised" />
              <div class="mt-3 h-6 w-40 rounded-full bg-surface-raised" />
              <div class="mt-2 h-4 w-28 rounded-full bg-surface-raised" />
            </div>
          </div>

          <div
            v-else-if="!onboardable.length"
            class="mt-5 rounded-[1.6rem] border border-dashed border-surface-border-subtle bg-surface-overlay/70 px-5 py-10 text-center"
          >
            <div class="mx-auto flex h-12 w-12 items-center justify-center rounded-2xl border border-surface-border bg-surface-raised text-gray-400">
              <Building2 class="h-5 w-5" />
            </div>
            <h3 class="mt-4 text-base font-medium text-white">
              No installed accounts yet
            </h3>
            <p class="mt-2 text-sm text-gray-400">
              Install the App on a forge organization first, then come back here to import it into Hibou.
            </p>
          </div>

          <div
            v-else
            class="mt-5 space-y-3"
          >
            <article
              v-for="account in onboardable"
              :key="`${account.provider}:${account.account}`"
              class="group rounded-[1.6rem] border border-surface-border-subtle bg-surface-overlay/80 p-4 transition hover:border-accent/20 hover:bg-surface-overlay"
            >
              <div class="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
                <div class="min-w-0 flex items-start gap-3">
                  <div class="flex h-11 w-11 shrink-0 items-center justify-center rounded-2xl border border-surface-border bg-surface-raised text-gray-300 transition group-hover:border-accent/25 group-hover:text-white">
                    <ForgeIcon
                      :provider="account.provider"
                      size="sm"
                    />
                  </div>
                  <div class="min-w-0">
                    <div class="flex flex-wrap items-center gap-2">
                      <h3 class="truncate text-base font-medium text-white">
                        {{ account.account }}
                      </h3>
                      <span
                        :class="statusBadgeClass(account.status)"
                        class="rounded-full border px-2.5 py-1 text-[11px] font-medium uppercase tracking-[0.16em]"
                      >
                        {{ account.status }}
                      </span>
                    </div>
                    <p class="mt-1 text-sm text-gray-500">
                      {{ account.provider }} / {{ account.slug }}
                    </p>
                  </div>
                </div>

                <div class="flex flex-wrap gap-2 sm:justify-end">
                  <button
                    v-if="account.status === 'importable'"
                    class="inline-flex min-w-[8.5rem] items-center justify-center gap-2 rounded-2xl border border-accent/30 bg-accent/12 px-4 py-2.5 text-sm font-medium text-white transition hover:border-accent/60 hover:bg-accent/18 disabled:cursor-not-allowed disabled:opacity-70"
                    type="button"
                    :disabled="importingKey === `${account.provider}:${account.account}`"
                    @click="handleImport(account)"
                  >
                    <LoaderCircle
                      v-if="importingKey === `${account.provider}:${account.account}`"
                      class="h-4 w-4 animate-spin"
                    />
                    <ArrowUpRight
                      v-else
                      class="h-4 w-4"
                    />
                    {{ importingKey === `${account.provider}:${account.account}` ? 'Importing...' : 'Import' }}
                  </button>

                  <RouterLink
                    v-else-if="account.status === 'imported' && importedOrgFor(account)"
                    :to="`/orgs/${account.provider}/${account.slug}`"
                    class="inline-flex items-center justify-center gap-2 rounded-2xl border border-emerald-500/30 bg-emerald-500/10 px-4 py-2.5 text-sm font-medium text-emerald-100 transition hover:bg-emerald-500/15"
                  >
                    <CheckCircle2 class="h-4 w-4" />
                    Already in Hibou
                  </RouterLink>

                  <div
                    v-else
                    class="inline-flex items-center justify-center gap-2 rounded-2xl border border-amber-500/25 bg-amber-500/10 px-4 py-2.5 text-sm font-medium text-amber-100"
                  >
                    <Clock3 class="h-4 w-4" />
                    Awaiting access
                  </div>
                </div>
              </div>

              <p
                v-if="account.status === 'pending'"
                class="mt-3 text-sm text-gray-400"
              >
                The organization already exists in Hibou. Sign in to the forge again after your membership claim completes.
              </p>
              <p
                v-else-if="account.status === 'imported'"
                class="mt-3 text-sm text-gray-400"
              >
                This account is already attached to a Hibou organization you can access.
              </p>
              <p
                v-else
                class="mt-3 text-sm text-gray-400"
              >
                Import creates the organization in Hibou and keeps the forge identity attached for later syncs.
              </p>
            </article>
          </div>
        </article>
      </section>
    </Transition>

    <section
      v-if="hasOrgs"
      class="overflow-hidden rounded-[2rem] border border-surface-border bg-surface-raised"
    >
      <div class="border-b border-surface-border-subtle px-6 py-4">
        <h2 class="text-lg font-semibold text-white">
          Your organizations
        </h2>
        <p class="mt-1 text-sm text-gray-400">
          Jump back into active workspaces or add another organization when you are ready.
        </p>
      </div>
      <ul class="divide-y divide-surface-border-subtle">
        <li
          v-for="org in orgs"
          :key="org.id"
          class="px-6 py-4"
        >
          <RouterLink
            :to="`/orgs/${org.provider}/${org.slug}`"
            class="group flex items-center justify-between gap-4 rounded-[1.5rem] border border-transparent p-1 transition hover:border-surface-border-subtle"
          >
            <div class="min-w-0 flex items-center gap-3">
              <div class="flex h-11 w-11 shrink-0 items-center justify-center rounded-2xl border border-surface-border bg-surface-overlay text-gray-300 transition group-hover:border-accent/25 group-hover:text-white">
                <ForgeIcon
                  :provider="org.provider"
                  size="sm"
                />
              </div>
              <div class="min-w-0">
                <div class="truncate text-base font-medium text-white">
                  {{ org.display_name || org.name }}
                </div>
                <div class="mt-1 flex flex-wrap items-center gap-2 text-sm text-gray-500">
                  <span>{{ org.provider }} / {{ org.slug }}</span>
                  <span class="rounded-full border border-surface-border-subtle bg-surface-overlay px-2 py-0.5 text-[11px] uppercase tracking-[0.14em] text-gray-400">
                    {{ org.role || 'member' }}
                  </span>
                </div>
              </div>
            </div>

            <span class="inline-flex items-center gap-2 text-sm text-gray-400 transition group-hover:text-white">
              Open
              <ArrowUpRight class="h-4 w-4" />
            </span>
          </RouterLink>
        </li>
      </ul>
    </section>

    <Teleport to="body">
      <Transition
        enter-active-class="transition duration-200 ease-out"
        enter-from-class="opacity-0"
        enter-to-class="opacity-100"
        leave-active-class="transition duration-150 ease-in"
        leave-from-class="opacity-100"
        leave-to-class="opacity-0"
      >
        <div
          v-if="showManualDialog"
          class="fixed inset-0 z-[80] bg-[#020409]/80 px-4 py-8 backdrop-blur-sm"
          @click.self="closeManualCreate"
        >
          <div class="mx-auto max-w-xl rounded-[2rem] border border-surface-border bg-surface-raised shadow-[0_40px_120px_-60px_rgba(0,0,0,0.95)]">
            <div class="flex items-start justify-between gap-4 border-b border-surface-border-subtle px-6 py-5">
              <div>
                <h2 class="text-xl font-semibold text-white">
                  Create organization
                </h2>
                <p class="mt-1 text-sm text-gray-400">
                  Manual fallback for accounts that are not yet importable.
                </p>
              </div>
              <button
                class="rounded-xl p-2 text-gray-500 transition hover:bg-surface-overlay hover:text-white"
                type="button"
                @click="closeManualCreate"
              >
                <X class="h-4 w-4" />
              </button>
            </div>

            <form
              class="space-y-5 px-6 py-6"
              @submit.prevent="submitManualCreate"
            >
              <label class="block">
                <span class="mb-2 block text-sm font-medium text-gray-200">Name</span>
                <input
                  v-model="manualForm.name"
                  type="text"
                  autocomplete="organization"
                  placeholder="Acme Platform"
                  class="w-full rounded-2xl border border-surface-border bg-surface-overlay px-4 py-3 text-sm text-gray-100 placeholder:text-gray-500 focus:border-accent/50 focus:outline-none"
                >
              </label>

              <div class="grid gap-5 sm:grid-cols-2">
                <label class="block">
                  <span class="mb-2 block text-sm font-medium text-gray-200">Slug</span>
                  <input
                    v-model="manualForm.slug"
                    type="text"
                    placeholder="acme-platform"
                    class="w-full rounded-2xl border px-4 py-3 text-sm text-gray-100 placeholder:text-gray-500 focus:outline-none"
                    :class="manualSlugError ? 'border-danger/40 bg-danger/10 focus:border-danger/60' : 'border-surface-border bg-surface-overlay focus:border-accent/50'"
                    @input="manualSlugTouched = true"
                  >
                  <p
                    v-if="manualSlugError"
                    class="mt-2 text-sm text-red-200"
                  >
                    {{ manualSlugError }}
                  </p>
                  <p
                    v-else
                    class="mt-2 text-xs uppercase tracking-[0.16em] text-gray-500"
                  >
                    2-63 chars, lowercase letters, numbers, hyphens.
                  </p>
                </label>

                <label class="block">
                  <span class="mb-2 block text-sm font-medium text-gray-200">Provider</span>
                  <select
                    v-model="manualForm.provider"
                    class="w-full rounded-2xl border border-surface-border bg-surface-overlay px-4 py-3 text-sm text-gray-100 focus:border-accent/50 focus:outline-none"
                  >
                    <option
                      v-for="provider in providerOptions"
                      :key="provider.id"
                      :value="provider.id"
                    >
                      {{ provider.name }}
                    </option>
                  </select>
                </label>
              </div>

              <div
                v-if="manualError"
                class="rounded-2xl border border-danger/30 bg-danger/10 px-4 py-3 text-sm text-red-100"
              >
                {{ manualError }}
              </div>

              <div class="flex flex-col-reverse gap-3 sm:flex-row sm:justify-end">
                <button
                  class="inline-flex items-center justify-center rounded-2xl border border-surface-border bg-surface-overlay px-4 py-3 text-sm font-medium text-gray-300 transition hover:border-accent/40 hover:text-white"
                  type="button"
                  @click="closeManualCreate"
                >
                  Cancel
                </button>
                <button
                  class="inline-flex items-center justify-center gap-2 rounded-2xl border border-accent/30 bg-accent/12 px-4 py-3 text-sm font-medium text-white transition hover:border-accent/60 hover:bg-accent/18 disabled:cursor-not-allowed disabled:opacity-70"
                  type="submit"
                  :disabled="manualSubmitting || !!manualSlugError || !manualForm.name.trim()"
                >
                  <LoaderCircle
                    v-if="manualSubmitting"
                    class="h-4 w-4 animate-spin"
                  />
                  {{ manualSubmitting ? 'Creating...' : 'Create organization' }}
                </button>
              </div>
            </form>
          </div>
        </div>
      </Transition>
    </Teleport>
  </div>
</template>

<script setup lang="ts">
import {
  ArrowUpRight,
  Building2,
  CheckCircle2,
  Clock3,
  LoaderCircle,
  Plus,
  ShieldCheck,
  Sparkles,
  TriangleAlert,
  X,
} from 'lucide-vue-next'
import { computed, onMounted, reactive, ref, watch } from 'vue'
import { RouterLink, useRouter } from 'vue-router'

import { api, type AuthProvider, type OnboardableAccount } from '@/api/client'
import ForgeIcon from '@/components/ForgeIcon.vue'
import { useToast } from '@/composables/useToast'
import { useAuthStore } from '@/stores/auth'
import { useOrgStore } from '@/stores/org'

const FORGE_PROVIDER_NAMES: Record<string, string> = {
  forgejo: 'Forgejo',
  github: 'GitHub',
  gitlab: 'GitLab',
}

const FORGE_INSTALL_URLS: Record<string, string> = {
  forgejo: 'https://forgejo.org/',
  github: 'https://github.com/apps',
  gitlab: 'https://gitlab.com/',
}

const FORGE_SITE_HINTS: Record<string, string> = {
  forgejo: 'Direct App install URL is not wired yet, so this opens the provider site.',
  github: 'Opens the provider install surface until a direct Hibou App URL is configured.',
  gitlab: 'Direct App install URL is not wired yet, so this opens the provider site.',
}

const SLUG_PATTERN = /^[a-z0-9-]{2,63}$/

const orgStore = useOrgStore()
const authStore = useAuthStore()
const router = useRouter()
const toast = useToast()

const providerOptions = ref<AuthProvider[]>([])
const pageReady = ref(false)
const showOnboardingPanel = ref(false)
const showManualDialog = ref(false)
const importingKey = ref('')
const manualSubmitting = ref(false)
const manualError = ref('')
const manualSlugTouched = ref(false)
const manualForm = reactive({
  name: '',
  slug: '',
  provider: 'github',
})

const orgs = computed(() => orgStore.orgs)
const onboardable = computed(() => orgStore.onboardable)
const listError = computed(() => orgStore.error)
const onboardingError = computed(() => orgStore.onboardableError)
const loadingInitial = computed(() => !pageReady.value || (orgStore.loading && !orgStore.orgs.length && !orgStore.error))
const onboardableLoading = computed(() => orgStore.onboardableLoading)
const hasOrgs = computed(() => orgs.value.length > 0)
const shouldShowOnboarding = computed(() => !hasOrgs.value || showOnboardingPanel.value)
const preferredProvider = computed(() => {
  const candidate = authStore.user?.provider?.toLowerCase() || manualForm.provider || providerOptions.value[0]?.id || 'github'
  return FORGE_PROVIDER_NAMES[candidate] ? candidate : 'github'
})
const preferredProviderLabel = computed(() => FORGE_PROVIDER_NAMES[preferredProvider.value] || preferredProvider.value)
const hibouAppInstallUrl = computed(() => FORGE_INSTALL_URLS[preferredProvider.value] || FORGE_INSTALL_URLS.github)
const installLinkHint = computed(() => FORGE_SITE_HINTS[preferredProvider.value] || FORGE_SITE_HINTS.github)
const orgLookup = computed(() => new Map(orgs.value.map((org) => [`${org.provider}:${org.slug}`, org])))
const manualSlugError = computed(() => {
  if (!manualForm.slug.trim()) {
    return 'Slug is required.'
  }
  if (!SLUG_PATTERN.test(manualForm.slug.trim())) {
    return 'Use 2-63 lowercase letters, numbers, or hyphens.'
  }
  return ''
})

watch(() => manualForm.name, (nextName) => {
  if (manualSlugTouched.value) {
    return
  }
  manualForm.slug = slugifyValue(nextName)
})

watch(hasOrgs, (nextHasOrgs) => {
  if (!nextHasOrgs) {
    showOnboardingPanel.value = true
  }
})

function slugifyValue(value: string) {
  return value
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 63)
}

function normalizeProviders(rawProviders: AuthProvider[]) {
  const merged = new Map<string, AuthProvider>()
  for (const [id, name] of Object.entries(FORGE_PROVIDER_NAMES)) {
    merged.set(id, { id, name })
  }
  for (const provider of rawProviders) {
    if (!provider?.id) {
      continue
    }
    const id = provider.id.toLowerCase()
    if (!FORGE_PROVIDER_NAMES[id]) {
      continue
    }
    merged.set(id, { id, name: provider.name || FORGE_PROVIDER_NAMES[id] })
  }
  return Array.from(merged.values())
}

function importedOrgFor(account: OnboardableAccount) {
  return orgLookup.value.get(`${account.provider}:${account.slug}`) || null
}

function statusBadgeClass(status: OnboardableAccount['status']) {
  switch (status) {
    case 'imported':
      return 'border-emerald-500/30 bg-emerald-500/10 text-emerald-100'
    case 'pending':
      return 'border-amber-500/25 bg-amber-500/10 text-amber-100'
    default:
      return 'border-accent/25 bg-accent/10 text-accent'
  }
}

function resetManualForm() {
  manualForm.name = ''
  manualForm.slug = ''
  manualForm.provider = preferredProvider.value
  manualError.value = ''
  manualSubmitting.value = false
  manualSlugTouched.value = false
}

function openManualCreate() {
  resetManualForm()
  showManualDialog.value = true
}

function closeManualCreate() {
  showManualDialog.value = false
}

function toggleOnboardingPanel() {
  showOnboardingPanel.value = !showOnboardingPanel.value
}

function showClaimedOrgToasts() {
  for (const org of orgStore.consumeClaimedOrgs()) {
    toast.success(`You're now admin of ${org.display_name || org.name}`, `${org.provider} / ${org.slug}`)
  }
}

async function loadProviders() {
  try {
    const response = await api.getProviders()
    providerOptions.value = normalizeProviders(response.data)
  } catch {
    providerOptions.value = normalizeProviders([])
  }
  manualForm.provider = preferredProvider.value
}

async function reloadPageData() {
  const tasks = [orgStore.fetchOrgs(), orgStore.fetchOnboardable(), loadProviders()]
  const results = await Promise.allSettled(tasks)
  pageReady.value = true
  showClaimedOrgToasts()
  if (!hasOrgs.value) {
    showOnboardingPanel.value = true
  }
  if (results.some((result) => result.status === 'rejected') && !hasOrgs.value && !listError.value) {
    toast.error('Unable to fully refresh onboarding data', 'Some onboarding details may be incomplete.')
  }
}

async function handleImport(account: OnboardableAccount) {
  const key = `${account.provider}:${account.account}`
  importingKey.value = key
  try {
    await orgStore.importOrg(account)
    toast.success(`Imported ${account.account}`, 'The organization is now available in Hibou.')
  } catch (caught) {
    toast.error('Import failed', caught instanceof Error ? caught.message : 'Unable to import the organization.')
  } finally {
    importingKey.value = ''
  }
}

async function submitManualCreate() {
  manualError.value = ''
  manualSlugTouched.value = true
  if (manualSlugError.value) {
    return
  }

  manualSubmitting.value = true
  try {
    const response = await api.createOrg({
      name: manualForm.name.trim(),
      slug: manualForm.slug.trim(),
      display_name: manualForm.name.trim(),
      provider: manualForm.provider,
    })
    await Promise.all([
      orgStore.fetchOrgs({ suppressClaimToast: true }),
      orgStore.fetchOnboardable(),
    ])
    closeManualCreate()
    toast.success(`Created ${response.data.display_name || response.data.name}`, `${response.data.provider} / ${response.data.slug}`)
    await router.push(`/orgs/${response.data.provider}/${response.data.slug}`)
  } catch (caught) {
    manualError.value = caught instanceof Error ? caught.message : 'Unable to create the organization.'
  } finally {
    manualSubmitting.value = false
  }
}

onMounted(async () => {
  await reloadPageData()
})
</script>
