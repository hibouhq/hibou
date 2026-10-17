<template>
  <div class="space-y-6">
    <section>
      <div class="flex items-center justify-between border-b border-surface-border pb-2">
        <h2 class="text-base font-semibold text-white">
          Dependency policy
        </h2>
        <span
          v-if="!isOrgAdmin"
          class="text-xs text-gray-500"
        >Read-only — org admins can change this</span>
      </div>
      <p class="mt-3 text-sm text-gray-500">
        The organization's floor for release cooldown, install-time verification and private
        packages (ADR-048), and what never ships to clients (ADR-045). A repository's
        <code class="rounded bg-surface-overlay px-1 font-mono text-xs">.hibou.yaml</code> can tighten
        any of it, never loosen it.
      </p>

      <div
        v-if="loading"
        class="mt-3 text-sm text-gray-500"
      >
        Loading settings…
      </div>
      <div
        v-else-if="loadFailed"
        class="mt-3 text-sm text-gray-500"
      >
        Settings could not be loaded.
      </div>
      <div
        v-else
        class="mt-1 divide-y divide-surface-border-subtle"
      >
        <div class="flex items-start justify-between gap-6 py-3">
          <div>
            <div class="text-sm font-medium text-gray-200">
              Cooldown window
            </div>
            <p class="mt-0.5 text-xs text-gray-500">
              How long a freshly published version waits before a pull request may adopt it:
              <span class="font-mono">auto</span> follows deps.dev's own end, a duration such as
              <span class="font-mono">7d</span> counts from the publish date, <span class="font-mono">off</span> disables it.
            </p>
          </div>
          <input
            v-model="form.dependency_cooldown_window"
            type="text"
            placeholder="auto"
            class="h-8 w-28 shrink-0 rounded-md border border-surface-border bg-surface-overlay px-2 font-mono text-sm text-gray-200 focus:border-accent/50 focus:outline-none disabled:opacity-60"
            :disabled="!isOrgAdmin"
          >
        </div>

        <div class="flex items-start justify-between gap-6 py-3">
          <div>
            <div class="text-sm font-medium text-gray-200">
              Enforcement
            </div>
            <p class="mt-0.5 text-xs text-gray-500">
              Whether a cooldown hold fails the pull request gate or only notes it.
            </p>
          </div>
          <select
            v-model="form.dependency_cooldown_enforcement"
            class="h-8 shrink-0 rounded-md border border-surface-border bg-surface-overlay px-2 text-sm text-gray-200 focus:border-accent/50 focus:outline-none disabled:opacity-60"
            :disabled="!isOrgAdmin"
          >
            <option value="">
              Inherit the gate
            </option>
            <option value="advisory">
              Advisory
            </option>
            <option value="blocking">
              Blocking
            </option>
          </select>
        </div>

        <div class="flex items-start justify-between gap-6 py-3">
          <div>
            <div class="text-sm font-medium text-gray-200">
              Install-time cooldown
            </div>
            <p class="mt-0.5 text-xs text-gray-500">
              The gate holds a merge; only the package manager's own setting (npm
              <span class="font-mono">min-release-age</span>, pnpm <span class="font-mono">minimumReleaseAge</span>,
              uv <span class="font-mono">exclude-newer</span>…) keeps a fresh version off a build. A missing
              setting is a coverage gap, a warning, or ignored.
            </p>
          </div>
          <select
            v-model="form.dependency_install_config"
            class="h-8 shrink-0 rounded-md border border-surface-border bg-surface-overlay px-2 text-sm text-gray-200 focus:border-accent/50 focus:outline-none disabled:opacity-60"
            :disabled="!isOrgAdmin"
          >
            <option value="">
              Warn (default)
            </option>
            <option value="require">
              Require
            </option>
            <option value="off">
              Off
            </option>
          </select>
        </div>

        <div class="py-3">
          <div class="text-sm font-medium text-gray-200">
            Private namespaces
          </div>
          <p class="mt-0.5 text-xs text-gray-500">
            Package URL patterns never sent to third-party APIs, one per line:
            <span class="font-mono">pkg:npm/@acme/*</span>, <span class="font-mono">pkg:maven/com.acme.*</span>.
          </p>
          <textarea
            v-model="privateNamespacesText"
            rows="3"
            class="mt-2 w-full rounded-md border border-surface-border bg-surface-overlay px-2 py-1 font-mono text-xs text-gray-200 focus:border-accent/50 focus:outline-none disabled:opacity-60"
            :disabled="!isOrgAdmin"
          />
        </div>

        <div class="py-3">
          <div class="text-sm font-medium text-gray-200">
            Trust declared dev and test scopes
          </div>
          <p class="mt-0.5 text-xs text-gray-500">
            Ecosystems whose declared scopes (Maven <span class="font-mono">test</span>, Cargo
            <span class="font-mono">dev-dependencies</span>…) count as not shipped without an explicit
            entry. Off by default: a bundler ships npm devDependencies all the time.
          </p>
          <div class="mt-2 flex flex-wrap gap-3">
            <label
              v-for="ecosystem in TRUSTABLE_ECOSYSTEMS"
              :key="ecosystem"
              class="inline-flex items-center gap-1.5 text-xs text-gray-300"
            >
              <input
                type="checkbox"
                class="h-3.5 w-3.5 accent-accent"
                :checked="form.trusted_declared_scopes?.includes(ecosystem)"
                :disabled="!isOrgAdmin"
                @change="toggleTrusted(ecosystem, ($event.target as HTMLInputElement).checked)"
              >
              {{ ecosystem }}
            </label>
          </div>
        </div>

        <div class="flex items-center gap-3 py-3">
          <button
            type="button"
            class="rounded-md bg-accent px-3 py-1.5 text-sm font-medium text-white transition hover:bg-accent/80 disabled:cursor-not-allowed disabled:opacity-50"
            :disabled="!isOrgAdmin || !isDirty || saving"
            @click="save"
          >
            {{ saving ? 'Saving…' : 'Save' }}
          </button>
          <span
            v-if="saved"
            class="text-xs text-ok"
          >Saved</span>
          <span
            v-if="saveError"
            class="text-xs text-danger"
          >{{ saveError }}</span>
        </div>
      </div>
    </section>

    <!-- Organization not-shipped list (ADR-045 §6): inherited by every
         repository, shown with the built-in defaults a repository can cancel. -->
    <section>
      <div class="flex items-center justify-between border-b border-surface-border pb-2">
        <h2 class="text-base font-semibold text-white">
          Not shipped
        </h2>
        <span class="text-xs text-gray-500">{{ entries.length }} {{ entries.length === 1 ? 'entry' : 'entries' }}</span>
      </div>
      <p class="mt-3 text-sm text-gray-500">
        Components that never reach clients, for every repository: purl globs
        (<span class="font-mono">pkg:npm/@types/*</span>), regular expressions
        (<span class="font-mono">re:^pkg:npm/eslint</span>), whole ecosystems
        (<span class="font-mono">ecosystem:terraform</span>) or paths (<span class="font-mono">tools/**</span>).
        They stay listed with <span class="font-mono">shipped: no</span>; nothing is hidden. Built in:
        <span class="font-mono">{{ DEFAULT_PATTERNS.join(', ') }}</span>, which a repository cancels with
        <span class="font-mono">dependencies.shipped</span>.
      </p>
      <ul class="mt-3 divide-y divide-surface-border-subtle text-sm">
        <li
          v-for="entry in entries"
          :key="entry.id"
          class="flex flex-wrap items-center justify-between gap-2 py-2"
        >
          <span class="flex flex-wrap items-center gap-2">
            <span class="font-mono text-gray-200">{{ entry.pattern }}</span>
            <span class="text-xs text-gray-500">{{ entry.reason }}</span>
          </span>
          <button
            v-if="isOrgAdmin"
            type="button"
            class="text-xs text-gray-500 transition hover:text-danger"
            @click="removeEntry(entry.id)"
          >
            remove
          </button>
        </li>
        <li
          v-if="entries.length === 0"
          class="py-2 text-xs text-gray-500"
        >
          No organization entries yet.
        </li>
      </ul>
      <form
        v-if="isOrgAdmin"
        class="mt-3 flex flex-wrap items-center gap-2"
        @submit.prevent="addEntry"
      >
        <input
          v-model="newPattern"
          type="text"
          placeholder="pattern"
          class="h-8 min-w-[16rem] flex-1 rounded-md border border-surface-border bg-surface-overlay px-2 font-mono text-xs text-gray-200 focus:border-accent/50 focus:outline-none"
        >
        <input
          v-model="newReason"
          type="text"
          placeholder="reason"
          class="h-8 min-w-[10rem] rounded-md border border-surface-border bg-surface-overlay px-2 text-xs text-gray-200 focus:border-accent/50 focus:outline-none"
        >
        <button
          type="submit"
          class="rounded-md border border-surface-border px-3 py-1.5 text-xs text-gray-300 transition hover:border-accent/50 hover:text-white disabled:opacity-50"
          :disabled="!newPattern.trim() || !newReason.trim() || adding"
        >
          Add
        </button>
        <span
          v-if="entryError"
          class="text-xs text-danger"
        >{{ entryError }}</span>
      </form>
    </section>
  </div>
</template>

<script setup lang="ts">
import { computed, reactive, ref, watch } from 'vue'
import { useRoute } from 'vue-router'

import { api, type NotShippedEntry, type OrgSettings } from '@/api/client'
import { useOrgRole } from '@/composables/useOrgRole'

const TRUSTABLE_ECOSYSTEMS = ['maven', 'gradle', 'npm', 'pypi', 'cargo', 'go', 'nuget', 'rubygems']
const DEFAULT_PATTERNS = ['ecosystem:terraform', 'ecosystem:helm', 'ecosystem:githubactions', 'ecosystem:gitlabci', 'ecosystem:oci', 'ecosystem:ansible']

const route = useRoute()
const provider = computed(() => route.params.provider as string)
const slug = computed(() => route.params.slug as string)
const { isOrgAdmin } = useOrgRole()

const loading = ref(true)
const loadFailed = ref(false)
const saving = ref(false)
const saved = ref(false)
const saveError = ref('')
const persisted = ref<OrgSettings | null>(null)
const form = reactive<Partial<OrgSettings>>({
  dependency_cooldown_window: '',
  dependency_cooldown_enforcement: '',
  dependency_install_config: '',
  dependency_private_namespaces: [],
  trusted_declared_scopes: [],
})
const privateNamespacesText = ref('')

const isDirty = computed(() => {
  const current = persisted.value
  if (!current) return false
  return (current.dependency_cooldown_window ?? '') !== (form.dependency_cooldown_window ?? '')
    || (current.dependency_cooldown_enforcement ?? '') !== (form.dependency_cooldown_enforcement ?? '')
    || (current.dependency_install_config ?? '') !== (form.dependency_install_config ?? '')
    || (current.dependency_private_namespaces ?? []).join('\n') !== parsedNamespaces().join('\n')
    || (current.trusted_declared_scopes ?? []).join(',') !== (form.trusted_declared_scopes ?? []).join(',')
})

function parsedNamespaces(): string[] {
  return privateNamespacesText.value.split('\n').map((line) => line.trim()).filter(Boolean)
}

function toggleTrusted(ecosystem: string, checked: boolean) {
  const current = new Set(form.trusted_declared_scopes ?? [])
  if (checked) current.add(ecosystem)
  else current.delete(ecosystem)
  form.trusted_declared_scopes = Array.from(current)
}

const entries = ref<NotShippedEntry[]>([])
const newPattern = ref('')
const newReason = ref('')
const adding = ref(false)
const entryError = ref('')

async function load() {
  loading.value = true
  loadFailed.value = false
  try {
    const [settings, list] = await Promise.all([
      api.getOrgSettings(provider.value, slug.value),
      api.listOrgNotShipped(provider.value, slug.value),
    ])
    persisted.value = settings.data
    form.dependency_cooldown_window = settings.data.dependency_cooldown_window ?? ''
    form.dependency_cooldown_enforcement = settings.data.dependency_cooldown_enforcement ?? ''
    form.dependency_install_config = settings.data.dependency_install_config ?? ''
    form.trusted_declared_scopes = [...(settings.data.trusted_declared_scopes ?? [])]
    privateNamespacesText.value = (settings.data.dependency_private_namespaces ?? []).join('\n')
    entries.value = list.data ?? []
  } catch {
    loadFailed.value = true
  } finally {
    loading.value = false
  }
}

watch([provider, slug], () => { void load() }, { immediate: true })

async function save() {
  if (!persisted.value) return
  saving.value = true
  saved.value = false
  saveError.value = ''
  try {
    const body: OrgSettings = {
      ...persisted.value,
      dependency_cooldown_window: form.dependency_cooldown_window ?? '',
      dependency_cooldown_enforcement: form.dependency_cooldown_enforcement ?? '',
      dependency_install_config: form.dependency_install_config ?? '',
      dependency_private_namespaces: parsedNamespaces(),
      trusted_declared_scopes: form.trusted_declared_scopes ?? [],
    }
    const res = await api.updateOrgSettings(provider.value, slug.value, body)
    persisted.value = res.data
    saved.value = true
  } catch (error) {
    saveError.value = error instanceof Error ? error.message : 'Failed to save settings'
  } finally {
    saving.value = false
  }
}

async function addEntry() {
  adding.value = true
  entryError.value = ''
  try {
    await api.addOrgNotShippedEntries(provider.value, slug.value, [{ pattern: newPattern.value.trim(), reason: newReason.value.trim() }])
    newPattern.value = ''
    newReason.value = ''
    const list = await api.listOrgNotShipped(provider.value, slug.value)
    entries.value = list.data ?? []
  } catch (error) {
    entryError.value = error instanceof Error ? error.message : 'Could not add the entry'
  } finally {
    adding.value = false
  }
}

async function removeEntry(id: string) {
  entryError.value = ''
  try {
    await api.deleteOrgNotShippedEntry(provider.value, slug.value, id)
    entries.value = entries.value.filter((entry) => entry.id !== id)
  } catch (error) {
    entryError.value = error instanceof Error ? error.message : 'Could not remove the entry'
  }
}
</script>
