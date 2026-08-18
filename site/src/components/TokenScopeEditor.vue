<script setup lang="ts">
import { computed, ref, watch } from 'vue'

import type { Organization, Repository, TokenAccessLevel, TokenCapability, TokenScope } from '../api/client'
import { api } from '../api/client'
import { TOKEN_PRESETS } from '../lib/tokenPresets'

const props = defineProps<{ modelValue: TokenScope }>()
const emit = defineEmits<{ 'update:modelValue': [TokenScope] }>()

// Ordered so the read-mostly surfaces come first and `admin` — the one that can
// reshape the org — sits last, visually separated from the routine grants.
const CAPABILITIES: Array<{ key: TokenCapability; label: string; hint: string }> = [
  { key: 'coverage', label: 'Coverage', hint: 'Coverage, tests, and source-level coverage' },
  { key: 'vulnerabilities', label: 'Findings', hint: 'Read findings; write files new ones' },
  { key: 'triage', label: 'Triage', hint: 'Change the state of existing findings — accept, dismiss, VEX' },
  { key: 'components', label: 'Components', hint: 'SBOM, dependency graphs, clients' },
  { key: 'quality_gates', label: 'Quality gates', hint: 'Read gate results; write overrides one' },
  { key: 'secrets', label: 'Secrets', hint: 'Secret scan jobs and results' },
  { key: 'uploads', label: 'Uploads', hint: 'Submit scan artifacts and read upload status' },
  { key: 'admin', label: 'Admin', hint: 'Org settings, members, teams, integrations' },
]

const LEVELS: TokenAccessLevel[] = ['none', 'read', 'write']

// Presets live in lib/tokenPresets.ts, pinned by tests so the safe token stays
// the easy one to mint (ADR-020).
const PRESETS = TOKEN_PRESETS

const orgs = ref<Organization[]>([])
const repos = ref<Repository[]>([])
const loadingRepos = ref(false)
const repoError = ref('')
const repoFilter = ref('')

// A discovered (not yet enrolled) repo has no slug yet. Its first CI upload
// auto-enrolls it with slug = the repo name the CLI sends, and the upload
// scope check matches that same value pre-enrollment — so the name IS the
// slug this token must carry to cover the repo.
function repoScopeValue(repo: Repository) {
  return repo.slug || repo.name
}

// Selected repos always stay visible even when they don't match the filter,
// so a filter can never hide what the token is being granted.
const visibleRepos = computed(() => {
  const query = repoFilter.value.trim().toLowerCase()
  if (!query) return repos.value
  const selected = new Set(scope.value.repos.slugs ?? [])
  return repos.value.filter(
    (repo) =>
      repoScopeValue(repo).toLowerCase().includes(query) || selected.has(repoScopeValue(repo)),
  )
})

const scope = computed(() => props.modelValue)

function patch(next: Partial<TokenScope>) {
  emit('update:modelValue', { ...props.modelValue, ...next })
}

function levelFor(capability: TokenCapability): TokenAccessLevel {
  return scope.value.permissions[capability] ?? 'none'
}

function setLevel(capability: TokenCapability, level: TokenAccessLevel) {
  const permissions = { ...scope.value.permissions }
  if (level === 'none') {
    delete permissions[capability]
  } else {
    permissions[capability] = level
  }
  patch({ permissions })
}

function applyPreset(key: string) {
  const preset = PRESETS.find((candidate) => candidate.key === key)
  if (preset) patch({ permissions: { ...preset.permissions } })
}

function toggleRepo(slug: string) {
  const slugs = new Set(scope.value.repos.slugs ?? [])
  if (slugs.has(slug)) slugs.delete(slug)
  else slugs.add(slug)
  patch({ repos: { mode: 'list', slugs: [...slugs] } })
}

function setRepoMode(mode: 'all' | 'list') {
  patch({ repos: mode === 'all' ? { mode: 'all' } : { mode: 'list', slugs: scope.value.repos.slugs ?? [] } })
}

const grantedCount = computed(() => Object.values(scope.value.permissions).filter((level) => level && level !== 'none').length)
const isReadOnly = computed(() => !Object.values(scope.value.permissions).some((level) => level === 'write'))

async function loadOrgs() {
  try {
    const response = await api.listOrgs()
    orgs.value = response.data ?? []
    if (!scope.value.org && orgs.value.length === 1) patch({ org: orgs.value[0].slug })
  } catch {
    orgs.value = []
  }
}

async function loadRepos(org: Organization | undefined) {
  repos.value = []
  repoError.value = ''
  if (!org) return

  loadingRepos.value = true
  try {
    const response = await api.listRepos(org.provider, org.slug)
    repos.value = response.data ?? []
  } catch (error) {
    repoError.value = error instanceof Error ? error.message : 'Failed to load repositories'
  } finally {
    loadingRepos.value = false
  }
}

const selectedOrg = computed(() => orgs.value.find((org) => org.slug === scope.value.org))

// Changing org invalidates any repo allowlist built against the previous one.
watch(
  () => scope.value.org,
  (org, previous) => {
    if (previous !== undefined && org !== previous && scope.value.repos.mode === 'list') {
      patch({ repos: { mode: 'list', slugs: [] } })
    }
    void loadRepos(selectedOrg.value)
  },
)

void loadOrgs()
</script>

<template>
  <div class="space-y-6">
    <div>
      <div class="mb-2 flex items-baseline justify-between">
        <label
          for="token-org"
          class="text-sm font-medium text-gray-200"
        >Organization</label>
        <span class="text-xs text-gray-500">One org per token</span>
      </div>
      <select
        id="token-org"
        :value="scope.org"
        class="w-full rounded-lg border border-surface-border bg-surface-overlay px-3 py-2 text-sm text-gray-200"
        @change="patch({ org: ($event.target as HTMLSelectElement).value })"
      >
        <option value="">
          Select an organization…
        </option>
        <option
          v-for="org in orgs"
          :key="org.slug"
          :value="org.slug"
        >
          {{ org.display_name || org.name }}
        </option>
      </select>
    </div>

    <div>
      <div class="mb-2 text-sm font-medium text-gray-200">
        Repositories
      </div>
      <div class="flex gap-2">
        <button
          v-for="mode in (['all', 'list'] as const)"
          :key="mode"
          type="button"
          class="rounded-lg border px-3 py-1.5 text-sm transition"
          :class="scope.repos.mode === mode
            ? 'border-accent bg-accent-muted text-white'
            : 'border-surface-border bg-surface-overlay text-gray-300 hover:text-white'"
          @click="setRepoMode(mode)"
        >
          {{ mode === 'all' ? 'All repositories' : 'Selected repositories' }}
        </button>
      </div>

      <p
        v-if="scope.repos.mode === 'all'"
        class="mt-2 text-xs text-gray-500"
      >
        Includes repositories added later. Required for org-wide reads such as the dashboard and global search.
      </p>

      <div
        v-else
        class="mt-3"
      >
        <p
          v-if="!scope.org"
          class="text-xs text-gray-500"
        >
          Select an organization first.
        </p>
        <p
          v-else-if="loadingRepos"
          class="text-xs text-gray-500"
        >
          Loading repositories…
        </p>
        <p
          v-else-if="repoError"
          class="text-xs text-red-400"
        >
          {{ repoError }}
        </p>
        <p
          v-else-if="repos.length === 0"
          class="text-xs text-gray-500"
        >
          No repositories in this organization.
        </p>
        <div v-else>
          <input
            v-if="repos.length > 8"
            v-model="repoFilter"
            type="search"
            placeholder="Filter repositories…"
            class="mb-2 w-full rounded-lg border border-surface-border bg-surface-overlay px-3 py-1.5 text-sm text-gray-200 placeholder:text-gray-600"
          >
          <div class="max-h-48 space-y-1 overflow-y-auto rounded-lg border border-surface-border bg-surface-overlay p-2">
            <label
              v-for="repo in visibleRepos"
              :key="repo.full_name || repoScopeValue(repo)"
              class="flex cursor-pointer items-center gap-2 rounded px-2 py-1 text-sm text-gray-300 hover:bg-surface-raised"
            >
              <input
                type="checkbox"
                :checked="(scope.repos.slugs ?? []).includes(repoScopeValue(repo))"
                class="rounded border-surface-border"
                @change="toggleRepo(repoScopeValue(repo))"
              >
              <span class="font-mono text-xs">{{ repoScopeValue(repo) }}</span>
              <span
                v-if="!repo.enrolled"
                class="text-[10px] uppercase tracking-wide text-gray-500"
              >not enrolled</span>
            </label>
            <p
              v-if="visibleRepos.length === 0"
              class="px-2 py-1 text-xs text-gray-500"
            >
              No repositories match the filter.
            </p>
          </div>
        </div>
        <p
          v-if="scope.repos.mode === 'list' && (scope.repos.slugs ?? []).length === 0"
          class="mt-1.5 text-xs text-amber-400"
        >
          Select at least one repository, or switch to all repositories.
        </p>
      </div>
    </div>

    <div>
      <div class="mb-2 text-sm font-medium text-gray-200">
        Presets
      </div>
      <div class="flex flex-wrap gap-2">
        <button
          v-for="preset in PRESETS"
          :key="preset.key"
          type="button"
          :title="preset.hint"
          class="rounded-lg border border-surface-border bg-surface-overlay px-3 py-1.5 text-sm text-gray-300 transition hover:border-accent hover:text-white"
          @click="applyPreset(preset.key)"
        >
          {{ preset.label }}
        </button>
      </div>
    </div>

    <div>
      <div class="mb-2 flex items-baseline justify-between">
        <div class="text-sm font-medium text-gray-200">
          Permissions
        </div>
        <span
          v-if="grantedCount > 0"
          class="text-xs"
          :class="isReadOnly ? 'text-emerald-400' : 'text-amber-400'"
        >
          {{ grantedCount }} granted · {{ isReadOnly ? 'read-only' : 'can write' }}
        </span>
      </div>
      <div class="overflow-hidden rounded-lg border border-surface-border">
        <div
          v-for="capability in CAPABILITIES"
          :key="capability.key"
          class="flex items-center justify-between gap-4 border-b border-surface-border-subtle px-3 py-2.5 last:border-b-0"
          :class="capability.key === 'admin' ? 'bg-surface-overlay/60' : ''"
        >
          <div class="min-w-0">
            <div class="text-sm text-gray-200">
              {{ capability.label }}
            </div>
            <div class="truncate text-xs text-gray-500">
              {{ capability.hint }}
            </div>
          </div>
          <div class="flex shrink-0 gap-1">
            <button
              v-for="level in LEVELS"
              :key="level"
              type="button"
              class="rounded border px-2 py-1 text-xs transition"
              :class="levelFor(capability.key) === level
                ? 'border-accent bg-accent-muted text-white'
                : 'border-surface-border bg-surface-overlay text-gray-400 hover:text-white'"
              @click="setLevel(capability.key, level)"
            >
              {{ level }}
            </button>
          </div>
        </div>
      </div>
      <p
        v-if="grantedCount === 0"
        class="mt-1.5 text-xs text-amber-400"
      >
        Grant at least one permission — a token with none can do nothing.
      </p>
    </div>
  </div>
</template>
