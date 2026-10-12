<template>
  <div class="space-y-6">
    <div class="border-b border-surface-border pb-2">
      <h2 class="text-base font-semibold text-white">
        Scanner requirements
      </h2>
    </div>
    <p class="text-sm text-gray-500">
      Require an analysis capability for a language. Every repository with code in that language must run a scanner that provides it;
      a repository can add scanners but cannot drop a required one without an exception you approve. Blocking requirements fail the coverage check.
    </p>

    <p
      v-if="loadError"
      class="text-sm text-danger"
    >
      {{ loadError }}
    </p>

    <section
      v-if="bundle"
      class="rounded-lg border px-4 py-3 text-sm"
      :class="bundle.stale ? 'border-warning/50 bg-warning/5' : 'border-surface-border'"
    >
      <div class="text-gray-100">
        Offline scanner bundle
        <template v-if="catalog?.bundle?.created_at">
          · exported {{ relativeTime(catalog.bundle.created_at) }}
        </template>
        <template v-if="catalog?.bundle?.catalog_revision">
          · catalog {{ catalog.bundle.catalog_revision }}
        </template>
      </div>
      <p class="mt-0.5 text-xs text-gray-500">
        Scanners run from this bundle, so its age is the age of what they check.
        {{ bundle.maxDays ? `Your strictest requirement allows ${bundle.maxDays} days.` : 'No requirement sets a freshness limit.' }}
      </p>
      <ul
        v-if="bundle.problems.length"
        class="mt-1 list-disc pl-5 text-xs text-warning"
      >
        <li
          v-for="problem in bundle.problems"
          :key="problem"
        >
          {{ problem }}
        </li>
      </ul>
    </section>

    <section>
      <ul
        v-if="requirements.length"
        class="divide-y divide-surface-border-subtle rounded-lg border border-surface-border"
      >
        <li
          v-for="requirement in requirements"
          :key="requirement.id"
          class="flex items-center gap-3 px-4 py-3 text-sm"
        >
          <div class="min-w-0 flex-1">
            <div class="text-gray-100">
              {{ requirement.language }} · {{ requirement.capability }}
              <span
                class="ml-1 rounded-full px-1.5 text-[10px]"
                :class="requirement.enforcement === 'blocking' ? 'bg-danger/15 text-danger' : 'bg-surface-overlay text-gray-400'"
              >{{ requirement.enforcement }}</span>
            </div>
            <div class="mt-0.5 text-xs text-gray-500">
              {{ requirement.scanner_ids.length ? `Only ${requirement.scanner_ids.join(', ')}` : 'Any catalog scanner with the capability' }}
              <template v-if="requirement.freshness_days">
                · at most {{ requirement.freshness_days }} days old
              </template>
            </div>
          </div>
          <button
            v-if="isOrgAdmin"
            type="button"
            class="text-xs text-gray-400 hover:text-danger"
            @click="remove(requirement)"
          >
            Remove
          </button>
        </li>
      </ul>
      <p
        v-else
        class="text-sm text-gray-500"
      >
        No requirement: every repository runs what applies to it by default.
      </p>
    </section>

    <section
      v-if="isOrgAdmin"
      class="rounded-lg border border-surface-border p-4"
    >
      <h3 class="text-sm font-medium text-gray-100">
        Add a requirement
      </h3>
      <div class="mt-3 flex flex-wrap items-end gap-3 text-xs">
        <label class="flex flex-col gap-1 text-gray-400">
          Capability
          <select
            v-model="draftPair"
            class="rounded-md border border-surface-border bg-surface-overlay px-2 py-1.5 text-gray-200"
          >
            <option
              v-for="pair in capabilityPairs"
              :key="pair.key"
              :value="pair.key"
            >
              {{ pair.label }}
            </option>
          </select>
        </label>
        <label class="flex flex-col gap-1 text-gray-400">
          Enforcement
          <select
            v-model="draftEnforcement"
            class="rounded-md border border-surface-border bg-surface-overlay px-2 py-1.5 text-gray-200"
          >
            <option value="advisory">
              Advisory (warn)
            </option>
            <option value="blocking">
              Blocking (fail the check)
            </option>
          </select>
        </label>
        <label class="flex flex-col gap-1 text-gray-400">
          Max age (days, 0 = none)
          <input
            v-model.number="draftFreshness"
            type="number"
            min="0"
            class="w-24 rounded-md border border-surface-border bg-surface-overlay px-2 py-1.5 text-gray-200"
          >
        </label>
        <button
          type="button"
          class="rounded-md border border-surface-border bg-surface-overlay px-3 py-1.5 text-gray-200 hover:border-accent/50 disabled:opacity-50"
          :disabled="!draftPair || saving"
          @click="add"
        >
          Add
        </button>
      </div>
    </section>

    <section v-if="pending.length">
      <h3 class="text-xs font-semibold uppercase tracking-wide text-gray-500">
        Exception requests
      </h3>
      <ul class="mt-2 divide-y divide-surface-border-subtle rounded-lg border border-surface-border">
        <li
          v-for="exception in pending"
          :key="exception.id"
          class="flex flex-wrap items-center gap-3 px-4 py-3 text-xs"
        >
          <div class="min-w-0 flex-1">
            <div class="text-sm text-gray-100">
              {{ exception.repo_slug }} · {{ requirementLabel(exception.requirement_id) }}
            </div>
            <div class="mt-0.5 text-gray-500">
              “{{ exception.reason }}” · would expire {{ relativeTime(exception.expires_at) }}
            </div>
          </div>
          <template v-if="isOrgAdmin">
            <button
              type="button"
              class="rounded-md border border-surface-border px-2 py-1 text-emerald-300 hover:border-emerald-500/50"
              @click="decide(exception, true)"
            >
              Approve
            </button>
            <button
              type="button"
              class="rounded-md border border-surface-border px-2 py-1 text-gray-300 hover:border-danger/50 hover:text-danger"
              @click="decide(exception, false)"
            >
              Reject
            </button>
          </template>
        </li>
      </ul>
    </section>
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { useRoute } from 'vue-router'

import { api, type CoverageException, type ScannerCatalog, type ScannerRequirement } from '@/api/client'
import { useOrgRole } from '@/composables/useOrgRole'
import { relativeTime } from '@/lib/datetime'
import { bundleFreshness } from '@/lib/scanCoverage'

const route = useRoute()
const provider = route.params.provider as string
const slug = route.params.slug as string
const { isOrgAdmin } = useOrgRole()

const requirements = ref<ScannerRequirement[]>([])
const pending = ref<CoverageException[]>([])
const catalog = ref<ScannerCatalog | null>(null)
const loadError = ref('')
const saving = ref(false)
const draftPair = ref('')
const draftEnforcement = ref<'advisory' | 'blocking'>('advisory')
const draftFreshness = ref(0)

const bundle = computed(() => catalog.value?.bundle
  ? bundleFreshness(catalog.value.bundle, requirements.value.map(requirement => requirement.freshness_days))
  : null)

// Every language × capability pair some catalog scanner provides, marking
// whether hibou measured it or the engine only declares it.
const capabilityPairs = computed(() => {
  const pairs = new Map<string, { key: string; label: string; measured: boolean }>()
  for (const scanner of catalog.value?.scanners ?? []) {
    for (const capability of scanner.capabilities) {
      const key = `${capability.language}|${capability.capability}`
      const measured = capability.evidence.startsWith('measured:')
      const existing = pairs.get(key)
      if (!existing || (measured && !existing.measured)) {
        pairs.set(key, { key, label: `${capability.language} · ${capability.capability}${measured ? '' : ' (declared)'}`, measured })
      }
    }
  }
  return [...pairs.values()].sort((a, b) => a.label.localeCompare(b.label))
})

function requirementLabel(id: string) {
  const requirement = requirements.value.find(candidate => candidate.id === id)
  return requirement ? `${requirement.language} · ${requirement.capability}` : 'requirement'
}

async function load() {
  try {
    const [policy, scanners] = await Promise.all([api.getScannerRequirements(provider, slug), api.getScannerCatalog()])
    requirements.value = policy.data?.requirements ?? []
    pending.value = policy.data?.pending_exceptions ?? []
    catalog.value = scanners.data ?? null
  } catch (err) {
    loadError.value = err instanceof Error ? err.message : 'Could not load scanner requirements'
  }
}

async function add() {
  const [language, capability] = draftPair.value.split('|')
  if (!language || !capability) return
  saving.value = true
  try {
    await api.setScannerRequirement(provider, slug, { language, capability, scanner_ids: [], freshness_days: draftFreshness.value, enforcement: draftEnforcement.value })
    draftPair.value = ''
    await load()
  } catch (err) {
    loadError.value = err instanceof Error ? err.message : 'Could not save the requirement'
  } finally {
    saving.value = false
  }
}

async function remove(requirement: ScannerRequirement) {
  try {
    await api.deleteScannerRequirement(provider, slug, requirement.id)
    await load()
  } catch (err) {
    loadError.value = err instanceof Error ? err.message : 'Could not remove the requirement'
  }
}

async function decide(exception: CoverageException, approve: boolean) {
  try {
    await api.decideCoverageException(provider, slug, exception.id, approve)
    await load()
  } catch (err) {
    loadError.value = err instanceof Error ? err.message : 'Could not record the decision'
  }
}

onMounted(load)
</script>
