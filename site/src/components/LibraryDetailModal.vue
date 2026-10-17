<template>
  <Teleport to="body">
    <div
      class="fixed inset-0 z-50 flex items-start justify-center overflow-y-auto bg-black/60 px-4 py-10 backdrop-blur-sm"
      @click.self="$emit('close')"
    >
      <div class="w-full max-w-3xl rounded-2xl border border-surface-border bg-surface-raised p-5 shadow-2xl">
        <!-- Header -->
        <div class="flex items-start justify-between gap-3">
          <div class="min-w-0">
            <h2 class="text-lg font-bold text-gray-100">
              {{ component.name }}
            </h2>
            <div class="mt-1 flex flex-wrap items-center gap-2">
              <span class="font-mono text-sm text-gray-400">{{ component.version }}</span>
              <span
                class="eco-badge"
                :class="`eco-${ecoKey}`"
              >{{ component.ecosystem || 'unknown' }}</span>
              <span
                v-for="source in sources"
                :key="source"
                class="source-badge"
                :class="`source-${sourceKeyFor(source)}`"
              >{{ source }}</span>
            </div>
            <div
              v-if="component.purl"
              class="mt-1.5 break-all font-mono text-[11px] leading-snug text-gray-500"
              :title="component.purl"
            >
              {{ component.purl }}
            </div>
            <!-- Shipped attribute (ADR-045 §6): a fact with its reason, and the
                 .hibou.yaml entry that would record it as not shipped. -->
            <div class="mt-2 flex flex-wrap items-center gap-2 text-xs">
              <span
                v-if="component.shipped === false"
                class="rounded-md border border-surface-border px-2 py-0.5 text-gray-400"
                :title="component.shipped_reason || 'Does not reach clients'"
              >not shipped · {{ component.shipped_reason || 'does not reach clients' }}</span>
              <span
                v-else-if="component.shipped_ignored"
                class="rounded-md border border-warn/40 px-2 py-0.5 text-warn"
                :title="`${component.shipped_ignored} matches, but an uploaded SBOM reports this component: the evidence says it ships`"
              >shipped · list entry ignored</span>
              <button
                v-if="canMarkNotShipped && component.shipped !== false"
                type="button"
                class="rounded-md border border-surface-border px-2 py-0.5 text-gray-300 transition hover:border-accent/50 hover:text-white"
                title="Copy the .hibou.yaml entry that records this package as not shipped; it stays listed with shipped: no"
                @click="emit('mark-not-shipped', component)"
              >
                Copy not-shipped entry
              </button>
            </div>
          </div>
          <button
            type="button"
            class="-mr-1 -mt-1 rounded-lg p-1 text-gray-500 transition hover:text-gray-200"
            title="Close"
            aria-label="Close"
            @click="$emit('close')"
          >
            <svg
              class="h-5 w-5"
              fill="none"
              viewBox="0 0 24 24"
              stroke="currentColor"
              stroke-width="2"
            >
              <path
                stroke-linecap="round"
                stroke-linejoin="round"
                d="M6 18L18 6M6 6l12 12"
              />
            </svg>
          </button>
        </div>

        <!-- Known vulnerabilities -->
        <div
          v-if="advisories.length > 0"
          class="mt-5"
        >
          <h3 class="mb-3 flex items-center gap-2 text-sm font-semibold uppercase tracking-wide text-gray-300">
            <span class="text-sev-high">⚠</span>
            Known Vulnerabilities
            <span class="vuln-count inline-flex min-w-[1.5rem] items-center justify-center rounded-full px-2 py-0.5 text-[11px] font-medium">{{ advisories.length }}</span>
          </h3>
          <!-- Fixed layout: long advisory ids, aliases and fix lists wrap
               inside their column instead of widening the table. -->
          <div class="max-h-[40vh] overflow-y-auto overflow-x-hidden rounded-xl border border-surface-border-subtle">
            <table class="w-full table-fixed divide-y divide-surface-border-subtle text-sm">
              <colgroup>
                <col class="w-[6.5rem]">
                <col class="w-14">
                <col class="w-40">
                <col class="w-24">
                <col>
                <col class="w-24">
              </colgroup>
              <thead class="bg-surface-overlay text-left text-xs uppercase tracking-[0.14em] text-gray-500">
                <tr>
                  <th class="px-3 py-2 font-medium">
                    Severity
                  </th>
                  <th class="px-3 py-2 text-center font-medium">
                    CVSS
                  </th>
                  <th class="px-3 py-2 font-medium">
                    Advisory
                  </th>
                  <th class="px-3 py-2 font-medium">
                    CWE
                  </th>
                  <th class="px-3 py-2 font-medium">
                    Summary
                  </th>
                  <th class="px-3 py-2 font-medium">
                    Fix
                  </th>
                </tr>
              </thead>
              <tbody class="divide-y divide-surface-border-subtle">
                <tr
                  v-for="advisory in advisories"
                  :key="advisory.id"
                  class="cursor-pointer transition hover:bg-white/5"
                  title="Open this finding in Vulnerabilities"
                  @click="emit('open-finding', { fingerprint: advisory.fingerprint, advisoryId: advisory.canonical_id })"
                >
                  <td class="px-3 py-2">
                    <span class="inline-flex items-center gap-1.5">
                      <MalwareIcon
                        v-if="advisory.is_malware"
                        size="sm"
                      />
                      <span
                        class="rounded-full px-2 py-0.5 text-xs font-medium"
                        :class="`sev-${sevKey(advisory.severity)}`"
                      >{{ advisory.severity }}</span>
                    </span>
                  </td>
                  <td class="px-3 py-2 text-center font-mono text-xs text-gray-300">
                    {{ advisory.cvss_score ?? '—' }}
                  </td>
                  <td class="px-3 py-2 text-xs">
                    <!-- The id opens the finding here; the upstream record is
                         one icon further, so a click never leaves the app by
                         accident. -->
                    <span class="inline-flex items-center gap-1">
                      <button
                        type="button"
                        class="break-all text-left font-mono text-accent hover:underline"
                        title="Open this finding in Vulnerabilities"
                        @click.stop="emit('open-finding', { fingerprint: advisory.fingerprint, advisoryId: advisory.canonical_id })"
                      >
                        {{ advisory.canonical_id }}
                      </button>
                      <a
                        v-if="advisoryUrl(advisory.canonical_id)"
                        :href="advisoryUrl(advisory.canonical_id)"
                        class="text-gray-500 transition hover:text-accent"
                        target="_blank"
                        rel="noopener"
                        :title="`Open ${advisory.canonical_id} upstream`"
                        :aria-label="`Open ${advisory.canonical_id} upstream`"
                        @click.stop
                      >
                        <ExternalLink class="h-3 w-3" />
                      </a>
                    </span>
                    <div
                      v-if="advisory.aliases?.length"
                      class="mt-1 flex flex-wrap gap-1"
                    >
                      <template
                        v-for="alias in advisory.aliases"
                        :key="alias"
                      >
                        <a
                          v-if="advisoryUrl(alias)"
                          :href="advisoryUrl(alias)"
                          target="_blank"
                          rel="noopener noreferrer"
                          class="max-w-full break-all rounded bg-surface-overlay px-1.5 py-0.5 font-mono text-[11px] text-accent hover:underline"
                          @click.stop
                        >{{ alias }}</a>
                        <span
                          v-else
                          class="max-w-full break-all rounded bg-surface-overlay px-1.5 py-0.5 font-mono text-[11px] text-gray-400"
                        >{{ alias }}</span>
                      </template>
                    </div>
                  </td>
                  <td class="px-3 py-2 text-xs">
                    <CweChips
                      v-if="advisory.cwes?.length"
                      :cwes="advisory.cwes"
                    />
                    <span
                      v-else
                      class="text-gray-600"
                    >—</span>
                  </td>
                  <td class="px-3 py-2 text-xs text-gray-400">
                    <span class="line-clamp-2">{{ advisory.summary || advisory.title || '—' }}</span>
                  </td>
                  <td class="px-3 py-2 font-mono text-xs">
                    <span
                      class="break-words"
                      :class="advisory.fixed_versions?.length ? 'text-ok' : 'text-gray-600'"
                    >
                      {{ advisory.fixed_versions?.join(', ') || '—' }}
                    </span>
                  </td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>

        <div
          v-else
          class="mt-5 py-6 text-center"
        >
          <p class="text-sm text-gray-500">
            No known vulnerabilities
          </p>
        </div>

        <!-- Where it comes from (ADR-045 §5): the files, the sources and what
             they say about the component. -->
        <div
          v-if="hasProvenance"
          class="mt-5"
        >
          <h3 class="mb-3 text-sm font-semibold uppercase tracking-wide text-gray-300">
            Where it comes from
          </h3>
          <dl class="grid grid-cols-[8rem_minmax(0,1fr)] gap-x-4 gap-y-2 rounded-xl border border-surface-border-subtle bg-surface-overlay px-3 py-2.5 text-xs">
            <template v-if="paths.length">
              <dt class="text-gray-500">
                {{ paths.length === 1 ? 'File' : 'Files' }}
              </dt>
              <dd class="flex flex-col gap-0.5">
                <span
                  v-for="file in paths"
                  :key="file"
                  class="break-all font-mono text-gray-200"
                >{{ file }}</span>
              </dd>
            </template>
            <template v-if="relationshipText">
              <dt class="text-gray-500">
                Relationship
              </dt>
              <dd class="text-gray-200">
                {{ relationshipText }}
              </dd>
            </template>
            <template v-if="resolutionText">
              <dt class="text-gray-500">
                Version
              </dt>
              <dd class="text-gray-200">
                {{ resolutionText }}
              </dd>
            </template>
            <template v-if="modules.length && !paths.length">
              <dt class="text-gray-500">
                {{ modules.length === 1 ? 'Module' : 'Modules' }}
              </dt>
              <dd class="break-all font-mono text-gray-200">
                {{ modules.map(moduleLabel).join(', ') }}
              </dd>
            </template>
            <template v-if="inventorySources.length">
              <dt class="text-gray-500">
                Reported by
              </dt>
              <dd class="break-all font-mono text-gray-200">
                {{ inventorySources.join(', ') }}
              </dd>
            </template>
            <template v-if="component.scopes?.length">
              <dt class="text-gray-500">
                Declared scope
              </dt>
              <dd class="text-gray-200">
                {{ component.scopes.join(', ') }}
              </dd>
            </template>
            <template v-if="component.registry === 'private'">
              <dt class="text-gray-500">
                Registry
              </dt>
              <dd class="text-gray-200">
                private (not the ecosystem's public registry)
              </dd>
            </template>
            <template v-if="component.layer !== undefined">
              <dt class="text-gray-500">
                Image layer
              </dt>
              <dd class="text-gray-200">
                {{ component.layer }}{{ component.base_image ? ' · base image' : '' }}
              </dd>
            </template>
          </dl>
        </div>

        <!-- Where is it used? -->
        <div
          v-if="usagePaths.length > 0"
          class="mt-5"
        >
          <h3 class="mb-3 flex items-center gap-2 text-sm font-semibold uppercase tracking-wide text-gray-300">
            Where is it used?
            <span class="text-[11px] font-normal normal-case tracking-normal text-gray-500">
              {{ usagePaths.length }} dependency {{ usagePaths.length === 1 ? 'chain' : 'chains' }}
            </span>
          </h3>
          <div class="flex flex-col gap-2">
            <div
              v-for="(path, pi) in usagePaths"
              :key="pi"
              class="flex flex-wrap items-center gap-1 rounded-lg border border-surface-border bg-surface-overlay px-2.5 py-1.5"
            >
              <template
                v-for="(seg, si) in path"
                :key="si"
              >
                <span
                  class="rounded px-1.5 py-0.5 font-mono text-[11px]"
                  :class="si === 0 ? 'text-[#bc8cff] font-semibold' : si === path.length - 1 ? 'bg-accent/10 text-accent font-semibold' : 'bg-surface text-gray-400'"
                >{{ seg }}</span>
                <span
                  v-if="si < path.length - 1"
                  class="text-gray-600"
                >›</span>
              </template>
            </div>
          </div>
        </div>
        <p
          v-else
          class="mt-5 text-center text-[11px] text-gray-600"
        >
          No dependency chain: the sources that reported this package record no dependency
          graph for it (an SBOM without relationships, or a manifest without a lockfile).
        </p>
      </div>
    </div>
  </Teleport>
</template>

<script setup lang="ts">
import { ExternalLink } from 'lucide-vue-next'
import { computed, onMounted, onUnmounted } from 'vue'

import type { ComponentWithVulns } from '@/api/client'
import CweChips from '@/components/finding/CweChips.vue'
import MalwareIcon from '@/components/finding/MalwareIcon.vue'
import { advisoryUrl } from '@/lib/findingDisplay'
import { ecosystemKey, sourceKey } from '@/lib/purl'

const props = defineProps<{
  component: ComponentWithVulns
  /** Offer the .hibou.yaml not-shipped entry for this component (ADR-045 §6). */
  canMarkNotShipped?: boolean
}>()

const emit = defineEmits<{
  (event: 'close'): void
  (event: 'mark-not-shipped', component: ComponentWithVulns): void
  /** A row was clicked: open that finding in the findings view. The
   * fingerprint lands on the exact finding; without one (older server) the
   * advisory id becomes the search. */
  (event: 'open-finding', target: { fingerprint?: string; advisoryId: string }): void
}>()

const ecoKey = computed(() => ecosystemKey(props.component.ecosystem))
// Malware advisories first: a malicious package outranks any CVE on it.
const advisories = computed(() => [...(props.component.advisories ?? [])].sort((a, b) => Number(b.is_malware) - Number(a.is_malware)))
const sources = computed(() => props.component.sources ?? [])
const usagePaths = computed(() => props.component.usage_paths ?? [])
const paths = computed(() => props.component.paths ?? [])
const modules = computed(() => props.component.modules ?? [])
const inventorySources = computed(() => props.component.inventory_sources ?? [])

const relationshipText = computed(() => {
  switch (props.component.relationship) {
    case 'direct': return 'direct: declared by the project'
    case 'indirect': return 'indirect: pulled in by another dependency'
    case 'unknown': return 'unknown: the source does not say'
    default: return ''
  }
})

const resolutionText = computed(() => {
  if (props.component.constraint) return `unresolved: only the range ${props.component.constraint} is declared`
  switch (props.component.resolution) {
    case 'recorded': return 'recorded in a lockfile'
    case 'declared': return 'pinned in a manifest'
    default: return ''
  }
})

const hasProvenance = computed(() => Boolean(
  paths.value.length || modules.value.length || inventorySources.value.length
    || relationshipText.value || resolutionText.value || props.component.layer !== undefined,
))

function moduleLabel(module: string): string {
  return module === '.' || module === '' ? '(repository root)' : module
}

function sourceKeyFor(source: string) {
  return sourceKey(source)
}

function sevKey(severity: string): string {
  const value = (severity || '').toLowerCase().replace(/[. ]/g, '')
  if (value === 'critical' || value === 'veryhigh') return 'critical'
  if (value === 'high') return 'high'
  if (value === 'medium' || value === 'moderate') return 'medium'
  if (value === 'unknown') return 'unknown'
  if (value === 'info' || value === 'informational' || value === 'none') return 'info'
  return 'low'
}


function onEsc(event: KeyboardEvent) {
  if (event.key === 'Escape') {
    emit('close')
  }
}

onMounted(() => document.addEventListener('keydown', onEsc))
onUnmounted(() => document.removeEventListener('keydown', onEsc))
</script>
