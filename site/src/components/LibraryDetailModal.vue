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
          <div class="max-h-[40vh] overflow-auto rounded-xl border border-surface-border-subtle">
            <table class="min-w-full divide-y divide-surface-border-subtle text-sm">
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
                >
                  <td class="px-3 py-2">
                    <span
                      class="rounded-full px-2 py-0.5 text-xs font-medium"
                      :class="`sev-${sevKey(advisory.severity)}`"
                    >{{ advisory.severity }}</span>
                  </td>
                  <td class="px-3 py-2 text-center font-mono text-xs text-gray-300">
                    {{ advisory.cvss_score ?? '—' }}
                  </td>
                  <td class="px-3 py-2 text-xs">
                    <a
                      v-if="advisoryUrl(advisory.canonical_id)"
                      :href="advisoryUrl(advisory.canonical_id)"
                      class="font-mono text-accent hover:underline"
                      target="_blank"
                      rel="noopener"
                    >{{ advisory.canonical_id }}</a>
                    <span
                      v-else
                      class="font-mono text-gray-300"
                    >{{ advisory.canonical_id }}</span>
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
                          class="rounded bg-surface-overlay px-1.5 py-0.5 font-mono text-[11px] text-accent hover:underline"
                        >{{ alias }}</a>
                        <span
                          v-else
                          class="rounded bg-surface-overlay px-1.5 py-0.5 font-mono text-[11px] text-gray-400"
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
                  <td class="max-w-xs px-3 py-2 text-xs text-gray-400">
                    <span class="line-clamp-2">{{ advisory.summary || advisory.title || '—' }}</span>
                  </td>
                  <td class="px-3 py-2 font-mono text-xs">
                    <span :class="advisory.fixed_versions?.length ? 'text-ok' : 'text-gray-600'">
                      {{ advisory.fixed_versions?.join(', ') || '—' }}
                    </span>
                  </td>
                </tr>
              </tbody>
            </table>
          </div>
          <p
            v-if="!advisoriesEnriched"
            class="mt-2 text-[11px] text-gray-600"
          >
            CWE, summary and fix details appear once the backend exposes them — see
            <span class="font-mono">TODO-BACKEND-deps-nodata.md</span>.
          </p>
        </div>

        <div
          v-else
          class="mt-5 py-6 text-center"
        >
          <p class="text-sm text-gray-500">
            No known vulnerabilities
          </p>
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
          Dependency chains ("where is it used") appear once the backend exposes the SBOM
          dependency graph — see <span class="font-mono">TODO-BACKEND-deps-nodata.md</span>.
        </p>
      </div>
    </div>
  </Teleport>
</template>

<script setup lang="ts">
import { computed, onMounted, onUnmounted } from 'vue'

import type { ComponentWithVulns } from '@/api/client'
import CweChips from '@/components/finding/CweChips.vue'
import { advisoryUrl } from '@/lib/findingDisplay'
import { ecosystemKey, sourceKey } from '@/lib/purl'

const props = defineProps<{
  component: ComponentWithVulns
}>()

const emit = defineEmits<{
  (event: 'close'): void
}>()

const ecoKey = computed(() => ecosystemKey(props.component.ecosystem))
const advisories = computed(() => props.component.advisories ?? [])
const sources = computed(() => props.component.sources ?? [])
const usagePaths = computed(() => props.component.usage_paths ?? [])
const advisoriesEnriched = computed(() => advisories.value.some((advisory) => advisory.cwes?.length || advisory.summary || advisory.fixed_versions?.length))

function sourceKeyFor(source: string) {
  return sourceKey(source)
}

function sevKey(severity: string): string {
  const value = (severity || '').toLowerCase().replace(/[. ]/g, '')
  if (value === 'critical' || value === 'veryhigh') return 'critical'
  if (value === 'high') return 'high'
  if (value === 'medium' || value === 'moderate') return 'medium'
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
