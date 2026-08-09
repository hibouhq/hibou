<template>
  <!-- Side drawer: keeps the list context; ESC or backdrop closes. -->
  <div class="fixed inset-0 z-40">
    <div
      class="absolute inset-0 bg-black/50"
      @click="emit('close')"
    />
    <aside
      class="absolute inset-y-0 right-0 flex w-full max-w-xl flex-col overflow-y-auto border-l border-surface-border bg-surface-raised shadow-2xl"
      role="dialog"
      aria-label="Finding detail"
    >
      <div
        v-if="loading"
        class="px-6 py-10 text-sm text-gray-500"
      >
        Loading finding…
      </div>
      <div
        v-else-if="error"
        class="px-6 py-10 text-sm text-danger"
      >
        {{ error }}
      </div>
      <template v-else-if="detail?.finding">
        <!-- Header: identity + state in one glance -->
        <div class="sticky top-0 z-10 border-b border-surface-border-subtle bg-surface-raised/95 px-6 py-4 backdrop-blur">
          <div class="flex items-start justify-between gap-3">
            <div class="min-w-0">
              <div class="flex flex-wrap items-center gap-2">
                <span :class="severityBadgeClass(detail.finding.severity)">{{ detail.finding.severity }}</span>
                <span class="rounded-full bg-surface-overlay px-2 py-0.5 text-[11px] text-gray-400">{{ detail.finding.type }}</span>
                <span
                  v-if="detail.finding.reachability === 'not_reachable'"
                  class="rounded-full border border-surface-border bg-surface-overlay px-2 py-0.5 text-[11px] text-gray-500"
                  title="Call-graph analysis (govulncheck) proved the vulnerable symbol is never called from this code"
                >unreachable</span>
                <span
                  v-else-if="detail.finding.reachability === 'reachable'"
                  class="rounded-full border border-danger/40 bg-danger/10 px-2 py-0.5 text-[11px] text-danger"
                  title="Call-graph analysis found the vulnerable symbol on this code's call path"
                >reachable</span>
                <span
                  class="inline-flex items-center rounded-full border px-2 py-0.5 text-[11px] font-medium"
                  :class="state.badgeClass"
                  :title="state.description"
                >{{ state.label }}</span>
              </div>
              <h2 class="mt-2 truncate text-base font-semibold text-white">
                {{ detail.finding.title }}
              </h2>
              <p class="mt-0.5 font-mono text-xs text-accent">
                {{ detail.finding.primary_identifier_value || detail.finding.scanner_name }}
              </p>
            </div>
            <button
              type="button"
              class="shrink-0 rounded-lg border border-surface-border p-1.5 text-gray-400 transition hover:text-white"
              aria-label="Close"
              @click="emit('close')"
            >
              <X class="h-4 w-4" />
            </button>
          </div>
        </div>

        <div class="flex-1 space-y-5 px-6 py-5">
          <!-- Description -->
          <section v-if="detail.finding.description">
            <p class="whitespace-pre-wrap text-sm text-gray-300">
              {{ detail.finding.description }}
            </p>
          </section>

          <!-- Advisory (dependency findings) -->
          <section
            v-if="detail.advisory"
            class="rounded-xl border border-surface-border-subtle bg-surface-overlay/50 p-4"
          >
            <h3 class="text-xs uppercase tracking-[0.18em] text-gray-500">
              Advisory
            </h3>
            <p class="mt-2 font-mono text-sm text-white">
              {{ detail.advisory.canonical_id }}
            </p>
            <p
              v-if="detail.advisory.title"
              class="mt-1 text-sm text-gray-300"
            >
              {{ detail.advisory.title }}
            </p>
            <p
              v-if="detail.advisory.cvss_score"
              class="mt-1 text-xs text-gray-400"
            >
              CVSS {{ detail.advisory.cvss_score }}
              <span
                v-if="detail.advisory.cvss_vector"
                class="font-mono text-gray-500"
              > · {{ detail.advisory.cvss_vector }}</span>
            </p>
            <p
              v-if="detail.advisory.cwes?.length"
              class="mt-1 text-xs text-gray-500"
            >
              {{ detail.advisory.cwes.join(', ') }}
            </p>
            <p
              v-if="detail.finding.has_remediation"
              class="mt-2 text-xs text-emerald-300"
            >
              <a
                v-if="detail.finding.remediation_link"
                :href="detail.finding.remediation_link"
                target="_blank"
                rel="noopener noreferrer"
                class="underline"
              >Fix available</a>
              <template v-else>
                Fix available
              </template>
              <span v-if="detail.finding.solution"> — {{ detail.finding.solution }}</span>
            </p>
          </section>

          <!-- Location: kind-specific -->
          <section class="text-sm text-gray-300">
            <h3 class="text-xs uppercase tracking-[0.18em] text-gray-500">
              Location
            </h3>
            <p class="mt-2">
              <template v-if="detail.finding.component_name">
                <span class="font-mono">{{ detail.finding.component_name }}<template v-if="detail.finding.component_version">@{{ detail.finding.component_version }}</template></span>
                <span
                  v-if="detail.finding.ecosystem"
                  class="ml-2 text-xs text-gray-500"
                >{{ detail.finding.ecosystem }}</span>
              </template>
              <template v-else-if="detail.finding.file_path">
                <span class="font-mono">{{ detail.finding.file_path }}<template v-if="detail.finding.start_line">:{{ detail.finding.start_line }}</template></span>
              </template>
              <template v-else>
                <span class="text-gray-500">n/a</span>
              </template>
            </p>
            <p
              v-if="detail.finding.type === 'secret'"
              class="mt-1 text-xs text-amber-300"
            >
              A leaked credential stays open until revocation is attested — deleting the line does not fix it.
            </p>
          </section>

          <!-- Triage decision -->
          <section
            v-if="detail.acceptance"
            class="rounded-xl border border-surface-border-subtle bg-surface-overlay/50 p-4"
          >
            <h3 class="text-xs uppercase tracking-[0.18em] text-gray-500">
              Decision
            </h3>
            <p class="mt-2 text-sm text-gray-200">
              <span class="font-medium">{{ detail.acceptance.reason_kind === 'false_positive' ? 'False positive' : 'Risk accepted' }}</span>
              <span v-if="detail.acceptance.reason"> — {{ detail.acceptance.reason }}</span>
            </p>
            <p class="mt-1 text-xs text-gray-500">
              <template v-if="detail.acceptance.expires_at">
                expires {{ formatDate(detail.acceptance.expires_at) }} ·
              </template>
              <template v-if="detail.acceptance.created_at">
                decided {{ formatDate(detail.acceptance.created_at) }}
              </template>
            </p>
            <div
              v-if="detail.acceptance.labels?.length"
              class="mt-2 flex flex-wrap gap-1"
            >
              <span
                v-for="label in detail.acceptance.labels"
                :key="label"
                class="rounded-full bg-surface-overlay px-2 py-0.5 text-[11px] text-gray-400"
              >{{ label }}</span>
            </div>
          </section>

          <!-- VEX statements -->
          <section v-if="detail.vex?.length">
            <h3 class="text-xs uppercase tracking-[0.18em] text-gray-500">
              VEX
            </h3>
            <ul class="mt-2 space-y-2">
              <li
                v-for="(statement, index) in detail.vex"
                :key="index"
                class="rounded-lg border border-surface-border-subtle px-3 py-2 text-xs text-gray-300"
              >
                <span class="font-medium text-white">{{ statement.status }}</span>
                <span
                  v-if="statement.justification"
                  class="text-gray-400"
                > · {{ statement.justification }}</span>
                <span class="text-gray-500"> · {{ statement.source }}</span>
                <p
                  v-if="statement.statement"
                  class="mt-1 text-gray-400"
                >
                  {{ statement.statement }}
                </p>
              </li>
            </ul>
          </section>
          <p
            v-else-if="!componentBacked"
            class="text-xs text-gray-600"
          >
            VEX not applicable — VEX describes third-party component exploitability; this is a first-party code finding.
          </p>

          <!-- Fix availability: open PRs that already resolve this -->
          <section
            v-if="detail.finding.fixed_in_prs?.length"
            class="rounded-xl border border-emerald-500/30 bg-emerald-500/5 p-4"
          >
            <h3 class="text-xs uppercase tracking-[0.18em] text-emerald-300">
              Fix already in flight
            </h3>
            <ul class="mt-2 space-y-1 text-sm text-gray-200">
              <li
                v-for="fix in detail.finding.fixed_in_prs"
                :key="fix.ref_name"
              >
                <RouterLink
                  :to="{ name: 'repo-compare', params: { provider, slug, repoSlug }, query: { head: fix.ref_name } }"
                  class="underline decoration-emerald-500/40 underline-offset-2 transition hover:decoration-emerald-300"
                >
                  #{{ fix.number }}<template v-if="fix.title">
                    — {{ fix.title }}
                  </template>
                </RouterLink>
              </li>
            </ul>
            <p class="mt-2 text-xs text-gray-500">
              Merging it resolves this finding — usually better than accepting the risk.
            </p>
          </section>

          <!-- Occurrences across refs -->
          <section v-if="detail.occurrences.length > 0">
            <h3 class="text-xs uppercase tracking-[0.18em] text-gray-500">
              Detected on
            </h3>
            <ul class="mt-2 divide-y divide-surface-border-subtle rounded-xl border border-surface-border-subtle">
              <li
                v-for="occurrence in detail.occurrences"
                :key="occurrence.ref_name"
                class="flex items-center gap-3 px-3 py-2 text-xs"
              >
                <span class="min-w-0 flex-1 truncate font-mono text-gray-300">{{ occurrence.ref_name }}</span>
                <span class="font-mono text-gray-500">{{ occurrence.commit_sha.slice(0, 7) }}</span>
                <span
                  class="rounded-full px-2 py-0.5 text-[10px]"
                  :class="occurrence.status === 'resolved' ? 'bg-emerald-500/10 text-emerald-300' : occurrence.status === 'suppressed' ? 'bg-surface-overlay text-gray-500' : 'bg-amber-500/10 text-amber-300'"
                >{{ occurrence.status }}</span>
              </li>
            </ul>
          </section>
        </div>

        <!-- Actions: the same Accept ▾ / Reopen as the row — one implementation -->
        <div class="sticky bottom-0 border-t border-surface-border-subtle bg-surface-raised/95 px-6 py-3 backdrop-blur">
          <div class="flex items-center gap-2">
            <template v-if="detail.acceptance">
              <button
                type="button"
                class="rounded-lg border border-surface-border px-3 py-1.5 text-xs text-gray-300 transition hover:border-accent/50 hover:text-white"
                @click="emit('reopen', fingerprint)"
              >
                Reopen
              </button>
            </template>
            <template v-else>
              <button
                type="button"
                class="rounded-l-lg border border-surface-border px-3 py-1.5 text-xs text-gray-300 transition hover:border-accent/50 hover:text-white"
                @click="emit('accept', 'risk_accepted', fingerprint)"
              >
                Accept
              </button>
              <button
                type="button"
                class="-ml-2 rounded-r-lg border border-l-0 border-surface-border px-3 py-1.5 text-xs text-gray-300 transition hover:border-accent/50 hover:text-white"
                @click="emit('accept', 'false_positive', fingerprint)"
              >
                False positive…
              </button>
            </template>
            <span class="ml-auto text-[11px] text-gray-600">j/k to walk findings · esc closes</span>
          </div>
        </div>
      </template>
    </aside>
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref, watch } from 'vue'

import { X } from 'lucide-vue-next'

import { api, type AcceptanceReasonKind, type FindingDetail } from '@/api/client'
import { triageState } from '@/lib/triage'

const props = defineProps<{
  provider: string
  slug: string
  repoSlug: string
  fingerprint: string
}>()

const emit = defineEmits<{
  close: []
  accept: [kind: AcceptanceReasonKind, fingerprint: string]
  reopen: [fingerprint: string]
  navigate: [delta: number]
}>()

const detail = ref<FindingDetail | null>(null)
const loading = ref(true)
const error = ref('')

const state = computed(() => triageState(detail.value?.finding ?? { status: '' }, detail.value?.acceptance))
const componentBacked = computed(() => {
  const type = detail.value?.finding?.type
  return type === 'dependency' || type === 'container'
})

async function load() {
  loading.value = true
  error.value = ''
  try {
    const res = await api.getFindingDetail(props.provider, props.slug, props.repoSlug, props.fingerprint)
    detail.value = res.data
  } catch (err) {
    error.value = err instanceof Error ? err.message : 'Failed to load the finding'
  } finally {
    loading.value = false
  }
}

watch(() => props.fingerprint, load, { immediate: true })

function onKeydown(event: KeyboardEvent) {
  if (event.target instanceof HTMLInputElement || event.target instanceof HTMLTextAreaElement) return
  if (event.key === 'Escape') emit('close')
  if (event.key === 'j') emit('navigate', 1)
  if (event.key === 'k') emit('navigate', -1)
}

onMounted(() => document.addEventListener('keydown', onKeydown))
onUnmounted(() => document.removeEventListener('keydown', onKeydown))

function severityBadgeClass(severity: unknown): string {
  const base = 'rounded-full px-2 py-0.5 text-[11px] font-medium '
  switch (String(severity)) {
    case 'critical': return base + 'bg-danger/15 text-danger'
    case 'high': return base + 'bg-orange-500/15 text-orange-300'
    case 'medium': return base + 'bg-amber-500/15 text-amber-300'
    case 'low': return base + 'bg-sky-500/15 text-sky-300'
    default: return base + 'bg-surface-overlay text-gray-400'
  }
}

function formatDate(value?: string): string {
  if (!value) return ''
  return new Date(value).toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' })
}

// Expose reload so the parent can refresh after an accept/reopen.
defineExpose({ reload: load })
</script>
