<template>
  <!-- Side drawer: keeps the list context; ESC or backdrop closes. -->
  <div class="fixed inset-0 z-[70]">
    <div
      class="absolute inset-0 bg-black/60 backdrop-blur-[1px]"
      @click="emit('close')"
    />
    <aside
      class="absolute inset-y-0 right-0 flex w-full max-w-2xl flex-col border-l border-surface-border bg-surface-raised shadow-2xl"
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
        <!-- Header: identity, state, and the two dates that frame everything
             below it — when it appeared, when it was last seen. -->
        <header class="border-b border-surface-border-subtle px-6 pb-3 pt-4">
          <div class="flex items-start justify-between gap-3">
            <div class="min-w-0">
              <div class="flex flex-wrap items-center gap-1.5">
                <span :class="severityBadgeClass(detail.finding.severity)">{{ detail.finding.severity }}</span>
                <span :class="findingTypeBadgeClass(detail.finding.type)">{{ detail.finding.type }}</span>
                <span
                  class="inline-flex items-center rounded-full border px-2 py-0.5 text-[11px] font-medium"
                  :class="state.badgeClass"
                  :title="state.description"
                >{{ state.label }}</span>
                <span
                  v-if="detail.finding.reachability === 'not_reachable'"
                  class="rounded-full border border-surface-border bg-surface-overlay px-2 py-0.5 text-[11px] text-gray-500"
                  title="Call-graph analysis proved the vulnerable symbol is never called from this code"
                >unreachable</span>
                <span
                  v-else-if="detail.finding.reachability === 'reachable'"
                  class="rounded-full border border-danger/40 bg-danger/10 px-2 py-0.5 text-[11px] text-danger"
                  title="Call-graph analysis found the vulnerable symbol on this code's call path"
                >reachable</span>
                <FindingOriginBadge :finding="detail.finding" />
              </div>

              <h2 class="mt-2 text-base font-semibold leading-snug text-white">
                {{ detail.finding.title }}
              </h2>

              <div class="mt-1 flex flex-wrap items-center gap-x-3 gap-y-1 text-xs text-gray-500">
                <span class="font-mono text-accent">{{ identifier }}</span>
                <span v-if="firstSeen">
                  first detected <span
                    class="text-gray-400"
                    :title="formatDateTime(firstSeen)"
                  >{{ formatDate(firstSeen) }}</span>
                </span>
                <span v-if="lastSeen">
                  last seen <span
                    class="text-gray-400"
                    :title="formatDateTime(lastSeen)"
                  >{{ relativeTime(lastSeen) }}</span>
                </span>
                <span v-if="detail.occurrences.length > 0">on {{ detail.occurrences.length }} {{ detail.occurrences.length === 1 ? 'ref' : 'refs' }}</span>
              </div>
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

          <!-- Tabs: the evidence, then the story. -->
          <nav class="-mb-3 mt-3 flex gap-4 text-sm">
            <button
              v-for="tabOption in tabs"
              :key="tabOption.key"
              type="button"
              class="border-b-2 pb-2 transition"
              :class="tab === tabOption.key ? 'border-accent text-white' : 'border-transparent text-gray-400 hover:text-gray-200'"
              @click="tab = tabOption.key"
            >
              {{ tabOption.label }}
            </button>
          </nav>
        </header>

        <div class="flex-1 overflow-y-auto px-6 py-5">
          <template v-if="tab === 'details'">
            <!-- Kind-specific body: a CVE on a package and a rule hit in source
                 are different objects, and one generic renderer serves neither. -->
            <component
              :is="detailsComponent"
              :detail="detail"
              :provider="provider"
              :slug="slug"
              :repo-slug="repoSlug"
              :repo-html-url="repoHtmlUrl"
              :forge-provider="forgeProvider"
            />

            <div class="mt-5 space-y-5">
              <!-- Fix availability: open PRs that already resolve this -->
              <FindingSection
                v-if="detail.finding.fixed_in_prs?.length"
                title="Fix already in flight"
                boxed
                class="!border-ok/30 !bg-ok/5"
              >
                <ul class="space-y-1 text-sm text-gray-200">
                  <li
                    v-for="fix in detail.finding.fixed_in_prs"
                    :key="fix.ref_name"
                  >
                    <RouterLink
                      :to="{ name: 'repo-compare', params: { provider, slug, repoSlug }, query: { head: fix.ref_name } }"
                      class="underline decoration-ok/40 underline-offset-2 transition hover:decoration-ok"
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
              </FindingSection>

              <!-- Triage decision -->
              <FindingSection
                v-if="detail.acceptance"
                title="Decision"
                boxed
              >
                <p class="text-sm text-gray-200">
                  <span class="font-medium">{{ detail.acceptance.reason_kind === 'false_positive' ? 'False positive' : 'Risk accepted' }}</span>
                  <span v-if="detail.acceptance.reason"> — {{ detail.acceptance.reason }}</span>
                </p>
                <p class="mt-1 text-xs text-gray-500">
                  <template v-if="detail.acceptance.created_at">
                    decided {{ formatDate(detail.acceptance.created_at) }}
                  </template>
                  <template v-if="detail.acceptance.expires_at">
                    · expires {{ formatDate(detail.acceptance.expires_at) }}
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
              </FindingSection>

              <!-- VEX statements -->
              <FindingSection
                v-if="detail.vex?.length"
                title="VEX"
              >
                <ul class="space-y-2">
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
              </FindingSection>
              <p
                v-else-if="!componentBacked"
                class="text-xs text-gray-600"
              >
                VEX not applicable — VEX describes third-party component exploitability; this is a first-party code finding.
              </p>

              <!-- Occurrences across refs -->
              <FindingSection
                v-if="detail.occurrences.length > 0"
                title="Detected on"
              >
                <ul class="divide-y divide-surface-border-subtle rounded-xl border border-surface-border-subtle">
                  <li
                    v-for="occurrence in detail.occurrences"
                    :key="occurrence.ref_name"
                    class="flex items-center gap-3 px-3 py-2 text-xs"
                  >
                    <a
                      v-if="refUrl(occurrence.ref_name, occurrence.ref_type)"
                      :href="refUrl(occurrence.ref_name, occurrence.ref_type) ?? undefined"
                      target="_blank"
                      rel="noopener noreferrer"
                      class="min-w-0 flex-1 truncate font-mono text-gray-300 underline decoration-transparent underline-offset-2 transition hover:decoration-gray-500"
                    >{{ shortRef(occurrence.ref_name) }}</a>
                    <span
                      v-else
                      class="min-w-0 flex-1 truncate font-mono text-gray-300"
                    >{{ shortRef(occurrence.ref_name) }}</span>
                    <span
                      class="font-mono text-gray-500"
                      :title="occurrence.commit_sha"
                    >{{ occurrence.commit_sha.slice(0, 7) }}</span>
                    <span
                      class="text-gray-600"
                      :title="formatDateTime(occurrence.snapshot_at)"
                    >{{ relativeTime(occurrence.snapshot_at) }}</span>
                    <span
                      class="rounded-full px-2 py-0.5 text-[10px]"
                      :class="occurrence.status === 'resolved' ? 'bg-ok/10 text-ok' : occurrence.status === 'suppressed' ? 'bg-surface-overlay text-gray-500' : 'bg-amber-500/10 text-amber-300'"
                    >{{ occurrence.status }}</span>
                  </li>
                </ul>
              </FindingSection>
            </div>
          </template>

          <FindingTimeline
            v-else
            :provider="provider"
            :slug="slug"
            :repo-slug="repoSlug"
            :fingerprint="fingerprint"
          />
        </div>

        <!-- Actions: the same Accept ▾ / Reopen as the row — one implementation -->
        <footer class="border-t border-surface-border-subtle bg-surface-raised/95 px-6 py-3">
          <div class="flex flex-wrap items-center gap-2">
            <template v-if="detail.acceptance">
              <button
                type="button"
                class="rounded-lg border border-surface-border px-3 py-1.5 text-xs text-gray-300 transition hover:border-accent/50 hover:text-white"
                title="Remove the suppression: this counts against the gate again"
                @click="emit('reopen', fingerprint)"
              >
                Reopen
              </button>
            </template>
            <template v-else>
              <button
                type="button"
                class="rounded-l-lg border border-surface-border px-3 py-1.5 text-xs text-gray-300 transition hover:border-accent/50 hover:text-white"
                title="Real, but deliberately not fixing now. Requires a reason; suppressed from the gate."
                @click="emit('accept', 'risk_accepted', detail.finding)"
              >
                Accept risk…
              </button>
              <button
                type="button"
                class="-ml-2 rounded-r-lg border border-l-0 border-surface-border px-3 py-1.5 text-xs text-gray-300 transition hover:border-accent/50 hover:text-white"
                @click="emit('accept', 'false_positive', detail.finding)"
              >
                False positive…
              </button>
            </template>
            <button
              v-if="detail.finding.type === 'secret' && detail.finding.status !== 'resolved'"
              type="button"
              class="rounded-lg border border-amber-500/40 bg-amber-500/10 px-3 py-1.5 text-xs text-amber-200 transition hover:bg-amber-500/20"
              title="Attest that the credential was revoked and rotated — the only way a secret resolves"
              @click="emit('revoke', detail.finding)"
            >
              Mark revoked…
            </button>
            <span class="ml-auto text-[11px] text-gray-600">j/k walks findings · esc closes</span>
          </div>
        </footer>
      </template>
    </aside>
  </div>
</template>

<script setup lang="ts">
import { computed, inject, onMounted, onUnmounted, ref, watch, type Ref } from 'vue'

import { X } from 'lucide-vue-next'

import { api, type AcceptanceReasonKind, type FindingDetail, type Repository, type Vulnerability } from '@/api/client'
import FindingOriginBadge from '@/components/FindingOriginBadge.vue'
import CodeFindingDetails from '@/components/finding/CodeFindingDetails.vue'
import DependencyFindingDetails from '@/components/finding/DependencyFindingDetails.vue'
import FindingSection from '@/components/finding/FindingSection.vue'
import FindingTimeline from '@/components/finding/FindingTimeline.vue'
import GenericFindingDetails from '@/components/finding/GenericFindingDetails.vue'
import SecretFindingDetails from '@/components/finding/SecretFindingDetails.vue'
import { formatDateTime, relativeTime } from '@/lib/datetime'
import { findingShape, findingTypeBadgeClass, isComponentBacked, severityBadgeClass } from '@/lib/findingDisplay'
import { forgeRefUrl } from '@/lib/forgeLinks'
import { triageState } from '@/lib/triage'

const props = defineProps<{
  provider: string
  slug: string
  repoSlug: string
  fingerprint: string
  // Repository coordinates for forge deep links. Optional: the repo views get
  // them from the injected repository, the org-wide view passes them in.
  repoHtmlUrl?: string
  forgeProvider?: string
}>()

const emit = defineEmits<{
  close: []
  // The finding travels with the event: the drawer is deep-linkable, so the
  // list behind it may not hold this row, and a parent-side lookup would
  // silently drop the VEX option (or do nothing at all on revoke).
  accept: [kind: AcceptanceReasonKind, finding: Vulnerability]
  reopen: [fingerprint: string]
  revoke: [finding: Vulnerability]
  navigate: [delta: number]
}>()

// RepoDetailView provides the repository; the org-wide findings view does not,
// hence the prop fallback.
const injectedRepo = inject<Ref<Repository | null> | null>('repo', null)
const repoHtmlUrl = computed(() => props.repoHtmlUrl || injectedRepo?.value?.html_url || '')
const forgeProvider = computed(() => props.forgeProvider || injectedRepo?.value?.provider || props.provider)

const detail = ref<FindingDetail | null>(null)
const loading = ref(true)
const error = ref('')
const tab = ref<'details' | 'history'>('details')

const tabs = [
  { key: 'details', label: 'Details' },
  { key: 'history', label: 'History' },
] as const

const state = computed(() => triageState(detail.value?.finding ?? { status: '' }, detail.value?.acceptance))
const componentBacked = computed(() => isComponentBacked(detail.value?.finding?.type))
const identifier = computed(() => detail.value?.finding.primary_identifier_value || detail.value?.finding.scanner_name || '')
const firstSeen = computed(() => detail.value?.finding.first_seen_at || detail.value?.finding.detected_at || '')
const lastSeen = computed(() => detail.value?.finding.last_seen_at || '')

const detailsComponent = computed(() => {
  switch (findingShape(detail.value?.finding.type ?? '')) {
    case 'component': return DependencyFindingDetails
    case 'code': return CodeFindingDetails
    case 'secret': return SecretFindingDetails
    default: return GenericFindingDetails
  }
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

watch(() => props.fingerprint, () => {
  // Walking to the next finding should land on its evidence, not on whichever
  // tab the previous one was left open at.
  tab.value = 'details'
  void load()
}, { immediate: true })

function onKeydown(event: KeyboardEvent) {
  if (event.target instanceof HTMLInputElement || event.target instanceof HTMLTextAreaElement) return
  if (event.key === 'Escape') emit('close')
  if (event.key === 'j') emit('navigate', 1)
  if (event.key === 'k') emit('navigate', -1)
}

onMounted(() => document.addEventListener('keydown', onKeydown))
onUnmounted(() => document.removeEventListener('keydown', onKeydown))

function shortRef(refName: string): string {
  return refName.replace(/^refs\/(heads|tags)\//, '')
}

function refUrl(refName: string, refType: string): string | null {
  return forgeRefUrl(repoHtmlUrl.value, forgeProvider.value, refName, refType)
}

function formatDate(value?: string): string {
  if (!value) return ''
  return new Date(value).toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' })
}

// Expose reload so the parent can refresh after an accept/reopen.
defineExpose({ reload: load })
</script>
