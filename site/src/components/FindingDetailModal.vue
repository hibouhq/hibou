<template>
  <!-- Centred dialog: a finding is the subject while it is open, so it takes
       the middle of the screen rather than a strip at the edge. -->
  <Teleport to="body">
    <div
      class="fixed inset-0 z-[70] flex items-start justify-center overflow-y-auto bg-black/70 px-4 py-6 backdrop-blur-sm sm:py-10"
      @click.self="emit('close')"
    >
      <div
        class="flex max-h-[88vh] w-full max-w-4xl flex-col overflow-hidden rounded-2xl border border-surface-border bg-surface-raised shadow-2xl"
        role="dialog"
        aria-modal="true"
        aria-label="Finding detail"
      >
        <div
          v-if="loading"
          class="px-6 py-16 text-center text-sm text-gray-500"
        >
          Loading finding…
        </div>
        <div
          v-else-if="error"
          class="px-6 py-16 text-center text-sm text-danger"
        >
          {{ error }}
        </div>

        <template v-else-if="detail?.finding">
          <!-- Header: identity, state, and the dates that frame everything below -->
          <header class="shrink-0 border-b border-surface-border-subtle px-6 pb-0 pt-4">
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

                <h2 class="mt-2 text-lg font-semibold leading-snug text-white">
                  {{ detail.finding.title }}
                </h2>

                <div class="mt-1 flex flex-wrap items-center gap-x-3 gap-y-1 text-xs text-gray-500">
                  <a
                    v-if="identifierUrl"
                    :href="identifierUrl"
                    target="_blank"
                    rel="noopener noreferrer"
                    class="font-mono text-accent underline decoration-accent/30 underline-offset-2 hover:decoration-accent"
                  >{{ identifier }}</a>
                  <span
                    v-else
                    class="font-mono text-accent"
                  >{{ identifier }}</span>
                  <!-- Every date says whose clock it is on. "First detected"
                       is ours — the first scan that matched a component — and
                       is easily read as "when the flaw appeared", which is a
                       different and usually much earlier date. -->
                  <span v-if="firstSeen">
                    first detected here <span
                      class="text-gray-400"
                      :title="`The first scan that matched this component — ${formatDateTime(firstSeen)}`"
                    >{{ formatDate(firstSeen) }}</span>
                  </span>
                  <span v-if="lastSeen">
                    last seen <span
                      class="text-gray-400"
                      :title="formatDateTime(lastSeen)"
                    >{{ relativeTime(lastSeen) }}</span>
                  </span>
                  <span
                    v-if="detectionLagDays"
                    class="text-warn"
                    :title="`Published upstream ${formatDate(advisoryPublished)}, first detected here ${formatDate(firstSeen)}`"
                  >
                    · {{ detectionLagDays }}d after publication
                  </span>
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

            <!-- Tabs: what to do about it first; the reference material behind it -->
            <nav class="mt-3 flex gap-4 text-sm">
              <button
                v-for="tabOption in tabs"
                :key="tabOption.key"
                type="button"
                class="flex items-center gap-1.5 border-b-2 pb-2 transition"
                :class="tab === tabOption.key ? 'border-accent text-white' : 'border-transparent text-gray-400 hover:text-gray-200'"
                @click="tab = tabOption.key"
              >
                {{ tabOption.label }}
                <span
                  v-if="tabOption.count"
                  class="rounded-full bg-surface-overlay px-1.5 text-[11px] text-gray-400"
                >{{ tabOption.count }}</span>
              </button>
            </nav>
          </header>

          <div class="min-h-0 flex-1 overflow-y-auto px-6 py-5">
            <!-- Overview: the finding and the decision it asks for -->
            <template v-if="tab === 'overview'">
              <component
                :is="detailsComponent"
                section="overview"
                :detail="detail"
                :provider="provider"
                :slug="slug"
                :repo-slug="repoSlug"
                :repo-html-url="repoHtmlUrl"
                :forge-provider="forgeProvider"
              />

              <div class="mt-5 space-y-5">
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
                        @click="emit('close')"
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

                <FindingSection
                  v-if="detail.finding.status === 'suppressed'"
                  title="Suppressed in source"
                  boxed
                >
                  <p class="text-sm text-gray-200">
                    The scanner excludes this finding: a suppression directive is in the code<template v-if="detail.finding.file_path">
                      at <span class="font-mono text-xs">{{ detail.finding.file_path }}<template v-if="detail.finding.start_line">:{{ detail.finding.start_line }}</template></span>
                    </template>.
                  </p>
                  <p
                    v-if="suppressionJustification"
                    class="mt-1 text-sm text-gray-300"
                  >
                    “{{ suppressionJustification }}”
                  </p>
                  <p class="mt-2 text-xs text-gray-500">
                    It cannot be reopened from here — remove the directive and rescan to reopen it. If the suppression is wrong, dispute it below: the finding then counts as open until the directive is removed or the dispute withdrawn.
                  </p>
                  <p
                    v-if="detail.dispute"
                    class="mt-2 rounded-lg border border-danger/40 bg-danger/10 px-3 py-2 text-sm text-danger"
                  >
                    Disputed — {{ detail.dispute.reason }}
                    <span
                      v-if="detail.dispute.created_at"
                      class="text-xs opacity-75"
                    > · {{ formatDate(detail.dispute.created_at) }}</span>
                  </p>
                </FindingSection>

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
              </div>
            </template>

            <!-- Details: the reference material — long descriptions, CVSS, VEX -->
            <template v-else-if="tab === 'details'">
              <component
                :is="detailsComponent"
                section="details"
                :detail="detail"
                :provider="provider"
                :slug="slug"
                :repo-slug="repoSlug"
                :repo-html-url="repoHtmlUrl"
                :forge-provider="forgeProvider"
              />

              <FindingSection
                v-if="detail.vex?.length"
                title="VEX"
                class="mt-5"
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
                class="mt-5 text-xs text-gray-600"
              >
                VEX not applicable — VEX describes third-party component exploitability; this is a first-party code finding.
              </p>
            </template>

            <!-- Occurrences: is this everywhere, or one branch? -->
            <template v-else-if="tab === 'occurrences'">
              <ul
                v-if="detail.occurrences.length > 0"
                class="divide-y divide-surface-border-subtle overflow-hidden rounded-xl border border-surface-border-subtle"
              >
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
                  <CommitLink
                    :sha="occurrence.commit_sha"
                    :repo-html-url="repoHtmlUrl"
                    :provider="forgeProvider"
                  />
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
              <p
                v-else
                class="py-8 text-center text-sm text-gray-500"
              >
                No ref currently reports this finding.
              </p>
            </template>

            <FindingTimeline
              v-else
              :provider="provider"
              :slug="slug"
              :repo-slug="repoSlug"
              :fingerprint="fingerprint"
              :repo-html-url="repoHtmlUrl"
              :forge-provider="forgeProvider"
            />
          </div>

          <!-- Actions: the same Accept ▾ / Reopen as the row — one implementation -->
          <footer class="shrink-0 border-t border-surface-border-subtle px-6 py-3">
            <div class="flex flex-wrap items-center gap-2">
              <!-- A scanner suppression has its own verbs (ADR-026): the code
                   owns the state, so triage offers dispute/withdraw, never
                   accept or reopen. -->
              <template v-if="detail.finding.status === 'suppressed'">
                <template v-if="detail.dispute">
                  <button
                    type="button"
                    class="rounded-lg border border-surface-border px-3 py-1.5 text-xs text-gray-300 transition hover:border-accent/50 hover:text-white"
                    :disabled="disputeBusy"
                    title="Accept the in-source suppression again: the finding stops counting against the gate"
                    @click="withdrawDispute"
                  >
                    Withdraw dispute
                  </button>
                </template>
                <template v-else-if="disputeFormOpen">
                  <input
                    v-model="disputeReason"
                    type="text"
                    class="w-64 rounded-lg border border-surface-border bg-surface-overlay px-3 py-1.5 text-xs text-gray-200 placeholder:text-gray-600 focus:border-accent/50 focus:outline-none"
                    placeholder="Why is this suppression wrong?"
                    @keyup.enter="submitDispute"
                    @keyup.esc="disputeFormOpen = false"
                  >
                  <button
                    type="button"
                    class="rounded-lg border border-danger/40 bg-danger/10 px-3 py-1.5 text-xs text-danger transition hover:bg-danger/20 disabled:opacity-50"
                    :disabled="disputeBusy || !disputeReason.trim()"
                    @click="submitDispute"
                  >
                    Dispute
                  </button>
                  <button
                    type="button"
                    class="px-2 py-1.5 text-xs text-gray-500 transition hover:text-gray-300"
                    @click="disputeFormOpen = false"
                  >
                    Cancel
                  </button>
                </template>
                <template v-else>
                  <button
                    type="button"
                    class="rounded-lg border border-surface-border px-3 py-1.5 text-xs text-gray-300 transition hover:border-danger/50 hover:text-danger"
                    title="Contest the in-source suppression: the finding counts as open until the directive is removed or the dispute withdrawn"
                    @click="disputeFormOpen = true"
                  >
                    Dispute suppression…
                  </button>
                </template>
                <span
                  v-if="disputeError"
                  class="text-xs text-danger"
                >{{ disputeError }}</span>
              </template>
              <template v-else-if="detail.acceptance">
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
              <span class="ml-auto hidden text-[11px] text-gray-600 sm:inline">j/k walks findings · esc closes</span>
            </div>
          </footer>
        </template>
      </div>
    </div>
  </Teleport>
</template>

<script setup lang="ts">
import { computed, inject, onMounted, onUnmounted, ref, watch, type Ref } from 'vue'

import { X } from 'lucide-vue-next'

import { api, type AcceptanceReasonKind, type FindingDetail, type FindingDispute, type Repository, type Vulnerability } from '@/api/client'
import CommitLink from '@/components/CommitLink.vue'
import FindingOriginBadge from '@/components/FindingOriginBadge.vue'
import CodeFindingDetails from '@/components/finding/CodeFindingDetails.vue'
import DependencyFindingDetails from '@/components/finding/DependencyFindingDetails.vue'
import FindingSection from '@/components/finding/FindingSection.vue'
import FindingTimeline from '@/components/finding/FindingTimeline.vue'
import GenericFindingDetails from '@/components/finding/GenericFindingDetails.vue'
import SecretFindingDetails from '@/components/finding/SecretFindingDetails.vue'
import { formatDateTime, relativeTime } from '@/lib/datetime'
import { advisoryUrl, findingShape, findingTypeBadgeClass, isComponentBacked, severityBadgeClass } from '@/lib/findingDisplay'
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
  // The finding travels with the event: the modal is deep-linkable, so the
  // list behind it may not hold this row, and a parent-side lookup would
  // silently drop the VEX option (or do nothing at all on revoke).
  accept: [kind: AcceptanceReasonKind, finding: Vulnerability]
  reopen: [fingerprint: string]
  revoke: [finding: Vulnerability]
  // ADR-026: the dispute is written by the modal itself (it owns the inline
  // reason form); the event lets the list behind it patch its row's badge.
  disputed: [fingerprint: string, dispute: FindingDispute | null]
  navigate: [delta: number]
}>()

// RepoDetailView provides the repository; the org-wide findings view does not,
// hence the prop fallback.
const injectedRepo = inject<Ref<Repository | null> | null>('repo', null)
const repoHtmlUrl = computed(() => props.repoHtmlUrl || injectedRepo?.value?.html_url || '')
const forgeProvider = computed(() => props.forgeProvider || injectedRepo?.value?.provider || props.provider)

type TabKey = 'overview' | 'details' | 'occurrences' | 'history'

const detail = ref<FindingDetail | null>(null)
const loading = ref(true)
const error = ref('')
const tab = ref<TabKey>('overview')

const state = computed(() => triageState(detail.value?.finding ?? { status: '' }, detail.value?.acceptance, new Date(), detail.value?.dispute))

// The in-source justification the scanner extracted (SARIF
// suppressions[].justification), carried on the finding's metadata by the
// ingest — e.g. the text after `#nosec G115 --`.
const suppressionJustification = computed(() => {
  const suppression = detail.value?.finding.metadata?.suppression
  if (!suppression || typeof suppression !== 'object') return ''
  const justification = (suppression as Record<string, unknown>).justification
  return typeof justification === 'string' ? justification.trim() : ''
})

const disputeFormOpen = ref(false)
const disputeReason = ref('')
const disputeBusy = ref(false)
const disputeError = ref('')

async function submitDispute() {
  const reason = disputeReason.value.trim()
  if (!reason || disputeBusy.value || !detail.value) return
  disputeBusy.value = true
  disputeError.value = ''
  try {
    const res = await api.setFindingDispute(props.provider, props.slug, props.repoSlug, detail.value.finding.id, reason)
    disputeFormOpen.value = false
    disputeReason.value = ''
    emit('disputed', props.fingerprint, res.data ?? { reason })
    await load()
  } catch (err) {
    disputeError.value = err instanceof Error ? err.message : 'Failed to dispute the suppression'
  } finally {
    disputeBusy.value = false
  }
}

async function withdrawDispute() {
  if (disputeBusy.value || !detail.value) return
  disputeBusy.value = true
  disputeError.value = ''
  try {
    await api.deleteFindingDispute(props.provider, props.slug, props.repoSlug, detail.value.finding.id)
    emit('disputed', props.fingerprint, null)
    await load()
  } catch (err) {
    disputeError.value = err instanceof Error ? err.message : 'Failed to withdraw the dispute'
  } finally {
    disputeBusy.value = false
  }
}
const componentBacked = computed(() => isComponentBacked(detail.value?.finding?.type))
const identifier = computed(() => detail.value?.finding.primary_identifier_value || detail.value?.finding.scanner_name || '')
const identifierUrl = computed(() => advisoryUrl(detail.value?.advisory?.canonical_id || identifier.value))
const firstSeen = computed(() => detail.value?.finding.first_seen_at || detail.value?.finding.detected_at || '')
const lastSeen = computed(() => detail.value?.finding.last_seen_at || '')
const advisoryPublished = computed(() => detail.value?.advisory?.published_at || '')

/**
 * How long the advisory was public before this instance matched it.
 *
 * Shown because the two dates beside each other invite the wrong reading:
 * "first detected" is our clock, not the world's, and the gap between them is
 * the number that actually says how exposed somebody was. Only rendered when
 * positive — a negative or zero gap means the advisory arrived after we were
 * already looking, which is unremarkable.
 */
const detectionLagDays = computed(() => {
  if (!firstSeen.value || !advisoryPublished.value) return 0
  const days = Math.floor(
    (new Date(firstSeen.value).getTime() - new Date(advisoryPublished.value).getTime()) / 86_400_000,
  )
  return days > 0 ? days : 0
})

// A tab that would open empty is not offered: secret and generic findings put
// everything on the overview, so only component- and code-shaped findings have
// reference material behind a Details tab (plus anything carrying VEX).
const hasDetails = computed(() => {
  const shape = findingShape(detail.value?.finding.type ?? '')
  return shape === 'component' || shape === 'code' || Boolean(detail.value?.vex?.length)
})

const tabs = computed(() => [
  { key: 'overview' as const, label: 'Overview', count: 0 },
  ...(hasDetails.value ? [{ key: 'details' as const, label: 'Details', count: 0 }] : []),
  { key: 'occurrences' as const, label: 'Detected on', count: detail.value?.occurrences.length ?? 0 },
  { key: 'history' as const, label: 'History', count: 0 },
])

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
  // Walking to the next finding should land on its overview, not on whichever
  // tab the previous one was left open at.
  tab.value = 'overview'
  void load()
}, { immediate: true })

function onKeydown(event: KeyboardEvent) {
  if (event.target instanceof HTMLInputElement || event.target instanceof HTMLTextAreaElement) return
  if (event.key === 'Escape') emit('close')
  if (event.key === 'j') emit('navigate', 1)
  if (event.key === 'k') emit('navigate', -1)
}

// The list behind the dialog must not scroll under it — with a centred dialog
// the stray scroll is very visible, and it loses the reader's place in the list.
onMounted(() => {
  document.addEventListener('keydown', onKeydown)
  document.body.style.overflow = 'hidden'
})
onUnmounted(() => {
  document.removeEventListener('keydown', onKeydown)
  document.body.style.overflow = ''
})

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
