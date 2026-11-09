<template>
  <div class="pb-8">
    <div
      v-if="loading"
      class="py-8 text-sm text-gray-500"
    >
      Loading incident…
    </div>

    <template v-else>
      <div
        v-if="error"
        class="rounded-md border border-danger/30 bg-danger/10 px-4 py-3 text-sm text-red-200"
      >
        {{ error }}
      </div>

      <template v-if="detail">
        <!-- Header -->
        <div class="pt-1">
          <!-- The actions keep the top-right corner whatever the title's
               length: the title wraps, the buttons do not move. -->
          <div class="flex flex-wrap items-start justify-between gap-3 md:flex-nowrap">
            <h1 class="flex min-w-0 flex-1 flex-wrap items-center gap-x-2 gap-y-1 text-xl">
              <Siren class="h-5 w-5 shrink-0 text-gray-500" />
              <RouterLink
                :to="{ name: 'org-incidents', params: { provider, slug } }"
                class="text-accent transition hover:underline"
              >
                {{ slug }} / incidents
              </RouterLink>
              <span class="font-mono text-gray-400">#{{ incident!.number }}</span>
              <span class="font-semibold text-white">{{ incident!.title }}</span>
            </h1>
            <div class="flex shrink-0 items-center gap-1.5">
              <a
                :href="incidentsApi.dossierUrl(provider, slug, incident!.number)"
                :class="ui.secondary"
                class="inline-flex items-center gap-1.5"
                title="Timeline, scope, actions, clocks, deliveries and documents, with a SHA-256 manifest"
              >
                <Download class="h-3.5 w-3.5" />
                Dossier
              </a>
              <template v-if="detail.can_manage">
                <button
                  type="button"
                  :class="ui.secondary"
                  :disabled="busy"
                  title="Recompute scope, actions and clocks now"
                  @click="reconcile"
                >
                  Reconcile
                </button>
                <template v-if="incidentOpen(incident!.state)">
                  <button
                    v-if="!pendingMerge"
                    type="button"
                    :class="ui.secondary"
                    title="Fold this incident into a duplicate; cannot be undone"
                    @click="mergeOpen = true"
                  >
                    Merge into…
                  </button>
                  <button
                    type="button"
                    :class="ui.danger"
                    :disabled="busy"
                    @click="withdraw"
                  >
                    Withdraw
                  </button>
                </template>
              </template>
            </div>
          </div>

          <div class="mt-2 flex flex-wrap items-center gap-2">
            <IncidentStatusPill
              :status="incident!.state"
              :label="STATE_LABELS[incident!.state]"
            />
            <IncidentPriorityPill :priority="incident!.priority" />
            <span
              class="cursor-help text-sm text-gray-300"
              :title="KIND_DESCRIPTIONS[incident!.kind]"
            >{{ incident!.kind_label || KIND_LABELS[incident!.kind] }}</span>
            <span
              v-for="regime in incident!.regimes"
              :key="regime"
              class="rounded-full bg-surface-overlay px-2 py-0.5 font-mono text-[11px] text-gray-300"
              :title="regimeLabel(regime)"
            >{{ regime }}</span>
            <span
              v-if="refreshing"
              class="text-xs text-gray-500"
            >refreshing…</span>
          </div>

          <div class="mt-2 flex flex-wrap items-center gap-x-4 gap-y-1 text-sm text-gray-400">
            <span v-if="detail.advisory">
              <VulnerabilityRef
                :id="detail.advisory.canonical_id"
                :title="detail.advisory.title"
                :aliases="detail.advisory.aliases.filter(alias => alias !== detail!.advisory!.canonical_id)"
                :first-party="detail.advisory.first_party"
                :findings-link="findingsLink"
                :repo-label="incident!.repo_slug || 'the repository'"
              />
              <span
                v-if="otherAliases > 0"
                class="ml-1 text-xs text-gray-500"
              >+{{ otherAliases }} {{ otherAliases === 1 ? 'alias' : 'aliases' }}</span>
            </span>
            <span v-if="incident!.repo_slug">
              in
              <RouterLink
                :to="{ name: 'repo-overview', params: { provider, slug, repoSlug: incident!.repo_slug } }"
                class="text-accent transition hover:underline"
              >{{ incident!.repo_name || incident!.repo_slug }}</RouterLink>
            </span>
            <span>owner <span class="text-gray-200">{{ ownerLabel }}</span></span>
            <span :title="nullString(incident!.trigger_rule) ? `Rule: ${nullString(incident!.trigger_rule)}` : undefined">
              {{ signalSourceLabel(incident!.signal_source) }} signal <DateTime
                :value="incident!.signal_at"
                class="text-gray-200"
              />
            </span>
            <span title="T0: when the organization became aware; the clocks count from it">
              T0 <DateTime
                :value="nullTime(incident!.aware_at)"
                placeholder="not set"
                class="text-gray-200"
              />
            </span>
            <span
              class="inline-flex items-center gap-1"
              title="The incident's ticket or link; autolinked when it matches an autolink reference"
            >
              ref
              <form
                v-if="editingRef"
                class="inline-flex items-center gap-1"
                @submit.prevent="saveRef"
              >
                <input
                  ref="refInput"
                  v-model="refDraft"
                  type="text"
                  :class="[ui.input, 'h-6 w-40 px-1.5 text-xs']"
                  placeholder="SEC-7, a link, …"
                  maxlength="200"
                  @keydown.escape="editingRef = false"
                >
                <button
                  type="submit"
                  :class="ui.secondary"
                  :disabled="busy"
                >Save</button>
              </form>
              <template v-else>
                <AutolinkedText
                  v-if="incident!.external_ref"
                  :text="incident!.external_ref"
                  :provider="provider"
                  :slug="slug"
                  class="text-gray-200"
                />
                <span
                  v-else
                  class="text-gray-500"
                >none</span>
                <button
                  v-if="detail.can_manage"
                  type="button"
                  class="rounded p-0.5 text-gray-500 transition hover:bg-surface-overlay hover:text-gray-200"
                  title="Edit the reference"
                  @click="startEditRef"
                >
                  <Pencil class="h-3 w-3" />
                </button>
              </template>
            </span>
            <span v-if="nullTime(incident!.fix_available_at)">
              fix <DateTime
                :value="nullTime(incident!.fix_available_at)"
                class="text-gray-200"
              />
            </span>
            <span v-if="nullTime(incident!.closed_at)">
              closed <DateTime
                :value="nullTime(incident!.closed_at)"
                class="text-gray-200"
              />
            </span>
          </div>

          <div
            v-if="detail.tracker_links.length > 0"
            class="mt-1.5 flex flex-wrap items-center gap-3 text-sm"
          >
            <span
              v-for="link in detail.tracker_links"
              :key="link.integration_id"
              class="inline-flex items-center gap-1.5"
            >
              <ExternalLink class="h-3.5 w-3.5 text-gray-500" />
              <a
                v-if="isSafeUrl(link.external_url)"
                :href="link.external_url"
                target="_blank"
                rel="noreferrer"
                class="text-accent transition hover:underline"
              >{{ link.external_key || link.integration_name }}</a>
              <span v-else>{{ link.external_key || link.integration_name }}</span>
              <span class="text-xs text-gray-500">{{ link.integration_name }}</span>
              <span
                v-if="link.last_error"
                class="text-xs text-danger"
                :title="link.last_error"
              >mirror lagging</span>
            </span>
          </div>

          <IncidentMergeDialog
            v-if="mergeOpen"
            :provider="provider"
            :slug="slug"
            :incident="incident!"
            :own-subject="detail.advisory?.canonical_id"
            :four-eyes="detail.settings.four_eyes"
            @cancel="mergeOpen = false"
            @merged="onMerged"
            @proposed="onMergeProposed"
          />

          <!-- A merge waiting for a second person (four-eyes) -->
          <div
            v-if="pendingMerge"
            class="mt-3 flex flex-wrap items-center gap-3 rounded-lg border border-warn/40 bg-warn/5 px-3 py-2 text-sm"
          >
            <GitMerge class="h-4 w-4 shrink-0 text-warn" />
            <span class="min-w-0 flex-1 text-gray-200">
              {{ proposerName }} proposed merging this incident into
              <RouterLink
                :to="{ name: 'incident-detail', params: { provider, slug, number: String(pendingMerge.into_number) } }"
                class="text-accent hover:underline"
              >#{{ pendingMerge.into_number }}</RouterLink>,
              <DateTime :value="pendingMerge.proposed_at" />: {{ pendingMerge.reason }}
            </span>
            <template v-if="detail.can_manage">
              <button
                v-if="pendingMerge.proposed_by !== currentUserId"
                type="button"
                :class="ui.primary"
                :disabled="busy"
                title="Apply the merge; it cannot be undone"
                @click="approveMerge"
              >
                Approve merge
              </button>
              <button
                type="button"
                :class="ui.secondary"
                :disabled="busy"
                @click="cancelMerge"
              >
                {{ pendingMerge.proposed_by === currentUserId ? 'Cancel proposal' : 'Reject' }}
              </button>
            </template>
          </div>
          <p
            v-if="footerError"
            :class="[ui.error, 'mt-2']"
          >
            {{ footerError }}
          </p>

          <div class="mt-4">
            <IncidentClocks
              :deadlines="detail.deadlines"
              :regimes="detail.regimes"
              :aware-at="nullTime(incident!.aware_at)"
            />
            <p
              v-if="detail.deadlines.length === 0 && incidentOpen(incident!.state)"
              class="text-xs text-gray-500"
            >
              No clock running. Regulatory clocks start from T0, set by a reportable decision.
            </p>
          </div>
        </div>

        <!-- Tabs -->
        <nav
          class="mt-5 flex items-center gap-0.5 overflow-x-auto border-b border-surface-border"
          aria-label="Incident sections"
          role="tablist"
        >
          <button
            v-for="tab in tabs"
            :key="tab.id"
            type="button"
            role="tab"
            :aria-selected="activeTab === tab.id"
            class="flex shrink-0 items-center gap-1.5 whitespace-nowrap border-b-2 px-3 py-2 text-sm transition"
            :class="activeTab === tab.id
              ? 'border-accent font-semibold text-white'
              : 'border-transparent text-gray-400 hover:border-surface-border hover:text-gray-200'"
            @click="selectTab(tab.id)"
          >
            {{ tab.label }}
            <span
              v-if="tab.count !== null"
              class="inline-flex min-w-[1.25rem] items-center justify-center rounded-full px-1.5 text-[10px] leading-[18px]"
              :class="activeTab === tab.id ? 'bg-accent/15 text-accent' : 'bg-surface-overlay text-gray-500'"
              :title="tab.countTitle"
            >{{ tab.count }}</span>
          </button>
        </nav>

        <div class="mt-4 space-y-4">
          <template v-if="activeTab === 'overview'">
            <IncidentFlowGraph
              :detail="detail"
              :names="names"
            />

            <IncidentDecisionPanel
              :provider="provider"
              :slug="slug"
              :detail="detail"
              :current-user-id="currentUserId"
              :names="names"
              @changed="refresh"
            />

            <!-- Fix available -->
            <section
              v-if="canMarkFix"
              id="incident-fix"
              :class="ui.card"
            >
              <form
                class="flex flex-wrap items-end gap-3"
                @submit.prevent="markFixAvailable"
              >
                <div class="min-w-[12rem]">
                  <h2 :class="ui.heading">
                    Fix available
                  </h2>
                  <p class="mt-0.5 text-xs text-gray-500">
                    Starts the final report's 14-day clock.
                  </p>
                </div>
                <label :class="ui.label">
                  Since
                  <input
                    v-model="fixForm.at"
                    type="datetime-local"
                    :class="ui.input"
                  >
                </label>
                <label :class="[ui.label, 'min-w-[14rem] flex-1']">
                  Note
                  <input
                    v-model="fixForm.note"
                    type="text"
                    :class="ui.input"
                    placeholder="Release 4.2.2, workaround published, …"
                  >
                </label>
                <button
                  type="submit"
                  :class="ui.primary"
                  :disabled="busy"
                >
                  Mark fix available
                </button>
              </form>
              <p
                v-if="fixError"
                :class="[ui.error, 'mt-3']"
              >
                {{ fixError }}
              </p>
            </section>

            <IncidentActionsList
              :provider="provider"
              :slug="slug"
              :detail="detail"
              :current-user-id="currentUserId"
              :names="names"
              @changed="refresh"
              @notice="requestNotice"
            />
          </template>

          <IncidentScopeTable
            v-else-if="activeTab === 'scope'"
            :provider="provider"
            :slug="slug"
            :detail="detail"
            @changed="refresh"
          />

          <IncidentDeliveriesPanel
            v-else-if="activeTab === 'notices'"
            :provider="provider"
            :slug="slug"
            :detail="detail"
            :client-names="clientNames"
            :notice-request="noticeRequest"
            @changed="refresh"
          />

          <IncidentTimeline
            v-else-if="activeTab === 'timeline'"
            :provider="provider"
            :slug="slug"
            :number="incident!.number"
            :events="detail.events"
            :can-note="detail.can_manage"
            @changed="refresh"
          />
        </div>
      </template>

      <div
        v-else-if="!error"
        class="py-8 text-sm text-gray-500"
      >
        Incident not found.
      </div>
    </template>
  </div>
</template>

<script setup lang="ts">
import { Download, ExternalLink, GitMerge, Pencil, Siren } from 'lucide-vue-next'
import { computed, nextTick, reactive, ref, watch } from 'vue'
import { RouterLink, useRoute, useRouter } from 'vue-router'

import { api } from '@/api/client'
import {
  incidentOpen,
  incidentsApi,
  KIND_DESCRIPTIONS,
  KIND_LABELS,
  nullString,
  nullTime,
  nullUUID,
  pendingActions,
  STATE_LABELS,
  type IncidentDetail,
} from '@/api/incidents'
import DateTime from '@/components/DateTime.vue'
import AutolinkedText from '@/components/incidents/AutolinkedText.vue'
import IncidentActionsList from '@/components/incidents/IncidentActionsList.vue'
import IncidentClocks from '@/components/incidents/IncidentClocks.vue'
import IncidentDecisionPanel from '@/components/incidents/IncidentDecisionPanel.vue'
import IncidentFlowGraph from '@/components/incidents/IncidentFlowGraph.vue'
import IncidentMergeDialog from '@/components/incidents/IncidentMergeDialog.vue'
import IncidentDeliveriesPanel from '@/components/incidents/IncidentDeliveriesPanel.vue'
import IncidentPriorityPill from '@/components/incidents/IncidentPriorityPill.vue'
import IncidentScopeTable from '@/components/incidents/IncidentScopeTable.vue'
import IncidentStatusPill from '@/components/incidents/IncidentStatusPill.vue'
import IncidentTimeline from '@/components/incidents/IncidentTimeline.vue'
import { ui } from '@/components/incidents/ui'
import VulnerabilityRef from '@/components/incidents/VulnerabilityRef.vue'
import { useDialog } from '@/composables/useDialog'
import { errorText, fromLocalInput, signalSourceLabel, toLocalInput } from '@/lib/incidentView'
import { isSafeUrl } from '@/lib/safeUrl'
import { useAuthStore } from '@/stores/auth'

const route = useRoute()
const router = useRouter()
const auth = useAuthStore()
const { confirmDialog, promptDialog } = useDialog()

const detail = ref<IncidentDetail | null>(null)
const loading = ref(true)
const refreshing = ref(false)
const error = ref('')
const busy = ref(false)
const fixError = ref('')
const footerError = ref('')
const mergeOpen = ref(false)
const names = ref<Record<string, string>>({})
const teamNames = ref<Record<string, string>>({})
const orgClientNames = ref<Record<string, string>>({})
const noticeRequest = ref<{ clientId: string; seq: number } | null>(null)
const fixForm = reactive({ at: toLocalInput(new Date()), note: '' })

const provider = computed(() => route.params.provider as string)
const slug = computed(() => route.params.slug as string)
const number = computed(() => route.params.number as string)
const incident = computed(() => detail.value?.incident ?? null)
const currentUserId = computed(() => auth.user?.id ?? '')

type IncidentTab = 'overview' | 'scope' | 'notices' | 'timeline'
const TAB_IDS: IncidentTab[] = ['overview', 'scope', 'notices', 'timeline']

// The open tab lives in the URL, so a link can point at the timeline.
const activeTab = computed<IncidentTab>(() => {
  const value = route.query.tab
  return typeof value === 'string' && (TAB_IDS as string[]).includes(value) ? value as IncidentTab : 'overview'
})

const tabs = computed(() => {
  const current = detail.value
  const pending = current ? pendingActions(current.actions).length : 0
  const openScope = current ? current.scope.filter(row => row.status === 'pending' || row.status === 'unknown').length : 0
  return [
    { id: 'overview' as const, label: 'Overview', count: pending || null, countTitle: `${pending} pending ${pending === 1 ? 'action' : 'actions'}` },
    { id: 'scope' as const, label: 'Scope', count: current?.scope.length ?? null, countTitle: `${openScope} still open` },
    { id: 'notices' as const, label: 'Notices', count: current?.deliveries.length || null, countTitle: 'Deliveries' },
    { id: 'timeline' as const, label: 'Timeline', count: current?.events.length ?? null, countTitle: 'Events' },
  ]
})

function selectTab(id: IncidentTab) {
  void router.replace({ query: { ...route.query, tab: id === 'overview' ? undefined : id } })
}

const pendingMerge = computed(() => incident.value?.proposed_merge ?? null)
const proposerName = computed(() => {
  const id = pendingMerge.value?.proposed_by
  if (!id) return 'Someone'
  return id === currentUserId.value ? 'You' : names.value[id] ?? 'Someone'
})

const otherAliases = computed(() => (detail.value?.advisory?.aliases ?? []).filter(alias => alias !== detail.value?.advisory?.canonical_id).length)

// The findings this vulnerability raised in the incident's repository.
const findingsLink = computed(() => {
  const repoSlug = incident.value?.repo_slug
  const id = detail.value?.advisory?.canonical_id
  if (!repoSlug || !id) return null
  return { name: 'repo-vulnerabilities', params: { provider: provider.value, slug: slug.value, repoSlug }, query: { q: id } }
})

const canMarkFix = computed(() => {
  const current = incident.value
  return !!current && !!detail.value?.can_manage && current.kind === 'exploited_vulnerability'
    && incidentOpen(current.state) && !nullTime(current.fix_available_at)
})

const ownerLabel = computed(() => {
  const current = incident.value
  if (!current) return '—'
  const user = nullUUID(current.owner_id)
  if (user) return names.value[user] ?? user
  const team = nullUUID(current.owner_team_id)
  if (team) return `team ${teamNames.value[team] ?? team}`
  return 'unassigned'
})

const clientNames = computed(() => {
  const out = { ...orgClientNames.value }
  for (const row of detail.value?.scope ?? []) {
    for (const client of row.clients) out[client.id] = client.name
  }
  return out
})

watch(
  () => [provider.value, slug.value, number.value],
  () => {
    // Params clear before the view unmounts on navigation away.
    if (!provider.value || !slug.value || !number.value) return
    loading.value = true
    void load()
    void loadNames()
  },
  { immediate: true },
)

async function load() {
  error.value = ''
  try {
    const response = await incidentsApi.get(provider.value, slug.value, number.value)
    detail.value = response.data
  } catch (loadError) {
    detail.value = null
    error.value = errorText(loadError, 'Failed to load the incident')
  } finally {
    loading.value = false
  }
}

// Refreshes in place: panels keep their state (a "proposed" notice, an open form).
async function refresh() {
  refreshing.value = true
  try {
    const response = await incidentsApi.get(provider.value, slug.value, number.value)
    detail.value = response.data
  } catch (refreshError) {
    error.value = errorText(refreshError, 'Failed to refresh the incident')
  } finally {
    refreshing.value = false
  }
}

// Display names only; a failure leaves ids shown.
async function loadNames() {
  const [members, teams, clients] = await Promise.allSettled([
    api.listOrgMembers(provider.value, slug.value),
    api.listTeams(provider.value, slug.value),
    api.listClients(provider.value, slug.value, { per_page: 100 }),
  ])
  if (members.status === 'fulfilled') {
    names.value = Object.fromEntries(members.value.data.map(member => [member.user_id, member.user?.display_name || member.user?.email || member.user_id]))
  }
  if (teams.status === 'fulfilled') {
    teamNames.value = Object.fromEntries(teams.value.data.map(team => [team.id, team.name]))
  }
  if (clients.status === 'fulfilled') {
    orgClientNames.value = Object.fromEntries(clients.value.data.map(client => [client.id, client.name]))
  }
}

function regimeLabel(name: string) {
  return detail.value?.regimes.find(regime => regime.name === name)?.label ?? name
}

function requestNotice(clientId: string) {
  noticeRequest.value = { clientId, seq: (noticeRequest.value?.seq ?? 0) + 1 }
  selectTab('notices')
}

async function footerRun(task: () => Promise<unknown>, fallback: string) {
  busy.value = true
  footerError.value = ''
  try {
    await task()
    await refresh()
    return true
  } catch (taskError) {
    footerError.value = errorText(taskError, fallback)
    return false
  } finally {
    busy.value = false
  }
}

async function markFixAvailable() {
  if (!incident.value) return
  const current = incident.value
  busy.value = true
  fixError.value = ''
  try {
    await incidentsApi.fixAvailable(provider.value, slug.value, current.number, { at: fromLocalInput(fixForm.at), note: fixForm.note.trim() || undefined })
    fixForm.note = ''
    await refresh()
  } catch (fixAvailableError) {
    fixError.value = errorText(fixAvailableError, 'Failed to record the fix')
  } finally {
    busy.value = false
  }
}

// The incident's reference: edited in place, saved on Enter.
const editingRef = ref(false)
const refDraft = ref('')
const refInput = ref<HTMLInputElement | null>(null)

async function startEditRef() {
  refDraft.value = incident.value?.external_ref ?? ''
  editingRef.value = true
  await nextTick()
  refInput.value?.focus()
}

async function saveRef() {
  if (!incident.value) return
  busy.value = true
  footerError.value = ''
  try {
    await incidentsApi.update(provider.value, slug.value, incident.value.number, { external_ref: refDraft.value.trim() })
    editingRef.value = false
    await refresh()
  } catch (saveError) {
    footerError.value = errorText(saveError, 'Failed to save the reference')
  } finally {
    busy.value = false
  }
}

async function reconcile() {
  if (!incident.value) return
  const current = incident.value
  await footerRun(() => incidentsApi.reconcile(provider.value, slug.value, current.number), 'Failed to reconcile')
}

async function withdraw() {
  if (!incident.value) return
  const current = incident.value
  const reason = await promptDialog({
    title: `Withdraw incident #${current.number}`,
    message: 'Withdrawn is terminal and distinct from closed: wrong advisory, duplicate, opened in error.',
    confirmLabel: 'Withdraw',
    tone: 'danger',
    input: { label: 'Reason', required: true },
  })
  if (!reason?.trim()) return
  await footerRun(() => incidentsApi.withdraw(provider.value, slug.value, current.number, reason.trim()), 'Failed to withdraw')
}

function onMerged(into: number) {
  mergeOpen.value = false
  void router.push({ name: 'incident-detail', params: { provider: provider.value, slug: slug.value, number: String(into) } })
}

function onMergeProposed() {
  mergeOpen.value = false
  void refresh()
}

async function approveMerge() {
  if (!incident.value || !pendingMerge.value) return
  const current = incident.value
  const into = pendingMerge.value.into_number
  const confirmed = await confirmDialog({
    title: `Merge #${current.number} into #${into}`,
    message: 'Its timeline, notices and completed actions move to the surviving incident; its pending actions are dropped. A merge cannot be undone.',
    confirmLabel: 'Merge',
    tone: 'danger',
  })
  if (!confirmed) return
  busy.value = true
  footerError.value = ''
  try {
    const response = await incidentsApi.approveMerge(provider.value, slug.value, current.number)
    void router.push({ name: 'incident-detail', params: { provider: provider.value, slug: slug.value, number: String(response.data.merged_into) } })
  } catch (approveError) {
    footerError.value = errorText(approveError, 'Failed to approve the merge')
  } finally {
    busy.value = false
  }
}

async function cancelMerge() {
  if (!incident.value) return
  const current = incident.value
  await footerRun(() => incidentsApi.cancelMerge(provider.value, slug.value, current.number), 'Failed to cancel the merge')
}
</script>
