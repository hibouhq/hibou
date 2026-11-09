<template>
  <div class="space-y-6">
    <!-- Product identity -->
    <section>
      <div class="flex flex-wrap items-center justify-between gap-2 border-b border-surface-border pb-2">
        <h2 class="text-base font-semibold text-white">
          Product identity
        </h2>
        <code class="rounded bg-surface-overlay px-1.5 py-0.5 font-mono text-xs text-gray-400">.hibou.yaml · product</code>
      </div>
      <p class="mt-2 text-sm text-gray-400">
        How this repository's product is named in VEX statements, CSAF advisories and client notices.
        The purl is the primary key; the CPE is the alias NVD and clients' scanners use once a CVE is assigned.
        Set them under <code class="rounded bg-surface-overlay px-1 py-0.5 font-mono text-xs">product:</code> in
        <code class="rounded bg-surface-overlay px-1 py-0.5 font-mono text-xs">.hibou.yaml</code>; without it hibou derives a generic purl from the organization and repository.
      </p>

      <div
        v-if="rulesLoading"
        class="mt-4 text-sm text-gray-500"
      >
        Loading…
      </div>
      <div
        v-else-if="rulesError"
        class="mt-4 rounded-md border border-surface-border bg-surface-overlay/40 px-4 py-3 text-sm text-gray-400"
      >
        {{ rulesError }}
      </div>
      <template v-else-if="rules">
        <dl class="mt-4 divide-y divide-surface-border-subtle overflow-hidden rounded-md border border-surface-border text-sm">
          <div
            v-for="row in productRows"
            :key="row.label"
            class="flex items-start justify-between gap-4 px-3 py-2"
          >
            <dt class="text-gray-400">
              {{ row.label }}
            </dt>
            <dd
              class="break-all text-right font-mono text-xs"
              :class="row.value ? 'text-gray-200' : 'text-gray-600'"
            >
              {{ row.value || 'not set' }}
            </dd>
          </div>
        </dl>
        <div class="relative mt-3">
          <pre class="overflow-x-auto rounded-md border border-surface-border bg-surface-overlay/40 px-3 py-2 font-mono text-xs leading-relaxed text-gray-300">{{ productSnippet }}</pre>
          <button
            type="button"
            class="absolute right-2 top-2 inline-flex items-center gap-1 rounded border border-surface-border bg-surface-overlay px-2 py-0.5 text-[11px] text-gray-400 transition hover:text-white"
            @click="copy(productSnippet)"
          >
            <Copy class="h-3 w-3" />
            Copy
          </button>
        </div>
      </template>
    </section>

    <!-- Incident rules -->
    <section>
      <div class="flex flex-wrap items-center justify-between gap-2 border-b border-surface-border pb-2">
        <h2 class="text-base font-semibold text-white">
          Incident rules
        </h2>
        <span
          v-if="rules?.owner"
          class="text-xs text-gray-500"
        >
          Owner <span class="font-mono text-gray-300">{{ rules.owner }}</span>
        </span>
      </div>
      <p class="mt-2 text-sm text-gray-400">
        Which findings open an incident, of which kind, with which obligations. The first matching rule wins.
        Rules come from <code class="rounded bg-surface-overlay px-1 py-0.5 font-mono text-xs">incidents:</code> in
        <code class="rounded bg-surface-overlay px-1 py-0.5 font-mono text-xs">.hibou.yaml</code> and from the organization's
        <RouterLink
          :to="{ name: 'org-settings-incidents', params: { provider, slug } }"
          class="text-accent hover:underline"
        >
          incident settings
        </RouterLink>; rules the organization locks apply whatever the file says.
      </p>

      <div
        v-if="rules && rules.rules.length === 0"
        class="mt-4 rounded-md border border-dashed border-surface-border px-4 py-3 text-xs text-gray-500"
      >
        No rule applies: findings of this repository never open an incident on their own.
      </div>
      <div
        v-else-if="rules"
        class="mt-4 overflow-hidden rounded-md border border-surface-border"
      >
        <div
          v-for="(rule, index) in rules.rules"
          :key="index"
          class="flex flex-wrap items-baseline gap-x-3 gap-y-1 border-b border-surface-border/50 px-3 py-2 text-xs last:border-0"
        >
          <span class="w-5 shrink-0 text-gray-600">{{ index + 1 }}</span>
          <code class="font-mono text-gray-200">{{ rule.match }}</code>
          <span class="text-gray-400">{{ rule.kind ? KIND_LABELS[rule.kind] : 'kind from match' }}</span>
          <span class="text-gray-500">refs {{ rule.refs?.length ? rule.refs.join(', ') : 'default for kind' }}</span>
          <span class="text-gray-500">{{ rule.regimes?.length ? rule.regimes.join(', ') : 'internal' }}</span>
          <span class="font-mono text-gray-300">{{ rule.priority || 'P2' }}</span>
          <span
            v-if="rule.due"
            class="text-gray-500"
          >due {{ rule.due }}</span>
          <span
            class="ml-auto rounded border px-1.5 py-0.5 text-[10px]"
            :class="sourceClass(rule.source)"
          >{{ SOURCE_LABELS[rule.source ?? 'builtin'] }}</span>
        </div>
      </div>

      <details class="mt-3">
        <summary class="cursor-pointer text-xs text-gray-400 hover:text-white">
          Example <code class="font-mono">incidents:</code> section
        </summary>
        <div class="relative mt-2">
          <pre class="overflow-x-auto rounded-md border border-surface-border bg-surface-overlay/40 px-3 py-2 font-mono text-xs leading-relaxed text-gray-300">{{ EXAMPLE_RULES }}</pre>
          <button
            type="button"
            class="absolute right-2 top-2 inline-flex items-center gap-1 rounded border border-surface-border bg-surface-overlay px-2 py-0.5 text-[11px] text-gray-400 transition hover:text-white"
            @click="copy(EXAMPLE_RULES)"
          >
            <Copy class="h-3 w-3" />
            Copy
          </button>
        </div>
      </details>
    </section>

    <!-- Incidents of this repository -->
    <section>
      <div class="flex flex-wrap items-center justify-between gap-2 border-b border-surface-border pb-2">
        <h2 class="text-base font-semibold text-white">
          Incidents of this repository
        </h2>
        <RouterLink
          :to="{ name: 'org-incidents', params: { provider, slug } }"
          class="text-xs text-accent hover:underline"
        >
          All incidents →
        </RouterLink>
      </div>
      <div
        v-if="incidentsLoading"
        class="mt-4 text-sm text-gray-500"
      >
        Loading incidents…
      </div>
      <p
        v-else-if="incidents.length === 0"
        class="mt-4 text-xs text-gray-500"
      >
        No incident has been opened on this repository.
      </p>
      <ul
        v-else
        class="mt-4 divide-y divide-surface-border-subtle overflow-hidden rounded-md border border-surface-border"
      >
        <li
          v-for="incident in incidents"
          :key="incident.id"
          class="flex flex-wrap items-center gap-x-3 gap-y-1 px-3 py-2 text-sm"
        >
          <span class="rounded border border-surface-border px-1.5 py-0.5 font-mono text-[10px] text-gray-400">{{ incident.priority }}</span>
          <RouterLink
            :to="{ name: 'incident-detail', params: { provider, slug, number: String(incident.number) } }"
            class="min-w-0 truncate text-accent hover:underline"
          >
            #{{ incident.number }} {{ incident.title }}
          </RouterLink>
          <span class="text-xs text-gray-500">{{ incident.kind_label || KIND_LABELS[incident.kind] }}</span>
          <span class="ml-auto text-xs text-gray-400">{{ STATE_LABELS[incident.state] ?? incident.state }}</span>
          <span
            v-if="incidentOpen(incident.state) && nullTime(incident.due_at)"
            class="font-mono text-xs"
            :class="countdown(nullTime(incident.due_at)).overdue ? 'text-danger' : 'text-gray-500'"
          >{{ countdown(nullTime(incident.due_at)).text }}</span>
        </li>
      </ul>
    </section>

    <!-- First-party vulnerabilities -->
    <section>
      <div class="flex flex-wrap items-center justify-between gap-2 border-b border-surface-border pb-2">
        <h2 class="text-base font-semibold text-white">
          First-party vulnerabilities
        </h2>
        <button
          v-if="isReleaseManager && !showForm"
          type="button"
          class="inline-flex items-center gap-1.5 rounded-md bg-accent px-3 py-1.5 text-xs font-medium text-white transition hover:bg-accent/90"
          @click="openForm"
        >
          <Plus class="h-3.5 w-3.5" />
          Record a vulnerability
        </button>
      </div>
      <p class="mt-2 text-sm text-gray-400">
        Vulnerabilities in this product's own code, under a CVE you requested or a vendor identifier until one exists.
        Once recorded, a vulnerability can carry VEX statements, an incident and client notices like any advisory.
      </p>

      <form
        v-if="showForm"
        class="mt-4 space-y-3 rounded-md border border-surface-border bg-surface-overlay/30 p-4"
        @submit.prevent="submitFirstParty"
      >
        <div class="grid gap-3 sm:grid-cols-2">
          <label class="block">
            <span class="text-xs font-medium text-gray-400">Identifier</span>
            <input
              v-model="draft.identifier"
              type="text"
              required
              placeholder="CVE-2026-12345 or VENDOR-2026-001"
              class="mt-1 h-8 w-full rounded-md border border-surface-border bg-surface-overlay px-2.5 font-mono text-xs text-gray-200 focus:border-accent/50 focus:outline-none"
            >
          </label>
          <label class="block">
            <span class="text-xs font-medium text-gray-400">Aliases</span>
            <input
              v-model="draft.aliases"
              type="text"
              placeholder="Comma-separated, e.g. GHSA-xxxx-xxxx-xxxx"
              class="mt-1 h-8 w-full rounded-md border border-surface-border bg-surface-overlay px-2.5 font-mono text-xs text-gray-200 focus:border-accent/50 focus:outline-none"
            >
          </label>
        </div>
        <label class="block">
          <span class="text-xs font-medium text-gray-400">Title</span>
          <input
            v-model="draft.title"
            type="text"
            required
            class="mt-1 h-8 w-full rounded-md border border-surface-border bg-surface-overlay px-2.5 text-sm text-gray-200 focus:border-accent/50 focus:outline-none"
          >
        </label>
        <label class="block">
          <span class="text-xs font-medium text-gray-400">Description</span>
          <textarea
            v-model="draft.description"
            rows="3"
            class="mt-1 w-full rounded-md border border-surface-border bg-surface-overlay px-2.5 py-1.5 text-sm text-gray-200 focus:border-accent/50 focus:outline-none"
          />
        </label>
        <div class="grid gap-3 sm:grid-cols-[10rem_minmax(0,1fr)]">
          <label class="block">
            <span class="text-xs font-medium text-gray-400">Severity</span>
            <select
              v-model="draft.severity"
              class="mt-1 h-8 w-full rounded-md border border-surface-border bg-surface-overlay px-2 text-sm text-gray-200 focus:border-accent/50 focus:outline-none"
            >
              <option
                v-for="severity in SEVERITIES"
                :key="severity"
                :value="severity"
              >
                {{ severity }}
              </option>
            </select>
          </label>
          <label class="block">
            <span class="text-xs font-medium text-gray-400">CVSS vector (optional)</span>
            <input
              v-model="draft.cvssVector"
              type="text"
              placeholder="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
              class="mt-1 h-8 w-full rounded-md border border-surface-border bg-surface-overlay px-2.5 font-mono text-xs text-gray-200 focus:border-accent/50 focus:outline-none"
            >
          </label>
        </div>
        <div class="grid gap-3 sm:grid-cols-2">
          <label class="block">
            <span class="text-xs font-medium text-gray-400">Affected range (vers)</span>
            <input
              v-model="draft.affectedRange"
              type="text"
              required
              placeholder="vers:generic/>=4.0.0|<4.2.2"
              class="mt-1 h-8 w-full rounded-md border border-surface-border bg-surface-overlay px-2.5 font-mono text-xs text-gray-200 focus:border-accent/50 focus:outline-none"
            >
          </label>
          <label class="block">
            <span class="text-xs font-medium text-gray-400">Promoted from finding (optional)</span>
            <input
              v-model="draft.promotedFrom"
              type="text"
              placeholder="Finding id"
              class="mt-1 h-8 w-full rounded-md border border-surface-border bg-surface-overlay px-2.5 font-mono text-xs text-gray-200 focus:border-accent/50 focus:outline-none"
            >
          </label>
        </div>
        <div class="flex items-center gap-3">
          <button
            type="submit"
            class="rounded-md bg-accent px-3 py-1.5 text-xs font-medium text-white transition hover:bg-accent/90 disabled:cursor-not-allowed disabled:opacity-50"
            :disabled="submitting || !draft.identifier.trim() || !draft.title.trim() || !draft.affectedRange.trim()"
          >
            {{ submitting ? 'Recording…' : 'Record vulnerability' }}
          </button>
          <button
            type="button"
            class="rounded-md px-3 py-1.5 text-xs text-gray-400 transition hover:text-white"
            @click="showForm = false"
          >
            Cancel
          </button>
          <span
            v-if="submitError"
            class="text-xs text-danger"
          >{{ submitError }}</span>
        </div>
      </form>

      <div
        v-if="created"
        class="mt-4 flex flex-wrap items-center gap-2 rounded-md border border-ok/40 bg-ok/5 px-4 py-3 text-xs text-gray-300"
      >
        <span>Recorded <span class="font-mono text-gray-100">{{ created }}</span>.</span>
        <RouterLink
          :to="{ name: 'org-incidents', params: { provider, slug } }"
          class="text-accent hover:underline"
        >
          Open an incident on it →
        </RouterLink>
      </div>

      <div
        v-if="firstPartyLoading"
        class="mt-4 text-sm text-gray-500"
      >
        Loading…
      </div>
      <p
        v-else-if="firstParty.length === 0"
        class="mt-4 text-xs text-gray-500"
      >
        No first-party vulnerability recorded.
      </p>
      <div
        v-else
        class="mt-4 overflow-hidden rounded-md border border-surface-border"
      >
        <div class="overflow-x-auto">
          <table class="min-w-full divide-y divide-surface-border-subtle text-sm">
            <thead class="bg-surface-overlay text-left text-xs uppercase tracking-[0.14em] text-gray-500">
              <tr>
                <th class="px-4 py-2.5 font-medium">
                  Identifier
                </th>
                <th class="px-4 py-2.5 font-medium">
                  Affected
                </th>
                <th class="px-4 py-2.5 font-medium">
                  Product
                </th>
                <th class="px-4 py-2.5 font-medium">
                  Promoted from
                </th>
              </tr>
            </thead>
            <tbody class="divide-y divide-surface-border-subtle">
              <tr
                v-for="record in firstParty"
                :key="record.id"
              >
                <td class="px-4 py-2.5">
                  <div class="font-mono text-xs text-gray-200">
                    {{ record.canonical_id || record.advisory_id }}
                  </div>
                  <div
                    v-if="record.title"
                    class="mt-0.5 text-xs text-gray-400"
                  >
                    {{ record.title }}
                  </div>
                </td>
                <td class="px-4 py-2.5 font-mono text-xs text-gray-300">
                  {{ record.affected_range }}
                </td>
                <td class="px-4 py-2.5 font-mono text-[11px] text-gray-400">
                  <div class="break-all">
                    {{ record.product_purl }}
                  </div>
                  <div
                    v-if="nullString(record.product_cpe)"
                    class="break-all text-gray-500"
                  >
                    {{ nullString(record.product_cpe) }}
                  </div>
                </td>
                <td
                  class="px-4 py-2.5 font-mono text-[11px] text-gray-500"
                  :title="nullString(record.promoted_from) || undefined"
                >
                  {{ nullString(record.promoted_from) ? nullString(record.promoted_from).slice(0, 12) : '—' }}
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
    </section>
  </div>
</template>

<script setup lang="ts">
import { Copy, Plus } from 'lucide-vue-next'
import { computed, reactive, ref, watch } from 'vue'
import { RouterLink, useRoute } from 'vue-router'

import {
  countdown,
  incidentOpen,
  incidentsApi,
  KIND_LABELS,
  nullString,
  nullTime,
  STATE_LABELS,
  type FirstPartyAdvisory,
  type FirstPartyAdvisoryInput,
  type IncidentRule,
  type IncidentSummary,
  type RepoIncidentRules,
} from '@/api/incidents'
import { useOrgRole } from '@/composables/useOrgRole'
import { useToast } from '@/composables/useToast'

type RuleSource = NonNullable<IncidentRule['source']>

const SOURCE_LABELS: Record<RuleSource, string> = {
  'org-locked': 'locked by org',
  'repo': '.hibou.yaml',
  'org': 'org default',
  'builtin': 'built-in',
}

const SEVERITIES: FirstPartyAdvisoryInput['severity'][] = ['critical', 'high', 'medium', 'low', 'info']

const EXAMPLE_RULES = `# .hibou.yaml
incidents:
  owner: team:product-security          # who receives signals and countdowns
  rules:                                # first matching rule wins
    - match: "exploited:true"           # refs: released (default for vulnerabilities)
      regimes: [cra-article-14]
      priority: P1
    - match: "type:secret verified:true"  # refs: all (default for secrets and malware)
      priority: P1
    - match: "type:malware"
      priority: P1
    - match: "epss:>=0.5 OR (severity:critical AND fix:available)"
      refs: [released, default]         # released snapshots and the default branch
      due: 7d
      priority: P2
    - match: "type:secret"
      priority: P3
`

const route = useRoute()
const toast = useToast()
const { isReleaseManager } = useOrgRole()

const provider = computed(() => route.params.provider as string)
const slug = computed(() => route.params.slug as string)
const repoSlug = computed(() => route.params.repoSlug as string)

const rules = ref<RepoIncidentRules | null>(null)
const rulesLoading = ref(true)
const rulesError = ref('')
const incidents = ref<IncidentSummary[]>([])
const incidentsLoading = ref(true)
const firstParty = ref<FirstPartyAdvisory[]>([])
const firstPartyLoading = ref(true)

const showForm = ref(false)
const submitting = ref(false)
const submitError = ref('')
const created = ref('')
const draft = reactive({
  identifier: '',
  aliases: '',
  title: '',
  description: '',
  severity: 'high' as FirstPartyAdvisoryInput['severity'],
  cvssVector: '',
  affectedRange: '',
  promotedFrom: '',
})

const productRows = computed(() => {
  const product = rules.value?.product
  return [
    { label: 'Name', value: product?.Name ?? '' },
    { label: 'purl', value: product?.PURL ?? '' },
    { label: 'CPE', value: product?.CPE ?? '' },
  ]
})

const productSnippet = computed(() => {
  const product = rules.value?.product
  const versionless = (product?.PURL ?? '').replace(/@.*$/, '')
  return [
    'product:',
    `  name: ${product?.Name || repoSlug.value}`,
    `  purl: ${versionless || `pkg:generic/${slug.value}/${repoSlug.value}`}`,
    product?.CPE ? `  cpe: ${product.CPE}` : '  # cpe: cpe:2.3:a:<vendor>:<product>:*:*:*:*:*:*:*:*   # optional, version left as *',
  ].join('\n')
})

function sourceClass(source: IncidentRule['source']) {
  switch (source) {
    case 'org-locked':
      return 'border-danger/40 bg-danger/10 text-danger'
    case 'org':
      return 'border-warn/40 bg-warn/10 text-warn'
    case 'repo':
      return 'border-accent/40 bg-accent/10 text-accent'
    default:
      return 'border-surface-border bg-surface-overlay/40 text-gray-400'
  }
}

async function copy(text: string) {
  try {
    await navigator.clipboard.writeText(text)
    toast.success('Copied to clipboard')
  } catch {
    toast.error('Copy failed', 'Select the text and copy it by hand.')
  }
}

function openForm() {
  created.value = ''
  submitError.value = ''
  showForm.value = true
}

async function loadRules() {
  rulesLoading.value = true
  rulesError.value = ''
  try {
    const res = await incidentsApi.repoRules(provider.value, slug.value, repoSlug.value)
    rules.value = { ...res.data, rules: res.data.rules ?? [] }
  } catch {
    rules.value = null
    rulesError.value = 'The incident rules could not be resolved right now. Try again later.'
  } finally {
    rulesLoading.value = false
  }
}

async function loadIncidents() {
  incidentsLoading.value = true
  try {
    const res = await incidentsApi.listRepoIncidents(provider.value, slug.value, repoSlug.value)
    incidents.value = res.data ?? []
  } catch {
    incidents.value = []
  } finally {
    incidentsLoading.value = false
  }
}

async function loadFirstParty() {
  firstPartyLoading.value = true
  try {
    const res = await incidentsApi.listFirstParty(provider.value, slug.value, repoSlug.value)
    firstParty.value = res.data ?? []
  } catch {
    firstParty.value = []
  } finally {
    firstPartyLoading.value = false
  }
}

async function submitFirstParty() {
  submitError.value = ''
  submitting.value = true
  try {
    const identifier = draft.identifier.trim()
    await incidentsApi.createFirstParty(provider.value, slug.value, repoSlug.value, {
      identifier,
      aliases: draft.aliases.split(',').map((alias) => alias.trim()).filter(Boolean),
      title: draft.title.trim(),
      description: draft.description.trim(),
      severity: draft.severity,
      cvss_vector: draft.cvssVector.trim() || undefined,
      affected_range: draft.affectedRange.trim(),
      promoted_from: draft.promotedFrom.trim() || undefined,
    })
    created.value = identifier
    showForm.value = false
    Object.assign(draft, { identifier: '', aliases: '', title: '', description: '', severity: 'high', cvssVector: '', affectedRange: '', promotedFrom: '' })
    await loadFirstParty()
  } catch (caught) {
    submitError.value = caught instanceof Error ? caught.message : 'Unable to record the vulnerability.'
  } finally {
    submitting.value = false
  }
}

watch(
  [provider, slug, repoSlug],
  () => {
    if (!provider.value || !slug.value || !repoSlug.value) return
    created.value = ''
    showForm.value = false
    void loadRules()
    void loadIncidents()
    void loadFirstParty()
  },
  { immediate: true },
)
</script>
