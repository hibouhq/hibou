<template>
  <section :class="ui.card">
    <h2 :class="ui.heading">
      Scope
    </h2>
    <p class="mt-1 text-xs text-gray-500">
      Every row ends with a statement or an exclusion with its reason; an unknown row blocks closure.
    </p>

    <p
      v-if="error"
      :class="[ui.error, 'mt-3']"
    >
      {{ error }}
    </p>

    <p
      v-if="detail.scope.length === 0"
      class="mt-3 text-sm text-gray-500"
    >
      No scope rows.
    </p>

    <div
      v-else
      class="mt-3 overflow-x-auto rounded-md border border-surface-border"
    >
      <table class="min-w-full divide-y divide-surface-border-subtle text-sm">
        <thead :class="ui.thead">
          <tr>
            <th :class="ui.th">
              Subject
            </th>
            <th :class="ui.th">
              Status
            </th>
            <th :class="ui.th">
              Reason
            </th>
            <th :class="ui.th">
              Component
            </th>
            <th :class="ui.th">
              Reachable
            </th>
            <th :class="ui.th">
              Clients
            </th>
            <th
              v-if="detail.can_manage"
              :class="ui.th"
            />
          </tr>
        </thead>
        <tbody class="divide-y divide-surface-border-subtle">
          <template
            v-for="row in detail.scope"
            :key="rowKey(row)"
          >
            <tr>
              <td :class="ui.td">
                <RouterLink
                  v-if="refLink(row)"
                  :to="refLink(row)!"
                  class="font-mono text-xs text-accent hover:underline"
                  :title="`Findings at ${row.label}`"
                >
                  {{ row.label || row.subject_id }}
                </RouterLink>
                <div
                  v-else
                  class="font-mono text-xs text-white"
                >
                  {{ row.label || row.subject_id }}
                </div>
                <div class="text-[11px] text-gray-500">
                  {{ row.subject_type }}<template v-if="row.manual">
                    · set by hand
                  </template>
                </div>
              </td>
              <td :class="ui.td">
                <IncidentStatusPill :status="row.status" />
              </td>
              <td :class="[ui.td, 'max-w-xs text-xs text-gray-300']">
                {{ row.reason || '—' }}
              </td>
              <td :class="[ui.td, 'max-w-[16rem] break-all font-mono text-[11px] text-gray-400']">
                <RouterLink
                  v-if="row.component_purl && componentLink(row)"
                  :to="componentLink(row)!"
                  class="text-accent hover:underline"
                  title="Open the component"
                >
                  {{ row.component_purl }}
                </RouterLink>
                <template v-else>
                  {{ row.component_purl || '—' }}
                </template>
              </td>
              <td :class="[ui.td, 'text-xs text-gray-300']">
                {{ nullString(row.reachability) || '—' }}
              </td>
              <td :class="[ui.td, 'text-xs']">
                <span
                  v-if="row.clients.length === 0"
                  class="text-gray-600"
                >—</span>
                <span
                  v-for="(client, index) in row.clients"
                  :key="client.id"
                >
                  <RouterLink
                    :to="{ name: 'client-overview', params: { provider, slug, clientSlug: client.slug } }"
                    class="text-accent transition hover:underline"
                  >{{ client.name }}</RouterLink><template v-if="index < row.clients.length - 1">, </template>
                </span>
              </td>
              <td
                v-if="detail.can_manage"
                :class="[ui.td, 'whitespace-nowrap text-right']"
              >
                <div class="inline-flex gap-1.5">
                  <button
                    v-if="canStatement(row)"
                    type="button"
                    :class="ui.secondary"
                    @click="openStatement(row)"
                  >
                    Record statement
                  </button>
                  <button
                    v-if="canStatement(row) && row.status !== 'excluded'"
                    type="button"
                    :class="ui.danger"
                    :disabled="busy"
                    @click="exclude(row)"
                  >
                    Exclude
                  </button>
                  <button
                    v-if="row.manual"
                    type="button"
                    :class="ui.secondary"
                    :disabled="busy"
                    @click="clear(row)"
                  >
                    Clear
                  </button>
                </div>
              </td>
            </tr>
            <tr v-if="statementFor === rowKey(row)">
              <td
                :colspan="7"
                class="bg-surface-overlay/40 px-3 py-3"
              >
                <form
                  class="grid gap-3 sm:grid-cols-2"
                  @submit.prevent="submitStatement(row)"
                >
                  <label :class="ui.label">
                    Status
                    <select
                      v-model="statement.status"
                      :class="ui.input"
                    >
                      <option
                        v-for="status in STATEMENT_STATUSES"
                        :key="status"
                        :value="status"
                      >
                        {{ humanize(status) }}
                      </option>
                    </select>
                  </label>
                  <label
                    v-if="statement.status === 'not_affected'"
                    :class="ui.label"
                  >
                    Justification
                    <select
                      v-model="statement.justification"
                      required
                      :class="ui.input"
                    >
                      <option value="">
                        Choose a justification
                      </option>
                      <option
                        v-for="justification in VEX_JUSTIFICATIONS"
                        :key="justification.value"
                        :value="justification.value"
                      >
                        {{ justification.label }}
                      </option>
                    </select>
                  </label>
                  <label :class="[ui.label, 'sm:col-span-2']">
                    Impact statement
                    <textarea
                      v-model="statement.impact_statement"
                      rows="2"
                      :class="ui.textarea"
                      placeholder="Why this version is or is not affected"
                    />
                  </label>
                  <label :class="[ui.label, 'sm:col-span-2']">
                    Action statement
                    <textarea
                      v-model="statement.action_statement"
                      rows="2"
                      :class="ui.textarea"
                      placeholder="What users of this version should do"
                    />
                  </label>
                  <div class="flex items-center gap-2 sm:col-span-2">
                    <button
                      type="submit"
                      :class="ui.primary"
                      :disabled="busy || (statement.status === 'not_affected' && !statement.justification)"
                    >
                      Record statement
                    </button>
                    <button
                      type="button"
                      :class="ui.secondary"
                      @click="statementFor = ''"
                    >
                      Cancel
                    </button>
                  </div>
                </form>
              </td>
            </tr>
          </template>
        </tbody>
      </table>
    </div>
  </section>
</template>

<script setup lang="ts">
import { reactive, ref } from 'vue'
import { RouterLink, type RouteLocationRaw } from 'vue-router'

import { incidentsApi, nullString, type IncidentDetail, type IncidentScopeRow, type IncidentStatementInput } from '@/api/incidents'
import IncidentStatusPill from '@/components/incidents/IncidentStatusPill.vue'
import { ui } from '@/components/incidents/ui'
import { useDialog } from '@/composables/useDialog'
import { errorText, humanize } from '@/lib/incidentView'
import { VEX_JUSTIFICATIONS } from '@/lib/triage'

const props = defineProps<{ provider: string; slug: string; detail: IncidentDetail }>()

// Releases and refs open the repository's findings at that ref: a
// finding-subject incident has one row per branch, so its drawer opens
// directly; an advisory may match several components on one branch, so the
// list is filtered to the incident. A component opens its page in the
// dependencies.
function repoParams() {
  const repoSlug = props.detail.incident.repo_slug
  return repoSlug ? { provider: props.provider, slug: props.slug, repoSlug } : null
}

function refLink(row: IncidentScopeRow): RouteLocationRaw | null {
  const params = repoParams()
  if (!params || (row.subject_type !== 'release' && row.subject_type !== 'ref') || !row.label) return null
  const incident = props.detail.incident
  if (incident.subject_type === 'finding') return { name: 'repo-vulnerabilities', params, query: { ref: row.label, finding: incident.subject_id } }
  return { name: 'repo-vulnerabilities', params, query: { ref: row.label, q: `incident:${incident.number}` } }
}

function componentLink(row: IncidentScopeRow): RouteLocationRaw | null {
  const params = repoParams()
  if (!params) return null
  const atRef = (row.subject_type === 'release' || row.subject_type === 'ref') && row.label ? { ref: row.label } : {}
  return { name: 'repo-dependencies', params, query: { ...atRef, component: row.component_purl } }
}
const emit = defineEmits<{ changed: [] }>()

const STATEMENT_STATUSES: IncidentStatementInput['status'][] = ['not_affected', 'affected', 'fixed', 'under_investigation']

const { promptDialog } = useDialog()
const busy = ref(false)
const error = ref('')
const statementFor = ref('')
const statement = reactive({
  status: 'affected' as IncidentStatementInput['status'],
  justification: '',
  impact_statement: '',
  action_statement: '',
})

function rowKey(row: IncidentScopeRow) {
  return `${row.subject_type}:${row.subject_id}`
}

function canStatement(row: IncidentScopeRow) {
  return row.subject_type === 'release' && props.detail.incident.kind === 'exploited_vulnerability'
}

function openStatement(row: IncidentScopeRow) {
  Object.assign(statement, { status: 'affected', justification: '', impact_statement: '', action_statement: '' })
  statementFor.value = rowKey(row)
}

async function run(task: () => Promise<unknown>, fallback: string) {
  busy.value = true
  error.value = ''
  try {
    await task()
    emit('changed')
    return true
  } catch (taskError) {
    error.value = errorText(taskError, fallback)
    return false
  } finally {
    busy.value = false
  }
}

async function submitStatement(row: IncidentScopeRow) {
  const ok = await run(() => incidentsApi.statement(props.provider, props.slug, props.detail.incident.number, {
    release_id: row.subject_id,
    component_purl: row.component_purl || undefined,
    status: statement.status,
    justification: statement.status === 'not_affected' ? statement.justification : undefined,
    impact_statement: statement.impact_statement.trim() || undefined,
    action_statement: statement.action_statement.trim() || undefined,
  }), 'Failed to record the statement')
  if (ok) statementFor.value = ''
}

async function exclude(row: IncidentScopeRow) {
  const reason = await promptDialog({
    title: `Exclude ${row.label || row.subject_id}`,
    message: 'Excluding a release from the scope is a recorded decision.',
    confirmLabel: 'Exclude',
    tone: 'danger',
    input: { label: 'Reason', required: true },
  })
  if (!reason?.trim()) return
  await run(() => incidentsApi.scope(props.provider, props.slug, props.detail.incident.number, {
    subject_type: row.subject_type,
    subject_id: row.subject_id,
    status: 'excluded',
    reason: reason.trim(),
  }), 'Failed to exclude the row')
}

async function clear(row: IncidentScopeRow) {
  await run(() => incidentsApi.scope(props.provider, props.slug, props.detail.incident.number, {
    subject_type: row.subject_type,
    subject_id: row.subject_id,
    clear: true,
  }), 'Failed to clear the row')
}
</script>
