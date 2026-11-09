<template>
  <section
    id="incident-decision"
    :class="ui.card"
  >
    <div class="flex flex-wrap items-center justify-between gap-2">
      <h2 :class="ui.heading">
        Decision
      </h2>
      <button
        v-if="canDecide && decided && !formOpen"
        type="button"
        :class="ui.secondary"
        @click="openForm"
      >
        Change decision
      </button>
    </div>

    <p class="mt-1 text-xs text-gray-500">
      One decision per incident: it answers for the product. Each release in Scope carries its own
      VEX statement; a release that differs from the decision gets its own.
    </p>

    <dl
      v-if="decided"
      class="mt-3 grid gap-x-6 gap-y-2 text-sm sm:grid-cols-[auto_1fr]"
    >
      <dt class="text-xs text-gray-500">
        Decided
      </dt>
      <dd class="flex flex-wrap items-center gap-2 text-gray-200">
        <IncidentStatusPill
          v-if="incident.decided_state?.valid"
          :status="incident.decided_state.incident_state"
          :label="STATE_LABELS[incident.decided_state.incident_state]"
        />
        <span class="text-xs text-gray-400">
          by {{ nameOf(nullUUID(incident.decided_by)) }}
          <template v-if="nullTime(incident.decided_at)">, {{ formatDateTime(nullTime(incident.decided_at) as string) }}</template>
        </span>
      </dd>
      <template v-if="nullString(incident.decision_step)">
        <dt class="text-xs text-gray-500">
          Ladder step
        </dt>
        <dd class="text-gray-200">
          {{ stepLabel(nullString(incident.decision_step)) }}
          <code
            v-if="recordedVEX"
            class="ml-2 font-mono text-[11px] text-gray-400"
            title="The VEX statement this step means for the releases in scope"
          >{{ recordedVEX }}</code>
          <span
            v-if="contradictingReleases.length > 0"
            class="mt-1 block text-xs text-amber-200"
          >
            {{ contradictingReleases.join(', ') }} {{ contradictingReleases.length === 1 ? 'carries' : 'carry' }} an <em>affected</em> statement: the vulnerability can be exploited in that release, so this decision only holds if it was not exploited in your product (step 3). Review it.
          </span>
        </dd>
      </template>
      <dt class="text-xs text-gray-500">
        Reason
      </dt>
      <dd class="whitespace-pre-wrap text-gray-200">
        <AutolinkedText
          v-if="nullString(incident.decision_reason)"
          :text="nullString(incident.decision_reason)"
          :provider="provider"
          :slug="slug"
        />
        <template v-else>
          —
        </template>
      </dd>
    </dl>
    <p
      v-else-if="!canDecide"
      class="mt-2 text-sm text-gray-500"
    >
      Not decided yet.
    </p>

    <!-- Four-eyes proposal -->
    <div
      v-if="proposal"
      class="mt-3 rounded-md border border-warn/30 bg-warn/10 px-3 py-2.5 text-sm"
    >
      <div class="flex flex-wrap items-center gap-2 text-amber-200">
        Proposed:
        <IncidentStatusPill
          :status="proposal.state"
          :label="STATE_LABELS[proposal.state]"
        />
        <span class="text-xs text-amber-200/80">
          by {{ nameOf(proposal.proposed_by ?? null) }}<template v-if="proposal.proposed_at">, {{ formatDateTime(proposal.proposed_at) }}</template>
        </span>
      </div>
      <p
        v-if="proposal.decision_step"
        class="mt-1 text-xs text-gray-300"
      >
        {{ stepLabel(proposal.decision_step) }}
      </p>
      <p class="mt-1 whitespace-pre-wrap text-gray-200">
        {{ proposal.reason }}
      </p>
      <div
        v-if="detail.can_manage"
        class="mt-2"
      >
        <button
          v-if="proposal.proposed_by !== currentUserId"
          type="button"
          :class="ui.primary"
          :disabled="busy"
          @click="approve"
        >
          Approve
        </button>
        <span
          v-else
          class="text-xs text-gray-400"
        >Waiting for another person's approval.</span>
      </div>
    </div>

    <p
      v-if="notice"
      class="mt-3 text-sm text-amber-200"
    >
      {{ notice }}
    </p>

    <form
      v-if="formOpen"
      class="mt-3 space-y-4"
      @submit.prevent="submit"
    >
      <!-- An exploited vulnerability: the ladder step decides the state. -->
      <fieldset
        v-if="hasSteps"
        class="space-y-1.5"
      >
        <legend :class="ui.label">
          How far does the ladder go?
          <span class="font-normal text-gray-500">The first step that applies, in order (Commission guidance on the CRA, §218).</span>
        </legend>
        <label
          v-for="(step, index) in detail.decision_steps"
          :key="step"
          class="flex cursor-pointer items-start gap-3 rounded-lg border px-3 py-2 transition"
          :class="form.decision_step === step ? 'border-accent/60 bg-accent/5' : 'border-surface-border hover:border-gray-500'"
        >
          <input
            v-model="form.decision_step"
            type="radio"
            class="mt-1 accent-accent"
            :value="step"
          >
          <span class="min-w-0 flex-1">
            <span class="block text-sm text-gray-100">{{ index + 1 }}. {{ DECISION_STEP_LABELS[step] }}</span>
            <span
              class="mt-0.5 block text-[11px]"
              :class="stepReportable(step) ? 'text-danger' : 'text-gray-500'"
            >{{ DECISION_STEP_HINTS[step] }}</span>
            <span
              v-if="step === 'not_reachable' && form.decision_step === step"
              class="mt-2 flex flex-wrap gap-1.5"
            >
              <button
                v-for="justification in NOT_EXPLOITABLE_JUSTIFICATIONS"
                :key="justification.value"
                type="button"
                class="rounded-full border px-2 py-0.5 text-[11px] transition"
                :class="form.justification === justification.value ? 'border-accent/60 bg-accent/10 text-accent' : 'border-surface-border text-gray-400 hover:text-white'"
                :title="justification.value"
                @click="form.justification = justification.value"
              >
                {{ justification.label }}
              </button>
            </span>
          </span>
          <code
            class="shrink-0 self-start font-mono text-[11px] text-gray-400"
            title="The VEX statement this step means for the releases in scope"
          >{{ stepVEX(step, step === 'not_reachable' ? form.justification : '') }}</code>
        </label>
      </fieldset>

      <fieldset
        v-else
        class="flex flex-wrap gap-4"
      >
        <label
          v-for="state in detail.decision_states"
          :key="state"
          class="inline-flex items-center gap-1.5 text-sm text-gray-200"
          :title="STATE_DESCRIPTIONS[state]"
        >
          <input
            v-model="form.state"
            type="radio"
            class="accent-accent"
            :value="state"
          >
          {{ STATE_LABELS[state] }}
        </label>
      </fieldset>

      <label :class="ui.label">
        Reason
        <textarea
          v-model="form.reason"
          rows="3"
          required
          :class="ui.textarea"
          :placeholder="reasonPlaceholder"
        />
      </label>

      <label
        v-if="hasSteps && form.decision_step && !notAffectedStep"
        :class="ui.label"
      >
        What users can do (VEX action statement)
        <input
          v-model="form.action_statement"
          type="text"
          :class="ui.input"
          placeholder="Upgrade to 4.2.2; until then disable the feature, cap the rate, …"
        >
      </label>

      <label
        v-if="hasSteps && form.decision_step && pendingReleases.length > 0"
        class="flex items-start gap-2 text-xs text-gray-300"
      >
        <input
          v-model="form.write_statements"
          type="checkbox"
          class="mt-0.5 accent-accent"
        >
        <span>
          Record this as the VEX statement of the {{ pendingReleases.length }} {{ pendingReleases.length === 1 ? 'release' : 'releases' }} in scope without one
          ({{ pendingReleases.map(row => row.label).join(', ') }}).
          A release that differs gets its own statement in Scope; it takes precedence.
        </span>
      </label>

      <label
        v-if="needsAwareAt"
        :class="[ui.label, 'max-w-md']"
      >
        Became aware (T0)
        <input
          v-model="form.aware_at"
          type="datetime-local"
          :class="ui.input"
        >
        <span class="text-[11px] font-normal text-gray-500">
          When, after the initial assessment, you had a reasonable degree of certainty that the
          vulnerability in your product is being exploited (guidance §213). Starts the clocks; moves
          backwards only, never after a filing.
        </span>
      </label>

      <p
        v-if="form.decision_step === 'attacked'"
        class="text-xs text-gray-400"
      >
        If the attack also reached your own systems (build chain, signing keys, update server, hosted
        back-end), that is a separate report:
        <RouterLink
          :to="severeIncidentLink"
          class="text-accent hover:underline"
        >
          open a Security incident (Art. 14(3))
        </RouterLink> as well.
      </p>

      <div class="flex items-center gap-3">
        <button
          type="submit"
          :class="ui.primary"
          :disabled="busy || !form.state || !form.reason.trim()"
        >
          {{ busy ? 'Saving…' : 'Record decision' }}
        </button>
        <button
          v-if="decided"
          type="button"
          :class="ui.secondary"
          @click="formOpen = false"
        >
          Cancel
        </button>
      </div>
    </form>

    <p
      v-if="error"
      :class="[ui.error, 'mt-3']"
    >
      {{ error }}
    </p>
  </section>
</template>

<script setup lang="ts">
import AutolinkedText from '@/components/incidents/AutolinkedText.vue'
import { computed, reactive, ref, watch } from 'vue'
import { RouterLink } from 'vue-router'

import {
  DECISION_STEP_HINTS,
  DECISION_STEP_LABELS,
  incidentOpen,
  incidentsApi,
  nullString,
  nullTime,
  NOT_EXPLOITABLE_JUSTIFICATIONS,
  nullUUID,
  STATE_DESCRIPTIONS,
  STATE_LABELS,
  stepReportable,
  stepVEX,
  type DecisionStep,
  type IncidentDetail,
  type IncidentState,
} from '@/api/incidents'
import IncidentStatusPill from '@/components/incidents/IncidentStatusPill.vue'
import { ui } from '@/components/incidents/ui'
import { formatDateTime } from '@/lib/datetime'
import { decisionWasProposed, errorText, fromLocalInput, isExternalRegime, toLocalInput } from '@/lib/incidentView'

const props = defineProps<{
  provider: string
  slug: string
  detail: IncidentDetail
  currentUserId: string
  names: Record<string, string>
}>()
const emit = defineEmits<{ changed: [] }>()

const incident = computed(() => props.detail.incident)
const decided = computed(() => !!nullTime(incident.value.decided_at))
const canDecide = computed(() => props.detail.can_manage && incidentOpen(incident.value.state))
const proposal = computed(() => {
  const proposed = incident.value.proposed_decision
  return proposed && proposed.state ? proposed : null
})

const formOpen = ref(false)
const busy = ref(false)
const error = ref('')
const notice = ref('')
const form = reactive({
  state: '' as IncidentState | '',
  decision_step: '' as DecisionStep | '',
  justification: NOT_EXPLOITABLE_JUSTIFICATIONS[0].value,
  action_statement: '',
  write_statements: true,
  reason: '',
  aware_at: '',
})

const notAffectedStep = computed(() => form.decision_step === 'not_present' || form.decision_step === 'not_reachable')

// Releases in scope with no statement yet: the decision can write theirs.
const pendingReleases = computed(() => props.detail.scope.filter(row => row.subject_type === 'release' && !row.vex_statement_id && (row.status === 'pending' || row.status === 'unknown')))

// Releases whose statement says "affected" while the decision says the
// vulnerability cannot be exploited here: the two cannot both be right.
const contradictingReleases = computed(() => {
  const step = nullString(incident.value.decision_step)
  if (step !== 'not_present' && step !== 'not_reachable') return []
  return props.detail.scope.filter(row => row.subject_type === 'release' && row.status === 'affected').map(row => row.label)
})

const recordedVEX = computed(() => {
  const step = nullString(incident.value.decision_step) as DecisionStep | ''
  return step === 'not_reachable' ? 'not_affected' : stepVEX(step)
})

const reasonPlaceholder = computed(() => {
  switch (form.decision_step) {
    case 'not_present':
      return 'Which versions were checked, and how (SBOM, build manifest)'
    case 'not_reachable':
      return 'Why it cannot be exploited here: call graph, configuration, mitigation, analysis'
    case 'reachable_no_attack':
      return 'What was checked for signs of exploitation (logs, telemetry, customer reports) and found nothing'
    case 'attacked':
      return 'The evidence: who reported it, what was observed, where'
    default:
      return 'What the decision rests on: evidence, analysis, sources'
  }
})

const severeIncidentLink = computed(() => ({
  name: 'org-incidents',
  params: { provider: props.provider, slug: props.slug },
  query: { open: '1', kind: 'severe_incident', ...(incident.value.repo_slug ? { repo: incident.value.repo_slug } : {}) },
}))

const hasSteps = computed(() => (props.detail.decision_steps?.length ?? 0) > 0)

// Reportable goes with an attack on the product, and only with it.
function stateFor(step: DecisionStep): IncidentState {
  return step === 'attacked' ? props.detail.decision_states[0] : props.detail.decision_states[1]
}

watch(() => form.decision_step, (step) => {
  if (hasSteps.value) form.state = step ? stateFor(step) : ''
})

const needsAwareAt = computed(() => form.state === props.detail.decision_states[0] && incident.value.regimes.some(isExternalRegime))

watch(
  () => [incident.value.id, decided.value, canDecide.value],
  () => {
    formOpen.value = canDecide.value && !decided.value
    if (formOpen.value) resetForm()
  },
  { immediate: true },
)

function resetForm() {
  form.decision_step = (nullString(incident.value.decision_step) as DecisionStep) || ''
  form.state = hasSteps.value && form.decision_step ? stateFor(form.decision_step) : ''
  form.reason = ''
  form.aware_at = toLocalInput(nullTime(incident.value.aware_at) ?? new Date())
}

function openForm() {
  resetForm()
  notice.value = ''
  formOpen.value = true
}

function nameOf(id: string | null) {
  if (!id) return 'someone'
  return props.names[id] ?? `${id.slice(0, 8)}…`
}

function stepLabel(step: string) {
  return DECISION_STEP_LABELS[step as DecisionStep] ?? step
}

async function submit() {
  if (!form.state) return
  busy.value = true
  error.value = ''
  notice.value = ''
  const before = incident.value.state
  try {
    const response = await incidentsApi.decide(props.provider, props.slug, incident.value.number, {
      state: form.state,
      reason: form.reason.trim(),
      decision_step: form.decision_step || undefined,
      justification: form.decision_step === 'not_reachable' ? form.justification : undefined,
      action_statement: hasSteps.value && !notAffectedStep.value ? form.action_statement.trim() || undefined : undefined,
      write_statements: hasSteps.value && form.write_statements && pendingReleases.value.length > 0,
      aware_at: needsAwareAt.value ? fromLocalInput(form.aware_at) : undefined,
    })
    if (decisionWasProposed(before, response.data)) {
      notice.value = "Proposed: waiting for another person's approval."
    }
    formOpen.value = false
    emit('changed')
  } catch (decideError) {
    error.value = errorText(decideError, 'Failed to record the decision')
  } finally {
    busy.value = false
  }
}

async function approve() {
  busy.value = true
  error.value = ''
  notice.value = ''
  try {
    await incidentsApi.approveDecision(props.provider, props.slug, incident.value.number)
    emit('changed')
  } catch (approveError) {
    error.value = errorText(approveError, 'Failed to approve the decision')
  } finally {
    busy.value = false
  }
}
</script>
