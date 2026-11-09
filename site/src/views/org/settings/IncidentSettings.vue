<template>
  <div class="space-y-6">
    <div class="flex items-center justify-between border-b border-surface-border pb-2">
      <h2 class="text-base font-semibold text-white">
        Incidents
      </h2>
      <span
        v-if="!isOrgAdmin"
        class="text-xs text-gray-500"
      >Read-only — org admins can change incident settings</span>
    </div>

    <p class="text-sm text-gray-500">
      Who receives signals, the approvals the organization requires, internal targets, national
      regimes and the trigger rules repositories start from.
    </p>

    <div
      v-if="loading"
      class="text-sm text-gray-500"
    >
      Loading incident settings…
    </div>
    <div
      v-else-if="loadError"
      class="rounded-md border border-danger/30 bg-danger/10 px-4 py-3 text-sm text-red-200"
    >
      {{ loadError }}
    </div>

    <form
      v-else
      class="space-y-6"
      @submit.prevent="save"
    >
      <fieldset
        :disabled="!isOrgAdmin"
        class="space-y-6"
      >
        <!-- Owner -->
        <section class="space-y-2">
          <h3 class="text-sm font-semibold text-white">
            Owner
          </h3>
          <p class="text-xs text-gray-500">
            Receives signals and countdowns when a repository names no owner.
          </p>
          <select
            v-model="form.owner"
            aria-label="Owner"
            :class="[ui.input, 'w-full max-w-sm']"
          >
            <option value="">
              Nobody
            </option>
            <optgroup
              v-if="teams.length > 0"
              label="Teams"
            >
              <option
                v-for="team in teams"
                :key="team.id"
                :value="`team:${team.id}`"
              >
                {{ team.name }}
              </option>
            </optgroup>
            <optgroup
              v-if="members.length > 0"
              label="Members"
            >
              <option
                v-for="member in members"
                :key="member.user_id"
                :value="`user:${member.user_id}`"
              >
                {{ member.user?.display_name || member.user?.email || member.user_id }}
              </option>
            </optgroup>
            <option
              v-if="form.owner && !ownerKnown"
              :value="form.owner"
            >
              {{ form.owner }}
            </option>
          </select>
        </section>

        <!-- Approvals -->
        <section class="space-y-2">
          <h3 class="text-sm font-semibold text-white">
            Approvals
          </h3>
          <label
            v-for="toggle in TOGGLES"
            :key="toggle.key"
            class="flex items-start gap-2 text-sm text-gray-200"
          >
            <input
              v-model="form[toggle.key]"
              type="checkbox"
              class="mt-0.5 h-4 w-4 shrink-0 accent-accent"
            >
            <span>
              {{ toggle.label }}
              <span class="block text-xs text-gray-500">{{ toggle.help }}</span>
            </span>
          </label>
        </section>

        <!-- Timing -->
        <section class="space-y-2">
          <h3 class="text-sm font-semibold text-white">
            Timing
          </h3>
          <div class="grid max-w-2xl gap-3 sm:grid-cols-3">
            <label :class="ui.label">
              Due-soon lead (minutes)
              <input
                v-model.number="form.due_soon_lead_minutes"
                type="number"
                min="0"
                :class="ui.input"
              >
            </label>
            <label :class="ui.label">
              Internal early warning (h, ≤ 24)
              <input
                v-model.number="form.early_warning_hours"
                type="number"
                min="1"
                max="24"
                placeholder="24"
                :class="ui.input"
              >
            </label>
            <label :class="ui.label">
              Internal notification (h, ≤ 72)
              <input
                v-model.number="form.notification_hours"
                type="number"
                min="1"
                max="72"
                placeholder="72"
                :class="ui.input"
              >
            </label>
          </div>
          <p class="text-xs text-gray-500">
            Internal targets may only be stricter than the regulation; the regulatory deadline is always shown next to them.
          </p>
        </section>

        <!-- National regimes -->
        <section class="space-y-2">
          <div class="flex items-center justify-between">
            <h3 class="text-sm font-semibold text-white">
              National regimes
            </h3>
            <button
              v-if="isOrgAdmin"
              type="button"
              class="text-xs text-accent transition hover:underline"
              @click="addRegime"
            >
              Add regime
            </button>
          </div>
          <p
            v-if="form.national_regimes.length === 0"
            class="text-xs text-gray-500"
          >
            None. A national regime adds its own clocks and filings, used as <span class="font-mono">national:&lt;code&gt;</span>.
          </p>
          <div
            v-for="(regime, regimeIndex) in form.national_regimes"
            :key="regimeIndex"
            class="space-y-2 rounded-md border border-surface-border p-3"
          >
            <div class="grid gap-3 sm:grid-cols-[6rem_1fr_1fr_1fr_auto]">
              <label :class="ui.label">
                Code
                <input
                  v-model="regime.code"
                  type="text"
                  placeholder="fr"
                  :class="[ui.input, 'font-mono']"
                >
              </label>
              <label :class="ui.label">
                Label
                <input
                  v-model="regime.label"
                  type="text"
                  :class="ui.input"
                >
              </label>
              <label :class="ui.label">
                Recipient
                <input
                  v-model="regime.recipient"
                  type="text"
                  placeholder="National authority"
                  :class="ui.input"
                >
              </label>
              <label :class="ui.label">
                Portal URL
                <input
                  v-model="regime.url"
                  type="url"
                  placeholder="https://"
                  :class="ui.input"
                >
              </label>
              <button
                v-if="isOrgAdmin"
                type="button"
                class="self-end rounded-md p-1.5 text-gray-500 transition hover:text-danger"
                aria-label="Remove regime"
                @click="form.national_regimes.splice(regimeIndex, 1)"
              >
                <X class="h-3.5 w-3.5" />
              </button>
            </div>
            <div class="space-y-1.5">
              <div
                v-for="(step, stepIndex) in regime.steps"
                :key="stepIndex"
                class="flex items-center gap-2"
              >
                <input
                  v-model="step.name"
                  type="text"
                  aria-label="Step name"
                  placeholder="Step name"
                  :class="[ui.input, 'flex-1']"
                >
                <input
                  v-model.number="step.hours"
                  type="number"
                  min="1"
                  aria-label="Hours after T0"
                  :class="[ui.input, 'w-24']"
                >
                <span class="text-xs text-gray-500">h after T0</span>
                <button
                  v-if="isOrgAdmin"
                  type="button"
                  class="rounded-md p-1.5 text-gray-500 transition hover:text-danger"
                  aria-label="Remove step"
                  @click="regime.steps.splice(stepIndex, 1)"
                >
                  <X class="h-3.5 w-3.5" />
                </button>
              </div>
              <button
                v-if="isOrgAdmin"
                type="button"
                class="text-xs text-accent transition hover:underline"
                @click="regime.steps.push({ name: '', hours: 72 })"
              >
                Add step
              </button>
            </div>
          </div>
        </section>

        <!-- Rules -->
        <section class="space-y-2">
          <h3 class="text-sm font-semibold text-white">
            Default trigger rules
          </h3>
          <p class="text-xs text-gray-500">
            First matching rule wins. Match is a filter expression; refs take <span class="font-mono">default</span>,
            <span class="font-mono">all</span>, <span class="font-mono">released</span> or branch globs; due applies to policy breaches.
            A repository's <span class="font-mono">.hibou.yaml</span> replaces these.
          </p>
          <label class="flex items-center gap-2 text-sm text-gray-200">
            <input
              v-model="form.use_builtin"
              type="checkbox"
              class="h-4 w-4 accent-accent"
              @change="onBuiltinToggle"
            >
            Use the built-in rules
          </label>
          <IncidentRuleEditor
            v-if="!form.use_builtin"
            v-model="form.default_rules"
            :readonly="!isOrgAdmin"
            empty-text="No default rules: repositories open no incidents unless they write their own."
          />
        </section>

        <section class="space-y-2">
          <h3 class="text-sm font-semibold text-white">
            Locked rules
          </h3>
          <p class="text-xs text-gray-500">
            Evaluated before every repository's rules; repositories cannot weaken them.
          </p>
          <IncidentRuleEditor
            v-model="form.locked_rules"
            :readonly="!isOrgAdmin"
            empty-text="No locked rules."
          />
        </section>
      </fieldset>

      <section class="space-y-2">
        <h3 class="text-sm font-semibold text-white">
          Built-in rules
        </h3>
        <p class="text-xs text-gray-500">
          For reference: what applies when neither the organization nor the repository writes rules.
        </p>
        <IncidentRuleEditor
          :model-value="builtinRules"
          readonly
        />
      </section>

      <div
        v-if="isOrgAdmin"
        class="flex items-center gap-3"
      >
        <button
          type="submit"
          :class="ui.primary"
          :disabled="saving"
        >
          {{ saving ? 'Saving…' : 'Save' }}
        </button>
        <p
          v-if="saveError"
          class="text-sm text-danger"
        >
          {{ saveError }}
        </p>
      </div>
    </form>
  </div>
</template>

<script setup lang="ts">
import { X } from 'lucide-vue-next'
import { computed, reactive, ref, watch } from 'vue'
import { useRoute } from 'vue-router'

import { api, type OrgMember, type Team } from '@/api/client'
import { incidentsApi, nullUUID, type IncidentRule, type IncidentSettingsRow, type NationalRegime } from '@/api/incidents'
import IncidentRuleEditor from '@/components/incidents/IncidentRuleEditor.vue'
import { ui } from '@/components/incidents/ui'
import { useOrgRole } from '@/composables/useOrgRole'
import { useToast } from '@/composables/useToast'
import { cleanRule, errorText } from '@/lib/incidentView'

type ToggleKey = 'four_eyes' | 'require_vex_approval' | 'require_notice_approval' | 'require_acknowledgement'

const TOGGLES: { key: ToggleKey; label: string; help: string }[] = [
  { key: 'four_eyes', label: 'Four-eyes on decisions that end obligations', help: 'Not reportable, dismissed and waivers are proposed by one person and approved by another.' },
  { key: 'require_vex_approval', label: 'Approve VEX statements', help: 'A vex action is done only once its statement is approved.' },
  { key: 'require_notice_approval', label: 'Approve notices before sending', help: 'Client notices wait in pending approval until signed off.' },
  { key: 'require_acknowledgement', label: 'Require acknowledgement', help: 'A client notice is done when acknowledged, not when sent.' },
]

const route = useRoute()
const { isOrgAdmin } = useOrgRole()
const toast = useToast()

const loading = ref(true)
const loadError = ref('')
const saving = ref(false)
const saveError = ref('')
const members = ref<OrgMember[]>([])
const teams = ref<Team[]>([])
const builtinRules = ref<IncidentRule[]>([])

const form = reactive({
  owner: '',
  four_eyes: false,
  require_vex_approval: false,
  require_notice_approval: false,
  require_acknowledgement: false,
  due_soon_lead_minutes: 360,
  early_warning_hours: undefined as number | undefined,
  notification_hours: undefined as number | undefined,
  national_regimes: [] as NationalRegime[],
  use_builtin: true,
  default_rules: [] as IncidentRule[],
  locked_rules: [] as IncidentRule[],
})

const provider = computed(() => route.params.provider as string)
const slug = computed(() => route.params.slug as string)

const ownerKnown = computed(() => {
  const [type, id] = form.owner.split(':')
  return type === 'team' ? teams.value.some(team => team.id === id) : members.value.some(member => member.user_id === id)
})

watch(
  () => [provider.value, slug.value],
  () => {
    if (!provider.value || !slug.value) return
    void load()
  },
  { immediate: true },
)

// Leaving the built-in rules starts from a copy of them.
function onBuiltinToggle() {
  if (!form.use_builtin && form.default_rules.length === 0) {
    form.default_rules = builtinRules.value.map(cleanRule)
  }
}

async function load() {
  loading.value = true
  loadError.value = ''
  try {
    const [settings, memberList, teamList] = await Promise.allSettled([
      incidentsApi.getSettings(provider.value, slug.value),
      api.listOrgMembers(provider.value, slug.value),
      api.listTeams(provider.value, slug.value),
    ])
    if (settings.status === 'rejected') throw settings.reason
    applySettings(settings.value.data.settings)
    builtinRules.value = settings.value.data.builtin_rules ?? []
    members.value = memberList.status === 'fulfilled' ? memberList.value.data : []
    teams.value = teamList.status === 'fulfilled' ? teamList.value.data : []
  } catch (error) {
    loadError.value = errorText(error, 'Failed to load incident settings')
  } finally {
    loading.value = false
  }
}

function applySettings(row: IncidentSettingsRow) {
  const ownerUser = nullUUID(row.owner_id)
  const ownerTeam = nullUUID(row.owner_team_id)
  Object.assign(form, {
    owner: ownerUser ? `user:${ownerUser}` : ownerTeam ? `team:${ownerTeam}` : '',
    four_eyes: row.four_eyes,
    require_vex_approval: row.require_vex_approval,
    require_notice_approval: row.require_notice_approval,
    require_acknowledgement: row.require_acknowledgement,
    due_soon_lead_minutes: row.due_soon_lead_minutes,
    early_warning_hours: row.internal_targets?.early_warning_hours,
    notification_hours: row.internal_targets?.notification_hours,
    national_regimes: (row.national_regimes ?? []).map(regime => ({ ...regime, steps: (regime.steps ?? []).map(step => ({ ...step })) })),
    use_builtin: row.default_rules === null,
    default_rules: (row.default_rules ?? []).map(rule => ({ ...rule })),
    locked_rules: (row.locked_rules ?? []).map(rule => ({ ...rule })),
  })
}

function addRegime() {
  form.national_regimes.push({ code: '', label: '', recipient: '', url: '', steps: [{ name: 'Notification', hours: 72 }] })
}

// v-model.number leaves '' in a cleared field.
function hours(value: number | undefined | string): number | undefined {
  return typeof value === 'number' && Number.isFinite(value) && value > 0 ? value : undefined
}

async function save() {
  saveError.value = ''
  const rules = [...form.locked_rules, ...(form.use_builtin ? [] : form.default_rules)]
  if (rules.some(rule => !rule.match.trim())) {
    saveError.value = 'Every rule needs a match expression'
    return
  }
  const [ownerType, ownerID] = form.owner.split(':')
  saving.value = true
  try {
    const response = await incidentsApi.putSettings(provider.value, slug.value, {
      owner_id: ownerType === 'user' ? ownerID : null,
      owner_team_id: ownerType === 'team' ? ownerID : null,
      four_eyes: form.four_eyes,
      require_vex_approval: form.require_vex_approval,
      require_notice_approval: form.require_notice_approval,
      require_acknowledgement: form.require_acknowledgement,
      due_soon_lead_minutes: Number(form.due_soon_lead_minutes) || 0,
      internal_targets: {
        early_warning_hours: hours(form.early_warning_hours),
        notification_hours: hours(form.notification_hours),
      },
      national_regimes: form.national_regimes.map(regime => ({
        code: regime.code.trim().toLowerCase(),
        label: regime.label.trim(),
        recipient: regime.recipient.trim(),
        url: (regime.url ?? '').trim(),
        steps: regime.steps.map(step => ({ name: step.name.trim(), hours: Number(step.hours) || 0 })),
      })),
      default_rules: form.use_builtin ? null : form.default_rules.map(cleanRule),
      locked_rules: form.locked_rules.map(cleanRule),
    })
    applySettings(response.data)
    toast.success('Incident settings saved')
  } catch (error) {
    saveError.value = errorText(error, 'Failed to save incident settings')
  } finally {
    saving.value = false
  }
}
</script>
