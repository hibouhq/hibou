// The resolution map of an incident (ADR-053), built in the browser from the
// detail the server already sends: the steps a kind of incident goes through,
// one branch per possible decision, each node coloured by what happened to
// it. The nodes mirror the server's derivation (internal/incident/derive.go):
// a node backed by actions is done when they are, a filing node when its
// deadline is met, so the map never disagrees with the Actions list.

import {
  DECISION_STEP_HINTS,
  DECISION_STEP_LABELS,
  DECISION_STEP_SHORT,
  STATE_DESCRIPTIONS,
  STATE_LABELS,
  nullString,
  nullTime,
  type DecisionStep,
  type IncidentAction,
  type IncidentDeadline,
  type IncidentDetail,
} from '@/api/incidents'

import { filingStep, humanize } from './incidentView'

/**
 * done: happened; current: next thing to do, every step before it done;
 * overdue: current and past its due time; remaining: later on the chosen
 * path; possible: on a branch still open (no decision yet); skipped: on a
 * branch the decision did not take; waived: not needed, with a reason.
 */
export type FlowStatus = 'done' | 'current' | 'overdue' | 'remaining' | 'possible' | 'skipped' | 'waived'

export type FlowTab = 'overview' | 'scope' | 'notices' | 'timeline'

export interface FlowNode {
  id: string
  label: string
  /** One sentence on what the step is, for the hover card. */
  detail: string
  status: FlowStatus
  optional: boolean
  /** When it happened (done, waived) or is due (current, remaining). */
  at: string | null
  due: string | null
  /** Who did it, as a user id. */
  by: string | null
  /** Progress of an aggregate node: "3 of 5 done". */
  progress: string
  /** Where a click goes. */
  tab: FlowTab
  anchor: string
  /** Column, from 0. */
  layer: number
  /** Row: branches from 0; the trunk and the close node sit on the middle row. */
  row: number
  /** Branch the node belongs to; empty for the trunk and the close node. */
  branch: string
}

export interface FlowEdge {
  from: string
  to: string
  status: 'done' | 'active' | 'remaining' | 'possible' | 'skipped'
}

export interface FlowBranch {
  id: string
  label: string
  detail: string
  row: number
  /** Whether the decision took this branch; null while undecided. */
  taken: boolean | null
}

export interface Flow {
  nodes: FlowNode[]
  edges: FlowEdge[]
  branches: FlowBranch[]
  layers: number
  rows: number
}

/** A step in a branch template, resolved against the detail. */
interface StepSpec {
  id: string
  label: string
  detail: string
  /** Where the step's status comes from. */
  source:
    | { kind: 'aware' }
    | { kind: 'filing'; step: string }
    | { kind: 'actions'; kinds: string[]; tab?: FlowTab }
    | { kind: 'fix' }
    | { kind: 'close' }
  optional?: boolean
}

interface BranchSpec {
  id: string
  label: string
  detail: string
  steps: StepSpec[]
}

const FILING_DETAIL: Record<string, string> = {
  early_warning: 'Within 24 h of T0: that an actively exploited vulnerability or an incident exists, and the Member States where the product is available.',
  notification: 'Within 72 h of T0: the product, the general nature of the vulnerability or incident, measures taken and measures users can take.',
  final_report: 'A description, severity and impact, the actor where known, and the corrective measures. 14 days after a fix is available for a vulnerability, one month after the notification for an incident.',
  resolve: 'The internal deadline of the rule that opened the incident.',
}

const CLOSE: StepSpec = { id: 'close', label: 'Closed', detail: STATE_DESCRIPTIONS.closed, source: { kind: 'close' } }
const T0: StepSpec = { id: 't0', label: 'T0', detail: 'The moment of awareness: a reasonable degree of certainty after a prompt initial assessment. Every regulatory clock counts from here.', source: { kind: 'aware' } }
const EARLY_WARNING: StepSpec = { id: 'early_warning', label: 'Early warning', detail: FILING_DETAIL.early_warning, source: { kind: 'filing', step: 'early_warning' } }
const NOTIFICATION: StepSpec = { id: 'notification', label: 'Notification', detail: FILING_DETAIL.notification, source: { kind: 'filing', step: 'notification' } }
const FINAL_REPORT: StepSpec = { id: 'final_report', label: 'Final report', detail: FILING_DETAIL.final_report, source: { kind: 'filing', step: 'final_report' } }
const FIX: StepSpec = { id: 'fix', label: 'Fix available', detail: 'A fixed version, or a workaround, exists for every affected version. Starts the final report clock.', source: { kind: 'fix' } }
const VEX: StepSpec = { id: 'vex', label: 'VEX statements', detail: 'One statement per version in scope, recorded from the decision or by hand. Never edited in place: a revision supersedes.', source: { kind: 'actions', kinds: ['vex'], tab: 'scope' } }
const UPSTREAM: StepSpec = { id: 'upstream', label: 'Tell the maintainer', detail: 'A vulnerability you found in a component and the maintainer does not know about yet: report it to them, for the version you integrate, through their disclosure channel (Art. 13(6)).', source: { kind: 'actions', kinds: ['upstream_notice'] } }
const NOTICES_OWED: StepSpec = { id: 'notices', label: 'Inform impacted users', detail: 'Every client running an affected version is told, with the mitigations they can apply (Art. 14(8)); proportionate, not a public disclosure.', source: { kind: 'actions', kinds: ['client_notice'], tab: 'notices' } }
const NOTICES_VOLUNTARY: StepSpec = { ...NOTICES_OWED, label: 'Warn clients (voluntary)', detail: 'Not owed: the vulnerability was not exploited here. Warning the clients that run an affected version is good practice (Art. 15).', optional: true }
const REMEDIATION: StepSpec = { id: 'remediation', label: 'Contain and remediate', detail: 'Stop the attack, remove its means, and attach the evidence.', source: { kind: 'actions', kinds: ['remediation'] } }

function exploitedBranches(detail: IncidentDetail): BranchSpec[] {
  const hasClients = detail.scope.some(row => row.clients.length > 0)
  // Owed upstream only for a vulnerability in a component that its
  // maintainer does not know about yet: a public identifier means they do.
  const component = detail.advisory ? !detail.advisory.first_party && !detail.advisory.public : false
  const step = (id: DecisionStep, steps: StepSpec[]): BranchSpec => ({ id, label: DECISION_STEP_SHORT[id], detail: `${DECISION_STEP_LABELS[id]}. ${DECISION_STEP_HINTS[id]}`, steps })
  const optional = (spec: StepSpec, keep: boolean) => (keep ? [spec] : [])
  return [
    step('not_present', [CLOSE]),
    step('not_reachable', [VEX, ...optional(UPSTREAM, component), CLOSE]),
    step('reachable_no_attack', [VEX, FIX, ...optional(NOTICES_VOLUNTARY, hasClients), ...optional(UPSTREAM, component), CLOSE]),
    step('attacked', [T0, EARLY_WARNING, NOTIFICATION, ...optional(NOTICES_OWED, hasClients), FIX, FINAL_REPORT, CLOSE]),
  ]
}

function stateBranches(detail: IncidentDetail, positive: StepSpec[]): BranchSpec[] {
  const [yes, no] = detail.decision_states
  return [
    { id: yes, label: STATE_LABELS[yes], detail: STATE_DESCRIPTIONS[yes], steps: positive },
    { id: no, label: STATE_LABELS[no], detail: STATE_DESCRIPTIONS[no], steps: [CLOSE] },
  ]
}

function branchesFor(detail: IncidentDetail): BranchSpec[] {
  const hasClients = detail.scope.some(row => row.clients.length > 0)
  const external = detail.incident.regimes.some(regime => regime !== 'internal')
  const filings = external ? [T0, EARLY_WARNING, NOTIFICATION] : []
  switch (detail.incident.kind) {
    case 'exploited_vulnerability':
      return exploitedBranches(detail)
    case 'severe_incident':
      return stateBranches(detail, [...filings, ...(hasClients ? [NOTICES_OWED] : []), REMEDIATION, ...(external ? [FINAL_REPORT] : []), CLOSE])
    case 'secret_leak':
      return stateBranches(detail, [
        { id: 'revoke', label: 'Revoke', detail: 'Revoke the credential at its provider; a validator confirming it dead counts.', source: { kind: 'actions', kinds: ['revoke'] } },
        { id: 'rotate', label: 'Rotate', detail: 'Deploy a new credential, or record why none is needed.', source: { kind: 'actions', kinds: ['rotate'] } },
        { id: 'exposure', label: 'Assess exposure', detail: 'Visibility of the repository, forks, time the secret spent in history.', source: { kind: 'actions', kinds: ['assess_exposure'] } },
        { id: 'remove', label: 'Remove from branches', detail: 'The secret is gone from every branch; a later scan confirms it.', source: { kind: 'actions', kinds: ['remove'] }, optional: true },
        ...(detail.actions.some(action => action.kind === 'notify_owner')
          ? [{ id: 'owner', label: 'Tell the owner', detail: 'The credential belongs to someone else; they are told.', source: { kind: 'actions', kinds: ['notify_owner'] } } satisfies StepSpec]
          : []),
        CLOSE,
      ])
    case 'malware':
      return stateBranches(detail, [
        { id: 'remove_package', label: 'Remove the package', detail: 'The malicious package is gone from every branch.', source: { kind: 'actions', kinds: ['remove_package'] } },
        { id: 'rotate_ci', label: 'Rotate CI secrets', detail: 'Every secret the package could read during a build is rotated.', source: { kind: 'actions', kinds: ['rotate_ci_secrets'] } },
        { id: 'registry', label: 'Report to the registry', detail: 'The package is reported to its registry for takedown.', source: { kind: 'actions', kinds: ['report_registry'] } },
        ...(hasClients ? [NOTICES_OWED] : []),
        ...filings.filter(spec => spec.id !== 't0'),
        CLOSE,
      ])
    case 'policy_breach':
      return stateBranches(detail, [
        { id: 'remediate', label: 'Fix or exception', detail: 'Fix the finding, or record an approved exception, before the rule\'s deadline.', source: { kind: 'actions', kinds: ['remediate'] } },
        CLOSE,
      ])
  }
}

/** The decision the incident carries, as the id of the branch it took; null while undecided. */
export function takenBranch(detail: IncidentDetail): string | null {
  const incident = detail.incident
  if (incident.state === 'withdrawn') return null
  if (incident.kind === 'exploited_vulnerability') {
    return nullString(incident.decision_step) || null
  }
  const decided = incident.decided_state?.valid ? incident.decided_state.incident_state : null
  if (decided) return decided
  const [yes, no] = detail.decision_states
  if (incident.state === yes || incident.state === no) return incident.state
  return null
}

interface Resolved {
  status: FlowStatus
  at: string | null
  due: string | null
  by: string | null
  progress: string
  anchor: string
  tab: FlowTab
}

function current(actions: IncidentAction[]): IncidentAction[] {
  return actions.filter(action => !action.obsolete)
}

function resolveActions(detail: IncidentDetail, kinds: string[], tab: FlowTab | undefined, now: number): Resolved {
  const actions = current(detail.actions).filter(action => kinds.includes(action.kind))
  // No action derived yet (before the decision, or before the step it
  // depends on): the step is still ahead.
  if (actions.length === 0) return { status: 'remaining', at: null, due: null, by: null, progress: '', anchor: '', tab: tab ?? 'overview' }
  const done = actions.filter(action => action.state !== 'pending')
  const pending = actions.filter(action => action.state === 'pending')
  const first = pending[0] ?? actions[0]
  const resolved: Resolved = {
    status: 'current',
    at: null,
    due: null,
    by: null,
    progress: actions.length > 1 ? `${done.length} of ${actions.length} done` : '',
    anchor: `action-${first.id}`,
    tab: tab ?? 'overview',
  }
  if (pending.length === 0) {
    const waived = done.every(action => action.state === 'waived')
    const last = [...done].sort((a, b) => (nullTime(a.done_at) ?? a.created_at).localeCompare(nullTime(b.done_at) ?? b.created_at)).at(-1)!
    resolved.status = waived ? 'waived' : 'done'
    resolved.at = nullTime(last.done_at) ?? last.created_at
    resolved.by = last.done_by ?? last.waived_by
    return resolved
  }
  const dues = pending.map(action => nullTime(action.due_at)).filter((value): value is string => value !== null).sort()
  resolved.due = dues[0] ?? null
  if (resolved.due && new Date(resolved.due).getTime() < now) resolved.status = 'overdue'
  return resolved
}

function regulatory(deadlines: IncidentDeadline[], step: string): IncidentDeadline[] {
  return deadlines.filter(deadline => deadline.regime !== 'internal' && deadline.step === step).sort((a, b) => a.due_at.localeCompare(b.due_at))
}

function resolveFiling(detail: IncidentDetail, step: string, now: number): Resolved {
  const rows = regulatory(detail.deadlines, step)
  const actions = current(detail.actions).filter(action => action.subject_type === 'regime' && filingStep(action.kind, detail.regimes) === step)
  const anchor = actions.find(action => action.state === 'pending') ?? actions[0]
  const resolved: Resolved = { status: 'remaining', at: null, due: null, by: null, progress: '', anchor: anchor ? `action-${anchor.id}` : '', tab: 'overview' }
  if (rows.length === 0) return anchor ? resolveActions(detail, [anchor.kind], 'overview', now) : resolved
  const met = rows.filter(row => nullTime(row.met_at) !== null)
  if (rows.length > 1) resolved.progress = `${met.length} of ${rows.length} regimes`
  if (met.length === rows.length) {
    resolved.status = 'done'
    resolved.at = met.map(row => nullTime(row.met_at)!).sort().at(-1)!
    resolved.by = anchor?.done_by ?? null
    return resolved
  }
  const open = rows.filter(row => nullTime(row.met_at) === null)
  resolved.status = 'current'
  resolved.due = open[0].due_at
  if (new Date(resolved.due).getTime() < now) resolved.status = 'overdue'
  return resolved
}

function resolveStep(spec: StepSpec, detail: IncidentDetail, now: number): Resolved {
  const incident = detail.incident
  switch (spec.source.kind) {
    case 'aware': {
      const at = nullTime(incident.aware_at)
      return { status: at ? 'done' : 'current', at, due: null, by: at ? incident.decided_by : null, progress: '', anchor: 'incident-decision', tab: 'overview' }
    }
    case 'filing':
      return resolveFiling(detail, spec.source.step, now)
    case 'actions':
      return resolveActions(detail, spec.source.kinds, spec.source.tab, now)
    case 'fix': {
      const at = nullTime(incident.fix_available_at)
      if (at) return { status: 'done', at, due: null, by: null, progress: '', anchor: 'incident-fix', tab: 'overview' }
      const fromActions = resolveActions(detail, ['fix_release'], 'overview', now)
      return { ...fromActions, status: fromActions.status === 'remaining' ? 'current' : fromActions.status, anchor: 'incident-fix' }
    }
    case 'close': {
      const at = nullTime(incident.closed_at)
      return { status: at ? 'done' : 'remaining', at, due: null, by: null, progress: '', anchor: '', tab: 'timeline' }
    }
  }
}

/** Builds the map. `now` decides what is overdue. */
export function buildFlow(detail: IncidentDetail, now = Date.now()): Flow {
  const incident = detail.incident
  const specs = branchesFor(detail)
  const taken = takenBranch(detail)
  const decided = taken !== null || incident.state === 'withdrawn'
  const middle = (specs.length - 1) / 2
  const nodes: FlowNode[] = []
  const edges: FlowEdge[] = []

  const rule = nullString(incident.trigger_rule)
  nodes.push({
    id: 'signal', label: 'Signal',
    detail: rule ? `Opened by the rule ${rule}.` : `Opened from ${humanize(incident.signal_source).toLowerCase()}.`,
    status: 'done', optional: false, at: incident.signal_at, due: null, by: incident.created_by, progress: '', tab: 'timeline', anchor: '', layer: 0, row: middle, branch: '',
  })

  const proposed = incident.proposed_decision
  const decidedAt = nullTime(incident.decided_at)
  nodes.push({
    id: 'decision',
    label: incident.state === 'withdrawn' ? 'Withdrawn' : proposed && !decided ? 'Decision proposed' : 'Decision',
    detail: incident.state === 'withdrawn'
      ? STATE_DESCRIPTIONS.withdrawn
      : taken
        ? `${specs.find(spec => spec.id === taken)?.label ?? humanize(taken)}${nullString(incident.decision_reason) ? ` — ${nullString(incident.decision_reason)}` : ''}`
        : proposed
          ? `Waiting for a second person to approve: ${specs.find(spec => spec.id === (proposed.decision_step || proposed.state))?.label ?? humanize(proposed.decision_step || proposed.state)}.`
          : 'Which path the incident takes. One decision per incident; it answers for the product.',
    status: decided ? 'done' : 'current',
    optional: false,
    at: incident.state === 'withdrawn' ? nullTime(incident.closed_at) : decidedAt,
    due: null,
    by: decided ? incident.decided_by : null,
    progress: '',
    tab: 'overview',
    anchor: 'incident-decision',
    layer: 1,
    row: middle,
    branch: '',
  })
  edges.push({ from: 'signal', to: 'decision', status: 'done' })

  const branches: FlowBranch[] = []
  let longest = 0
  specs.forEach((spec, row) => {
    const branchTaken = decided ? spec.id === taken : null
    branches.push({ id: spec.id, label: spec.label, detail: spec.detail, row, taken: branchTaken })
    let previous = 'decision'
    let blocked = false
    let layer = 2
    for (const step of spec.steps) {
      if (step.source.kind === 'close') continue
      const resolved = resolveStep(step, detail, now)
      let status: FlowStatus = resolved.status
      if (branchTaken === false) status = 'skipped'
      else if (branchTaken === null && status !== 'done' && status !== 'waived') status = 'possible'
      else if (status === 'current' || status === 'overdue') {
        // Only the first open step of the path is "current"; the ones after
        // it wait, unless they are already late.
        if (blocked && status === 'current') status = 'remaining'
        blocked = true
      }
      const id = `${spec.id}.${step.id}`
      nodes.push({
        id, label: step.label, detail: step.detail, status, optional: step.optional ?? false,
        at: resolved.at, due: resolved.due, by: resolved.by, progress: resolved.progress,
        tab: resolved.tab, anchor: resolved.anchor, layer, row, branch: spec.id,
      })
      edges.push({ from: previous, to: id, status: edgeStatus(nodeStatus(nodes, previous), status) })
      previous = id
      layer++
    }
    longest = Math.max(longest, layer)
    if (spec.steps.some(step => step.source.kind === 'close')) {
      const closeStatus: FlowStatus = branchTaken === false ? 'skipped' : branchTaken === null ? 'possible' : incident.state === 'closed' ? 'done' : 'remaining'
      edges.push({ from: previous, to: 'close', status: edgeStatus(nodeStatus(nodes, previous), closeStatus) })
    }
  })

  const close = resolveStep(CLOSE, detail, now)
  nodes.push({
    id: 'close', label: incident.state === 'withdrawn' ? 'Closed' : CLOSE.label, detail: CLOSE.detail,
    status: incident.state === 'closed' || incident.state === 'withdrawn' ? 'done' : decided ? 'remaining' : 'possible',
    optional: false, at: close.at, due: null, by: null, progress: '', tab: 'timeline', anchor: '', layer: longest, row: middle, branch: '',
  })
  if (incident.state === 'withdrawn') {
    edges.push({ from: 'decision', to: 'close', status: 'done' })
  }

  return { nodes, edges, branches, layers: longest + 1, rows: specs.length }
}

function nodeStatus(nodes: FlowNode[], id: string): FlowStatus {
  return nodes.find(node => node.id === id)?.status ?? 'remaining'
}

function edgeStatus(from: FlowStatus, to: FlowStatus): FlowEdge['status'] {
  if (to === 'skipped' || from === 'skipped') return 'skipped'
  if (to === 'possible') return 'possible'
  if (to === 'done' || to === 'waived') return 'done'
  if (to === 'current' || to === 'overdue') return 'active'
  return 'remaining'
}

/** One word per status, for the legend and the hover card. */
export const FLOW_STATUS_LABELS: Record<FlowStatus, string> = {
  done: 'done',
  waived: 'waived',
  current: 'now',
  overdue: 'overdue',
  remaining: 'later',
  possible: 'possible',
  skipped: 'not taken',
}
