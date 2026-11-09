// One displayed vocabulary for finding triage.
//
// A finding carries two independent axes (ADR-023): the machine-owned
// observation status (detected/resolved/suppressed, which dies with its
// snapshot) and an optional fingerprint-keyed acceptance — the human decision,
// which survives snapshots. Every view derives one displayed state from here.

import type { AcceptanceReasonKind, FindingAcceptance, FindingDispute, VexJustification, Vulnerability } from '@/api/client'
import { isComponentBacked } from '@/lib/findingDisplay'

export type TriageState = 'open' | 'accepted_risk' | 'false_positive' | 'fixed' | 'suppressed' | 'disputed'

export interface TriageStateInfo {
  state: TriageState
  label: string
  /** One line explaining what the state means, for tooltips and the dialog. */
  description: string
  badgeClass: string
  /** Whether findings in this state still count against the quality gate. */
  countsAgainstGate: boolean
  /** True when a human decided this, as opposed to the scanner reporting it. */
  humanDecision: boolean
}

const STATES: Record<TriageState, TriageStateInfo> = {
  open: {
    state: 'open',
    label: 'Open',
    description: 'Not triaged yet.',
    badgeClass: 'border-amber-500/40 bg-amber-500/10 text-amber-300',
    countsAgainstGate: true,
    humanDecision: false,
  },
  accepted_risk: {
    state: 'accepted_risk',
    label: 'Risk accepted',
    description: 'Real, but deliberately not being fixed now. Suppressed from the quality gate; still counts as risk.',
    badgeClass: 'whitespace-nowrap border-amber-500/40 bg-amber-500/10 text-amber-300',
    countsAgainstGate: false,
    humanDecision: true,
  },
  false_positive: {
    state: 'false_positive',
    label: 'False positive',
    description: 'Not a real issue. Suppressed from the quality gate and excluded from risk reporting.',
    badgeClass: 'whitespace-nowrap border-surface-border bg-surface-overlay text-gray-400',
    countsAgainstGate: false,
    humanDecision: true,
  },
  fixed: {
    state: 'fixed',
    label: 'Fixed',
    description: 'No longer present in the latest scan.',
    badgeClass: 'border-ok/40 bg-ok/10 text-ok',
    countsAgainstGate: false,
    humanDecision: false,
  },
  suppressed: {
    state: 'suppressed',
    label: 'Suppressed',
    description: 'Excluded by the scanner itself (in-source suppression), not a Hibou decision.',
    badgeClass: 'whitespace-nowrap border-surface-border bg-surface-overlay text-gray-500',
    countsAgainstGate: false,
    humanDecision: false,
  },
  disputed: {
    state: 'disputed',
    label: 'Disputed',
    description: 'The in-source suppression is contested (ADR-026): the finding counts as open until the directive is removed or the dispute withdrawn.',
    badgeClass: 'whitespace-nowrap border-danger/40 bg-danger/10 text-danger',
    countsAgainstGate: true,
    humanDecision: true,
  },
}

/** An acceptance past its expiry no longer suppresses anything. */
export function isAcceptanceActive(acceptance: FindingAcceptance | null | undefined, now = new Date()): boolean {
  if (!acceptance) return false
  if (!acceptance.expires_at) return true
  const expiry = new Date(acceptance.expires_at)
  return Number.isNaN(expiry.getTime()) ? true : expiry > now
}

/**
 * triageState derives the single displayed state.
 *
 * A human decision (the acceptance) wins over the scanner's enum, because it is
 * the durable fingerprint-keyed one — that is why the table exists. An expired
 * acceptance is ignored, so suppression can never outlive its stated window.
 */
export function triageState(
  vulnerability: Pick<Vulnerability, 'status'>,
  acceptance?: FindingAcceptance | null,
  now = new Date(),
  dispute?: FindingDispute | null,
): TriageStateInfo {
  if (isAcceptanceActive(acceptance, now)) {
    return acceptance!.reason_kind === 'false_positive' ? STATES.false_positive : STATES.accepted_risk
  }
  switch ((vulnerability.status ?? '').toLowerCase()) {
    case 'resolved':
      return STATES.fixed
    case 'suppressed':
      // A dispute (ADR-026) overrides the scanner's suppression: the human
      // axis wins the display exactly as an acceptance does for open findings.
      return dispute ? STATES.disputed : STATES.suppressed
    default:
      return STATES.open
  }
}

export function triageStateInfo(state: TriageState): TriageStateInfo {
  return STATES[state]
}

/**
 * The Accept ▾ split-button menu (ADR-023): one decision, the menu carries
 * the justification. Default (main click) = risk accepted.
 */
export const ACCEPT_KINDS = [
  {
    kind: 'risk_accepted' as const,
    label: 'Accept risk',
    resulting: 'accepted_risk' as TriageState,
  },
  {
    kind: 'false_positive' as const,
    label: 'False positive',
    resulting: 'false_positive' as TriageState,
  },
]

/**
 * Whether a decision on this finding writes a VEX statement (ADR-053 §4a): it
 * needs a vulnerability identifier on a component. Code and secret findings
 * name a rule, not a CVE, and keep the free reason only.
 */
export function triageMakesStatement(finding: Pick<Vulnerability, 'type' | 'advisory_id'> | null | undefined): boolean {
  return Boolean(finding && isComponentBacked(finding.type) && finding.advisory_id)
}

/** Common reasons, offered as one-click prefills that stay editable. */
export const REASON_PRESETS: Record<string, string[]> = {
  risk_accepted: [
    'Risk accepted by the team for this release',
    'Fix scheduled — tracked separately',
    'No upstream fix available yet',
  ],
  false_positive: [
    'Intentional test fixture, not production code',
    'Scanner misidentified the pattern',
    'Value is a placeholder, not a real credential',
  ],
}

/** Presets of the "Not affected" VEX decision: the evidence detail. */
export const NOT_AFFECTED_PRESETS = [
  'Not exploitable in this context',
  'The vulnerable function is never called',
  'Input to the vulnerable code is not attacker-controlled',
]

/** The presets offered for a decision; `statement` selects the VEX wording. */
export function reasonPresets(kind: AcceptanceReasonKind, statement: boolean): string[] {
  if (statement && kind === 'false_positive') return NOT_AFFECTED_PRESETS
  return REASON_PRESETS[kind] ?? []
}

/**
 * The CISA/OpenVEX justifications of a not_affected statement. The first two
 * say the detection is wrong; the last three that it is right but not
 * exploitable in this product.
 */
export const VEX_JUSTIFICATIONS = [
  { value: 'component_not_present', label: 'Component not present', hint: 'The package is not in the product: the detection is wrong.' },
  { value: 'vulnerable_code_not_present', label: 'Vulnerable code not present', hint: 'This version or build does not include the flawed code.' },
  { value: 'vulnerable_code_not_in_execute_path', label: 'Vulnerable code never runs', hint: 'The code is shipped but no execution path reaches it.' },
  { value: 'vulnerable_code_cannot_be_controlled_by_adversary', label: 'Attacker cannot reach it', hint: 'The code runs, but an adversary cannot control its input.' },
  { value: 'inline_mitigations_already_exist', label: 'Already mitigated', hint: 'A control in the product blocks exploitation.' },
] as const satisfies ReadonlyArray<{ value: VexJustification; label: string; hint: string }>

export interface TriageDecisionInput {
  kind: AcceptanceReasonKind
  /** The decision writes a VEX statement for at least one finding. */
  statement: boolean
  /** A justification is required (statement known), not just offered. */
  justificationRequired: boolean
  justification: '' | VexJustification
  reason: string
  expiresAt: string
  expiryRequired: boolean
}

/**
 * What still blocks a triage decision, or '' when it can be submitted. A
 * not-affected statement needs its justification; an affected one, its action
 * statement; and the expiry is required where the caller says so (an
 * exploited advisory, a live credential).
 */
export function triageDecisionProblem(input: TriageDecisionInput): string {
  const reason = input.reason.trim()
  if (input.statement && input.kind === 'false_positive') {
    if (input.justificationRequired && !input.justification) return 'Pick the justification of the not-affected statement.'
    if (!input.justification && !reason) return 'Pick a justification or give a reason.'
  } else if (!reason) {
    return input.statement ? 'The action statement is required.' : 'A reason is required.'
  }
  if (input.kind === 'risk_accepted' && input.expiryRequired && !input.expiresAt) return 'An expiry is required.'
  return ''
}

/** What the triage dialog emits on confirm. */
export interface TriageConfirmPayload {
  /** The decision taken; the VEX question may change the kind the dialog opened with. */
  kind: AcceptanceReasonKind
  reason: string
  labels: string[]
  vexJustification?: VexJustification
  expiresAt?: string
}
