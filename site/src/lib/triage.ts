// One displayed vocabulary for finding triage.
//
// A finding carries two independent states: the scanner's `status` enum
// (detected/confirmed/dismissed/resolved, which dies with its snapshot) and an
// optional fingerprint-keyed acceptance (accepted/false_positive, which
// survives snapshots). Showing both is what made the UI confusing, so every
// view derives a single state from here instead.

import type { FindingAcceptance, Vulnerability } from '@/api/client'

export type TriageState = 'open' | 'confirmed' | 'accepted_risk' | 'false_positive' | 'fixed'

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
  confirmed: {
    state: 'confirmed',
    label: 'Confirmed',
    description: 'A real issue, to be fixed.',
    badgeClass: 'border-danger/40 bg-danger/10 text-danger',
    countsAgainstGate: true,
    humanDecision: true,
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
): TriageStateInfo {
  if (isAcceptanceActive(acceptance, now)) {
    return acceptance!.reason_kind === 'false_positive' ? STATES.false_positive : STATES.accepted_risk
  }
  switch ((vulnerability.status ?? '').toLowerCase()) {
    case 'confirmed':
      return STATES.confirmed
    case 'resolved':
      return STATES.fixed
    // Legacy rows predating the acceptance table used the enum for suppression;
    // they read as accepted risk so history stays truthful without a migration.
    case 'dismissed':
      return STATES.accepted_risk
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

/** Common reasons, offered as one-click prefills that stay editable. */
export const REASON_PRESETS: Record<string, string[]> = {
  risk_accepted: [
    'Not exploitable in this context',
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

/** The CISA/OpenVEX justifications, offered for dependency false-positives. */
export const VEX_JUSTIFICATIONS = [
  { value: 'component_not_present', label: 'Component not present' },
  { value: 'vulnerable_code_not_present', label: 'Vulnerable code not present' },
  { value: 'vulnerable_code_not_in_execute_path', label: 'Vulnerable code not in execute path' },
  { value: 'vulnerable_code_cannot_be_controlled_by_adversary', label: 'Code cannot be controlled by adversary' },
  { value: 'inline_mitigations_already_exist', label: 'Inline mitigations already exist' },
] as const
