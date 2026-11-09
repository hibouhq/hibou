// Incidents (ADR-053): types and calls for the incident API, the client
// delivery settings, the repository's rules and first-party advisories, and
// Home. Nullable columns of the incident tables arrive as {…, Valid}
// wrappers; the helpers at the bottom unwrap them.

import { apiRequest, type ApiResponse, type PaginatedResponse, type SqlNullTime } from '@/api/client'

/** uuid.NullUUID marshals as the id or null, unlike the sql.Null* wrappers. */
export type NullableUUID = string | null

export interface SqlNullString {
  String: string
  Valid: boolean
}

export interface SqlNullInt64 {
  Int64: number
  Valid: boolean
}

export type IncidentKind = 'exploited_vulnerability' | 'severe_incident' | 'secret_leak' | 'malware' | 'policy_breach'
export type IncidentState = 'signal' | 'assessing' | 'reportable' | 'not_reportable' | 'confirmed' | 'dismissed' | 'closed' | 'withdrawn'
export type IncidentPriority = 'P1' | 'P2' | 'P3'
export type DecisionStep = 'not_present' | 'not_reachable' | 'reachable_no_attack' | 'attacked'

export const INCIDENT_KINDS: IncidentKind[] = ['exploited_vulnerability', 'severe_incident', 'secret_leak', 'malware', 'policy_breach']
export const SIGNAL_SOURCES = ['customer', 'csirt', 'researcher', 'internal', 'other', 'kev', 'euvd', 'epss', 'trigger'] as const

export const KIND_LABELS: Record<IncidentKind, string> = {
  exploited_vulnerability: 'Exploited vulnerability',
  severe_incident: 'Security incident (CRA Art. 14(3))',
  secret_leak: 'Secret leak',
  malware: 'Malicious package',
  policy_breach: 'Policy breach',
}

export const STATE_LABELS: Record<IncidentState, string> = {
  signal: 'Signal',
  assessing: 'Assessing',
  reportable: 'Reportable',
  not_reportable: 'Not reportable',
  confirmed: 'Confirmed',
  dismissed: 'Dismissed',
  closed: 'Closed',
  withdrawn: 'Withdrawn',
}

/** One short sentence per kind, for hovers and menus. */
export const KIND_DESCRIPTIONS: Record<IncidentKind, string> = {
  exploited_vulnerability: 'A vulnerability known to be exploited, present in a version you ship (CRA Art. 14(1)).',
  severe_incident: 'An attack on your product itself, e.g. a build, signing key or update server compromised (CRA Art. 14(3)).',
  secret_leak: 'A credential exposed in a repository; revoke and rotate it.',
  malware: 'A malicious package in your dependencies.',
  policy_breach: "A finding crossing your organization's own rule, with an internal deadline.",
}

/** One short sentence per state, for hovers. */
export const STATE_DESCRIPTIONS: Record<IncidentState, string> = {
  signal: 'Opened, not yet decided.',
  assessing: 'Being assessed; no decision yet.',
  reportable: 'Decided: must be reported to the authorities; clocks run from T0.',
  not_reportable: 'Decided: no report owed; remaining actions still apply.',
  confirmed: 'Decided: real, handled internally.',
  dismissed: 'Decided: not a real issue.',
  closed: 'Every required action is done or waived.',
  withdrawn: 'Opened in error, duplicate or wrong advisory; terminal.',
}

/** One short sentence per priority, for hovers. */
export const PRIORITY_DESCRIPTIONS: Record<string, string> = {
  P1: 'Urgent: handle now.',
  P2: 'Important: handle within the internal deadline.',
  P3: 'Routine: handle in normal work.',
}

/** Hovers for the other statuses a pill shows (scope rows, actions, deliveries). */
export const STATUS_DESCRIPTIONS: Record<string, string> = {
  pending: 'Still to do.',
  done: 'Completed.',
  waived: 'Not needed, with an approved reason.',
  affected: 'This version is affected.',
  not_affected: 'This version is not affected; a VEX statement says why.',
  fixed: 'This version contains the fix.',
  under_investigation: 'Still being analysed.',
  unknown: 'No inventory for this version yet; blocks closure.',
  excluded: 'Left out of scope, with a reason.',
  sent: 'Handed to the channel.',
  acknowledged: 'The client confirmed receipt.',
  failed: 'Sending failed.',
  proposed: 'Waiting for a second person to approve.',
}

/**
 * The exploited-vulnerability ladder, after the Commission guidance on the CRA
 * (C(2026) 5252, §218): a third-party vulnerability is reportable only when
 * it is in a shipped version, can be exploited in the product, and has been
 * exploited in the product. Each earlier exit is a VEX statement.
 */
export const DECISION_STEP_LABELS: Record<DecisionStep, string> = {
  not_present: 'No shipped version integrates the vulnerable version',
  not_reachable: 'Present, but it cannot be exploited in our product',
  reachable_no_attack: 'Exploitable in our product, no reliable evidence it was exploited here',
  attacked: 'Reliable evidence it was exploited in our product',
}

/** The steps in three words, for the resolution map's rows. */
export const DECISION_STEP_SHORT: Record<DecisionStep, string> = {
  not_present: 'Not in our product',
  not_reachable: 'Not exploitable here',
  reachable_no_attack: 'Exploitable, not exploited here',
  attacked: 'Exploited in our product',
}

/** What each step means, one sentence, for hovers and the form. */
export const DECISION_STEP_HINTS: Record<DecisionStep, string> = {
  not_present: 'Not reportable to the CSIRT. Nothing owed to clients or to the maintainer.',
  not_reachable: 'Not reportable to the CSIRT: e.g. the vulnerable code is not reachable, its input is not attacker-controlled, or a mitigation blocks it. Nothing owed to clients. Tell the maintainer unless they already know.',
  reachable_no_attack: 'Not reportable to the CSIRT (a voluntary report is possible, Art. 15). Fix without delay and advise the clients that run it with the fix. Tell the maintainer if you found or patched it.',
  attacked: 'Reportable to the CSIRT: T0 starts the clocks (early warning 24 h, notification 72 h, final report 14 days after the fix). Impacted clients must be informed (Art. 14(8)).',
}

/** The VEX justifications a "cannot be exploited here" step may carry. */
export const NOT_EXPLOITABLE_JUSTIFICATIONS: { value: string; label: string }[] = [
  { value: 'vulnerable_code_not_in_execute_path', label: 'the vulnerable code never runs' },
  { value: 'vulnerable_code_cannot_be_controlled_by_adversary', label: 'an attacker cannot control its input' },
  { value: 'inline_mitigations_already_exist', label: 'a mitigation in the product blocks it' },
  { value: 'vulnerable_code_not_present', label: 'this build does not include the flawed code' },
]

/** The VEX statement a step means for the releases in scope, as "status · justification". */
export function stepVEX(step: DecisionStep | '', justification = ''): string {
  switch (step) {
    case 'not_present':
      return 'not_affected · component_not_present'
    case 'not_reachable':
      return `not_affected · ${justification || 'vulnerable_code_not_in_execute_path'}`
    case 'reachable_no_attack':
    case 'attacked':
      return 'affected'
    default:
      return ''
  }
}

/** Only the last step ends in a mandatory report. */
export function stepReportable(step: DecisionStep | ''): boolean {
  return step === 'attacked'
}

export interface Incident {
  id: string
  org_id: string
  number: number
  repo_id: NullableUUID
  kind: IncidentKind
  regimes: string[]
  subject_type: string
  subject_id: string
  title: string
  state: IncidentState
  priority: IncidentPriority
  signal_source: string
  trigger_rule: SqlNullString
  signal_at: string
  aware_at: SqlNullTime
  decision_reason: SqlNullString
  decision_step: SqlNullString
  decided_by: NullableUUID
  decided_at: SqlNullTime
  decided_state: { incident_state: IncidentState; valid: boolean } | null
  proposed_decision: IncidentDecisionInput | null
  proposed_merge: MergeProposal | null
  fix_available_at: SqlNullTime
  owner_id: NullableUUID
  owner_team_id: NullableUUID
  /** The incident's ticket or link, free text; autolinked. */
  external_ref: string
  due_at: SqlNullTime
  target_seconds: SqlNullInt64
  merged_into: NullableUUID
  closed_at: SqlNullTime
  created_by: NullableUUID
  created_at: string
  updated_at: string
}

export interface IncidentSummary extends Incident {
  repo_slug?: string
  repo_name?: string
  kind_label: string
}

export interface IncidentClientRef {
  id: string
  name: string
  slug: string
}

export interface IncidentScopeRow {
  incident_id: string
  subject_type: 'release' | 'ref' | 'client' | string
  subject_id: string
  label: string
  status: string
  reason: string
  component_purl: string
  vex_statement_id: NullableUUID
  reachability: SqlNullString
  manual: boolean
  decided_by: NullableUUID
  decided_at: SqlNullTime
  updated_at: string
  clients: IncidentClientRef[]
}

export interface IncidentAction {
  id: string
  incident_id: string
  kind: string
  subject_type: string
  subject_id: string
  label: string
  automatic: boolean
  optional: boolean
  obsolete: boolean
  due_at: SqlNullTime
  state: 'pending' | 'done' | 'waived'
  assignee_id: NullableUUID
  done_at: SqlNullTime
  done_by: NullableUUID
  evidence: Record<string, unknown>
  waived_by: NullableUUID
  waived_reason: SqlNullString
  created_at: string
}

export interface IncidentDeadline {
  incident_id: string
  regime: string
  step: string
  due_at: string
  met_at: SqlNullTime
  reference: string
  notified: string
}

export interface DocumentRef {
  kind: string
  filename: string
  content_type: string
  sha256: string
  size: number
}

export interface IncidentDelivery {
  id: string
  incident_id: string
  client_id: NullableUUID
  action_id: NullableUUID
  channel: 'email' | 'webhook' | 'portal' | 'manual'
  recipient: string
  documents: DocumentRef[]
  approved_by: NullableUUID
  approved_at: SqlNullTime
  status: 'pending_approval' | 'sent' | 'failed' | 'acknowledged'
  error: string
  provider_ref: string
  created_by: NullableUUID
  created_at: string
  sent_at: SqlNullTime
  acknowledged_at: SqlNullTime
  ack_evidence: Record<string, unknown>
  audit_log_id: NullableUUID
  client_name: SqlNullString
  client_slug: SqlNullString
}

export interface IncidentEvent {
  id: string
  incident_id: string
  at: string
  actor_id: NullableUUID
  actor_type: string
  actor_display: string
  kind: string
  detail: Record<string, unknown>
}

export interface IncidentTrackerLink {
  incident_id: string
  integration_id: string
  external_key: string
  external_url: string
  synced_events: number
  last_synced_at: SqlNullTime
  last_error: string
  integration_name: string
  integration_type: string
}

export interface RegimeStep {
  step: string
  label: string
  anchor: string
  after: string
  filing?: string
  recipient?: string
  url?: string
}

export interface Regime {
  name: string
  label: string
  steps: RegimeStep[]
}

export interface IncidentDetail {
  incident: IncidentSummary
  decision_states: [IncidentState, IncidentState]
  decision_steps?: DecisionStep[]
  scope: IncidentScopeRow[]
  actions: IncidentAction[]
  deadlines: IncidentDeadline[]
  deliveries: IncidentDelivery[]
  events: IncidentEvent[]
  tracker_links: IncidentTrackerLink[]
  regimes: Regime[]
  settings: {
    four_eyes: boolean
    require_vex_approval: boolean
    require_notice_approval: boolean
    require_acknowledgement: boolean
  }
  can_manage: boolean
  advisory?: {
    id: string
    canonical_id: string
    aliases: string[]
    title: string
    first_party: boolean
    /** Has a public identifier: the component's maintainer already knows (guidance §223). */
    public: boolean
  }
}

export interface IncidentDecisionInput {
  state: IncidentState
  reason: string
  aware_at?: string
  decision_step?: DecisionStep | ''
  /** VEX justification of a "cannot be exploited here" step. */
  justification?: string
  /** VEX action statement of an affected step: what users can do. */
  action_statement?: string
  /** Record the step as the VEX statement of the releases in scope without one. */
  write_statements?: boolean
  proposed_by?: string
  proposed_at?: string
}

export interface OpenIncidentInput {
  kind: IncidentKind
  repo_slug?: string
  title?: string
  priority?: IncidentPriority
  signal_source: string
  regimes?: string[]
  vulnerability_id?: string
  finding_id?: string
  note?: string
  release_ids?: string[]
  client_ids?: string[]
}

export interface IncidentStatementInput {
  release_id?: string
  version_range?: string
  component_purl?: string
  status: 'not_affected' | 'affected' | 'fixed' | 'under_investigation'
  justification?: string
  impact_statement?: string
  action_statement?: string
  evidence?: string
}

export interface DeliverInput {
  client_ids: string[]
  channel?: 'email' | 'webhook' | 'portal' | 'manual' | ''
  measures?: string
  evidence?: string
  recipient?: string
}

export interface FilingDraft {
  step: string
  fields: { label: string; value: string }[]
  text: string
}

export interface VerifyResult {
  delivery_id: string
  verified: boolean
  documents: { sha256: string; kind?: string; stored_matches_digest: boolean; rerendered_matches?: boolean; note?: string; error?: string }[]
}

export interface IncidentRule {
  match: string
  kind?: IncidentKind | ''
  refs?: string[]
  regimes?: string[]
  priority?: IncidentPriority | ''
  due?: string
  locked?: boolean
  source?: 'org-locked' | 'repo' | 'org' | 'builtin'
}

export interface NationalRegime {
  code: string
  label: string
  recipient: string
  url?: string
  steps: { name: string; hours: number }[]
}

export interface IncidentSettingsRow {
  org_id: string
  owner_id: NullableUUID
  owner_team_id: NullableUUID
  default_rules: IncidentRule[] | null
  locked_rules: IncidentRule[]
  internal_targets: { early_warning_hours?: number; notification_hours?: number }
  national_regimes: NationalRegime[]
  require_vex_approval: boolean
  require_notice_approval: boolean
  require_acknowledgement: boolean
  four_eyes: boolean
  due_soon_lead_minutes: number
  updated_at: string
}

export interface IncidentSettingsResponse {
  settings: IncidentSettingsRow
  builtin_rules: IncidentRule[]
  kinds: IncidentKind[]
  regimes: string[]
}

export interface IncidentSettingsInput {
  owner_id?: string | null
  owner_team_id?: string | null
  default_rules?: IncidentRule[] | null
  locked_rules: IncidentRule[]
  internal_targets: { early_warning_hours?: number; notification_hours?: number }
  national_regimes: NationalRegime[]
  require_vex_approval: boolean
  require_notice_approval: boolean
  require_acknowledgement: boolean
  four_eyes: boolean
  due_soon_lead_minutes: number
}

export interface SecurityContact {
  name?: string
  email: string
  role?: string
}

export interface ClientDelivery {
  security_contacts: SecurityContact[]
  channel: '' | 'email' | 'webhook' | 'portal' | 'manual'
  webhook_url?: string
  webhook_secret_set: boolean
  effective_channel: 'email' | 'webhook' | 'portal' | 'manual'
}

export interface ClientDeliveryInput {
  security_contacts: SecurityContact[]
  channel: '' | 'email' | 'webhook' | 'portal' | 'manual'
  webhook_url?: string
  webhook_secret?: string
}

export interface PortalToken {
  id: string
  name: string
  created_at: string
  last_used_at?: string
  revoked: boolean
}

export interface ClientIncidentDelivery extends Omit<IncidentDelivery, 'client_name' | 'client_slug'> {
  incident_number: number
  incident_title: string
  incident_kind: IncidentKind
  incident_state: IncidentState
}

export interface RepoIncidentRules {
  rules: IncidentRule[]
  product: { PURL: string; Name: string; CPE: string }
  owner?: string
}

export interface FirstPartyAdvisory {
  id: string
  org_id: string
  repo_id: string
  advisory_id: string
  product_purl: string
  product_cpe: SqlNullString
  affected_range: string
  promoted_from: SqlNullString
  created_at: string
  canonical_id?: string
  title?: string
}

export interface FirstPartyAdvisoryInput {
  identifier: string
  aliases?: string[]
  title: string
  description: string
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info'
  cvss_vector?: string
  affected_range: string
  promoted_from?: string
}

export interface SecretChecklist {
  revoked: boolean
  revoked_where: string
  revoked_by: string
  reference: string
  rotation: '' | 'rotated' | 'not_needed'
  rotation_note: string
  exposure: '' | 'assessed'
  exposure_note: string
  owner_external: boolean
}

export interface SecretAttestation extends SecretChecklist {
  id: string
  repo_id: string
  fingerprint: string
  note: string
  attested_by: NullableUUID
  attested_at: string
}

export interface HomeOrg {
  id: string
  provider: string
  slug: string
  name: string
  display_name: string
  role: string
  open_incidents: number
}

export interface HomeAction {
  id: string
  incident_id: string
  kind: string
  label: string
  due_at: SqlNullTime
  number: number
  title: string
  org_id: string
  priority: IncidentPriority
  org_slug: string
  org_provider: string
}

/** A merge waiting for a second person (four-eyes), on the incident to absorb. */
export interface MergeProposal {
  into_id: string
  into_number: number
  reason: string
  proposed_by: string
  proposed_at: string
}

/** An incident this one could merge into; incompatible ones say why. */
export interface MergeCandidate {
  number: number
  title: string
  state: IncidentState
  subject: string
  compatible: boolean
  reason?: string
}

export interface HomeApproval {
  type: 'decision' | 'delivery' | 'waiver' | 'merge'
  org_slug: string
  org_provider: string
  incident_number: number
  incident_title: string
  detail: string
  id: string
}

export interface HomeIncident extends Incident {
  repo_slug: SqlNullString
  repo_name: SqlNullString
  org_slug: string
  org_provider: string
  org_name: string
}

export interface HomeRepo {
  id: string
  org_slug: string
  org_provider: string
  slug: string
  name: string
  visited: boolean
  last_visited_at?: string
}

export interface HomeResponse {
  orgs: HomeOrg[]
  repos: HomeRepo[]
  needs_you: HomeAction[]
  approvals: HomeApproval[]
  incidents: HomeIncident[]
  noisy_rules: { org_id: string; repo_id: NullableUUID; repo_slug: SqlNullString; trigger_rule: SqlNullString; opened: number }[]
  exposure: {
    clients: { client_id: string; client_name: string; client_slug: string; org_id: string; number: number; title: string; version: string; status: string; org_slug: string; org_provider: string }[]
    unknown_releases: { release_id: string; version: string; org_id: string; number: number; title: string; org_slug: string; org_provider: string }[]
  }
  recent: {
    since: string
    failed_gates: number
    catalogue_signals: number
    secrets_found: number
    malware_found: number
  }
}

const json = (body: unknown): RequestInit => ({ method: 'POST', body: JSON.stringify(body) })
const org = (provider: string, slug: string) => `/orgs/${provider}/${slug}`
const inc = (provider: string, slug: string, number: number | string) => `${org(provider, slug)}/incidents/${number}`

export const incidentsApi = {
  list(provider: string, slug: string, params: { state?: string; kind?: string; priority?: string; repo?: string; page?: number; per_page?: number } = {}) {
    const qs = new URLSearchParams()
    for (const [key, value] of Object.entries(params)) {
      if (value !== undefined && value !== '') qs.set(key, String(value))
    }
    const query = qs.toString()
    return apiRequest<PaginatedResponse<IncidentSummary>>(`${org(provider, slug)}/incidents${query ? `?${query}` : ''}`)
  },
  open(provider: string, slug: string, input: OpenIncidentInput) {
    return apiRequest<ApiResponse<Incident>>(`${org(provider, slug)}/incidents`, json(input))
  },
  get(provider: string, slug: string, number: number | string) {
    return apiRequest<ApiResponse<IncidentDetail>>(inc(provider, slug, number))
  },
  update(provider: string, slug: string, number: number, input: { title?: string; priority?: IncidentPriority; owner_id?: string; owner_team_id?: string; clear_owner?: boolean; regimes?: string[]; external_ref?: string }) {
    return apiRequest<ApiResponse<Incident>>(inc(provider, slug, number), { method: 'PATCH', body: JSON.stringify(input) })
  },
  decide(provider: string, slug: string, number: number, input: IncidentDecisionInput) {
    return apiRequest<ApiResponse<Incident>>(`${inc(provider, slug, number)}/decide`, json(input))
  },
  approveDecision(provider: string, slug: string, number: number) {
    return apiRequest<ApiResponse<Incident>>(`${inc(provider, slug, number)}/decision/approve`, json({}))
  },
  withdraw(provider: string, slug: string, number: number, reason: string) {
    return apiRequest<ApiResponse<Incident>>(`${inc(provider, slug, number)}/withdraw`, json({ reason }))
  },
  /** Merges, or under four-eyes proposes the merge (`proposed: true`). */
  merge(provider: string, slug: string, number: number, into: number, reason: string) {
    return apiRequest<ApiResponse<{ proposed: boolean; merged_into: number }>>(`${inc(provider, slug, number)}/merge`, json({ into, reason }))
  },
  mergeCandidates(provider: string, slug: string, number: number) {
    return apiRequest<ApiResponse<MergeCandidate[]>>(`${inc(provider, slug, number)}/merge-candidates`)
  },
  approveMerge(provider: string, slug: string, number: number) {
    return apiRequest<ApiResponse<{ merged_into: number }>>(`${inc(provider, slug, number)}/merge/approve`, json({}))
  },
  cancelMerge(provider: string, slug: string, number: number, reason = '') {
    return apiRequest<void>(`${inc(provider, slug, number)}/merge/cancel`, json({ reason }))
  },
  fixAvailable(provider: string, slug: string, number: number, input: { at?: string; note?: string }) {
    return apiRequest<ApiResponse<Incident>>(`${inc(provider, slug, number)}/fix-available`, json(input))
  },
  reconcile(provider: string, slug: string, number: number) {
    return apiRequest<ApiResponse<Incident>>(`${inc(provider, slug, number)}/reconcile`, json({}))
  },
  note(provider: string, slug: string, number: number, text: string) {
    return apiRequest<void>(`${inc(provider, slug, number)}/notes`, json({ text }))
  },
  scope(provider: string, slug: string, number: number, input: { subject_type: string; subject_id: string; label?: string; status?: string; reason?: string; clear?: boolean }) {
    return apiRequest<void>(`${inc(provider, slug, number)}/scope`, json(input))
  },
  statement(provider: string, slug: string, number: number, input: IncidentStatementInput) {
    return apiRequest<ApiResponse<unknown>>(`${inc(provider, slug, number)}/statements`, json(input))
  },
  action(provider: string, slug: string, number: number, actionId: string, op: 'complete' | 'file' | 'waive' | 'reopen' | 'assign', input: { note?: string; reference?: string; reason?: string; filed_at?: string; assignee_id?: string | null; approve?: boolean }) {
    return apiRequest<ApiResponse<IncidentAction>>(`${inc(provider, slug, number)}/actions/${actionId}/${op}`, json(input))
  },
  filingDraft(provider: string, slug: string, number: number, step: string) {
    return apiRequest<ApiResponse<FilingDraft>>(`${inc(provider, slug, number)}/filing-draft?step=${encodeURIComponent(step)}`)
  },
  deliver(provider: string, slug: string, number: number, input: DeliverInput) {
    return apiRequest<ApiResponse<IncidentDelivery[]>>(`${inc(provider, slug, number)}/deliveries`, json(input))
  },
  approveDelivery(provider: string, slug: string, number: number, deliveryId: string, evidence?: string) {
    return apiRequest<ApiResponse<IncidentDelivery>>(`${inc(provider, slug, number)}/deliveries/${deliveryId}/approve`, json({ evidence }))
  },
  verifyDelivery(provider: string, slug: string, number: number, deliveryId: string) {
    return apiRequest<ApiResponse<VerifyResult>>(`${inc(provider, slug, number)}/deliveries/${deliveryId}/verify`, json({}))
  },
  documentUrl(provider: string, slug: string, number: number, sha256: string) {
    return `/api/v1${inc(provider, slug, number)}/documents/${sha256}`
  },
  dossierUrl(provider: string, slug: string, number: number) {
    return `/api/v1${inc(provider, slug, number)}/dossier`
  },
  getSettings(provider: string, slug: string) {
    return apiRequest<ApiResponse<IncidentSettingsResponse>>(`${org(provider, slug)}/incident-settings`)
  },
  putSettings(provider: string, slug: string, input: IncidentSettingsInput) {
    return apiRequest<ApiResponse<IncidentSettingsRow>>(`${org(provider, slug)}/incident-settings`, { method: 'PUT', body: JSON.stringify(input) })
  },
  getClientDelivery(provider: string, slug: string, clientSlug: string) {
    return apiRequest<ApiResponse<ClientDelivery>>(`${org(provider, slug)}/clients/${clientSlug}/delivery`)
  },
  putClientDelivery(provider: string, slug: string, clientSlug: string, input: ClientDeliveryInput) {
    return apiRequest<ApiResponse<ClientDelivery>>(`${org(provider, slug)}/clients/${clientSlug}/delivery`, { method: 'PUT', body: JSON.stringify(input) })
  },
  listClientDeliveries(provider: string, slug: string, clientSlug: string) {
    return apiRequest<ApiResponse<ClientIncidentDelivery[]>>(`${org(provider, slug)}/clients/${clientSlug}/incident-deliveries`)
  },
  listPortalTokens(provider: string, slug: string, clientSlug: string) {
    return apiRequest<ApiResponse<PortalToken[]>>(`${org(provider, slug)}/clients/${clientSlug}/portal-tokens`)
  },
  createPortalToken(provider: string, slug: string, clientSlug: string, name: string) {
    return apiRequest<ApiResponse<{ token: string; id: string; name: string; created_at: string }>>(`${org(provider, slug)}/clients/${clientSlug}/portal-tokens`, json({ name }))
  },
  revokePortalToken(provider: string, slug: string, clientSlug: string, tokenId: string) {
    return apiRequest<void>(`${org(provider, slug)}/clients/${clientSlug}/portal-tokens/${tokenId}`, { method: 'DELETE' })
  },
  listRepoIncidents(provider: string, slug: string, repoSlug: string) {
    return apiRequest<ApiResponse<IncidentSummary[]>>(`${org(provider, slug)}/repos/${repoSlug}/incidents`)
  },
  repoRules(provider: string, slug: string, repoSlug: string) {
    return apiRequest<ApiResponse<RepoIncidentRules>>(`${org(provider, slug)}/repos/${repoSlug}/incident-rules`)
  },
  listFirstParty(provider: string, slug: string, repoSlug: string) {
    return apiRequest<ApiResponse<FirstPartyAdvisory[]>>(`${org(provider, slug)}/repos/${repoSlug}/first-party-advisories`)
  },
  createFirstParty(provider: string, slug: string, repoSlug: string, input: FirstPartyAdvisoryInput) {
    return apiRequest<ApiResponse<FirstPartyAdvisory>>(`${org(provider, slug)}/repos/${repoSlug}/first-party-advisories`, json(input))
  },
  findingIncidents(provider: string, slug: string, repoSlug: string, vulnId: string) {
    return apiRequest<ApiResponse<Incident[]>>(`${org(provider, slug)}/repos/${repoSlug}/vulnerabilities/${vulnId}/incidents`)
  },
  secretAttestations(provider: string, slug: string, repoSlug: string, vulnId: string) {
    return apiRequest<ApiResponse<SecretAttestation[]>>(`${org(provider, slug)}/repos/${repoSlug}/vulnerabilities/${vulnId}/revocation`)
  },
  attestSecret(provider: string, slug: string, repoSlug: string, vulnId: string, checklist: SecretChecklist, comment: string) {
    return apiRequest<ApiResponse<unknown>>(`${org(provider, slug)}/repos/${repoSlug}/vulnerabilities/${vulnId}/revocation`, json({ checklist, comment }))
  },
  recheckSecret(provider: string, slug: string, repoSlug: string, vulnId: string) {
    return apiRequest<ApiResponse<{ job_id: string; ref: string; status: string }>>(`${org(provider, slug)}/repos/${repoSlug}/vulnerabilities/${vulnId}/recheck`, json({}))
  },
  home(since?: string) {
    return apiRequest<ApiResponse<HomeResponse>>(`/me/home${since ? `?since=${encodeURIComponent(since)}` : ''}`)
  },
}

/** Unwraps a {Time, Valid} column. */
export function nullTime(value: SqlNullTime | null | undefined): string | null {
  return value && value.Valid ? value.Time : null
}

/** Unwraps a {String, Valid} column. */
export function nullString(value: SqlNullString | null | undefined): string {
  return value && value.Valid ? value.String : ''
}

/** A nullable uuid column: the id, or null. */
export function nullUUID(value: NullableUUID | undefined): string | null {
  return typeof value === 'string' && value !== '' ? value : null
}

/** "in 5h 12m", "overdue by 2h", for countdowns. */
export function countdown(iso: string | null, now = Date.now()): { text: string; overdue: boolean } {
  if (!iso) return { text: '—', overdue: false }
  const delta = new Date(iso).getTime() - now
  const overdue = delta < 0
  let seconds = Math.floor(Math.abs(delta) / 1000)
  const days = Math.floor(seconds / 86400)
  seconds -= days * 86400
  const hours = Math.floor(seconds / 3600)
  seconds -= hours * 3600
  const minutes = Math.floor(seconds / 60)
  seconds -= minutes * 60
  // Seconds only inside the last day, where they matter and show the clock is live.
  const parts = days > 0
    ? [`${days}d`, `${hours}h`, `${String(minutes).padStart(2, '0')}m`]
    : hours > 0
      ? [`${hours}h`, `${String(minutes).padStart(2, '0')}m`, `${String(seconds).padStart(2, '0')}s`]
      : minutes > 0
        ? [`${minutes}m`, `${String(seconds).padStart(2, '0')}s`]
        : [`${seconds}s`]
  return { text: overdue ? `overdue by ${parts.join(' ')}` : `in ${parts.join(' ')}`, overdue }
}

/** Whether an incident is still being handled. */
export function incidentOpen(state: IncidentState): boolean {
  return state !== 'closed' && state !== 'withdrawn'
}

/** The pending, current, required actions. */
export function pendingActions(actions: IncidentAction[]): IncidentAction[] {
  return actions.filter(action => !action.obsolete && action.state === 'pending')
}

/** Whether an action kind is a filing on an authority's platform. */
export function isFiling(kind: string): boolean {
  return kind.startsWith('srp_') || kind.startsWith('csirt_') || kind.startsWith('national_')
}
