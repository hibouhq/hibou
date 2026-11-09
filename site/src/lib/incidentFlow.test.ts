import { describe, expect, it } from 'vitest'

import type { IncidentAction, IncidentDeadline, IncidentDetail, IncidentSummary } from '@/api/incidents'

import { buildFlow, takenBranch } from './incidentFlow'

const NOW = Date.parse('2026-10-24T12:00:00Z')
const nullTime = { Time: '', Valid: false }
const time = (value: string) => ({ Time: value, Valid: true })

function incident(overrides: Partial<IncidentSummary> = {}): IncidentSummary {
  return {
    id: 'inc', org_id: 'org', number: 1, repo_id: 'repo', kind: 'exploited_vulnerability', regimes: ['cra-article-14', 'internal'],
    subject_type: 'advisory', subject_id: 'adv', title: 'CVE-2023-44487', state: 'signal', priority: 'P1', signal_source: 'kev',
    trigger_rule: { String: 'exploited', Valid: true }, signal_at: '2026-10-23T10:00:00Z', aware_at: nullTime,
    decision_reason: { String: '', Valid: false }, decision_step: { String: '', Valid: false }, decided_by: null, decided_at: nullTime,
    decided_state: null, proposed_decision: null, proposed_merge: null, fix_available_at: nullTime, owner_id: null, owner_team_id: null,
    due_at: nullTime, target_seconds: { Int64: 0, Valid: false }, merged_into: null, closed_at: nullTime, created_by: 'u1',
    created_at: '2026-10-23T10:00:00Z', updated_at: '2026-10-23T10:00:00Z', kind_label: 'Exploited vulnerability',
    ...overrides,
  } as IncidentSummary
}

function action(overrides: Partial<IncidentAction>): IncidentAction {
  return {
    id: 'a', incident_id: 'inc', kind: 'vex', subject_type: 'release', subject_id: 'r1', label: 'VEX for 1.0', automatic: true,
    optional: false, obsolete: false, due_at: nullTime, state: 'pending', assignee_id: null, done_at: nullTime, done_by: null,
    evidence: {}, waived_by: null, waived_reason: { String: '', Valid: false }, created_at: '2026-10-23T10:00:00Z',
    ...overrides,
  }
}

function deadline(step: string, due: string, met?: string): IncidentDeadline {
  return { incident_id: 'inc', regime: 'cra-article-14', step, due_at: due, met_at: met ? time(met) : nullTime, reference: '', notified: '' }
}

function detail(overrides: Partial<IncidentDetail> = {}): IncidentDetail {
  return {
    incident: incident(),
    decision_states: ['reportable', 'not_reportable'],
    scope: [{ incident_id: 'inc', subject_type: 'release', subject_id: 'r1', label: '1.0', status: 'pending', reason: '', component_purl: 'pkg:npm/a@1', vex_statement_id: null, reachability: { String: '', Valid: false }, manual: false, decided_by: null, decided_at: nullTime, updated_at: '', clients: [{ id: 'c1', name: 'Globex', slug: 'globex' }] }],
    actions: [action({})],
    deadlines: [],
    deliveries: [],
    events: [],
    tracker_links: [],
    regimes: [{ name: 'cra-article-14', label: 'Cyber Resilience Act, Art. 14', steps: [
      { step: 'early_warning', label: 'Early warning', anchor: 'aware', after: '24h', filing: 'srp_early_warning' },
      { step: 'notification', label: 'Notification', anchor: 'aware', after: '72h', filing: 'srp_notification' },
      { step: 'final_report', label: 'Final report', anchor: 'fix_available', after: '336h', filing: 'srp_final_report' },
    ] }],
    settings: { four_eyes: false, require_vex_approval: false, require_notice_approval: false, require_acknowledgement: false },
    can_manage: true,
    advisory: { id: 'adv', canonical_id: 'HIBOU-ADV-1', aliases: [], title: 'Parser overflow, reported to us privately', first_party: false, public: false },
    ...overrides,
  }
}

const byId = (flow: ReturnType<typeof buildFlow>) => new Map(flow.nodes.map(node => [node.id, node]))

describe('buildFlow', () => {
  it('shows the four ladder branches as possible before a decision', () => {
    const flow = buildFlow(detail(), NOW)
    expect(flow.branches.map(branch => branch.id)).toEqual(['not_present', 'not_reachable', 'reachable_no_attack', 'attacked'])
    expect(flow.branches.every(branch => branch.taken === null)).toBe(true)
    const nodes = byId(flow)
    expect(nodes.get('signal')?.status).toBe('done')
    expect(nodes.get('decision')?.status).toBe('current')
    expect(nodes.get('attacked.t0')?.status).toBe('possible')
    expect(nodes.get('not_reachable.vex')?.status).toBe('possible')
    expect(nodes.get('close')?.status).toBe('possible')
    // Clients exist and the advisory is a private third-party one: notices and upstream appear.
    expect(nodes.has('attacked.notices')).toBe(true)
    expect(nodes.has('not_reachable.upstream')).toBe(true)
  })

  it('owes nothing upstream for a public advisory: the maintainer already knows', () => {
    const flow = buildFlow(detail({ advisory: { id: 'adv', canonical_id: 'CVE-2021-44228', aliases: ['GHSA-jfh8-c2jp-5v3q'], title: 'Log4Shell', first_party: false, public: true } }), NOW)
    const nodes = byId(flow)
    expect(nodes.has('not_reachable.upstream')).toBe(false)
    expect(nodes.has('reachable_no_attack.upstream')).toBe(false)
  })

  it('greys the paths not taken and follows the clocks on the taken one', () => {
    const flow = buildFlow(detail({
      incident: incident({
        state: 'reportable', aware_at: time('2026-10-23T13:00:00Z'), decided_at: time('2026-10-23T13:30:00Z'), decided_by: 'u2',
        decision_step: { String: 'attacked', Valid: true }, decision_reason: { String: 'customer logs', Valid: true },
      }),
      actions: [
        action({ id: 'v1', state: 'done', done_at: time('2026-10-23T13:30:00Z'), done_by: 'u2' }),
        action({ id: 'f1', kind: 'srp_early_warning', subject_type: 'regime', subject_id: 'cra-article-14', label: 'Early warning' }),
        action({ id: 'n1', kind: 'client_notice', subject_type: 'client', subject_id: 'c1', label: 'Notice to Globex' }),
      ],
      deadlines: [deadline('early_warning', '2026-10-24T13:00:00Z'), deadline('notification', '2026-10-26T13:00:00Z')],
    }), NOW)
    const nodes = byId(flow)
    expect(flow.branches.find(branch => branch.id === 'attacked')?.taken).toBe(true)
    expect(nodes.get('decision')?.status).toBe('done')
    expect(nodes.get('decision')?.detail).toContain('customer logs')
    expect(nodes.get('attacked.t0')?.status).toBe('done')
    expect(nodes.get('attacked.early_warning')).toMatchObject({ status: 'current', due: '2026-10-24T13:00:00Z', anchor: 'action-f1' })
    expect(nodes.get('attacked.notification')?.status).toBe('remaining')
    expect(nodes.get('attacked.notices')).toMatchObject({ status: 'remaining', tab: 'notices' })
    expect(nodes.get('attacked.final_report')?.status).toBe('remaining')
    expect(nodes.get('not_reachable.vex')?.status).toBe('skipped')
    expect(nodes.get('reachable_no_attack.fix')?.status).toBe('skipped')
    expect(nodes.get('close')?.status).toBe('remaining')
    expect(flow.edges.find(edge => edge.to === 'attacked.early_warning')?.status).toBe('active')
    expect(flow.edges.find(edge => edge.to === 'not_present.close' || (edge.from === 'decision' && edge.to === 'close'))?.status).toBe('skipped')
  })

  it('marks a missed filing overdue', () => {
    const flow = buildFlow(detail({
      incident: incident({ state: 'reportable', aware_at: time('2026-10-22T13:00:00Z'), decided_at: time('2026-10-22T13:30:00Z'), decision_step: { String: 'attacked', Valid: true } }),
      deadlines: [deadline('early_warning', '2026-10-23T13:00:00Z'), deadline('notification', '2026-10-25T13:00:00Z')],
    }), NOW)
    const nodes = byId(flow)
    expect(nodes.get('attacked.early_warning')?.status).toBe('overdue')
    expect(nodes.get('attacked.notification')?.status).toBe('remaining')
  })

  it('aggregates per-release statements and closes the not-exploitable path', () => {
    const flow = buildFlow(detail({
      incident: incident({ state: 'closed', decided_at: time('2026-10-23T11:00:00Z'), decision_step: { String: 'not_reachable', Valid: true }, closed_at: time('2026-10-23T11:05:00Z') }),
      actions: [
        action({ id: 'v1', state: 'done', done_at: time('2026-10-23T11:00:00Z') }),
        action({ id: 'v2', subject_id: 'r2', state: 'done', done_at: time('2026-10-23T11:01:00Z') }),
        action({ id: 'up', kind: 'upstream_notice', subject_type: 'component', subject_id: 'pkg:npm/a@1', optional: true, state: 'waived', waived_by: 'u3' }),
      ],
    }), NOW)
    const nodes = byId(flow)
    expect(nodes.get('not_reachable.vex')).toMatchObject({ status: 'done', progress: '2 of 2 done', at: '2026-10-23T11:01:00Z', tab: 'scope' })
    expect(nodes.get('not_reachable.upstream')).toMatchObject({ status: 'waived', by: 'u3' })
    expect(nodes.get('close')).toMatchObject({ status: 'done', at: '2026-10-23T11:05:00Z' })
    expect(nodes.get('attacked.t0')?.status).toBe('skipped')
  })

  it('uses the decision states as branches for the other kinds', () => {
    const flow = buildFlow(detail({
      incident: incident({ kind: 'secret_leak', regimes: ['internal'], state: 'confirmed', decided_state: { incident_state: 'confirmed', valid: true }, decided_at: time('2026-10-23T11:00:00Z') }),
      decision_states: ['confirmed', 'dismissed'],
      actions: [
        action({ id: 'rv', kind: 'revoke', subject_type: 'finding', state: 'done', done_at: time('2026-10-23T11:10:00Z') }),
        action({ id: 'ro', kind: 'rotate', subject_type: 'finding' }),
        action({ id: 'ex', kind: 'assess_exposure', subject_type: 'finding' }),
        action({ id: 'rm', kind: 'remove', subject_type: 'finding', optional: true }),
      ],
    }), NOW)
    const nodes = byId(flow)
    expect(flow.branches.map(branch => branch.label)).toEqual(['Confirmed', 'Dismissed'])
    expect(nodes.get('confirmed.revoke')?.status).toBe('done')
    expect(nodes.get('confirmed.rotate')?.status).toBe('current')
    expect(nodes.get('confirmed.exposure')?.status).toBe('remaining')
    expect(nodes.has('confirmed.owner')).toBe(false)
    expect(nodes.get('close')?.status).toBe('remaining')
  })

  it('withdrawn incidents skip every path', () => {
    const flow = buildFlow(detail({ incident: incident({ state: 'withdrawn', closed_at: time('2026-10-23T12:00:00Z') }) }), NOW)
    const nodes = byId(flow)
    expect(nodes.get('decision')).toMatchObject({ label: 'Withdrawn', status: 'done' })
    expect(flow.nodes.filter(node => node.branch !== '').every(node => node.status === 'skipped')).toBe(true)
    expect(nodes.get('close')?.status).toBe('done')
  })
})

describe('takenBranch', () => {
  it('reads the ladder step for exploited vulnerabilities and the decided state otherwise', () => {
    expect(takenBranch(detail())).toBeNull()
    expect(takenBranch(detail({ incident: incident({ decision_step: { String: 'attacked', Valid: true } }) }))).toBe('attacked')
    expect(takenBranch(detail({ incident: incident({ kind: 'policy_breach', state: 'dismissed' }), decision_states: ['confirmed', 'dismissed'] }))).toBe('dismissed')
  })
})
