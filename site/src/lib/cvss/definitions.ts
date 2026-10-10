// CVSS metric definitions for every version hibou meets (v2, v3.0, v3.1,
// v4.0): names, groups and a plain-language explanation of each value, so a
// vector from any CVE can be read, and a new one chosen knowingly.
// Wording is hibou's own summary of the FIRST specifications.

export type CvssVersion = '2.0' | '3.0' | '3.1' | '4.0'

export interface CvssValue {
  code: string
  label: string
  description: string
}

export interface CvssMetric {
  key: string
  name: string
  /** What the metric asks, in one sentence. */
  question: string
  values: CvssValue[]
  /** Base metrics are mandatory; others default to "Not Defined" (X). */
  required?: boolean
}

export interface CvssGroup {
  id: string
  name: string
  description: string
  metrics: CvssMetric[]
  /** Optional groups are folded by default in the calculator. */
  optional?: boolean
}

const notDefined = (detail = 'Not assessed; the score uses the default.'): CvssValue => ({ code: 'X', label: 'Not Defined', description: detail })

// ---------------------------------------------------------------- v4.0

const v4Requirement = (letter: 'C' | 'I' | 'A', word: string): CvssMetric => ({
  key: `${letter}R`,
  name: `${word} Requirement`,
  question: `How much does ${word.toLowerCase()} of the affected system matter to your organisation?`,
  values: [
    notDefined('Treated as High (the worst case).'),
    { code: 'H', label: 'High', description: `Losing ${word.toLowerCase()} would have a catastrophic effect on your organisation.` },
    { code: 'M', label: 'Medium', description: `Losing ${word.toLowerCase()} would have a serious effect.` },
    { code: 'L', label: 'Low', description: `Losing ${word.toLowerCase()} would have a limited effect.` },
  ],
})

const v4Impact = (key: string, name: string, question: string, subject: string, safety = false): CvssMetric => ({
  key,
  name,
  question,
  required: !key.startsWith('M'),
  values: [
    ...(key.startsWith('M') ? [notDefined('Uses the base metric\'s value.')] : []),
    ...(safety ? [{ code: 'S', label: 'Safety', description: 'Exploitation could cause physical harm to people (IEC 61508 hazard categories).' }] : []),
    { code: 'H', label: 'High', description: `Total loss for the ${subject}, or a serious, directly exploitable loss.` },
    { code: 'L', label: 'Low', description: `Some loss for the ${subject}, limited in what the attacker controls or how much is affected.` },
    { code: 'N', label: 'None', description: `No loss for the ${subject}.` },
  ],
})

const V4_BASE_EXPLOITABILITY: CvssMetric[] = [
  {
    key: 'AV', name: 'Attack Vector', required: true,
    question: 'How close must the attacker be to the vulnerable system?',
    values: [
      { code: 'N', label: 'Network', description: 'Remotely exploitable across the network, up to the whole Internet.' },
      { code: 'A', label: 'Adjacent', description: 'Only from the same local network segment or a logically adjacent one (Bluetooth, same VLAN, VPN).' },
      { code: 'L', label: 'Local', description: 'The attacker needs local access (a shell, a console) or a user to open something locally.' },
      { code: 'P', label: 'Physical', description: 'The attacker must physically touch or manipulate the device.' },
    ],
  },
  {
    key: 'AC', name: 'Attack Complexity', required: true,
    question: 'Must the attacker defeat a security measure to succeed?',
    values: [
      { code: 'L', label: 'Low', description: 'No target-specific obstacle: the attack works reliably and repeatably.' },
      { code: 'H', label: 'High', description: 'Success needs evading or bypassing a protection, such as ASLR or obtaining a secret first.' },
    ],
  },
  {
    key: 'AT', name: 'Attack Requirements', required: true,
    question: 'Do conditions outside the attacker\'s control have to hold?',
    values: [
      { code: 'N', label: 'None', description: 'Works against the vulnerable system as deployed, without special conditions.' },
      { code: 'P', label: 'Present', description: 'Needs a specific deployment state, a race to win, or a network position (man-in-the-middle).' },
    ],
  },
  {
    key: 'PR', name: 'Privileges Required', required: true,
    question: 'What access must the attacker already have?',
    values: [
      { code: 'N', label: 'None', description: 'Unauthenticated: no account or access needed.' },
      { code: 'L', label: 'Low', description: 'An ordinary user account or basic access.' },
      { code: 'H', label: 'High', description: 'Administrative or significant privileges on the vulnerable system.' },
    ],
  },
  {
    key: 'UI', name: 'User Interaction', required: true,
    question: 'Must someone other than the attacker do something?',
    values: [
      { code: 'N', label: 'None', description: 'No action from any user is needed.' },
      { code: 'P', label: 'Passive', description: 'A user must do something ordinary and involuntary, such as visiting a page.' },
      { code: 'A', label: 'Active', description: 'A user must take a deliberate step, such as importing a file or dismissing a warning.' },
    ],
  },
]

const V4_VULNERABLE: CvssMetric[] = [
  v4Impact('VC', 'Confidentiality', 'How much information on the vulnerable system can the attacker read?', 'vulnerable system'),
  v4Impact('VI', 'Integrity', 'How much on the vulnerable system can the attacker modify?', 'vulnerable system'),
  v4Impact('VA', 'Availability', 'How much can the attacker disrupt the vulnerable system?', 'vulnerable system'),
]

const V4_SUBSEQUENT: CvssMetric[] = [
  v4Impact('SC', 'Confidentiality', 'Can the attacker read information on other systems downstream?', 'downstream systems'),
  v4Impact('SI', 'Integrity', 'Can the attacker modify other systems downstream?', 'downstream systems'),
  v4Impact('SA', 'Availability', 'Can the attacker disrupt other systems downstream?', 'downstream systems'),
]

const V4_MODIFIED_BASE: CvssMetric[] = [
  ...V4_BASE_EXPLOITABILITY.map(metric => ({ ...metric, key: `M${metric.key}`, name: `Modified ${metric.name}`, required: false, values: [notDefined('Uses the base metric\'s value.'), ...metric.values] })),
  v4Impact('MVC', 'Modified Confidentiality (vulnerable)', 'Confidentiality impact on the vulnerable system, in your environment.', 'vulnerable system'),
  v4Impact('MVI', 'Modified Integrity (vulnerable)', 'Integrity impact on the vulnerable system, in your environment.', 'vulnerable system'),
  v4Impact('MVA', 'Modified Availability (vulnerable)', 'Availability impact on the vulnerable system, in your environment.', 'vulnerable system'),
  v4Impact('MSC', 'Modified Confidentiality (subsequent)', 'Confidentiality impact on downstream systems, in your environment.', 'downstream systems'),
  v4Impact('MSI', 'Modified Integrity (subsequent)', 'Integrity impact on downstream systems, in your environment; Safety when people could be hurt.', 'downstream systems', true),
  v4Impact('MSA', 'Modified Availability (subsequent)', 'Availability impact on downstream systems, in your environment; Safety when people could be hurt.', 'downstream systems', true),
]

const V4_GROUPS: CvssGroup[] = [
  { id: 'exploitability', name: 'Exploitability', description: 'How the vulnerability is exploited.', metrics: V4_BASE_EXPLOITABILITY },
  { id: 'vulnerable', name: 'Vulnerable system impact', description: 'What exploitation does to the system that has the flaw.', metrics: V4_VULNERABLE },
  { id: 'subsequent', name: 'Subsequent system impact', description: 'What it does to other systems beyond it.', metrics: V4_SUBSEQUENT },
  {
    id: 'threat', name: 'Threat', optional: true, description: 'What is known about exploitation today. Lowers the score when exploitation is unproven.',
    metrics: [{
      key: 'E', name: 'Exploit Maturity', question: 'How likely is exploitation, given what is public?',
      values: [
        notDefined('Treated as Attacked (the worst case).'),
        { code: 'A', label: 'Attacked', description: 'Attacks are reported in the wild, or exploitation tools are readily available (e.g. a KEV listing).' },
        { code: 'P', label: 'POC', description: 'A proof-of-concept exploit is public, but no attacks are known.' },
        { code: 'U', label: 'Unreported', description: 'No public proof of concept and no reported attacks.' },
      ],
    }],
  },
  {
    id: 'environmental', name: 'Environmental', optional: true, description: 'Your deployment: what the affected assets are worth to you, and base metrics as they apply in your environment.',
    metrics: [v4Requirement('C', 'Confidentiality'), v4Requirement('I', 'Integrity'), v4Requirement('A', 'Availability'), ...V4_MODIFIED_BASE],
  },
  {
    id: 'supplemental', name: 'Supplemental', optional: true, description: 'Extra context for responders. Never changes the score.',
    metrics: [
      { key: 'S', name: 'Safety', question: 'Could exploitation endanger people?', values: [notDefined(), { code: 'N', label: 'Negligible', description: 'Consequences for safety are negligible.' }, { code: 'P', label: 'Present', description: 'Consequences could injure people.' }] },
      { key: 'AU', name: 'Automatable', question: 'Can an attacker automate exploitation across many targets?', values: [notDefined(), { code: 'N', label: 'No', description: 'At least one step of the attack cannot be scripted.' }, { code: 'Y', label: 'Yes', description: 'Every step can be automated (worm-like).' }] },
      { key: 'R', name: 'Recovery', question: 'How does the system recover after an attack?', values: [notDefined(), { code: 'A', label: 'Automatic', description: 'It recovers by itself.' }, { code: 'U', label: 'User', description: 'A person must intervene to recover it.' }, { code: 'I', label: 'Irrecoverable', description: 'It cannot be recovered.' }] },
      { key: 'V', name: 'Value Density', question: 'How much does one successful attack yield?', values: [notDefined(), { code: 'D', label: 'Diffuse', description: 'Small resources per target (e.g. a single user\'s device).' }, { code: 'C', label: 'Concentrated', description: 'Rich resources (e.g. a central server or database).' }] },
      { key: 'RE', name: 'Vulnerability Response Effort', question: 'How hard is it to respond to the vulnerability?', values: [notDefined(), { code: 'L', label: 'Low', description: 'Little effort: documentation or configuration.' }, { code: 'M', label: 'Moderate', description: 'Some effort, with modest service impact.' }, { code: 'H', label: 'High', description: 'Significant effort or downtime, possibly replacement.' }] },
      { key: 'U', name: 'Provider Urgency', question: 'How urgent does the supplier say the fix is?', values: [notDefined(), { code: 'Clear', label: 'Clear', description: 'Low urgency.' }, { code: 'Green', label: 'Green', description: 'Reduced urgency.' }, { code: 'Amber', label: 'Amber', description: 'Moderate urgency.' }, { code: 'Red', label: 'Red', description: 'Highest urgency.' }] },
    ],
  },
]

// ---------------------------------------------------------------- v3.x

const v3Impact = (key: string, name: string, question: string): CvssMetric => ({
  key, name, question, required: true,
  values: [
    { code: 'H', label: 'High', description: 'Total loss, or a serious loss directly exploitable by the attacker.' },
    { code: 'L', label: 'Low', description: 'Some loss, limited in scope or in what the attacker controls.' },
    { code: 'N', label: 'None', description: 'No loss.' },
  ],
})

const V3_BASE: CvssMetric[] = [
  { ...V4_BASE_EXPLOITABILITY[0] },
  V4_BASE_EXPLOITABILITY[1],
  V4_BASE_EXPLOITABILITY[3],
  {
    key: 'UI', name: 'User Interaction', required: true, question: 'Must a user other than the attacker take part?',
    values: [
      { code: 'N', label: 'None', description: 'No user action needed.' },
      { code: 'R', label: 'Required', description: 'A user must do something, such as open a link or a file.' },
    ],
  },
  {
    key: 'S', name: 'Scope', required: true, question: 'Can exploitation affect components beyond the vulnerable one?',
    values: [
      { code: 'U', label: 'Unchanged', description: 'Only the vulnerable component\'s own resources are affected.' },
      { code: 'C', label: 'Changed', description: 'It reaches beyond its security boundary, e.g. a VM escape or a sandbox break.' },
    ],
  },
  v3Impact('C', 'Confidentiality', 'How much information can the attacker read?'),
  v3Impact('I', 'Integrity', 'How much can the attacker modify?'),
  v3Impact('A', 'Availability', 'How much can the attacker disrupt the service?'),
]

const V3_TEMPORAL: CvssMetric[] = [
  { key: 'E', name: 'Exploit Code Maturity', question: 'How mature is public exploit code?', values: [notDefined(), { code: 'H', label: 'High', description: 'Functional, autonomous exploits exist or are not needed.' }, { code: 'F', label: 'Functional', description: 'A working exploit is available.' }, { code: 'P', label: 'Proof-of-Concept', description: 'A proof of concept exists, not practical in most cases.' }, { code: 'U', label: 'Unproven', description: 'No exploit code is known.' }] },
  { key: 'RL', name: 'Remediation Level', question: 'Is a fix available?', values: [notDefined(), { code: 'O', label: 'Official Fix', description: 'The vendor ships a complete fix.' }, { code: 'T', label: 'Temporary Fix', description: 'An official interim fix exists.' }, { code: 'W', label: 'Workaround', description: 'Only an unofficial workaround exists.' }, { code: 'U', label: 'Unavailable', description: 'No fix and no workaround.' }] },
  { key: 'RC', name: 'Report Confidence', question: 'How certain is the vulnerability\'s existence?', values: [notDefined(), { code: 'C', label: 'Confirmed', description: 'Confirmed by the vendor or reproducible.' }, { code: 'R', label: 'Reasonable', description: 'Significant detail published, root cause not fully confirmed.' }, { code: 'U', label: 'Unknown', description: 'Reports disagree or are unverified.' }] },
]

const v3Requirement = (letter: 'C' | 'I' | 'A', word: string): CvssMetric => ({
  ...v4Requirement(letter, word),
  values: [notDefined(), ...v4Requirement(letter, word).values.slice(1)],
})

const V3_ENVIRONMENTAL: CvssMetric[] = [
  v3Requirement('C', 'Confidentiality'), v3Requirement('I', 'Integrity'), v3Requirement('A', 'Availability'),
  ...V3_BASE.map(metric => ({ ...metric, key: `M${metric.key}`, name: `Modified ${metric.name}`, required: false, values: [notDefined('Uses the base metric\'s value.'), ...metric.values] })),
]

const v3Groups = (): CvssGroup[] => [
  { id: 'base', name: 'Base', description: 'The flaw\'s intrinsic characteristics. The score shown is the base score.', metrics: V3_BASE },
  { id: 'temporal', name: 'Temporal', optional: true, description: 'Exploit and fix status today. Shown for context; hibou scores the base metrics.', metrics: V3_TEMPORAL },
  { id: 'environmental', name: 'Environmental', optional: true, description: 'Your deployment. Shown for context; hibou scores the base metrics.', metrics: V3_ENVIRONMENTAL },
]

// ---------------------------------------------------------------- v2

const v2Impact = (key: string, name: string, question: string): CvssMetric => ({
  key, name, question, required: true,
  values: [
    { code: 'N', label: 'None', description: 'No impact.' },
    { code: 'P', label: 'Partial', description: 'Considerable but limited impact.' },
    { code: 'C', label: 'Complete', description: 'Total impact on the system.' },
  ],
})

const V2_GROUPS: CvssGroup[] = [
  {
    id: 'base', name: 'Base', description: 'CVSS v2 base metrics. The score shown is the base score.',
    metrics: [
      { key: 'AV', name: 'Access Vector', required: true, question: 'How is the vulnerability reached?', values: [{ code: 'L', label: 'Local', description: 'Requires local access or a local account.' }, { code: 'A', label: 'Adjacent Network', description: 'From the same broadcast or collision domain.' }, { code: 'N', label: 'Network', description: 'Remotely, over the network.' }] },
      { key: 'AC', name: 'Access Complexity', required: true, question: 'How hard is exploitation once access is gained?', values: [{ code: 'H', label: 'High', description: 'Specialised conditions are required.' }, { code: 'M', label: 'Medium', description: 'Somewhat specialised conditions.' }, { code: 'L', label: 'Low', description: 'No special conditions.' }] },
      { key: 'Au', name: 'Authentication', required: true, question: 'How many times must the attacker authenticate?', values: [{ code: 'M', label: 'Multiple', description: 'Two or more times.' }, { code: 'S', label: 'Single', description: 'Once.' }, { code: 'N', label: 'None', description: 'Not at all.' }] },
      v2Impact('C', 'Confidentiality Impact', 'How much information is disclosed?'),
      v2Impact('I', 'Integrity Impact', 'How much can be modified?'),
      v2Impact('A', 'Availability Impact', 'How much is availability reduced?'),
    ],
  },
  {
    id: 'temporal', name: 'Temporal', optional: true, description: 'Shown for context; hibou scores the base metrics.',
    metrics: [
      { key: 'E', name: 'Exploitability', question: 'How mature is exploit code?', values: [{ code: 'ND', label: 'Not Defined', description: 'Not assessed.' }, { code: 'U', label: 'Unproven', description: 'No exploit code.' }, { code: 'POC', label: 'Proof-of-Concept', description: 'A proof of concept exists.' }, { code: 'F', label: 'Functional', description: 'A working exploit exists.' }, { code: 'H', label: 'High', description: 'Exploits are widespread or not needed.' }] },
      { key: 'RL', name: 'Remediation Level', question: 'Is a fix available?', values: [{ code: 'ND', label: 'Not Defined', description: 'Not assessed.' }, { code: 'OF', label: 'Official Fix', description: 'Vendor fix available.' }, { code: 'TF', label: 'Temporary Fix', description: 'Interim official fix.' }, { code: 'W', label: 'Workaround', description: 'Unofficial workaround.' }, { code: 'U', label: 'Unavailable', description: 'No fix.' }] },
      { key: 'RC', name: 'Report Confidence', question: 'How certain is the report?', values: [{ code: 'ND', label: 'Not Defined', description: 'Not assessed.' }, { code: 'UC', label: 'Unconfirmed', description: 'Single unconfirmed source.' }, { code: 'UR', label: 'Uncorroborated', description: 'Multiple sources that disagree.' }, { code: 'C', label: 'Confirmed', description: 'Confirmed by the vendor.' }] },
    ],
  },
]

export const CVSS_GROUPS: Readonly<Record<CvssVersion, CvssGroup[]>> = {
  '2.0': V2_GROUPS,
  '3.0': v3Groups(),
  '3.1': v3Groups(),
  '4.0': V4_GROUPS,
}

/** Every metric of a version, keyed by its abbreviation. */
export function metricIndex(version: CvssVersion): Map<string, CvssMetric> {
  const index = new Map<string, CvssMetric>()
  for (const group of CVSS_GROUPS[version]) {
    for (const metric of group.metrics) index.set(metric.key, metric)
  }
  return index
}
