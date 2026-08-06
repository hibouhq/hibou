import type { TokenAccessLevel, TokenCapability } from '../api/client'

export interface TokenPreset {
  key: string
  label: string
  hint: string
  permissions: Partial<Record<TokenCapability, TokenAccessLevel>>
}

// These presets are the product's security recommendations — the safe token
// must be the easy one to mint (ADR-020). tokenPresets.test.ts pins their
// grants so an edit here cannot silently hand a preset a write it should not
// have.
export const TOKEN_PRESETS: TokenPreset[] = [
  {
    key: 'read-only-agent',
    label: 'Read-only agent',
    hint: 'Can observe everything it is scoped to, and change nothing',
    permissions: {
      coverage: 'read',
      vulnerabilities: 'read',
      components: 'read',
      triage: 'read',
      quality_gates: 'read',
      secrets: 'read',
      uploads: 'read',
    },
  },
  {
    key: 'ci-uploader',
    label: 'CI uploader',
    hint: 'Submits scan artifacts and reads back the gate result — nothing else',
    permissions: { uploads: 'write', quality_gates: 'read', coverage: 'read' },
  },
  {
    key: 'triage-agent',
    label: 'Triage agent',
    hint: 'Files findings and acts on them, but cannot touch gate definitions or org settings',
    permissions: { vulnerabilities: 'write', triage: 'write', coverage: 'read', components: 'read' },
  },
]
