// Helpers for the ADR-043 /device approval page.

import type { DeviceLoginPreset } from '@/api/client'

// Mirrors internal/apitoken/devicecode.go: RFC 8628 consonant alphabet, 8
// significant characters, dashes and spaces ignored.
const USER_CODE_ALPHABET = 'BCDFGHJKLMNPQRSTVWXZ'
const USER_CODE_LENGTH = 8

export const CLI_CLIENT_ID = 'hibou-cli'

/** Canonical form of a typed user code, or null when it cannot be one. */
export function normalizeUserCode(raw: string): string | null {
  let code = ''
  for (const ch of raw.toUpperCase()) {
    if (ch === '-' || ch === ' ' || ch === '\t') continue
    if (!USER_CODE_ALPHABET.includes(ch)) return null
    code += ch
  }
  return code.length === USER_CODE_LENGTH ? code : null
}

/** Whether two user codes are the same once normalised. */
export function userCodesMatch(a: string, b: string): boolean {
  const left = normalizeUserCode(a)
  return left !== null && left === normalizeUserCode(b)
}

/**
 * The preset pre-selected on the approval page: read-only, unless the hibou
 * CLI asked for something else, in which case its request is kept. Only an
 * offered preset is ever returned (the server offers the requested preset and
 * lower ones).
 */
export function defaultDevicePreset(
  clientId: string,
  requested: DeviceLoginPreset,
  offered: readonly DeviceLoginPreset[],
): DeviceLoginPreset {
  if (clientId === CLI_CLIENT_ID && offered.includes(requested)) return requested
  if (offered.includes('read-only')) return 'read-only'
  return offered[0] ?? 'read-only'
}
