import { describe, expect, it } from 'vitest'

import { newLicensesIntroduced, splitConjunctiveUnits } from './licenses'

describe('splitConjunctiveUnits', () => {
  it('leaves a bare id alone', () => {
    expect(splitConjunctiveUnits('MIT')).toEqual(['MIT'])
  })

  it('splits AND into independently-applying units', () => {
    expect(splitConjunctiveUnits('MPL-2.0 AND MIT')).toEqual(['MPL-2.0', 'MIT'])
  })

  it('keeps OR whole, because it is a choice and not two obligations', () => {
    expect(splitConjunctiveUnits('MIT OR GPL-3.0-only')).toEqual(['MIT OR GPL-3.0-only'])
  })

  it('strips parens that wrap the whole expression', () => {
    expect(splitConjunctiveUnits('(MPL-2.0 AND MIT)')).toEqual(['MPL-2.0', 'MIT'])
  })

  it('splits at top level only, keeping a parenthesised choice intact', () => {
    expect(splitConjunctiveUnits('(MIT OR GPL-3.0-only) AND Apache-2.0')).toEqual([
      'MIT OR GPL-3.0-only',
      'Apache-2.0',
    ])
  })

  it('does not strip parens that are not a wrapping pair', () => {
    expect(splitConjunctiveUnits('(MIT) AND (Apache-2.0)')).toEqual(['MIT', 'Apache-2.0'])
  })

  it('treats the AND keyword case-insensitively', () => {
    expect(splitConjunctiveUnits('MPL-2.0 and MIT')).toEqual(['MPL-2.0', 'MIT'])
  })

  it('keeps WITH exceptions attached to their license', () => {
    expect(splitConjunctiveUnits('GPL-2.0-only WITH Classpath-exception-2.0')).toEqual([
      'GPL-2.0-only WITH Classpath-exception-2.0',
    ])
  })

  it('returns nothing for empty or whitespace input', () => {
    expect(splitConjunctiveUnits('')).toEqual([])
    expect(splitConjunctiveUnits('   ')).toEqual([])
  })
})

describe('newLicensesIntroduced', () => {
  it('reports a genuinely new license', () => {
    const result = newLicensesIntroduced(['MIT'], [{ licenses: ['GPL-3.0-only'] }])
    expect(result).toEqual([['GPL-3.0-only', 1]])
  })

  // The bug this function exists for: the base set used to be reconstructed
  // from removed components only, so a license already carried by an untouched
  // dependency read as introduced.
  it('does not report a license the base snapshot already has', () => {
    const result = newLicensesIntroduced(['MIT', 'GPL-3.0-only'], [{ licenses: ['GPL-3.0-only'] }])
    expect(result).toEqual([])
  })

  it('compares case-insensitively but displays the head spelling', () => {
    expect(newLicensesIntroduced(['mit'], [{ licenses: ['MIT'] }])).toEqual([])
    expect(newLicensesIntroduced(['MIT'], [{ licenses: ['(MIT)'] }])).toEqual([])
  })

  // The compound-expression false positive: with MIT already in the base, only
  // the GPL half of "MIT AND GPL-3.0-only" is newly introduced. Reporting the
  // whole expression would name MIT as new when it plainly is not.
  it('reports only the new operand of a conjunctive expression', () => {
    const result = newLicensesIntroduced(['MIT'], [{ licenses: ['MIT AND GPL-3.0-only'] }])
    expect(result).toEqual([['GPL-3.0-only', 1]])
  })

  it('matches a conjunctive head operand against a bare base license', () => {
    const result = newLicensesIntroduced(['MPL-2.0', 'MIT'], [{ licenses: ['MPL-2.0 AND MIT'] }])
    expect(result).toEqual([])
  })

  it('matches a bare head license against a conjunctive base expression', () => {
    const result = newLicensesIntroduced(['MPL-2.0 AND MIT'], [{ licenses: ['MIT'] }])
    expect(result).toEqual([])
  })

  it('treats an elective expression as one unit', () => {
    const result = newLicensesIntroduced(['MIT'], [{ licenses: ['MIT OR GPL-3.0-only'] }])
    // Not split: a consumer under "MIT OR GPL" is not compelled by GPL, so the
    // introduced thing is the choice itself, which the base did not offer.
    expect(result).toEqual([['MIT OR GPL-3.0-only', 1]])
  })

  it('counts components, not occurrences within one component', () => {
    const result = newLicensesIntroduced(
      [],
      [
        { licenses: ['GPL-3.0-only', 'GPL-3.0-only'] },
        { licenses: ['GPL-3.0-only'] },
        { licenses: ['MIT'] },
      ],
    )
    expect(result).toEqual([
      ['GPL-3.0-only', 2],
      ['MIT', 1],
    ])
  })

  it('sorts by count, then alphabetically for a stable order', () => {
    const result = newLicensesIntroduced(
      [],
      [{ licenses: ['MIT'] }, { licenses: ['MIT'] }, { licenses: ['Apache-2.0'] }, { licenses: ['ISC'] }],
    )
    expect(result).toEqual([
      ['MIT', 2],
      ['Apache-2.0', 1],
      ['ISC', 1],
    ])
  })

  it('tolerates components with no license field', () => {
    expect(newLicensesIntroduced(['MIT'], [{}, { licenses: [] }])).toEqual([])
  })

  it('ignores blank entries rather than reporting an empty license', () => {
    expect(newLicensesIntroduced([], [{ licenses: ['', '   '] }])).toEqual([])
  })

  it('treats an empty base as introducing everything in the head', () => {
    expect(newLicensesIntroduced([], [{ licenses: ['MIT'] }])).toEqual([['MIT', 1]])
  })
})

describe('nested conjunctions', () => {
  // A parenthesised AND nested under an outer AND used to stay glued, so the
  // compound string was reported as one newly introduced license even when the
  // base branch already carried both halves.
  it('re-splits an AND hidden inside a group', () => {
    expect(splitConjunctiveUnits('(MIT AND Apache-2.0) AND GPL-3.0-only')).toEqual([
      'MIT',
      'Apache-2.0',
      'GPL-3.0-only',
    ])
  })

  it('does not report a nested operand the base already has', () => {
    const result = newLicensesIntroduced(
      ['MIT', 'Apache-2.0'],
      [{ licenses: ['(MIT AND Apache-2.0) AND GPL-3.0-only'] }],
    )
    expect(result).toEqual([['GPL-3.0-only', 1]])
  })

  it('still keeps a parenthesised OR whole when nested under an AND', () => {
    expect(splitConjunctiveUnits('(MIT OR Apache-2.0) AND GPL-3.0-only')).toEqual([
      'MIT OR Apache-2.0',
      'GPL-3.0-only',
    ])
  })

  it('terminates on pathological nesting', () => {
    expect(splitConjunctiveUnits('((((MIT))))')).toEqual(['MIT'])
    expect(splitConjunctiveUnits('((MIT AND ((Apache-2.0))))')).toEqual(['MIT', 'Apache-2.0'])
  })
})
