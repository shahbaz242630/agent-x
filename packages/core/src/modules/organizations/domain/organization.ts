// An organisation (PRD §3 `Organization`): the tenant, and what limits it.
//
// Its status is ACTIVE or FROZEN. A freeze stops every new hand-off (PRD
// §5.3) and is one of the instant brakes (ADR-003 §8): any admin, no step-up.
// Unfreezing needs step-up and a reason. Both routes are Phase 3's; the
// machine is written now because the database's status guard holds it from
// the first row (0008).
//
// Its name is what people call it: shown to its own members, never logged or
// put in an audit event, and not an authority field (it grants nothing). It
// is kept in Unicode's composed form (NFC), so two names that look the same
// are the same text, and it must be something a person can see and read.
import { defineStateMachine } from '../../../shared-kernel/index.ts';

export const ORGANIZATION = defineStateMachine({
  name: 'organization',
  states: ['ACTIVE', 'FROZEN'],
  initial: 'ACTIVE',
  events: {
    freeze: { from: ['ACTIVE'], to: 'FROZEN' },
    unfreeze: { from: ['FROZEN'], to: 'ACTIVE' },
  },
});

/** The most characters (Unicode code points) a name may have: the table's own limit. */
const MAX_NAME = 200;

/**
 * What a name may not hold, anywhere: Unicode's "other" category (controls;
 * format characters, which reorder or hide text so one name reads as
 * another; unpaired surrogates; private-use and unassigned code points), the
 * line and paragraph separators, the code points Unicode says are shown as
 * nothing (the Hangul fillers, variation selectors), and braille, whose blank
 * pattern renders as a space.
 */
const INVISIBLE = /[\p{C}\p{Zl}\p{Zp}\p{Default_Ignorable_Code_Point}\p{Script=Braille}]/u;

/**
 * The zero-width non-joiner and joiner inside a word, where Persian, Urdu and
 * the Indic scripts need them: between two letters or marks. Anywhere else
 * they are as invisible as any other format character.
 */
const JOINER_IN_A_WORD = /(?<=[\p{L}\p{M}])\p{Join_Control}(?=[\p{L}\p{M}])/gu;

/** Something a person reads: a letter or a digit. */
const READABLE = /[\p{L}\p{N}]/u;

/** A name that starts with a combining mark, or five marks in a row: more than one character carries. */
const STACKED = /^\p{M}|\p{M}{5}/u;

/** The name can't be an organisation's; `problems` say why, never what it was. */
export class OrganizationRefused extends Error {
  readonly problems: readonly string[];

  constructor(problems: readonly string[]) {
    super(`The organisation was refused: ${problems.join('; ')}`);
    this.name = 'OrganizationRefused';
    this.problems = problems;
  }
}

/**
 * The name as it is kept (composed, NFC), or `OrganizationRefused` for one
 * that isn't 1 to 200 visible characters, with a letter or digit, no space at
 * either end, and no more than four combining marks on one character.
 */
export function organizationName(name: string): string {
  const composed = name.normalize('NFC');
  const problems: string[] = [];
  // Code points, as the table's check counts them (char_length), not UTF-16 units.
  const length = Array.from(composed).length;
  if (length === 0 || length > MAX_NAME) problems.push(`the name is 1 to ${String(MAX_NAME)} characters`);
  if (INVISIBLE.test(composed.replace(JOINER_IN_A_WORD, ''))) {
    problems.push('the name holds a control, format, invisible or unassigned character');
  }
  if (composed.trim() !== composed) problems.push('the name starts or ends with a space');
  if (!READABLE.test(composed)) problems.push('the name has no letter or digit');
  if (STACKED.test(composed)) problems.push('the name starts with a combining mark, or stacks more than 4 on one');
  if (problems.length > 0) throw new OrganizationRefused(problems);
  return composed;
}
