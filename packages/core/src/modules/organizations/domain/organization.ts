// An organisation (PRD §3 `Organization`): the tenant, and what limits it.
//
// Its status is ACTIVE or FROZEN. A freeze stops every new hand-off (PRD
// §5.3) and is one of the instant brakes (ADR-003 §8): any admin, no step-up.
// Unfreezing needs step-up and a reason. Both routes are Phase 3's; the
// machine is written now because the database's status guard holds it from
// the first row (0008).
//
// Its name is what people call it: shown to its own members, never logged or
// put in an audit event, and not an authority field (it grants nothing).
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
 * Any character in Unicode's "other" category: controls, format characters
 * (the ones that reorder or hide text, which could make one name look like
 * another), surrogates left unpaired, private-use and unassigned code points.
 */
const INVISIBLE = /\p{C}/u;

/** The name can't be an organisation's; `problems` say why, never what it was. */
export class OrganizationRefused extends Error {
  readonly problems: readonly string[];

  constructor(problems: readonly string[]) {
    super(`The organisation was refused: ${problems.join('; ')}`);
    this.name = 'OrganizationRefused';
    this.problems = problems;
  }
}

/** Refuses a name that isn't 1 to 200 visible characters with no space at either end. */
export function checkName(name: string): void {
  const problems: string[] = [];
  // Code points, as the table's check counts them (char_length), not UTF-16 units.
  const length = Array.from(name).length;
  if (length === 0 || length > MAX_NAME) problems.push(`the name is 1 to ${String(MAX_NAME)} characters`);
  if (INVISIBLE.test(name)) problems.push('the name holds a control, format or unassigned character');
  if (name.trim() !== name) problems.push('the name starts or ends with a space');
  if (problems.length > 0) throw new OrganizationRefused(problems);
}
