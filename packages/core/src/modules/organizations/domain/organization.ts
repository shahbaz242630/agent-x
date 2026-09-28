// An organisation (PRD §3 `Organization`): the tenant, and what limits it.
//
// Its status is ACTIVE or FROZEN. A freeze stops every new hand-off (PRD
// §5.3) and is one of the instant brakes (ADR-003 §8): any admin, no step-up.
// Unfreezing needs step-up and a reason. Both routes are Phase 3's; the
// machine is written now because the database's status guard holds it from
// the first row (0008).
//
// Its name is what people call it, held to the shared kernel's rules for a
// visible name (visible-name.ts).
import { defineStateMachine, visibleName } from '../../../shared-kernel/index.ts';

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
  const { name: composed, problems } = visibleName(name, MAX_NAME);
  if (problems.length > 0) throw new OrganizationRefused(problems);
  return composed;
}
