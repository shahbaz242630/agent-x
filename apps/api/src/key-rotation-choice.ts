// What happens to an agent's old key when it is rotated (Phase 3 E8; partner
// decisions 15 and 22, S120; Rule Book §1.9): the member rotating chooses,
// each time, with no default: the old key keeps working beside the new one
// for the overlap (KEY_OVERLAP_HOURS, or to its own expiry if sooner), so the
// agent can switch without a gap; or it ends at once (revoked), as after a
// leak. The choice is bound into the step-up (agent-key-changes.ts), so a
// step-up signed for one can't confirm the other, and kept on both keys'
// events with the version of the words confirmed. A key rotated before E8
// kept its overlap, and reads as not chosen.
import { z } from 'zod';

/** The choices, as a body names them. */
const OLD_KEY_CHOICES = ['overlap', 'end_now'] as const;
export type OldKeyChoice = (typeof OLD_KEY_CHOICES)[number];

/** The words each choice is confirmed with, by version: the console's confirm shows them, the events keep the version. */
const OLD_KEY_STATEMENTS = {
  overlap:
    'The old key keeps working for 24 hours beside the new one (or until its own expiry, if sooner), so the agent ' +
    'can switch without a gap. Then it stops.',
  end_now:
    'The old key stops at once: anything using it is refused from now on, until the agent is given the new key. ' +
    'This can’t be undone.',
} as const satisfies Record<OldKeyChoice, string>;

/** The version of OLD_KEY_STATEMENTS each event names: raised with any change to their words. */
const OLD_KEY_STATEMENT_VERSION = 1;

/** The choice as a body names it: confirmed by the member rotating, no default. */
export const OLD_KEY = z
  .enum(OLD_KEY_CHOICES)
  .describe(
    'What happens to the old key, confirmed by the member rotating; there is no default. ' +
      `\`overlap\`: ${OLD_KEY_STATEMENTS.overlap} \`end_now\`: ${OLD_KEY_STATEMENTS.end_now}`,
  );

/** The choice as the rotation's events keep it, with the words confirmed (named for the rotation: a detail named for a key is refused as one that could hold it, ADR-014 §3). */
export const rotationDetails = (choice: OldKeyChoice) =>
  ({ rotation: choice, rotationStatementVersion: OLD_KEY_STATEMENT_VERSION }) as const;
