// A request over the mandate's own per-order or monthly limit, chosen by the
// admin drafting each version (Phase 3 decisions 15, 23; Rule Book §1.9, its
// one loosened "limit the user set"): refused, or sent to an admin's approval
// while within the bank consent. One choice for both limits, no default. The
// choice is part of the version's terms hash, so the acceptance's passkey
// covers it, and kept on its signed event (`overLimit`, with the version of
// the words), not in a sealed field: a new one would break every row sealed
// before it. A version drafted before E9 keeps none: it refuses, shown as not
// chosen.
import type { AuditDetails } from '@agentx/core/modules/audit';
import { type ConsentAllows, OVER_LIMIT, type OverLimit } from '@agentx/core/modules/mandates';
import { type ConsentCeiling, MANDATE_LIMIT_CODES } from '@agentx/core/modules/policies';
import type { ReasonCode } from '@agentx/core/shared-kernel';
import { z } from 'zod';

/** The words each choice is confirmed with, by version: the console's confirm shows them, the event keeps the version. */
const OVER_LIMIT_STATEMENTS = {
  refuse:
    'A request above this mandate’s per-order or monthly limit is refused. The agent needs a new version of the ' +
    'mandate to spend more.',
  approval:
    'A request above this mandate’s per-order or monthly limit waits for an admin’s approval instead of being ' +
    'refused, and money is held for it meanwhile. Never above the bank consent, the organisation’s monthly cap or a ' +
    'policy that refuses it: those still refuse.',
} as const satisfies Record<OverLimit, string>;

/** The version of OVER_LIMIT_STATEMENTS each event names: raised with any change to their words. */
const OVER_LIMIT_STATEMENT_VERSION = 1;

/** The choice as a draft's body names it. */
export const OVER_LIMIT_CHOICE = z
  .enum(OVER_LIMIT)
  .describe(
    'Over the mandate’s own limits, chosen with no default (decision 23). ' +
      `\`refuse\`: ${OVER_LIMIT_STATEMENTS.refuse} \`approval\`: ${OVER_LIMIT_STATEMENTS.approval}`,
  );

/** The action of a choice made on the mandate in force (E9b, partner S121: any time, either way), naming its version. */
export const OVER_LIMIT_CHOSEN = 'mandate.over_limit_chosen';

/** The choice a version shows: `not-chosen` for one drafted before E9, which refuses. */
export const OVER_LIMIT_SHOWN = z
  .enum([...OVER_LIMIT, 'not-chosen'])
  .describe(
    'Over the mandate’s own limits (decision 23): `refuse`, `approval` (an admin’s, within the bank consent), or ' +
      '`not-chosen` (a version drafted before the choice existed: refused).',
  );

/** The choice as the version's event keeps it, with the words confirmed. */
export const overLimitDetails = (choice: OverLimit) =>
  ({ overLimit: choice, overLimitStatementVersion: OVER_LIMIT_STATEMENT_VERSION }) as const;

/** The choice an event keeps (a version's drafted one, or a later choice on it), or null: none recorded (a version from before E9). */
export const overLimitIn = (details: AuditDetails | undefined): OverLimit | null => {
  const chosen = details?.overLimit;
  return chosen === 'refuse' || chosen === 'approval' ? chosen : null;
};

/** Whether a weighing found the request over its mandate's own limits: one only an admin may approve (decision 23). */
export const overMandateLimit = (reasons: readonly ReasonCode[]): boolean =>
  reasons.some((code) => MANDATE_LIMIT_CODES.includes(code));

/** The bank consent an approval past the mandate's own limits may reach: per payment, and per month only when it counts by the month. */
export const consentCeilingOf = ({ maxPayment, maxPeriod, limitPeriod }: ConsentAllows): ConsentCeiling => ({
  maxPayment,
  maxMonth: limitPeriod === 'month' ? maxPeriod : null,
});
