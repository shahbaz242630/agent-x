// The organisation's monthly cap per agent, chosen by an admin (Phase 3
// decision 15, partner S113, E2; Rule Book §1.9): no hidden default. Until an
// admin chooses, an amount or none beyond each mandate's own monthly limit,
// no agent spends (ORG_MONTHLY_CAP_NOT_SET). The choice is confirmed with its
// words, bound into the change's passkey step-up and kept on the version's
// signed event (`monthlyCapChoice`, with the version of the words), not in a
// sealed field: a new one would break every row sealed before it.
//
// A version with a cap is an amount chosen. One with none is the choice of
// none only when its event says so: a version made before E2 with no cap
// meant the old AED 20,000 default, and reads as not chosen (fail-closed).
import type { AuditDetails } from '@agentx/core/modules/audit';
import { MONTHLY_CAP_FROM } from '@agentx/core/modules/policies';
import { z } from 'zod';

export const MONTHLY_CAP_CHOICES = ['amount', 'none'] as const;
export type MonthlyCapChoice = (typeof MONTHLY_CAP_CHOICES)[number];

/** The words each choice is confirmed with, by version: the console's confirm shows them, the event keeps the version. */
const MONTHLY_CAP_STATEMENTS = {
  amount:
    'Each agent may spend at most this amount in its month, under every mandate of its counted: a request above it is ' +
    'refused. A mandate’s own policy may set another cap for its agent, higher or lower.',
  none:
    'No organisation-wide cap: each agent is held only to its mandates’ own monthly limits and any cap a mandate’s ' +
    'policy sets. An agent with a large mandate may spend all of it every month.',
} as const satisfies Record<MonthlyCapChoice, string>;

/** The version of MONTHLY_CAP_STATEMENTS each event names: raised with any change to their words. */
const MONTHLY_CAP_STATEMENT_VERSION = 1;

/** What the console fills in for the admin to change or confirm (partner, S113): AED 20,000, never applied unchosen. */
export const SUGGESTED_MONTHLY_CAP_MINOR = 2_000_000;

/** The choice as an organisation policy's body names it. */
export const MONTHLY_CAP_CHOICE = z
  .enum(MONTHLY_CAP_CHOICES)
  .describe(
    'The organisation’s monthly cap per agent, confirmed by the admin; there is no default, and no agent may spend ' +
      'until it is chosen. `amount` (with monthlyCapMinor): ' +
      `${MONTHLY_CAP_STATEMENTS.amount} \`none\` (with no monthlyCapMinor): ${MONTHLY_CAP_STATEMENTS.none}`,
  );

/** Where an agent's monthly cap comes from, as a mandate and the agent's own view show it. */
export const MONTHLY_CAP_FROM_FIELD = z
  .enum(MONTHLY_CAP_FROM)
  .describe(
    'Where it comes from: the mandate’s own policy, the organisation’s, `none` (the organisation chose no cap: only the mandate’s own monthly limit), or `not-set` (its admin hasn’t chosen yet: every request is refused, ORG_MONTHLY_CAP_NOT_SET).',
  );

/** The choice as the version's event keeps it, with the words confirmed: what the step-up is bound to as well. */
export const capChoiceDetails = (choice: MonthlyCapChoice) =>
  ({ monthlyCapChoice: choice, monthlyCapStatementVersion: MONTHLY_CAP_STATEMENT_VERSION }) as const;

/** The choice a version's event keeps, or null: none recorded (a version from before E2, or a mandate's policy). */
export const capChoiceIn = (details: AuditDetails | undefined): MonthlyCapChoice | null => {
  const chosen = details?.monthlyCapChoice;
  return chosen === 'amount' || chosen === 'none' ? chosen : null;
};
