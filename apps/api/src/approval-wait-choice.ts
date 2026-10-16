// How long the organisation's requests wait for approval, chosen by an admin
// (Phase 3 E6; partner decisions 15 and 20, S119; Rule Book §1.9): 24, 48 or
// 72 hours, 72 the ceiling. Every organisation policy change states it,
// confirmed with its words, bound into the change's passkey step-up and kept
// on the version's signed event (`approvalWaitHours`, with the version of the
// words), as E2 keeps the monthly cap choice: not in a sealed field, which
// would break every row sealed before it.
//
// Until an admin chooses (a version made before E6), requests wait 72 hours,
// the rule then, and the policy shows the wait as not chosen (partner, S119).
// A request waits what was in force when it was decided, sealed on its own
// decision, so a lowered wait expires none already waiting (decision 20).
import type { AuditDetails } from '@agentx/core/modules/audit';
import { APPROVAL_WAITS, type ApprovalWaitHours } from '@agentx/core/modules/spend-requests';
import { z } from 'zod';

/** The words the choice is confirmed with, by version: the console's confirm shows them, the event keeps the version. */
const APPROVAL_WAIT_STATEMENT =
  'Requests asked from now on wait this many hours for an approver; past it each expires and the money held for it ' +
  'is freed. Requests already waiting keep the wait they were asked under.';

/** The version of APPROVAL_WAIT_STATEMENT each event names: raised with any change to its words. */
const APPROVAL_WAIT_STATEMENT_VERSION = 1;

/** The choice as an organisation policy's body names it. */
export const APPROVAL_WAIT_HOURS = z
  .literal(APPROVAL_WAITS)
  .describe(
    'How many hours the organisation’s requests wait for approval: 24, 48 or 72, confirmed by the admin with every ' +
      `change of the organisation’s policy. ${APPROVAL_WAIT_STATEMENT}`,
  );

/** The choice as the version's event keeps it, with the words confirmed: what the step-up is bound to as well. */
export const waitChoiceDetails = (hours: ApprovalWaitHours) =>
  ({ approvalWaitHours: hours, approvalWaitStatementVersion: APPROVAL_WAIT_STATEMENT_VERSION }) as const;

/** The wait a version's event keeps, or null: none chosen (a version from before E6, or a mandate's policy). */
export const waitChoiceIn = (details: AuditDetails | undefined): ApprovalWaitHours | null => {
  const chosen = details?.approvalWaitHours;
  return APPROVAL_WAITS.find((hours) => hours === chosen) ?? null;
};
