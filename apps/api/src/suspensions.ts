// What a suspension does to the pending spend requests of what it suspends
// (Phase 3 decision 7, ADR-014 §8, Rule Book §1.9): the suspender's choice,
// with no default, cancel or pause, confirmed and kept in the suspend's own
// signed event (`pendingRequests`, with the version of the statement they
// confirmed), so the evidence shows what was chosen, by whom and when. Not a
// sealed field: the seal covers every authority field, and a new one would
// break every row sealed before it.
//
// The suspension in force is the newest suspend event about its subject: a
// SUSPENDED status, verified, was put there by a suspend, and a resume in
// between is always followed by another. One recorded before the choice
// existed names none and cancels, as the PRD's rule did.
import { AGENTS } from '@agentx/core/modules/agents';
import type { AuditTransaction, SignedStates } from '@agentx/core/modules/audit';
import { SOURCES } from '@agentx/core/modules/funding-sources';
import { MANDATES } from '@agentx/core/modules/mandates';
import { type Pausable, PENDING_CHOICES, type PendingChoice } from '@agentx/core/modules/spend-requests';
import { SUPPLIERS } from '@agentx/core/modules/suppliers';
import { z } from 'zod';

/** The words each choice is confirmed with, by version: the console's confirm shows them, the event keeps the version. */
const STATEMENTS = {
  cancel:
    'Every request waiting for approval, approved or ready under it is cancelled now and the money held for it freed. ' +
    'This can’t be undone: the agent asks again once it is resumed.',
  pause:
    'Its requests are held as they are: none can be approved or paid while it is suspended, and they stand again ' +
    'once it is resumed. Requests waiting for approval still expire after 72 hours.',
} as const satisfies Record<PendingChoice, string>;

/** The version of STATEMENTS each event names: raised with any change to their words. */
const STATEMENT_VERSION = 1;

/** A suspend's choice, as its body names it. */
const PENDING_REQUESTS = z
  .enum(PENDING_CHOICES)
  .describe(
    'What happens to its pending spend requests, confirmed by the person suspending; there is no default. ' +
      `\`cancel\`: ${STATEMENTS.cancel} \`pause\`: ${STATEMENTS.pause}`,
  );

/** A suspend's body: its choice alone. */
export const SUSPEND_BODY = z.strictObject({ pendingRequests: PENDING_REQUESTS }).describe('The suspender’s choice.');

/** The most a suspend's body may be: its choice, with room to spare. */
export const SUSPEND_BODY_LIMIT = 64;

/** The choice as a suspend's event keeps it, with the statement confirmed. */
export const choiceDetails = (choice: PendingChoice) =>
  ({ pendingRequests: choice, pendingStatementVersion: STATEMENT_VERSION }) as const;

/** Each suspend's object type and action in the log. */
export const SUSPENDS = {
  agent: { type: AGENTS.subject, action: 'agent.suspended' },
  mandate: { type: MANDATES.subject, action: 'mandate.suspended' },
  source: { type: SOURCES.subject, action: 'funding_source.suspended' },
  supplier: { type: SUPPLIERS.subject, action: 'supplier.suspend' },
} as const satisfies Record<Pausable, { type: string; action: string }>;

/**
 * Of those SUSPENDED (each with its ID), the ones whose suspension in force
 * paused its requests, read from the log, each event believed only whole.
 * Throws for a history that can't be believed (its alarm already raised).
 */
export async function pausedOf(
  tx: AuditTransaction,
  states: SignedStates,
  orgId: string,
  suspended: readonly (readonly [Pausable, string])[],
): Promise<ReadonlySet<Pausable>> {
  const paused = new Set<Pausable>();
  for (const [which, id] of suspended) {
    const { type, action } = SUSPENDS[which];
    const history = await states.historyOf(tx, orgId, {
      subjectTypes: [type],
      subjectId: id,
      actions: [action],
      limit: 1,
      newest: true,
    });
    if (history.outcome !== 'read') throw new Error(`A suspension's history can't be believed: ${id}`);
    if (history.events.at(-1)?.event.details.pendingRequests === 'pause') paused.add(which);
  }
  return paused;
}
