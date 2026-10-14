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
//
// Suspending one suspended already (chosenAgain): the same choice, or a cancel
// over a cancel, is answered as it is (a brake pressed twice); a cancel over a
// pause is recorded as a further suspend event, the subject's signed state
// unchanged, so the newest suspension cancels; a pause over a cancel is
// refused (PENDING_REQUESTS_CANCELLED): a cancel can't be undone.
//
// A payee registration (decision 8, S111) asks the registering admin the same
// question, in its own words: a verified supplier it unverifies keeps its
// requests paused or cancels them. The pause in force for an UNVERIFIED
// supplier is the choice on the move that unverified it, its newest
// `supplier.unverify` or `supplier.reactivate` (which names none, so
// cancels): an old pause never comes back after the supplier is verified
// again.
import { AGENTS } from '@agentx/core/modules/agents';
import type {
  AuditActor,
  AuditDetails,
  AuditTransaction,
  SignedStates,
  VerifiedState,
} from '@agentx/core/modules/audit';
import { SOURCES } from '@agentx/core/modules/funding-sources';
import { MANDATES } from '@agentx/core/modules/mandates';
import { type Pausable, PENDING_CHOICES, type PendingChoice } from '@agentx/core/modules/spend-requests';
import { SUPPLIERS } from '@agentx/core/modules/suppliers';
import type { SignedStateTable } from '@agentx/platform/db';
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

/** The most a body holding a choice alone may be (a suspend's, a payee start's), with room to spare. */
export const CHOICE_BODY_LIMIT = 64;

/** The words a payee registration's choice is confirmed with (decision 8), by version, as STATEMENTS. */
const PAYEE_STATEMENTS = {
  cancel:
    'Once the partner confirms the new bank details, every request to this supplier waiting for approval, approved ' +
    'or ready is cancelled and the money held for it freed. This can’t be undone: the agent asks again once the ' +
    'supplier is verified again.',
  pause:
    'Once the partner confirms the new bank details, its requests are held as they are: none can be approved or paid ' +
    'while the supplier is unverified. Confirming the new details cancels them; withdrawing the change, they stand ' +
    'again once the supplier is verified again. Requests waiting for approval still expire after 72 hours.',
} as const satisfies Record<PendingChoice, string>;

/** The version of PAYEE_STATEMENTS each event names: raised with any change to their words. */
const PAYEE_STATEMENT_VERSION = 1;

/** A payee registration's choice, as its body names it (decision 8). */
export const PAYEE_PENDING_REQUESTS = z
  .enum(PENDING_CHOICES)
  .describe(
    'What happens to the supplier’s pending spend requests if this registration unverifies it, confirmed by the ' +
      `admin registering; there is no default. \`cancel\`: ${PAYEE_STATEMENTS.cancel} \`pause\`: ${PAYEE_STATEMENTS.pause}`,
  );

/** The choice as a payee registration's events keep it, with the statement confirmed. */
export const payeeChoiceDetails = (choice: PendingChoice) =>
  ({ pendingRequests: choice, pendingStatementVersion: PAYEE_STATEMENT_VERSION }) as const;

/**
 * The choice an event keeps (choiceDetails, payeeChoiceDetails), or none
 * (an event from before the choice existed, or a move that names none, as a
 * reactivation): only a pause recorded holds the requests, anything else
 * cancels, as the PRD's rule did.
 */
export const choiceIn = (details: AuditDetails | undefined): PendingChoice =>
  details?.pendingRequests === 'pause' ? 'pause' : 'cancel';

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

/** Where a pause's choice is kept: the newest of `actions` about an object of `type`. */
interface PauseEvents {
  readonly type: string;
  readonly actions: readonly string[];
}

const suspends = (which: Pausable): PauseEvents => ({ type: SUSPENDS[which].type, actions: [SUSPENDS[which].action] });

/**
 * For each status a pause may hold each in (as voidCauses has it), the
 * events whose newest holds the pause in force: its suspends; a supplier
 * UNVERIFIED, its unverifying moves, an unverify or a reactivation (which
 * names no choice, so cancels).
 */
export const PAUSE_EVENTS: Readonly<Record<Pausable, Readonly<Record<string, PauseEvents>>>> = {
  agent: { SUSPENDED: suspends('agent') },
  mandate: { SUSPENDED: suspends('mandate') },
  source: { SUSPENDED: suspends('source') },
  supplier: {
    SUSPENDED: suspends('supplier'),
    UNVERIFIED: { type: SUPPLIERS.subject, actions: ['supplier.unverify', 'supplier.reactivate'] },
  },
};

/**
 * Of those stopped (each with its ID and status), the ones whose stop in
 * force paused its requests (PAUSE_EVENTS), read from the log, each event
 * believed only whole. Throws for a history that can't be believed (its
 * alarm already raised).
 */
export async function pausedOf(
  tx: AuditTransaction,
  states: SignedStates,
  orgId: string,
  stopped: readonly (readonly [Pausable, string, string])[],
): Promise<ReadonlySet<Pausable>> {
  const paused = new Set<Pausable>();
  for (const [which, id, status] of stopped) {
    const events = PAUSE_EVENTS[which][status];
    if (events === undefined) continue;
    const history = await states.historyOf(tx, orgId, {
      subjectTypes: [events.type],
      subjectId: id,
      actions: events.actions,
      limit: 1,
      newest: true,
    });
    if (history.outcome !== 'read') throw new Error(`A suspension's history can't be believed: ${id}`);
    if (choiceIn(history.events.at(-1)?.event.details) === 'pause') paused.add(which);
  }
  return paused;
}

/**
 * Suspends again one SUSPENDED already, read for change (`state`), with the
 * member's `choice`: a pause made a cancel is recorded, as `actor`'s; the
 * same choice left as it is; `refused` for a cancel made a pause.
 */
export async function chosenAgain(
  tx: AuditTransaction,
  states: SignedStates,
  subject: {
    readonly which: Pausable;
    readonly table: SignedStateTable;
    readonly key: { readonly orgId: string; readonly id: string };
    readonly state: VerifiedState;
  },
  choice: PendingChoice,
  actor: AuditActor,
): Promise<'as_is' | 'refused'> {
  const { which, table, key, state } = subject;
  const paused = (await pausedOf(tx, states, key.orgId, [[which, key.id, 'SUSPENDED']])).has(which);
  if (!paused) return choice === 'cancel' ? 'as_is' : 'refused';
  if (choice === 'cancel') {
    await states.record(
      tx,
      table,
      key,
      state,
      {},
      { actor, action: SUSPENDS[which].action, details: choiceDetails(choice) },
    );
  }
  return 'as_is';
}
