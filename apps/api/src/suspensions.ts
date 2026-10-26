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
// `supplier.unverify` or `supplier.reactivate`: an old pause never comes
// back after the supplier is verified again. Cancel chosen for a supplier
// already stopped with its requests paused, suspended or unverified (C3c,
// partner S111), under the words that said so (cancelsAtOnce), is recorded
// over the pause as a further event of its own
// (`supplier.pending_requests_chosen`, read wherever the pause is), the
// signed state unchanged, as chosenAgain records a suspend's.
//
// Reactivating a suspended supplier (decision 9, partner S112, C3d) asks the
// admin too: a fresh start (cancel) or an un-pause (pause), kept on the
// reactivation's event, so one coming back UNVERIFIED keeps its requests held
// until it is verified again. One reactivated before the choice names none
// and cancels.
//
// A supplier's details change (decision 15, E3) asks the admin too, in its
// own words (DETAILS_STATEMENTS): cancel, whatever the supplier's status, or
// pause, kept on the change's event (and on the unverify it makes of a
// verified one, read as a payee registration's is). The requests a pause
// holds are carried to the new version (pausedFromOf): the change's event
// names the version it follows, so the walk back from the current version
// through changes chosen to pause finds the versions they were decided
// under.
//
// A stop chosen to cancel voids for good (decision 32a, F1 G1): a request
// decided before any of CANCEL_BRAKES about its organisation, agent,
// mandate, source or supplier is void, whatever they are now
// (cancelledSinceOf), so one its brake's batch left can't stand again once
// what was stopped is reactivated before the request-voids job reaches it.
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
import { ORGANIZATIONS } from '@agentx/core/modules/organizations';
import { type Pausable, PENDING_CHOICES, type PendingChoice } from '@agentx/core/modules/spend-requests';
import { SUPPLIERS } from '@agentx/core/modules/suppliers';
import type { SignedStateTable } from '@agentx/platform/db';
import { z } from 'zod';

import { CONSENT_EXPIRY_CHOSEN } from './consent-expiry-choice.ts';
import { CONSENT_LAPSED } from './consent-lapses.ts';
import { IntegrityFailure } from './errors.ts';

/** The words each choice is confirmed with, by version: the console's confirm shows them, the event keeps the version. */
export const STATEMENTS = {
  cancel:
    'Every request waiting for approval, approved or ready under it is cancelled now and the money held for it freed. ' +
    'This can’t be undone: the agent asks again once it is resumed.',
  pause:
    'Its requests are held as they are: none can be approved or paid while it is suspended, and they stand again ' +
    'once it is resumed, unless the admin reactivating a supplier chooses a fresh start. Requests waiting for ' +
    'approval still expire when their wait ends. Requests an earlier stop has already cancelled (a supplier unverified ' +
    'with them cancelled) stay cancelled.',
} as const satisfies Record<PendingChoice, string>;

/**
 * The version of STATEMENTS each event names: raised with any change to their
 * words (2: an earlier stop's cancel; 3: a supplier's fresh start; S113).
 */
export const STATEMENT_VERSION = 4;

/** A suspend's choice, as its body names it. */
const PENDING_REQUESTS = z
  .enum(PENDING_CHOICES)
  .describe(
    'What happens to its pending spend requests, confirmed by the person suspending; there is no default. ' +
      `\`cancel\`: ${STATEMENTS.cancel} \`pause\`: ${STATEMENTS.pause}`,
  );

/** A suspend's body: its choice alone. */
export const SUSPEND_BODY = z.strictObject({ pendingRequests: PENDING_REQUESTS }).describe('The suspender’s choice.');

/**
 * The words a supplier's reactivation is confirmed with (decision 9, C3d),
 * by version, as STATEMENTS: a fresh start cancels, an un-pause keeps them.
 */
export const REACTIVATE_STATEMENTS = {
  cancel:
    'A fresh start: every request to this supplier waiting for approval, approved or ready is cancelled now and ' +
    'the money held for it freed. This can’t be undone: the agent asks again.',
  pause:
    'Un-pause: its held requests stand again, at once if it comes back verified. If it comes back unverified (never ' +
    'verified, or new bank details still waiting), they stay held until a second person verifies it again; new bank ' +
    'details made current, or new details chosen to cancel, cancel them. Requests waiting for approval still expire ' +
    'when their wait ends. Not offered when its suspension cancelled them.',
} as const satisfies Record<PendingChoice, string>;

/**
 * The version of REACTIVATE_STATEMENTS each event names: raised with any
 * change to their words (2: new details may carry them, E3).
 */
export const REACTIVATE_STATEMENT_VERSION = 3;

/** A supplier's reactivation: the reactivator's choice alone (decision 9). */
export const REACTIVATE_BODY = z
  .strictObject({
    pendingRequests: z
      .enum(PENDING_CHOICES)
      .describe(
        'What happens to the supplier’s held spend requests, confirmed by the admin reactivating; there is no ' +
          `default. \`cancel\`: ${REACTIVATE_STATEMENTS.cancel} \`pause\`: ${REACTIVATE_STATEMENTS.pause}`,
      ),
  })
  .describe('The reactivator’s choice.');

/** The choice as a reactivation's event keeps it, with the statement confirmed: read for an UNVERIFIED one's pause. */
export const reactivationChoiceDetails = (choice: PendingChoice) =>
  ({ pendingRequests: choice, pendingStatementVersion: REACTIVATE_STATEMENT_VERSION }) as const;

/**
 * The words an organisation's freeze is confirmed with (decision 10, D1), by
 * version, as STATEMENTS: the console's confirm (decision 11) shows them.
 */
export const FREEZE_STATEMENTS = {
  cancel:
    'Every spend request of the organisation waiting for approval, approved or ready is cancelled now and the money ' +
    'held for it freed. This can’t be undone: the agents ask again once it is unfrozen.',
  pause:
    'Its spend requests are held as they are: none can be approved or paid while it is frozen, and they stand again ' +
    'once it is unfrozen, unless the admin unfreezing it chooses a fresh start. Requests waiting for approval still ' +
    'expire when their wait ends.',
} as const satisfies Record<PendingChoice, string>;

/** The version of FREEZE_STATEMENTS each event names: raised with any change to their words (2: a fresh start, D2). */
export const FREEZE_STATEMENT_VERSION = 3;

/** A freeze's body: the member's choice, and their confirmation (decision 11: the console's are-you-sure). */
export const FREEZE_BODY = z
  .strictObject({
    pendingRequests: z
      .enum(PENDING_CHOICES)
      .describe(
        'What happens to the organisation’s pending spend requests, chosen by the admin or approver freezing; there ' +
          `is no default. \`cancel\`: ${FREEZE_STATEMENTS.cancel} \`pause\`: ${FREEZE_STATEMENTS.pause}`,
      ),
    confirmed: z
      .literal(true)
      .describe('They confirmed the freeze, shown what it does: no request is decided or approved while frozen.'),
  })
  .describe('The freezing admin’s or approver’s choice and confirmation.');

/** The choice as a freeze's event keeps it, with the statement confirmed. */
export const freezeChoiceDetails = (choice: PendingChoice) =>
  ({ pendingRequests: choice, pendingStatementVersion: FREEZE_STATEMENT_VERSION }) as const;

/**
 * The words an unfreeze is confirmed with (decision 14, D2), by version, as
 * REACTIVATE_STATEMENTS: a fresh start cancels, an un-pause keeps them.
 */
export const UNFREEZE_STATEMENTS = {
  cancel:
    'A fresh start: every spend request of the organisation waiting for approval, approved or ready is cancelled ' +
    'now and the money held for it freed. This can’t be undone: the agents ask again.',
  pause:
    'Un-pause: the held spend requests stand again at once, unless something else still stops them. Requests ' +
    'waiting for approval still expire when their wait ends. Not offered when its freeze cancelled them.',
} as const satisfies Record<PendingChoice, string>;

/** The version of UNFREEZE_STATEMENTS each event names: raised with any change to their words. */
export const UNFREEZE_STATEMENT_VERSION = 2;

/** An unfreeze's choice, as its bodies name it (decision 14). */
export const UNFREEZE_PENDING_REQUESTS = z
  .enum(PENDING_CHOICES)
  .describe(
    'What happens to the organisation’s held spend requests, confirmed by the admin unfreezing; there is no ' +
      `default. \`cancel\`: ${UNFREEZE_STATEMENTS.cancel} \`pause\`: ${UNFREEZE_STATEMENTS.pause}`,
  );

/** The choice as an unfreeze's event keeps it, with the statement confirmed. */
export const unfreezeChoiceDetails = (choice: PendingChoice) =>
  ({ pendingRequests: choice, pendingStatementVersion: UNFREEZE_STATEMENT_VERSION }) as const;

/** The most a body holding a choice alone may be (a suspend's, a payee start's), with room to spare. */
export const CHOICE_BODY_LIMIT = 64;

/** The words a payee registration's choice is confirmed with (decision 8), by version, as STATEMENTS. */
export const PAYEE_STATEMENTS = {
  cancel:
    'Once the partner confirms the new bank details, every request to this supplier waiting for approval, approved ' +
    'or ready is cancelled and the money held for it freed. This can’t be undone: the agent asks again once the ' +
    'supplier is verified again.',
  pause:
    'Once the partner confirms the new bank details, its requests are held as they are: none can be approved or paid ' +
    'while the supplier is unverified. Confirming the new details cancels them; withdrawing the change, they stand ' +
    'again once the supplier is verified again. A supplier already suspended or unverified keeps the choice it was ' +
    'stopped with. Requests waiting for approval still expire when their wait ends.',
} as const satisfies Record<PendingChoice, string>;

/** The version of PAYEE_STATEMENTS each event names: raised with any change to their words (2: cancel always, C3c). */
export const PAYEE_STATEMENT_VERSION = 3;

/** A payee registration's choice, as its body names it (decision 8). */
export const PAYEE_PENDING_REQUESTS = z
  .enum(PENDING_CHOICES)
  .describe(
    'What happens to the supplier’s pending spend requests once the partner confirms the new bank details, ' +
      'confirmed by the admin registering; there is no default. ' +
      `\`cancel\`: ${PAYEE_STATEMENTS.cancel} \`pause\`: ${PAYEE_STATEMENTS.pause}`,
  );

/** A payee registration's cancel recorded over a supplier's pause (C3c): read wherever the pause is (PAUSE_EVENTS). */
const PAYEE_CANCEL = 'supplier.pending_requests_chosen';

/** The choice as a payee registration's events keep it, with the statement confirmed. */
export const payeeChoiceDetails = (choice: PendingChoice) =>
  ({ pendingRequests: choice, pendingStatementVersion: PAYEE_STATEMENT_VERSION }) as const;

/**
 * The words a supplier's details change is confirmed with (decision 15, E3),
 * by version, as STATEMENTS: a waiting request carried to the new details
 * isn't approved under the old ones (decision 16, S115: the approver
 * re-checks it, E5).
 */
export const DETAILS_STATEMENTS = {
  cancel:
    'Once you confirm the new details, every request to this supplier waiting for approval, approved or ready is ' +
    'cancelled and the money held for it freed, whatever the supplier’s status. This can’t be undone: the agent ' +
    'asks again once a second person verifies the supplier.',
  pause:
    'Once you confirm the new details, its requests are held as they are: none can be approved or paid until a ' +
    'second person verifies the supplier with its new details, when approved ones stand again. Requests waiting ' +
    'for approval can’t be approved under the old details, and still expire when their wait ends. New bank details made ' +
    'current, or a later change chosen to cancel, cancel them, and so does an eleventh change in a row chosen to ' +
    'pause, for the requests held since before the first. A supplier already suspended or unverified keeps the ' +
    'choice it was stopped with.',
} as const satisfies Record<PendingChoice, string>;

/** The version of DETAILS_STATEMENTS each event names: raised with any change to their words. */
export const DETAILS_STATEMENT_VERSION = 2;

/** A details change's choice, as its bodies name it (decision 15). */
export const DETAILS_PENDING_REQUESTS = z
  .enum(PENDING_CHOICES)
  .describe(
    'What happens to the supplier’s pending spend requests once the new details are confirmed, chosen by the ' +
      `admin changing them; there is no default. \`cancel\`: ${DETAILS_STATEMENTS.cancel} ` +
      `\`pause\`: ${DETAILS_STATEMENTS.pause}`,
  );

/** The choice as a details change's events keep it (its `supplier.details_changed`, and an unverify it made). */
export const detailsChoiceDetails = (choice: PendingChoice) =>
  ({ pendingRequests: choice, pendingStatementVersion: DETAILS_STATEMENT_VERSION }) as const;

/** A supplier's version moves: a details change (its choice kept, E3) and a new payee made current (always cancels). */
export const DETAILS_CHANGED = 'supplier.details_changed';
export const VERSION_MOVES = [DETAILS_CHANGED, 'supplier.payee_change_confirmed'] as const;

/**
 * The most details changes back a request is carried through: one decided
 * before them is voided (fail-closed), as DETAILS_STATEMENTS' pause says.
 */
export const MOST_CARRIED_CHANGES = 10;

/**
 * The versions the supplier's current one carries requests from (E3): each
 * one a details change chosen to pause moved it on from, walking back from
 * the current version through its newest version moves, each event believed
 * only whole, until a move that isn't one (a new payee, a cancel, or one
 * from before the choice, which names no version it follows). A request
 * decided under one of them isn't void for its new details; its supplier's
 * status is judged as ever. Throws for a history that can't be believed (its
 * alarm already raised): `unbelieved`'s error, a plain one when not given (a
 * use case passes its INTEGRITY_FAILED refusal).
 */
export async function pausedFromOf(
  tx: AuditTransaction,
  states: SignedStates,
  orgId: string,
  supplier: { readonly id: string; readonly currentVersionId: string },
  unbelieved: () => Error = () => new Error(`A supplier's version history can't be believed: ${supplier.id}`),
): Promise<readonly string[]> {
  const history = await states.historyOf(tx, orgId, {
    subjectTypes: [SUPPLIERS.subject],
    subjectId: supplier.id,
    actions: VERSION_MOVES,
    limit: MOST_CARRIED_CHANGES,
    newest: true,
  });
  if (history.outcome !== 'read') throw unbelieved();
  const carried: string[] = [];
  let expected = supplier.currentVersionId;
  for (const { event } of history.events.toReversed()) {
    const follows = event.details.followsVersionId;
    if (
      event.action !== DETAILS_CHANGED ||
      event.details.versionId !== expected ||
      choiceIn(event.details) !== 'pause' ||
      typeof follows !== 'string'
    ) {
      break;
    }
    carried.push(follows);
    expected = follows;
  }
  return carried;
}

/** The first PAYEE_STATEMENTS whose cancel said it acts whatever the supplier's status (C3c). */
const CANCELS_AT_ONCE_FROM = 2;

/**
 * Whether a payee registration's choice, as its event keeps it, cancels the
 * requests of a supplier already stopped (C3c): only a cancel confirmed under
 * words that said so. None (a registration from before the choice), or one
 * confirmed before, leaves the stop's own choice as it is (Rule Book §1.9).
 */
export const cancelsAtOnce = (details: AuditDetails | undefined): boolean =>
  details?.pendingRequests === 'cancel' && Number(details.pendingStatementVersion) >= CANCELS_AT_ONCE_FROM;

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

/** Each suspend's object type and action in the log: an organisation's freeze too (decision 10, D1). */
export const SUSPENDS = {
  organization: { type: ORGANIZATIONS.subject, action: 'organization.freeze' },
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
 * names no choice, so cancels); a supplier's either way, a payee
 * registration's cancel over its pause (C3c).
 */
export const PAUSE_EVENTS: Readonly<Record<Pausable, Readonly<Record<string, PauseEvents>>>> = {
  organization: { FROZEN: suspends('organization') },
  agent: { SUSPENDED: suspends('agent') },
  mandate: { SUSPENDED: suspends('mandate') },
  source: { SUSPENDED: suspends('source') },
  supplier: {
    SUSPENDED: { type: SUPPLIERS.subject, actions: [SUSPENDS.supplier.action, PAYEE_CANCEL] },
    UNVERIFIED: { type: SUPPLIERS.subject, actions: ['supplier.unverify', 'supplier.reactivate', PAYEE_CANCEL] },
  },
};

/**
 * The events about each that cancel its pending requests (F1 G1): `cancels`
 * unless they chose to pause (one from before the choice names none, so
 * cancels); `cancelsIfChosen` only when they chose to cancel (a fresh start;
 * a consent's lapse under a cancel, decision 21); `cancelsPastEnd` only when
 * chosen to cancel once the consent had run out (`lapsedConsentId`, a hold
 * made a cancel): one chosen before the end cancels nothing until its lapse.
 */
export const CANCEL_BRAKES: Readonly<
  Record<
    Pausable,
    {
      readonly type: string;
      readonly cancels: readonly string[];
      readonly cancelsIfChosen: readonly string[];
      readonly cancelsPastEnd: readonly string[];
    }
  >
> = {
  organization: {
    type: ORGANIZATIONS.subject,
    cancels: [SUSPENDS.organization.action],
    cancelsIfChosen: ['organization.unfreeze'],
    cancelsPastEnd: [],
  },
  agent: { type: AGENTS.subject, cancels: [SUSPENDS.agent.action], cancelsIfChosen: [], cancelsPastEnd: [] },
  mandate: { type: MANDATES.subject, cancels: [SUSPENDS.mandate.action], cancelsIfChosen: [], cancelsPastEnd: [] },
  source: {
    type: SOURCES.subject,
    cancels: [SUSPENDS.source.action],
    cancelsIfChosen: [CONSENT_LAPSED],
    cancelsPastEnd: [CONSENT_EXPIRY_CHOSEN],
  },
  supplier: {
    type: SUPPLIERS.subject,
    cancels: [SUSPENDS.supplier.action, 'supplier.unverify', PAYEE_CANCEL],
    cancelsIfChosen: ['supplier.reactivate', 'supplier.reactivate_verified'],
    cancelsPastEnd: [],
  },
};

/** Where a choice made once the consent had run out names that consent (CANCEL_BRAKES' `cancelsPastEnd`). */
export const LAPSED_CONSENT_KEY = 'lapsedConsentId';

/** How many stops one read of a request's takes: the next page is read only when none of these cancels. */
const BRAKES_A_PAGE = 20;

/** Whether an event of CANCEL_BRAKES[which] cancels, as its details keep the choice. */
const cancels = (which: Pausable, action: string, details: AuditDetails): boolean => {
  const brakes = CANCEL_BRAKES[which];
  if (brakes.cancels.includes(action)) return choiceIn(details) === 'cancel';
  const chosen = details.pendingRequests === 'cancel';
  if (brakes.cancelsPastEnd.includes(action)) return chosen && typeof details[LAPSED_CONSENT_KEY] === 'string';
  return chosen && brakes.cancelsIfChosen.includes(action);
};

/**
 * Those of a request's organisation, agent, mandate, source and supplier
 * (`ids`) stopped by a stop chosen to cancel after its decided event
 * (`decidedSeq`), read from the log oldest first, a page at a time until one
 * holds a cancel or the stops run out, each event believed only whole; one it
 * doesn't name (null) is left out. Every stop read is a person's (each lift
 * stepped up with a passkey), so the pages are few. Throws for a history
 * that can't be believed (its alarm already raised): `unbelieved`'s error, a
 * plain one when not given (a use case passes its INTEGRITY_FAILED refusal).
 */
export async function cancelledSinceOf(
  tx: AuditTransaction,
  states: SignedStates,
  orgId: string,
  decidedSeq: bigint,
  ids: Readonly<Record<Pausable, string | null>>,
  unbelieved: () => Error = () => new Error(`A spend request's stops can't be believed: ${orgId}`),
): Promise<ReadonlySet<Pausable>> {
  const kinds = (Object.keys(CANCEL_BRAKES) as Pausable[]).filter((which) => ids[which] !== null);
  const whichOf = ({ type, id }: { readonly type: string; readonly id: string }) =>
    kinds.find((kind) => CANCEL_BRAKES[kind].type === type && ids[kind]?.toLowerCase() === id.toLowerCase());
  const cancelledBy = new Set<Pausable>();
  let afterSeq = decidedSeq;
  let more = true;
  while (more && cancelledBy.size === 0) {
    const history = await states.historyOf(tx, orgId, {
      subjectTypes: kinds.map((which) => CANCEL_BRAKES[which].type),
      subjectIds: kinds.map((which) => String(ids[which])),
      actions: kinds.flatMap((which) => {
        const { cancels: always, cancelsIfChosen, cancelsPastEnd } = CANCEL_BRAKES[which];
        return [...always, ...cancelsIfChosen, ...cancelsPastEnd];
      }),
      afterSeq,
      limit: BRAKES_A_PAGE,
      oldest: true,
    });
    if (history.outcome !== 'read') throw unbelieved();
    for (const { event } of history.events) {
      const which = whichOf(event.subject);
      if (which !== undefined && cancels(which, event.action, event.details)) cancelledBy.add(which);
    }
    afterSeq = history.events.at(-1)?.seq ?? afterSeq;
    more = history.events.length === BRAKES_A_PAGE;
  }
  return cancelledBy;
}

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
    if (history.outcome !== 'read') throw new IntegrityFailure(`A suspension's history can't be believed: ${id}`);
    if (choiceIn(history.events.at(-1)?.event.details) === 'pause') paused.add(which);
  }
  return paused;
}

/**
 * Whether the stop in force on one SUSPENDED (an organisation: FROZEN)
 * cancelled its requests (pausedOf): its reactivation voids those its brake
 * left first, in its own transaction (F1 G1), the request-voids job any past
 * that batch.
 */
export const cancelledInForce = async (
  tx: AuditTransaction,
  states: SignedStates,
  orgId: string,
  which: Pausable,
  id: string,
): Promise<boolean> =>
  !(await pausedOf(tx, states, orgId, [[which, id, which === 'organization' ? 'FROZEN' : 'SUSPENDED']])).has(which);

/**
 * Suspends again one SUSPENDED already (an organisation: FROZEN), read for
 * change (`state`), with the member's `choice`: a pause made a cancel is
 * recorded, as `actor`'s, with `details` (a suspend's words unless named);
 * the same choice left as it is; `refused` for a cancel made a pause.
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
  details: AuditDetails = choiceDetails(choice),
): Promise<'as_is' | 'refused'> {
  const { which, table, key, state } = subject;
  const stoppedIn = which === 'organization' ? 'FROZEN' : 'SUSPENDED';
  const paused = (await pausedOf(tx, states, key.orgId, [[which, key.id, stoppedIn]])).has(which);
  if (!paused) return choice === 'cancel' ? 'as_is' : 'refused';
  if (choice === 'cancel') {
    await states.record(tx, table, key, state, {}, { actor, action: SUSPENDS[which].action, details });
  }
  return 'as_is';
}

/**
 * A payee registration's cancel over a supplier, read for change (`state`),
 * stopped in `status` with its requests paused (C3c): recorded as `actor`'s,
 * the signed state unchanged, with the version of the words the admin
 * confirmed (`chosen`, the registration's), so the stop in force cancels and
 * the request-voids job takes any past the batch. True when recorded; false
 * for a supplier no pause holds.
 */
export async function payeeCancelOverPause(
  tx: AuditTransaction,
  states: SignedStates,
  supplier: {
    readonly key: { readonly orgId: string; readonly id: string };
    readonly state: VerifiedState;
    readonly status: string;
  },
  chosen: AuditDetails | undefined,
  actor: AuditActor,
): Promise<boolean> {
  const { key, state, status } = supplier;
  if (!(await pausedOf(tx, states, key.orgId, [['supplier', key.id, status]])).has('supplier')) return false;
  await states.record(
    tx,
    SUPPLIERS,
    key,
    state,
    {},
    {
      actor,
      action: PAYEE_CANCEL,
      details: { pendingRequests: 'cancel', pendingStatementVersion: chosen?.pendingStatementVersion ?? null },
    },
  );
  return true;
}
