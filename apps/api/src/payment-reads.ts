// Reading the organisation's payments, for its members (Phase 6 C1; ADR-007
// §10; BR-17): every payment newest first, or those of one group; the
// exception list, every UNKNOWN payment and every contradicted one (S196
// decision, revised: the verified row's kept bank word still contradicts its
// status, by the bank check's own rule, AND the bank check raised its
// `payment.contradicted` alert for it, read through the verified log; it
// leaves the list by itself once the bank agrees again; payments-page.ts says
// why the word alone isn't enough); and one in full, with where marking it
// failed stands and its history.
// Each payment is its transaction and the instruction it follows, read
// through their signed states, and the supplier's details it was handed off
// to pay too: one tampered with refuses the answer, 503 INTEGRITY_FAILED, and
// holds the organisation; one that can't be checked right now (a backlog of
// events) leaves only that payment out of a list, named in `unchecked` (A1b).
// Never the payee's reference, the consent or the partner's legal references.
//
// ADR-006's lock order (supplier 6, payment 10) is kept, as the spend
// requests' reads keep it: a list reads its page of payments in one
// transaction and the supplier details they name in a second (their names,
// read a moment later); one payment is read in one transaction, its supplier
// details first, found by their IDs alone, then checked against what the
// payment's verified instruction names.
//
// A payment's history is an allow-list of each event's facts (when, what, the
// status it moved to, who by ID, how, the evidence reference), never the event
// whole: the audit log itself is its admins' alone. It is read newest first,
// at most TIMELINE_MOST events, and says when older ones were left out
// (`earlier`), so a payment with a long history is still shown. Only events
// about this payment's own objects are kept: its transaction's and its alerts'
// by its ID, its instruction's by the instruction's, and a proposal's only
// where the proposal's own first event names this payment. A proposal whose
// first event fell outside the newest TIMELINE_MOST leaves its later events
// out too: shown short rather than unchecked.
import type { AuditActor, PageAsked, ReadEvent, SignedStates } from '@agentx/core/modules/audit';
import {
  type InstructionRecord,
  INSTRUCTIONS,
  instructionOf,
  type InstructionsTables,
} from '@agentx/core/modules/instructions';
import {
  contradictionsOf,
  MARK_FAILED_AFTER_MS,
  PAYMENT_ALERT_SUBJECT,
  paymentOf,
  type PaymentRecord,
  type PaymentsAsked,
  paymentsPage,
} from '@agentx/core/modules/outcomes';
import { SUPPLIER_VERSIONS, type SuppliersTables, versionOf, versionsNamed } from '@agentx/core/modules/suppliers';
import {
  FAILURE_PROPOSALS,
  type FailureProposalRecord,
  openProposalOf,
  TRANSACTION,
  transactionOf,
  type TransactionRecord,
  TRANSACTIONS,
  type TransactionsTables,
  type TransactionStatus,
} from '@agentx/core/modules/transactions';
import type { IdGenerator } from '@agentx/core/shared-kernel';
import type { Database, DatabaseTransaction } from '@agentx/platform/db';
import type { KeyProvider } from '@agentx/platform/keys';
import type { Logger } from '@agentx/platform/observability';

import { type Refused, refused } from './refused.ts';
import { createUseCaseWork, pointedTo, UseCaseRefused, type UseCaseTables } from './use-case-work.ts';

export type PaymentReadTables = UseCaseTables & SuppliersTables & InstructionsTables & TransactionsTables;
type ReadTx = DatabaseTransaction<PaymentReadTables>;

/** The groups a list may ask for, each the statuses it holds. */
export const PAYMENT_GROUPS = {
  pending: ['SUBMISSION_PENDING', 'SUBMITTED', 'PROCESSING'],
  paid: ['SUCCEEDED'],
  failed: ['FAILED'],
  cancelled: ['CANCELLED'],
  unknown: ['UNKNOWN'],
  reversed: ['REVERSED'],
} as const satisfies Record<string, readonly TransactionStatus[]>;

export type PaymentGroup = keyof typeof PAYMENT_GROUPS;

/** The most events of a payment's history one read shows: its newest. */
export const TIMELINE_MOST = 100;

/** A payment as people see it, with the supplier it was handed off to pay, by the name those details gave it. */
export interface PaymentShown {
  readonly payment: PaymentRecord;
  readonly supplierId: string;
  readonly supplierName: string;
}

export type PaymentsListed =
  | {
      readonly outcome: 'listed';
      readonly payments: readonly PaymentShown[];
      readonly next: string | null;
      readonly unchecked: readonly string[];
    }
  | Refused;

/** One event of a payment's history, as its team is shown it: an allow-list of its facts. */
interface TimelineEntry {
  readonly at: Date;
  /** The event's action, as the audit log names it (`transaction.succeed`, `payment.contradicted`). */
  readonly what: string;
  /** The status the payment moved to, for its transaction's own moves; else null. */
  readonly status: TransactionStatus | null;
  readonly by: AuditActor;
  /** How it came (`bank_check`, `admin`), where the event says; else null. */
  readonly via: string | null;
  /** The evidence it rests on (the bank's reference an admin gave, the bank's status), where the event names it. */
  readonly evidenceRef: string | null;
}

/** Where marking an UNKNOWN payment failed stands (gate H10): from when it may be proposed, and the proposal open. */
interface MarkFailedShown {
  readonly markableFrom: Date;
  readonly openProposal: FailureProposalRecord | null;
}

export type PaymentFound =
  | {
      readonly outcome: 'found';
      readonly shown: PaymentShown;
      /** Null for a payment that isn't UNKNOWN: only an UNKNOWN one is marked failed. */
      readonly markFailed: MarkFailedShown | null;
      /** Its newest events, oldest first. */
      readonly timeline: readonly TimelineEntry[];
      /** Whether older events were left out past TIMELINE_MOST. */
      readonly earlier: boolean;
    }
  | Refused;

export interface PaymentReads {
  /** Every payment, or one group's, or the exceptions, newest first. */
  list(
    orgId: string,
    page: PageAsked,
    which: PaymentGroup | 'all' | 'exceptions',
    correlationId: string,
  ): Promise<PaymentsListed>;
  show(orgId: string, paymentId: string, correlationId: string): Promise<PaymentFound>;
}

/** Refused inside a payment's read, so its transaction ends there. */
class PaymentReadRefused extends UseCaseRefused {}

/** A record that can't be believed (its alarm raised): 503 INTEGRITY_FAILED. */
const integrityFailed = () => new PaymentReadRefused(503, 'INTEGRITY_FAILED');

const asked = (which: PaymentGroup | 'all' | 'exceptions'): PaymentsAsked => {
  if (which === 'exceptions') return which;
  return { statuses: which === 'all' ? null : PAYMENT_GROUPS[which] };
};

/** The subjects a payment's history is about: its instruction, its transaction, its proposals, its alerts. */
const HISTORY_SUBJECTS = [INSTRUCTIONS.subject, TRANSACTIONS.subject, FAILURE_PROPOSALS.subject, PAYMENT_ALERT_SUBJECT];

/** A detail of the event's, when it is short text; else null. */
const textOf = (event: ReadEvent, name: string): string | null => {
  const value = event.event.details[name];
  return typeof value === 'string' ? value : null;
};

/** The status a transaction's own event moved it to: its opening's first, or a move's `statusTo`; else null. */
const statusOf = (event: ReadEvent): TransactionStatus | null => {
  if (event.event.subject.type !== TRANSACTIONS.subject) return null;
  if (event.event.action === 'transaction.opened') return TRANSACTION.initial;
  const to = textOf(event, 'statusTo');
  return TRANSACTION.states.find((status) => status === to) ?? null;
};

/** The payment's history as its team is shown it, its newest events oldest first, each its own (aboutPayment). */
function timelineOf(
  events: readonly ReadEvent[],
  ids: { readonly transactionId: string; readonly instructionId: string },
): readonly TimelineEntry[] {
  return aboutPayment(events, ids).map((event) => ({
    at: event.recordedAt,
    what: event.event.action,
    status: statusOf(event),
    by: { type: event.event.actor.type, id: event.event.actor.id },
    via: textOf(event, 'via'),
    evidenceRef: textOf(event, 'evidenceRef'),
  }));
}

/**
 * The payment's IDs alone, its instruction's and the supplier details' it
 * names, found by its ID before any is read through its signed state
 * (ADR-006: the supplier's details at 6 come first); with its proposals' IDs.
 */
async function idsOf(tx: ReadTx, orgId: string, paymentId: string) {
  const named = await tx
    // eslint-disable-next-line agentx/authority-tables-through-signed-state -- IDs alone, each read through its signed state below
    .selectFrom(`${TRANSACTIONS.table} as t`)
    // eslint-disable-next-line agentx/authority-tables-through-signed-state -- the same: IDs alone
    .innerJoin(`${INSTRUCTIONS.table} as i`, (join) =>
      join.onRef('i.org_id', '=', 't.org_id').onRef('i.id', '=', 't.instruction_id'),
    )
    // eslint-disable-next-line agentx/authority-tables-through-signed-state -- the same: IDs alone
    .innerJoin(`${SUPPLIER_VERSIONS.table} as v`, (join) =>
      join.onRef('v.org_id', '=', 'i.org_id').onRef('v.id', '=', 'i.supplier_version_id'),
    )
    .select(['t.instruction_id as instructionId', 'v.id as versionId', 'v.supplier_id as supplierId'])
    .where('t.org_id', '=', orgId)
    .where('t.id', '=', paymentId)
    .executeTakeFirst();
  if (named === undefined) return undefined;
  const proposals = await tx
    // eslint-disable-next-line agentx/authority-tables-through-signed-state -- IDs alone, for the events about them; each proposal's own first event must name this payment (timelineOf)
    .selectFrom(FAILURE_PROPOSALS.table)
    .select('id')
    .where('org_id', '=', orgId)
    .where('transaction_id', '=', paymentId)
    .execute();
  return { ...named, proposalIds: proposals.map(({ id }) => id) };
}

/** The payment's newest events and whether older ones were left out, in one read; one that can't be believed refuses it. */
async function historyIn(tx: ReadTx, states: SignedStates, orgId: string, subjectIds: readonly string[]) {
  const history = await states.historyOf(tx, orgId, {
    subjectTypes: HISTORY_SUBJECTS,
    subjectIds,
    // One past the most shown tells there were older ones.
    limit: TIMELINE_MOST + 1,
    newest: true,
  });
  if (history.outcome === 'tampered') throw integrityFailed();
  const earlier = history.events.length > TIMELINE_MOST;
  return { events: earlier ? history.events.slice(1) : history.events, earlier };
}

/** Where marking it failed stands: from when, and the proposal open, for an UNKNOWN payment alone; else null; or tampered with. */
async function markFailedOf(
  tx: ReadTx,
  states: SignedStates,
  orgId: string,
  transaction: TransactionRecord,
): Promise<MarkFailedShown | null | 'tampered'> {
  if (transaction.status !== 'UNKNOWN') return null;
  const open = await openProposalOf(tx, states, { orgId, transactionId: transaction.id }, 'share');
  if (open.outcome === 'tampered') return 'tampered';
  return {
    markableFrom: new Date(transaction.createdAt.getTime() + MARK_FAILED_AFTER_MS),
    openProposal: open.outcome === 'found' ? open.proposal : null,
  };
}

/** A payment read whole (paymentInOrder): as shown, with its instruction, where marking it failed stands, and its proposals' IDs. */
interface PaymentRead {
  readonly outcome: 'found';
  readonly shown: PaymentShown;
  readonly instruction: InstructionRecord;
  readonly markFailed: MarkFailedShown | null;
  /** Its proposals' IDs as their rows name it, not yet believed: their events must name this payment (aboutPayment). */
  readonly proposalIds: readonly string[];
}

/**
 * One payment, its supplier's details first (ADR-006: 6 before 10), then its
 * transaction and instruction, each verified and locked `share`, with where
 * marking it failed stands and whether the bank contradicts it, in the
 * caller's transaction (withSignedStates' for the organisation): `none` for
 * no payment of the organisation's; `unbelieved` when a record fails its seal
 * (its alarm raised) or the payment names others than the IDs first found by.
 * The team's one payment and a spend request's evidence (C2) alike.
 */
export async function paymentInOrder(
  tx: ReadTx,
  states: SignedStates,
  orgId: string,
  paymentId: string,
): Promise<PaymentRead | { readonly outcome: 'none' } | { readonly outcome: 'unbelieved' }> {
  const named = await idsOf(tx, orgId, paymentId);
  if (named === undefined) return { outcome: 'none' };
  const version = await versionOf(tx, states, { orgId, id: named.versionId }, named.supplierId);
  const read = await transactionOf(tx, states, { orgId, id: paymentId }, 'share');
  if (version.outcome !== 'found' || read.outcome !== 'found') return { outcome: 'unbelieved' };
  const instruction = await instructionOf(tx, states, { orgId, id: read.transaction.instructionId });
  // The sealed payment names its instruction and its supplier's details: the IDs found first must be those.
  if (
    instruction.outcome !== 'found' ||
    read.transaction.instructionId !== named.instructionId.toLowerCase() ||
    instruction.instruction.supplierVersionId !== version.version.id
  ) {
    return { outcome: 'unbelieved' };
  }
  const markFailed = await markFailedOf(tx, states, orgId, read.transaction);
  const alerts = await contradictionsOf(tx, states, orgId, [read.transaction]);
  if (markFailed === 'tampered' || alerts.outcome === 'tampered') return { outcome: 'unbelieved' };
  const payment = paymentOf(read.transaction, read.state.recordedAt, instruction.instruction, alerts.alerted);
  return {
    outcome: 'found',
    shown: { payment, supplierId: version.version.supplierId, supplierName: version.version.displayName },
    instruction: instruction.instruction,
    markFailed,
    proposalIds: named.proposalIds,
  };
}

/**
 * A payment's events kept as its own: its transaction's and alerts' by its
 * ID, its instruction's by its own, and a proposal's only where the
 * proposal's own first event names this payment. The read matches every
 * subject type against every ID asked, and the proposals' IDs come from rows
 * not yet believed, so a proposal row pointed at it past the app can't bring
 * in another payment's history.
 */
export function aboutPayment<Event extends ReadEvent>(
  events: readonly Event[],
  { transactionId, instructionId }: { readonly transactionId: string; readonly instructionId: string },
): readonly Event[] {
  const proposals = new Set(
    events
      .filter(({ event }) => event.action === 'failure_proposal.made')
      .filter((event) => textOf(event, 'transactionId') === transactionId)
      .map(({ event }) => event.subject.id.toLowerCase()),
  );
  const ours: Readonly<Record<string, (id: string) => boolean>> = {
    [TRANSACTIONS.subject]: (id) => id === transactionId,
    [PAYMENT_ALERT_SUBJECT]: (id) => id === transactionId,
    [INSTRUCTIONS.subject]: (id) => id === instructionId,
    [FAILURE_PROPOSALS.subject]: (id) => proposals.has(id),
  };
  return events.filter(({ event }) => ours[event.subject.type]?.(event.subject.id.toLowerCase()) === true);
}

export function createPaymentReads({
  database,
  keys,
  ids,
  logger,
}: {
  readonly database: Database<PaymentReadTables>;
  readonly keys: KeyProvider;
  readonly ids: IdGenerator;
  readonly logger: Logger;
}): PaymentReads {
  const work = createUseCaseWork({ database, keys, ids, logger, Refusal: PaymentReadRefused });

  return {
    async list(orgId, page, which, correlationId) {
      const listed = await work.inOrganisation(orgId, correlationId, (tx, states) =>
        paymentsPage(tx, states, orgId, page, asked(which)),
      );
      if (listed.outcome === 'tampered') return refused(503, 'INTEGRITY_FAILED');
      // Nothing here refuses as an area's refusal: a plain read, as the first.
      const named = await work.inOrganisation(orgId, correlationId, (tx, states) =>
        versionsNamed(tx, states, orgId, [...new Set(listed.items.map(({ supplierVersionId }) => supplierVersionId))]),
      );
      if (named.outcome === 'tampered') return refused(503, 'INTEGRITY_FAILED');
      const stuck = (payment: PaymentRecord) => named.stuck.has(payment.supplierVersionId);
      return {
        outcome: 'listed',
        payments: listed.items
          .filter((payment) => !stuck(payment))
          .map((payment) => {
            const version = pointedTo(named.versions, payment.supplierVersionId);
            return { payment, supplierId: version.supplierId, supplierName: version.displayName };
          }),
        next: listed.next,
        unchecked: [...listed.unchecked, ...listed.items.filter(stuck).map(({ transaction }) => transaction.id)],
      };
    },

    show: (orgId, paymentId, correlationId) =>
      work.answered(orgId, correlationId, async (tx, states) => {
        const read = await paymentInOrder(tx, states, orgId, paymentId);
        if (read.outcome === 'none') throw new PaymentReadRefused(404, 'NOT_FOUND');
        if (read.outcome === 'unbelieved') throw integrityFailed();
        const { transaction } = read.shown.payment;
        const ids = { transactionId: transaction.id, instructionId: transaction.instructionId };
        const history = await historyIn(tx, states, orgId, [ids.instructionId, ids.transactionId, ...read.proposalIds]);
        return {
          outcome: 'found' as const,
          shown: read.shown,
          markFailed: read.markFailed,
          timeline: timelineOf(history.events, ids),
          earlier: history.earlier,
        };
      }),
  };
}
