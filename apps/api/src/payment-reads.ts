// Reading the organisation's payments, for its members (Phase 6 C1; ADR-007
// §10; BR-17): every payment newest first, or those of one group; the
// exception list, every UNKNOWN payment and every settled one the bank's word
// on its row still contradicts (S196 decision: by `contradicts`, the bank
// check's own rule, from the verified row's own provider status, so it leaves
// the list by itself once the bank agrees again; no audit event is read for
// it); and one in full, with where marking it failed stands and its history.
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
// (`earlier`), so a payment with a long history is still shown.
import type { AuditActor, PageAsked, ReadEvent, SignedStates } from '@agentx/core/modules/audit';
import { INSTRUCTIONS, instructionOf, type InstructionsTables } from '@agentx/core/modules/instructions';
import {
  MARK_FAILED_AFTER_MS,
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
  TRANSACTIONS,
  type TransactionsTables,
  type TransactionStatus,
} from '@agentx/core/modules/transactions';
import type { IdGenerator } from '@agentx/core/shared-kernel';
import type { Database, DatabaseTransaction } from '@agentx/platform/db';
import type { KeyProvider } from '@agentx/platform/keys';
import type { Logger } from '@agentx/platform/observability';

import { type Refused, refused } from './refused.ts';
import { createUseCaseWork, UseCaseRefused, type UseCaseTables } from './use-case-work.ts';

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
const HISTORY_SUBJECTS = [INSTRUCTIONS.subject, TRANSACTIONS.subject, FAILURE_PROPOSALS.subject, 'payment_alert'];

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

/**
 * The payment's history as its team is shown it, its newest events oldest
 * first. A proposal's events count only where the proposal's own first event
 * names this payment, so a proposal row pointed at it past the app can't
 * bring in another payment's history.
 */
function timelineOf(events: readonly ReadEvent[], transactionId: string): readonly TimelineEntry[] {
  const ours = new Set(
    events
      .filter(({ event }) => event.action === 'failure_proposal.made')
      .filter((event) => textOf(event, 'transactionId') === transactionId)
      .map(({ event }) => event.subject.id.toLowerCase()),
  );
  return events
    .filter(({ event }) => event.subject.type !== FAILURE_PROPOSALS.subject || ours.has(event.subject.id.toLowerCase()))
    .map((event) => ({
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

/** The entry a verified list's own rows point to; one missing is a bug. */
function pointedTo<T>(named: ReadonlyMap<string, T>, id: string): T {
  const entry = named.get(id);
  if (entry === undefined) throw new Error(`A verified payment names supplier details not read: ${id}`);
  return entry;
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
      const named = await work.answered(orgId, correlationId, (tx, states) =>
        versionsNamed(tx, states, orgId, [...new Set(listed.items.map(({ supplierVersionId }) => supplierVersionId))]),
      );
      if (named.outcome === 'refused') return named;
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
        const named = await idsOf(tx, orgId, paymentId);
        if (named === undefined) throw new PaymentReadRefused(404, 'NOT_FOUND');
        const version = await versionOf(tx, states, { orgId, id: named.versionId }, named.supplierId);
        const read = await transactionOf(tx, states, { orgId, id: paymentId }, 'share');
        if (version.outcome !== 'found' || read.outcome !== 'found') throw integrityFailed();
        const instruction = await instructionOf(tx, states, { orgId, id: read.transaction.instructionId });
        // The sealed payment names its instruction and its supplier's details: the IDs found first must be those.
        if (
          instruction.outcome !== 'found' ||
          read.transaction.instructionId !== named.instructionId.toLowerCase() ||
          instruction.instruction.supplierVersionId !== version.version.id
        ) {
          throw integrityFailed();
        }
        const payment = paymentOf(read.transaction, read.state.recordedAt, instruction.instruction);
        let markFailed: MarkFailedShown | null = null;
        if (payment.transaction.status === 'UNKNOWN') {
          const open = await openProposalOf(tx, states, { orgId, transactionId: payment.transaction.id }, 'share');
          if (open.outcome === 'tampered') throw integrityFailed();
          markFailed = {
            markableFrom: new Date(payment.transaction.createdAt.getTime() + MARK_FAILED_AFTER_MS),
            openProposal: open.outcome === 'found' ? open.proposal : null,
          };
        }
        const history = await historyIn(tx, states, orgId, [named.instructionId, paymentId, ...named.proposalIds]);
        return {
          outcome: 'found' as const,
          shown: { payment, supplierId: version.version.supplierId, supplierName: version.version.displayName },
          markFailed,
          timeline: timelineOf(history.events, payment.transaction.id),
          earlier: history.earlier,
        };
      }),
  };
}
