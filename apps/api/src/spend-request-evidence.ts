// A spend request's evidence, downloaded by an admin (Phase 6 C2a; BR-16;
// PRD §8: evidence is keyed by spend request, exists for every one, a denied
// one too, and omits financial secrets and unnecessary personal data; decision
// 24: admins only, as the audit log, since it names every person).
//
// - `POST /v1/spend-requests/{id}/evidence-exports`, with an idempotency key:
//   the request is read first (another organisation's is NOT_FOUND, with
//   nothing written); an admin's sixth download in an hour is
//   EVIDENCE_EXPORTS_SPENT, and a request whose objects hold more events than
//   one bundle may (MOST_EVIDENCE_EVENTS) is EVIDENCE_TOO_LARGE, each with
//   nothing written; then the download is recorded, EVIDENCE_EXPORTED about the
//   request's evidence, before a byte of it is read: so reading the evidence
//   out is on the log. A retry with its key answers that record again
//   (`recordSeq`), with the bundle as it stands then.
// - One moment: the rows are read in two transactions (below), so the bundle
//   holds at `upToSeq`, the newest of the record's seq and the signed events
//   the rows were believed by (signedMoment), the log read up to it; a row that
//   moved while the others were read (a hand-off landing in between) is read
//   again, at most MOST_READS times, then EVIDENCE_CHANGED_WHILE_READING.
// - Its answer is the bundle whole, machine-readable, in the contract's own
//   JSON (the console's human-readable form is built from it): the request as
//   decided (amount, supplier and order, the agent's purpose as written, its
//   decision and reasons, its evaluation input's hash, the versions of the
//   mandate, policies and supplier it was decided under, with the mandate's
//   acceptance and the supplier version's verification as their signed events,
//   each found exactly), the agent and the key it asked with, a person's
//   approval, reject or a void, the limit reservation, the funding source by
//   its holder's name and masked hint alone, and, once handed off, the
//   instruction (route, partner and its legal-entity and licence references,
//   normalized hash), the payment (the partner's reference and word, its
//   canonical status) and where its reconciliation stands. Then every signed
//   event about the request and its objects (its evidence downloads, its
//   instruction, payment, the payment's alerts, remittance and failure
//   proposals), oldest first, with their chain hashes; each actor named as the
//   audit log names them. Filtered by object, the events are each checked
//   whole but aren't consecutive in the chain: an event deleted from between
//   them is caught by a walk of the whole chain (the audit log's own check),
//   not here.
// - Every record through its signed state and every event believed only whole,
//   the reservation as the holdings check judges it: any that can't be is 503
//   INTEGRITY_FAILED, the alarm raised and the organisation held, never a
//   bundle with a part left out.
// - Never in it: the payee's reference or account, the consent, a key's
//   version, a keyed fingerprint or a MAC (the audit log's seals left out as on
//   its page, and any fact of an event whose name is secret-shaped:
//   evidenceFacts), SEC-EVD-04. The partner's legal-entity and licence
//   references are the licensed partner's public identifiers, kept (S197).
//
// ADR-006's lock order is kept by reading the rows in two transactions, the
// request with its agent and supplier (3, 6, 8) and its holdings (10), then the
// funding source (5), the supplier's details it was decided under (6) and the
// payment (6, 10); one more finds their moment, and the log is read alone, a
// batch to a transaction, with what names its actors (agents read after no row
// of ours).
import {
  type AuditSubjectKey,
  createAuditTrail,
  eventsInRange,
  type LogEvent,
  type LogPageToRead,
  type SignedRowRead,
  signedMoment,
  type SignedStates,
  type VerifiedState,
} from '@agentx/core/modules/audit';
import {
  type ActorName,
  actorsOf,
  createActorNamer,
  eventShown,
  EVIDENCE_EXPORTED,
  EVIDENCE_SUBJECT,
  evidenceFacts,
  EXPORT_BATCH,
  heldLogPage,
} from '@agentx/core/modules/evidence';
import { type FundingSourcesTables, SOURCES, sourceOf } from '@agentx/core/modules/funding-sources';
import type { DirectoryNames } from '@agentx/core/modules/identity';
import { INSTRUCTIONS } from '@agentx/core/modules/instructions';
import {
  type LimitReservationsTables,
  RESERVATION,
  type ReservationState,
  reservationsFor,
} from '@agentx/core/modules/limit-reservations';
import { MANDATES } from '@agentx/core/modules/mandates';
import { PAYMENT_ALERT_SUBJECT, paymentHoldsOf } from '@agentx/core/modules/outcomes';
import { DECISIONS } from '@agentx/core/modules/policies';
import {
  bankReferenceOf,
  ORDER_REFERENCE_MOST,
  REQUEST_PURPOSE_MOST,
  requestHoldingsWhole,
  requestOf,
  SPEND_REQUEST,
  SPEND_REQUESTS,
} from '@agentx/core/modules/spend-requests';
import { SUPPLIERS, VERIFIER_RECORDED, versionOf } from '@agentx/core/modules/suppliers';
import { FAILURE_PROPOSALS, paymentsOfRequests, TRANSACTION, TRANSACTIONS } from '@agentx/core/modules/transactions';
import { type Clock, type IdGenerator, isReasonCode, type ReasonCode } from '@agentx/core/shared-kernel';
import type { Database, DatabaseTransaction, IdempotentRequest } from '@agentx/platform/db';
import { isUnwritten } from '@agentx/platform/db';
import type { KeyProvider } from '@agentx/platform/keys';
import type { Logger } from '@agentx/platform/observability';
import type { FastifyInstance } from 'fastify';
import type { ZodTypeProvider } from 'fastify-type-provider-zod';
import { z } from 'zod';

import { memberInSessionOf, need } from './access.ts';
import { API_SCHEMAS } from './api-schemas.ts';
import { EXPORTING_ROLES, exportsSpent } from './audit-log-exports.ts';
import { LOG_EVENT, SEQ } from './audit-log.ts';
import { answerRefusal, idempotentRequest } from './idempotent-writes.ts';
import { aboutPayment, paymentInOrder, type PaymentReadTables } from './payment-reads.ts';
import { type Refused, refused } from './refused.ts';
import { REMITTANCE_SUBJECT } from './remittances.ts';
import { NOTHING, NOTHING_BODY_LIMIT, REASONS, reasonsOf } from './route-schemas.ts';
import { requestInOrder, type RequestReadTables } from './spend-request-reads.ts';
import { createUseCaseWork, type Member, UseCaseRefused } from './use-case-work.ts';

export const EVIDENCE_OPERATION = 'spend-requests.evidence-export';

/** The advisory lock an admin's evidence downloads count their hourly budget under (ADR-006 §6, 2b). */
const EVIDENCE_EXPORTS_LOCK = 'spend-request-evidence-exports';

/** The most events one bundle holds: a request with more is downloaded through the audit log, filtered to it. */
const MOST_EVIDENCE_EVENTS = 2000;

/** How many times the rows are read for one moment before the download gives up (EVIDENCE_CHANGED_WHILE_READING). */
const MOST_READS = 3;

/** The tables the evidence reads: the request's, its payment's, its funding source's, its reservation's, and the log's. */
export type EvidenceTables = RequestReadTables & PaymentReadTables & FundingSourcesTables & LimitReservationsTables;
type EvidenceTx = DatabaseTransaction<EvidenceTables>;

/** Refused inside the evidence's work, so its transaction ends there. */
class EvidenceRefused extends UseCaseRefused {}

/** A record that can't be believed (its alarm raised): 503 INTEGRITY_FAILED. */
const integrityFailed = () => new EvidenceRefused(503, 'INTEGRITY_FAILED');

/** Every time the log can hold: the evidence is pinned by seq, never by time. */
const ALL_TIME = { from: new Date('2000-01-01T00:00:00.000Z'), to: new Date('9999-12-31T00:00:00.000Z') } as const;

const APPROVED = 'spend_request.approved';
const REJECTED = 'spend_request.rejected';
const VOIDED = 'spend_request.voided';
const DECIDED = 'spend_request.decided';
const MANDATE_ACCEPTED = 'mandate.accepted';

/** An event as the evidence shows it: as the audit log page does, its secret-shaped facts left out too (evidenceFacts). */
const shownEvent = (logged: LogEvent, names: ReadonlyMap<string, ActorName>) => ({
  ...eventShown(logged, names),
  details: evidenceFacts(logged.event.details).map(([name, value]) => ({ name, value })),
});

type ShownEvent = ReturnType<typeof shownEvent>;

/** A signed field of the request's verified state: 0039's checks hold each to its kind. */
const fieldOf = (state: VerifiedState, column: string): string | null => state.fields.get(column) ?? null;

/** A detail of the event's, as text; else null. */
const textOf = (logged: LogEvent | undefined, name: string): string | null => {
  const value = logged?.event.details[name];
  return typeof value === 'string' ? value : null;
};

/** The newest of the request's events with one of `actions`. */
const lastOf = (events: readonly LogEvent[], ...actions: string[]) =>
  events.findLast(({ event }) => event.subject.type === SPEND_REQUESTS.subject && actions.includes(event.action));

/** A person's approval or reject of the request, from its signed event: who, when, and the material fields their step-up bound (its change hash). */
const personDecisionOf = (logged: LogEvent) => ({
  eventId: logged.id,
  byUserId: logged.event.actor.id,
  at: logged.recordedAt.toISOString(),
  changeHash: textOf(logged, 'changeHash'),
  stepUpChallengeId: textOf(logged, 'stepUpChallengeId'),
});

/** The request's evidence as the bundle shows it, its events read already. */
export type Evidence = ReturnType<typeof bundleOf>;

export type EvidenceWrite =
  | { readonly outcome: 'exported'; readonly evidence: Evidence }
  | { readonly outcome: 'conflict' }
  | { readonly outcome: 'busy' }
  | Refused;

export interface SpendRequestEvidence {
  export(
    member: Member,
    idempotent: IdempotentRequest,
    requestId: string,
    correlationId: string,
  ): Promise<EvidenceWrite>;
}

/** The request, its agent and supplier, the key it came with and what it holds, read in its transaction. */
async function requestPart(tx: EvidenceTx, states: SignedStates, keys: KeyProvider, orgId: string, requestId: string) {
  const read = await requestInOrder(tx, states, orgId, requestId);
  // Found before its download was recorded, and requests are never deleted: one not found whole now is tampered with.
  if (read.outcome !== 'found') throw integrityFailed();
  // Its reservation and order claim as the holdings check judges them: a mismatch is a tamper (its alarm raised).
  if (!(await requestHoldingsWhole(tx, states, keys, orgId, requestId, paymentHoldsOf))) throw integrityFailed();
  const [reservation] = await reservationsFor(tx, [requestId]);
  // The payment as the holdings check judged it, still locked `share`: the reservation stands with this moment of it.
  const judged = (await paymentsOfRequests(tx, states, orgId, [requestId])).get(read.shown.request.id);
  if (judged?.outcome === 'tampered') throw integrityFailed();
  return { ...read, reservation, paymentJudged: judged };
}

type RequestPart = Awaited<ReturnType<typeof requestPart>>;

/** The objects a payment's events are about, by ID: its instruction, itself, and its failure proposals. */
interface PaymentObjects {
  readonly instructionId: string;
  readonly transactionId: string;
  readonly proposalIds: readonly string[];
}

/**
 * The request's payment's objects, by their IDs alone; undefined for none
 * handed off. For the count a download is capped by, before it is recorded,
 * and to find the payment to read through its signed state. An instruction
 * with no payment (they are made in one transaction, hand-off's Tx A) has
 * already failed the holdings check, which reads both by the request.
 */
async function paymentObjectsOf(tx: EvidenceTx, orgId: string, requestId: string): Promise<PaymentObjects | undefined> {
  const row = await tx
    // eslint-disable-next-line agentx/authority-tables-through-signed-state -- IDs alone, each read through its signed state after, or counted
    .selectFrom(`${INSTRUCTIONS.table} as i`)
    // eslint-disable-next-line agentx/authority-tables-through-signed-state -- the same: its ID alone
    .innerJoin(`${TRANSACTIONS.table} as t`, (join) =>
      join.onRef('t.org_id', '=', 'i.org_id').onRef('t.instruction_id', '=', 'i.id'),
    )
    .select(['i.id as instructionId', 't.id as transactionId'])
    .where('i.org_id', '=', orgId)
    .where('i.spend_request_id', '=', requestId)
    .executeTakeFirst();
  if (row === undefined) return undefined;
  const proposals = await tx
    // eslint-disable-next-line agentx/authority-tables-through-signed-state -- IDs alone, for the events about them; each proposal's own first event must name this payment (aboutPayment)
    .selectFrom(FAILURE_PROPOSALS.table)
    .select('id')
    .where('org_id', '=', orgId)
    .where('transaction_id', '=', row.transactionId)
    .execute();
  return { ...row, proposalIds: proposals.map(({ id }) => id) };
}

/** The funding source, the supplier's details it was decided under, and its payment, in ADR-006's order (5, 6, 10). */
async function fundingAndPayment(tx: EvidenceTx, states: SignedStates, orgId: string, request: RequestPart) {
  const { fundingSourceId, supplierId, id } = request.shown.request;
  const source = await sourceOf(tx, states, { orgId, id: fundingSourceId }, 'share');
  if (source.outcome !== 'found') throw integrityFailed();
  // A request names no version only for a supplier not the organisation's (0039), which requestInOrder never finds.
  const versionId = fieldOf(request.state, 'supplier_version_id');
  if (versionId === null) throw integrityFailed();
  const version = await versionOf(tx, states, { orgId, id: versionId }, supplierId);
  if (version.outcome !== 'found') throw integrityFailed();
  const objects = await paymentObjectsOf(tx, orgId, id);
  const payment = objects === undefined ? null : await paymentInOrder(tx, states, orgId, objects.transactionId);
  // Found by its instruction's request, a signed field: a row moved to another request fails its seal there.
  if (payment !== null && payment.outcome !== 'found') throw integrityFailed();
  return { source: source.source, sourceEventId: source.state.eventId, version: version.version, payment };
}

type FundingAndPayment = Awaited<ReturnType<typeof fundingAndPayment>>;
type PaymentRead = FundingAndPayment['payment'];

/** The objects of a payment read whole, by ID. */
const objectsOfPayment = (payment: NonNullable<PaymentRead>): PaymentObjects => ({
  instructionId: payment.instruction.id,
  transactionId: payment.shown.payment.transaction.id,
  proposalIds: payment.proposalIds,
});

/**
 * The rows read through their signed states whose moves the bundle shows: the
 * request and its payment as the holdings check judged them (the reservation's
 * moment), the funding source, and the payment's transaction and open proposal
 * as read with it. The supplier's details and the instruction are each made
 * once (madeOnce).
 */
function rowsReadOf(request: RequestPart, { source, sourceEventId, payment }: FundingAndPayment): SignedRowRead[] {
  const rows: SignedRowRead[] = [
    { subject: { type: SPEND_REQUESTS.subject, id: request.shown.request.id }, eventId: request.state.eventId },
    { subject: { type: SOURCES.subject, id: source.id }, eventId: sourceEventId },
  ];
  // The payment as the reservation was judged with it: settled since (its reservation moved by no signed event of
  // the request's), its transaction's newer event shows it moved.
  const judged = request.paymentJudged;
  if (judged !== undefined) {
    rows.push({ subject: { type: TRANSACTIONS.subject, id: judged.transactionId }, eventId: judged.eventId });
  }
  if (payment === null) return rows;
  rows.push({
    subject: { type: TRANSACTIONS.subject, id: payment.shown.payment.transaction.id },
    eventId: payment.transactionEventId,
  });
  const proposal = payment.markFailed?.openProposal;
  const proposalEventId = payment.markFailed?.openProposalEventId;
  if (proposal && proposalEventId) {
    rows.push({ subject: { type: FAILURE_PROPOSALS.subject, id: proposal.id }, eventId: proposalEventId });
  }
  return rows;
}

/** The objects whose events are the request's evidence: the request, its downloads, and its payment's when handed off. */
function subjectsOf(requestId: string, payment: PaymentObjects | undefined): readonly AuditSubjectKey[] {
  const own = [
    { type: SPEND_REQUESTS.subject, id: requestId },
    { type: EVIDENCE_SUBJECT, id: requestId },
  ];
  if (payment === undefined) return own;
  const { instructionId, transactionId, proposalIds } = payment;
  return [
    ...own,
    { type: INSTRUCTIONS.subject, id: instructionId },
    { type: TRANSACTIONS.subject, id: transactionId },
    { type: PAYMENT_ALERT_SUBJECT, id: transactionId },
    { type: REMITTANCE_SUBJECT, id: transactionId },
    ...proposalIds.map((id) => ({ type: FAILURE_PROPOSALS.subject, id })),
  ];
}

/**
 * The events kept as the request's own: its and its downloads' as read, and
 * of its payment's only those aboutPayment keeps (a proposal row pointed at
 * it past the app brings in no other payment's events), with its remittance's.
 */
function ownEvents(events: readonly LogEvent[], payment: PaymentRead): readonly LogEvent[] {
  if (payment === null) return events;
  const { transactionId, instructionId } = objectsOfPayment(payment);
  const ofPayment = new Set(aboutPayment(events, { transactionId, instructionId }).map(({ id }) => id));
  return events.filter(
    ({ id, event }) =>
      ofPayment.has(id) ||
      event.subject.type === SPEND_REQUESTS.subject ||
      event.subject.type === EVIDENCE_SUBJECT ||
      (event.subject.type === REMITTANCE_SUBJECT && event.subject.id.toLowerCase() === transactionId),
  );
}

/** The voiding of a request, from its signed event: when, and why (registered codes alone). */
const voidingOf = (logged: LogEvent | undefined) => {
  if (logged === undefined) return null;
  const causes: ReasonCode[] = (textOf(logged, 'causes') ?? '').split(',').filter(isReasonCode);
  return { eventId: logged.id, at: logged.recordedAt.toISOString(), reasons: reasonsOf(causes) };
};

/** The payment as the bundle shows it, once handed off: never its payee's reference or its consent. */
function paymentEvidenceOf(payment: PaymentRead) {
  if (payment === null) return null;
  const { instruction, markFailed } = payment;
  const { transaction, changedAt, contradicted } = payment.shown.payment;
  return {
    instruction: {
      id: instruction.id,
      route: instruction.route,
      routeReason: instruction.routeReason,
      partner: instruction.partner,
      partnerLegalEntityId: instruction.partnerLegalEntityId,
      partnerLicenceRef: instruction.partnerLicenceRef,
      paymentReference: instruction.paymentReference,
      intentHash: instruction.intentHash,
      createdAt: instruction.createdAt.toISOString(),
    },
    id: transaction.id,
    status: transaction.status,
    partnerReference: transaction.paymentInstructionRef,
    bankStatus: transaction.providerStatus,
    rejectCode: transaction.rejectCode,
    bankChangedAt: transaction.providerChangedAt?.toISOString() ?? null,
    createdAt: transaction.createdAt.toISOString(),
    changedAt: changedAt.toISOString(),
    reconciliation: {
      contradicted,
      markableFrom: markFailed?.markableFrom.toISOString() ?? null,
      openProposalId: markFailed?.openProposal?.id ?? null,
    },
  };
}

/** The log's part of a bundle: its events, the two it was decided under, and every actor's name. */
interface LoggedPart {
  readonly events: readonly LogEvent[];
  readonly acceptance: ShownEvent | null;
  readonly verification: ShownEvent | null;
  readonly names: ReadonlyMap<string, ActorName>;
}

/** The bundle, from what was read: every part named, those that don't apply null. */
function bundleOf(
  record: {
    readonly id: string;
    readonly recordSeq: bigint;
    readonly upToSeq: bigint;
    readonly mandateVersionId: string | null;
  },
  request: RequestPart,
  { source, version, payment }: FundingAndPayment,
  logged: LoggedPart,
) {
  const { shown, state, reservation } = request;
  const { events, names } = logged;
  const asked = shown.request;
  const approved = lastOf(events, APPROVED);
  const rejected = lastOf(events, REJECTED);
  return {
    id: record.id,
    recordSeq: record.recordSeq.toString(),
    upToSeq: record.upToSeq.toString(),
    spendRequest: {
      id: asked.id,
      status: asked.status,
      decision: asked.decision,
      reasons: reasonsOf(asked.reasons),
      amountMinor: Number(asked.amount.minor),
      currency: asked.amount.currency,
      orderReference: asked.orderReference,
      bankReference: bankReferenceOf(asked.orderReference, asked.id),
      purpose: asked.purpose,
      idempotencyKey: fieldOf(state, 'idempotency_key'),
      inputHash: fieldOf(state, 'input_hash'),
      decidedAt: lastOf(events, DECIDED)?.recordedAt.toISOString() ?? null,
      changedAt: shown.changedAt.toISOString(),
      expiresAt: shown.expiresAt?.toISOString() ?? null,
    },
    agent: { id: asked.agentId, name: shown.agentName, keyId: fieldOf(state, 'agent_key_id') },
    mandate:
      asked.mandateId === null
        ? null
        : { id: asked.mandateId, versionId: record.mandateVersionId, acceptance: logged.acceptance },
    policies: {
      organizationPolicyVersionId: fieldOf(state, 'organization_policy_version_id'),
      mandatePolicyVersionId: fieldOf(state, 'mandate_policy_version_id'),
    },
    supplier: {
      id: asked.supplierId,
      name: shown.supplierName,
      version: {
        id: version.id,
        number: version.version,
        name: version.displayName,
        verification: logged.verification,
      },
    },
    fundingSource: {
      id: source.id,
      holderName: source.summary.holderName,
      hint: source.summary.hint,
      partner: source.partner,
    },
    approval: approved === undefined ? null : personDecisionOf(approved),
    rejection:
      rejected === undefined ? null : { ...personDecisionOf(rejected), reason: textOf(rejected, 'reason') ?? '' },
    voiding: voidingOf(lastOf(events, VOIDED)),
    reservation:
      reservation === undefined
        ? null
        : {
            // The table's check holds it to one of the states (0039), and the holdings check has just judged it.
            state: reservation.state as ReservationState,
            amountMinor: Number(reservation.amountMinor),
            currency: reservation.currency,
            month: reservation.month,
            reservedAt: reservation.reservedAt.toISOString(),
          },
    payment: paymentEvidenceOf(payment),
    events: events.map((event) => shownEvent(event, names)),
  };
}

export function createSpendRequestEvidence({
  database,
  keys,
  ids,
  clock,
  logger,
  directory,
  mostEvents = MOST_EVIDENCE_EVENTS,
  mostReads = MOST_READS,
  betweenReads,
}: {
  readonly database: Database<EvidenceTables>;
  readonly keys: KeyProvider;
  readonly ids: IdGenerator;
  readonly clock: Clock;
  readonly logger: Logger;
  /** The login service's names; undefined when none is set up, and people are named from the kept copy. */
  readonly directory: DirectoryNames | undefined;
  /** The cap, MOST_EVIDENCE_EVENTS unless a test sets it lower. */
  readonly mostEvents?: number;
  /** The reads for one moment, MOST_READS unless a test sets them. */
  readonly mostReads?: number;
  /** A test's change between the request's read and its payment's, as a hand-off landing in between: never set in the app. */
  readonly betweenReads?: () => Promise<void>;
}): SpendRequestEvidence {
  const work = createUseCaseWork({ database, keys, ids, logger, Refusal: EvidenceRefused });

  /** The rows read as one moment, at least the record's seq; undefined when one moved while the others were read. */
  const rowsAtOneMoment = async (orgId: string, requestId: string, recordSeq: bigint, correlationId: string) => {
    const request = await work.inOrganisation(orgId, correlationId, (tx, states) =>
      requestPart(tx, states, keys, orgId, requestId),
    );
    await betweenReads?.();
    const rows = await work.inOrganisation(orgId, correlationId, (tx, states) =>
      fundingAndPayment(tx, states, orgId, request),
    );
    const moment = await work.inOrganisation(orgId, correlationId, (tx) =>
      signedMoment(tx, orgId, rowsReadOf(request, rows), recordSeq),
    );
    return moment.outcome === 'moved' ? undefined : { request, rows, upToSeq: moment.upToSeq };
  };

  /**
   * The log's part, a batch to a transaction, up to the bundle's moment: the
   * events about `subjects` oldest first, the mandate version's acceptance and
   * the supplier version's verification, each found exactly; every actor named.
   */
  const loggedPart = async (
    orgId: string,
    upToSeq: bigint,
    subjects: readonly AuditSubjectKey[],
    basis: {
      readonly mandate: AuditSubjectKey | null;
      readonly mandateVersionId: string | null;
      readonly supplierId: string;
      readonly versionId: string;
    },
    correlationId: string,
  ): Promise<LoggedPart> => {
    // One namer for the whole bundle: once the login service fails, no later batch waits on it.
    const namer = createActorNamer({ directory, logger: logger.child({ correlationId }) });
    const names = new Map<string, ActorName>();
    /** Every event asked for up to the moment, newest first, a batch at a time, until `enough` says stop. */
    const newestFirst = async (
      asked: Omit<LogPageToRead, 'from' | 'to' | 'limit'>,
      enough: (events: readonly LogEvent[]) => boolean,
    ) => {
      const events: LogEvent[] = [];
      for (let before: bigint | null = upToSeq + 1n; before !== null && !enough(events);) {
        const beforeSeq = before;
        const page = await work.inOrganisation(orgId, correlationId, async (tx, states) => {
          const held = await heldLogPage(tx, states, keys, orgId, {
            ...ALL_TIME,
            ...asked,
            beforeSeq,
            limit: EXPORT_BATCH,
          });
          if (held === 'tampered') throw integrityFailed();
          for (const [key, name] of await namer.namesOf(actorsOf(held.events), held.held)) names.set(key, name);
          return held;
        });
        events.push(...page.events);
        before = page.next;
      }
      return events;
    };
    const events = await newestFirst({ subjects }, (read) => read.length > mostEvents);
    // Counted before the download was recorded: more since is a request still busy, refused rather than cut short.
    if (events.length > mostEvents) throw new EvidenceRefused(409, 'EVIDENCE_TOO_LARGE');
    /** The newest `action` about `subject` whose `detail` names `id`, paged back to the log's start: null is none at all. */
    const basisFound = async (subject: AuditSubjectKey, action: string, detail: string, id: string) => {
      const namesIt = (logged: LogEvent) => textOf(logged, detail) === id;
      const read = await newestFirst({ subjects: [subject], actions: [action] }, (sofar) => sofar.some(namesIt));
      return read.find(namesIt);
    };
    const { mandate, mandateVersionId, supplierId, versionId } = basis;
    const accepted =
      mandate === null || mandateVersionId === null
        ? undefined
        : await basisFound(mandate, MANDATE_ACCEPTED, 'versionId', mandateVersionId);
    const supplier = { type: SUPPLIERS.subject, id: supplierId };
    const verified = await basisFound(supplier, VERIFIER_RECORDED, 'verifiedVersionId', versionId);
    return {
      events: events.toReversed(),
      names,
      acceptance: accepted === undefined ? null : shownEvent(accepted, names),
      verification: verified === undefined ? null : shownEvent(verified, names),
    };
  };

  return {
    async export(member, idempotent, requestId, correlationId) {
      const { orgId } = member;
      const done = await work.write(member, idempotent, correlationId, async (tx, states) => {
        // Who may download it is read again for this decision, and the request is found before anything is written.
        await work.memberIn(tx, states, member, EXPORTING_ROLES);
        if (await exportsSpent(tx, clock, member, { lock: EVIDENCE_EXPORTS_LOCK, actions: [EVIDENCE_EXPORTED] })) {
          throw new EvidenceRefused(409, 'EVIDENCE_EXPORTS_SPENT');
        }
        const read = await requestOf(tx, states, { orgId, id: requestId });
        if (read.outcome === 'missing') throw new EvidenceRefused(404, 'NOT_FOUND');
        if (read.outcome === 'tampered') throw integrityFailed();
        const subjects = subjectsOf(read.request.id, await paymentObjectsOf(tx, orgId, read.request.id));
        const counted = await eventsInRange(tx, orgId, { ...ALL_TIME, subjects });
        if (counted.events > mostEvents) throw new EvidenceRefused(409, 'EVIDENCE_TOO_LARGE');
        const recorded = await createAuditTrail({ keys, ids, correlationId }).record(tx, orgId, {
          actor: { type: 'user', id: member.userId },
          action: EVIDENCE_EXPORTED,
          subject: { type: EVIDENCE_SUBJECT, id: read.request.id, version: 1 },
          details: { spendRequestId: read.request.id, status: read.request.status, format: 'json' },
        });
        return { status: 201, resourceId: recorded.id };
      });
      if (isUnwritten(done)) return done;
      const id = done.result.resourceId;
      return work.orRefused(async (): Promise<EvidenceWrite> => {
        // Its own record, through the signed states: a retry answers the same record, the bundle from its seq on.
        const recordSeq = await work.inOrganisation(orgId, correlationId, async (tx, states) => {
          const found = await states.eventOf(tx, orgId, { eventId: id });
          if (found.outcome !== 'read' || found.event === undefined) throw integrityFailed();
          return found.event.seq;
        });
        for (let reads = 0; reads < mostReads; reads += 1) {
          const read = await rowsAtOneMoment(orgId, requestId, recordSeq, correlationId);
          if (read === undefined) continue;
          const { request, rows, upToSeq } = read;
          const { mandateId, supplierId, id: spendRequestId } = request.shown.request;
          const mandateVersionId = fieldOf(request.state, 'mandate_version_id');
          const payment = rows.payment === null ? undefined : objectsOfPayment(rows.payment);
          const logged = await loggedPart(
            orgId,
            upToSeq,
            subjectsOf(spendRequestId, payment),
            {
              mandate: mandateId === null ? null : { type: MANDATES.subject, id: mandateId },
              mandateVersionId,
              supplierId,
              versionId: rows.version.id,
            },
            correlationId,
          );
          const events = ownEvents(logged.events, rows.payment);
          return {
            outcome: 'exported',
            evidence: bundleOf({ id, recordSeq, upToSeq, mandateVersionId }, request, rows, { ...logged, events }),
          };
        }
        return refused(409, 'EVIDENCE_CHANGED_WHILE_READING');
      });
    },
  };
}

/** A signed event the bundle names apart (a mandate's acceptance, a supplier version's verification), shown as the log's own. */
const basisEvent = (what: string) => LOG_EVENT.nullable().describe(what);

/** A person's step-up-confirmed decision on the request, from its signed event. */
const PERSON_DECISION = {
  eventId: z.uuid().describe('Its signed event in the log (in `events`).'),
  byUserId: z.uuid().describe('The member who decided, by their Agent X ID: `events` names them.'),
  at: z.iso.datetime().describe('When, as its signed event seals it.'),
  changeHash: z
    .string()
    .nullable()
    .describe('The hash of the material fields their step-up was bound to (hex), as sealed; null if none was.'),
  stepUpChallengeId: z.string().nullable().describe('The step-up they confirmed it with; null if none was.'),
};

const REQUEST_EVIDENCE = z
  .object({
    id: z.uuid().describe('The request, by its ID.'),
    status: z.enum(SPEND_REQUEST.states).describe('Where it stands now.'),
    decision: z.enum(DECISIONS).describe('What its decision was when the agent asked.'),
    reasons: REASONS,
    amountMinor: z.number().describe('The amount asked for, in whole minor units.'),
    currency: z.string().describe('The amount’s currency.'),
    orderReference: z
      .string()
      .describe(
        `The supplier’s order or invoice number, as the agent gave it: 1 to ${String(ORDER_REFERENCE_MOST)} characters.`,
      ),
    bankReference: z.string().describe('What the bank’s payment reference reads for it, from the order reference.'),
    purpose: z
      .string()
      .describe(
        `What the agent says it is for, as it wrote it (1 to ${String(REQUEST_PURPOSE_MOST)} characters): the agent’s words, never Agent X’s.`,
      ),
    idempotencyKey: z.string().nullable().describe('The idempotency key the agent sent it with.'),
    inputHash: z
      .string()
      .nullable()
      .describe('The keyed hash of what its decision weighed (the evaluation input), as sealed with it.'),
    decidedAt: z.iso.datetime().nullable().describe('When its decision was signed; null if none is in the log.'),
    changedAt: z.iso.datetime().describe('When it last moved, as its signed record says.'),
    expiresAt: z.iso.datetime().nullable().describe('While it waits for approval, when it expires; else null.'),
  })
  .describe('The request as the agent asked and as it was decided.');

const PAYMENT_EVIDENCE = z
  .object({
    instruction: z
      .object({
        id: z.uuid().describe('The instruction, by its ID: the partner’s idempotency key.'),
        route: z.string().describe('The rail it was routed to.'),
        routeReason: z.string().describe('Why that rail.'),
        partner: z.string().describe('The payment partner it went to.'),
        partnerLegalEntityId: z.string().describe('The licensed partner’s legal-entity reference, as sealed with it.'),
        partnerLicenceRef: z.string().describe('The licensed partner’s licence reference, as sealed with it.'),
        paymentReference: z.string().describe('The payment reference the bank received.'),
        intentHash: z.string().describe('The normalized instruction’s hash, as sealed with it.'),
        createdAt: z.iso.datetime().describe('When it was made.'),
      })
      .describe(
        'The instruction handed off, with the licensed partner’s public references; never its payee’s reference or its consent.',
      ),
    id: z.uuid().describe('The payment, by its ID.'),
    status: z.enum(TRANSACTION.states).describe('Its canonical outcome as it stands.'),
    partnerReference: z.string().nullable().describe('The partner’s reference for it, or null until given.'),
    bankStatus: z.string().nullable().describe('The partner’s own word for where it stands, or null until given.'),
    rejectCode: z.string().nullable().describe('The reject code the partner gave, or null.'),
    bankChangedAt: z.iso.datetime().nullable().describe('When the partner says it last changed, or null.'),
    createdAt: z.iso.datetime().describe('When it was handed off.'),
    changedAt: z.iso.datetime().describe('When it last moved, as its signed record says.'),
    reconciliation: z
      .object({
        contradicted: z.boolean().describe('Settled, and the bank’s latest word still contradicts it.'),
        markableFrom: z.iso
          .datetime()
          .nullable()
          .describe('For an UNKNOWN payment, when an admin may propose marking it failed; else null.'),
        openProposalId: z
          .uuid()
          .nullable()
          .describe('A proposal to mark it failed waiting for a second admin, or null.'),
      })
      .describe('Where its reconciliation stands: UNKNOWN and contradicted payments are its exceptions.'),
  })
  .nullable()
  .describe('Its payment once handed off; null for one never handed off (denied, waiting, cancelled, expired).');

const EVIDENCE = z
  .object({
    id: z.uuid().describe('This download’s own record in the audit log (`spend_request.evidence_exported`).'),
    recordSeq: SEQ.describe('The download’s own record’s place in the chain: a retry with its key answers the same.'),
    upToSeq: SEQ.describe(
      'The moment the bundle holds at: every row in it as it stood then, and every event about them up to and including this one. At least `recordSeq`; a retry reads the request as it stands then, so it may be later.',
    ),
    spendRequest: REQUEST_EVIDENCE,
    agent: z
      .object({
        id: z.uuid().describe('The AI agent that asked, by its ID.'),
        name: z.string().describe('The name the team gave it.'),
        keyId: z.uuid().nullable().describe('The agent key it asked with, by its ID (never the key itself).'),
      })
      .describe('Who asked.'),
    mandate: z
      .object({
        id: z.uuid().describe('The mandate it was weighed against.'),
        versionId: z
          .uuid()
          .nullable()
          .describe('The mandate’s version it was weighed against (or carried to while waiting).'),
        acceptance: basisEvent('The signed acceptance of that version, as the log holds it; null if none is found.'),
      })
      .nullable()
      .describe('The mandate it was weighed against; null when the agent had none in force.'),
    policies: z
      .object({
        organizationPolicyVersionId: z
          .uuid()
          .nullable()
          .describe('The organisation’s policy version it was weighed under.'),
        mandatePolicyVersionId: z.uuid().nullable().describe('The mandate’s policy version it was weighed under.'),
      })
      .describe('The policy versions its decision applied.'),
    supplier: z
      .object({
        id: z.uuid().describe('The supplier to pay.'),
        name: z.string().describe('The name its current verified details give it.'),
        version: z
          .object({
            id: z.uuid().describe('The supplier’s details it was decided under, by their ID.'),
            number: z.int().describe('Those details’ version number.'),
            name: z.string().describe('The name those details gave it.'),
            verification: basisEvent(
              'The signed verification of those details, as the log holds it; null if they were never verified as such.',
            ),
          })
          .describe('The supplier’s details it was decided under.'),
      })
      .describe('The supplier, never its payee’s reference or account.'),
    fundingSource: z
      .object({
        id: z.uuid().describe('The bank account it pays from, by its ID.'),
        holderName: z.string().describe('The account holder’s name, as the partner gave it.'),
        hint: z
          .string()
          .describe('The country and the account number’s last four characters, masked, such as `AE…6026`.'),
        partner: z.string().describe('The payment partner the account is linked through.'),
      })
      .describe('The funding source chosen, as the console shows it: never its consent or full account number.'),
    approval: z
      .object(PERSON_DECISION)
      .nullable()
      .describe('A person’s approval, from its signed event; null if none approved it.'),
    rejection: z
      .object({ ...PERSON_DECISION, reason: z.string().describe('Their reason, as they wrote it.') })
      .nullable()
      .describe('A person’s reject, from its signed event; null if none rejected it.'),
    voiding: z
      .object({
        eventId: z.uuid().describe('Its signed event in the log (in `events`).'),
        at: z.iso.datetime().describe('When, as its signed event seals it.'),
        reasons: REASONS.describe('Why: what it was decided under that stopped.'),
      })
      .nullable()
      .describe('Its void, when what it was decided under stopped before it was paid; else null.'),
    reservation: z
      .object({
        state: z
          .enum(RESERVATION.states)
          .describe(
            'Where the reservation stands: HELD, FINALISED (paid), RELEASED, or BLOCKED_UNKNOWN (outcome unknown).',
          ),
        amountMinor: z.number().describe('The amount it holds, in whole minor units.'),
        currency: z.string().describe('Its currency.'),
        month: z.string().describe('The agent’s month it counts in.'),
        reservedAt: z.iso.datetime().describe('When it was taken.'),
      })
      .nullable()
      .describe(
        'The limit reservation, as the holdings check judges it; null for a request that never held one (denied).',
      ),
    payment: PAYMENT_EVIDENCE,
    events: z
      .array(LOG_EVENT)
      .describe(
        'Every signed event about the request and its objects (its downloads, instruction, payment, the payment’s alerts, remittance and failure proposals), oldest first, with their chain hashes: the platform’s seals left out.',
      ),
  })
  .register(API_SCHEMAS, {
    id: 'SpendRequestEvidence',
    description:
      'A spend request’s evidence, whole: what was asked, decided and done, and every signed event about it.',
  });

const EVIDENCE_SCHEMA = {
  summary: 'Download a spend request’s evidence, whole: the download is itself logged',
  params: z.object({ id: z.uuid().describe('The spend request, by its ID.') }),
  body: NOTHING,
  response: {
    201: z.object({ evidence: EVIDENCE }).describe('The evidence, the download recorded in the log first.'),
  },
};

/** The evidence's route. Without `evidence` it is still documented, and no one reaches it. */
export function registerSpendRequestEvidence(
  app: FastifyInstance,
  { evidence }: { evidence: SpendRequestEvidence | undefined },
): void {
  const routes = app.withTypeProvider<ZodTypeProvider>();

  routes.post(
    '/v1/spend-requests/:id/evidence-exports',
    {
      schema: EVIDENCE_SCHEMA,
      bodyLimit: NOTHING_BODY_LIMIT,
      config: { access: [...EXPORTING_ROLES], operation: EVIDENCE_OPERATION },
    },
    async (request, reply) => {
      const member = memberInSessionOf(request);
      const written = await need(evidence).export(
        member,
        idempotentRequest(request, member.orgId),
        request.params.id,
        request.id,
      );
      if (written.outcome !== 'exported') return answerRefusal(written, request, reply);
      return reply.code(201).send({ evidence: written.evidence });
    },
  );
}
